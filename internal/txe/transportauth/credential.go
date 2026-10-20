// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package transportauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/flock"

	"github.com/dagucloud/dagu/v2/internal/cmn/fileutil"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
)

// CredentialSchema is the version of the machine credential file.
const CredentialSchema = 1

const (
	// RenewBefore is how long before its expiry an access token is replaced.
	RenewBefore = time.Minute

	maxTokenResponseBytes = 64 << 10
	// maxExpiresInSeconds bounds what is parsed; anything above the hub's
	// lifetime cap is refused afterwards anyway.
	maxExpiresInSeconds = 24 * 60 * 60
	defaultHTTPTimeout  = 30 * time.Second

	// saveRetryInterval is how often a source tries again to save a rotated
	// refresh token that it could not save.
	saveRetryInterval = 10 * time.Second
	// fileLockRetryDelay is how often a renewal waiting for another process
	// to finish its own renewal tries the lock again.
	fileLockRetryDelay = 20 * time.Millisecond
	// fileLockWait bounds that wait: longer than one renewal takes, so a
	// renewal in progress is waited for, and short enough that a process
	// holding the lock over an unsaved rotation is reported as an outage.
	fileLockWait = defaultHTTPTimeout + 15*time.Second
)

var (
	// ErrRevoked means the provider refused to renew the machine's
	// credential: the owner was disabled, the grant or session ended, or the
	// machine's client was disabled. It does not change until the machine is
	// enrolled again; the worker must stop and say so.
	ErrRevoked = errors.New("transportauth: the identity provider refused this machine's credential; enrol the machine again")
	// ErrProviderUnavailable means the provider could not be asked, or gave
	// no verdict, and no unexpired access token is held. It is not a
	// refusal; the caller retries later. Nothing is accepted meanwhile.
	ErrProviderUnavailable = errors.New("transportauth: the identity provider did not answer and no unexpired token is held")

	errNoOwnerOnlyFiles   = errors.New("transportauth: a machine credential cannot be kept on Windows: this package cannot check there that only its owner can read it")
	errCredentialReplaced = errors.New("transportauth: the machine credential file now holds a different credential; restart the worker")
)

// syncCredentialDir makes a rename in the credential file's directory
// durable. It is a variable so a test can make it fail.
var syncCredentialDir = fileutil.SyncDir

// revokingErrors are the OAuth error codes that are a verdict on the
// machine's credential. Every other code says nothing about it.
var revokingErrors = map[string]bool{
	"invalid_grant":  true,
	"not_allowed":    true,
	"invalid_client": true,
}

// MachineCredential is what an enrolled machine holds: the offline refresh
// token its owner obtained for it through the provider client that exists
// for this machine and class. The enrolment command writes it; the worker
// reads it and writes back a rotated refresh token. It never leaves the
// machine, and the hub never sees the refresh token.
type MachineCredential struct {
	Schema        int    `json:"schema"`
	Issuer        string `json:"issuer"`
	TokenEndpoint string `json:"token_endpoint"`
	// ClientID is the public provider client of this machine and class.
	ClientID string `json:"client_id"`
	// Class is "worker".
	Class     authn.Class `json:"class"`
	MachineID string      `json:"machine_id"`
	// RefreshToken is the offline refresh token. It is never logged.
	RefreshToken string `json:"refresh_token"`
}

// String hides the refresh token from anything that prints the credential.
func (c MachineCredential) String() string {
	return fmt.Sprintf("machine credential{machine %s, class %s, client %s}", c.MachineID, c.Class, c.ClientID)
}

// GoString is String, so %#v hides the refresh token as well.
func (c MachineCredential) GoString() string { return c.String() }

// Format prints String for every verb, so no verb prints the refresh token.
func (c MachineCredential) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// LogValue keeps the refresh token out of structured logs.
func (c MachineCredential) LogValue() slog.Value { return slog.StringValue(c.String()) }

// sameEnrolment reports whether two credentials are for the same machine,
// client and provider, whatever their refresh tokens.
func (c MachineCredential) sameEnrolment(other MachineCredential) bool {
	c.RefreshToken, other.RefreshToken = "", ""
	return c == other
}

// Validate checks that the credential is complete and is a machine's: a
// worker's, which the worker presents to the coordinator, or a reviewer's,
// which the reviewer's steps present to the hub (TXE-4733). The coordinator
// takes only a worker's.
func (c MachineCredential) Validate() error {
	if c.Schema != CredentialSchema {
		return fmt.Errorf("transportauth: machine credential schema %d is not %d", c.Schema, CredentialSchema)
	}
	if !c.Class.Machine() {
		return fmt.Errorf("transportauth: machine credential class %q is not %q or %q", c.Class, authn.ClassWorker, authn.ClassReviewer)
	}
	for name, value := range map[string]string{
		"issuer": c.Issuer, "client_id": c.ClientID, "machine_id": c.MachineID, "refresh_token": c.RefreshToken,
	} {
		if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
			return fmt.Errorf("transportauth: machine credential %s is missing or has surrounding space", name)
		}
	}
	endpoint, err := url.Parse(c.TokenEndpoint)
	if err != nil || endpoint.Host == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return errors.New("transportauth: machine credential token_endpoint is not an absolute URL")
	}
	if endpoint.Scheme != "https" && (endpoint.Scheme != "http" || !isLoopback(endpoint.Host)) {
		return errors.New("transportauth: machine credential token_endpoint must use https, or http to a loopback address")
	}
	return nil
}

// ReadMachineCredential reads a credential file. The file must be a regular
// file that only its owner can read or write. It is refused on Windows,
// where that cannot be checked.
func ReadMachineCredential(path string) (MachineCredential, error) {
	if runtime.GOOS == "windows" {
		return MachineCredential{}, errNoOwnerOnlyFiles
	}
	info, err := os.Lstat(path)
	if err != nil {
		return MachineCredential{}, fmt.Errorf("transportauth: read machine credential: %w", err)
	}
	if !info.Mode().IsRegular() {
		return MachineCredential{}, errors.New("transportauth: the machine credential is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return MachineCredential{}, fmt.Errorf("transportauth: the machine credential file has mode %#o; it must be readable by its owner only (0600)", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the path is the operator's configured credential file
	if err != nil {
		return MachineCredential{}, fmt.Errorf("transportauth: read machine credential: %w", err)
	}
	var credential MachineCredential
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credential); err != nil {
		return MachineCredential{}, errors.New("transportauth: the machine credential is not valid JSON of the expected shape")
	}
	if decoder.More() {
		return MachineCredential{}, errors.New("transportauth: the machine credential has trailing data")
	}
	if err := credential.Validate(); err != nil {
		return MachineCredential{}, err
	}
	return credential, nil
}

// WriteMachineCredential replaces a credential file atomically and durably,
// readable by its owner only. It is refused on Windows, where owner-only
// access cannot be set by a file mode.
func WriteMachineCredential(path string, credential MachineCredential) error {
	_, err := writeMachineCredential(path, credential)
	return err
}

// writeMachineCredential is WriteMachineCredential that also says whether
// the new file was renamed into place, which it can be although the
// directory sync after it failed.
func writeMachineCredential(path string, credential MachineCredential) (renamed bool, err error) {
	if runtime.GOOS == "windows" {
		return false, errNoOwnerOnlyFiles
	}
	if err := credential.Validate(); err != nil {
		return false, err
	}
	raw, err := json.MarshalIndent(credential, "", "  ") //nolint:gosec // writing the refresh token to its owner-only file is the point
	if err != nil {
		return false, err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return false, fmt.Errorf("transportauth: write machine credential: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("transportauth: write machine credential: %w", err)
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("transportauth: write machine credential: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("transportauth: write machine credential: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("transportauth: write machine credential: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return false, fmt.Errorf("transportauth: write machine credential: %w", err)
	}
	committed = true
	if err := syncCredentialDir(dir); err != nil {
		return true, fmt.Errorf("transportauth: write machine credential: the directory could not be synced: %w", err)
	}
	return true, nil
}

// RefreshingSource gives a worker machine's access token, renewing it from
// the machine's refresh token at the provider. It is safe for concurrent
// use. One renewal runs at a time in a process, and, through a lock file
// beside the credential file, one at a time among the processes sharing
// that file.
type RefreshingSource struct {
	path      string
	machineID string
	client    *http.Client
	now       func() time.Time
	fileLock  *flock.Flock
	// renewing holds one token while a renewal runs in this process.
	renewing chan struct{}
	// state holds the secrets and the lock that guards them.
	state *sourceState
}

type sourceState struct {
	mu         sync.Mutex
	credential MachineCredential
	access     string
	expires    time.Time
	revoked    bool
	// replaced is set once the credential file is found to hold another
	// enrolment. Like revoked, it does not change.
	replaced bool
	// inFile is the refresh token this source last knew the credential
	// file to hold: the one it read there, or the last one it renamed into
	// place.
	inFile string
	// unsaved is set while the file may not durably hold the credential's
	// refresh token; saveAfter is when saving is tried again.
	unsaved   error
	saveAfter time.Time
}

// SourceOption configures a RefreshingSource.
type SourceOption func(*RefreshingSource)

// WithHTTPClient sets the client used for the token endpoint. Redirects are
// never followed, whatever the client says.
func WithHTTPClient(client *http.Client) SourceOption {
	return func(s *RefreshingSource) {
		if client != nil {
			s.client = client
		}
	}
}

// WithSourceClock sets the clock.
func WithSourceClock(now func() time.Time) SourceOption {
	return func(s *RefreshingSource) {
		if now != nil {
			s.now = now
		}
	}
}

// NewRefreshingSource reads the machine credential at path. It does not
// contact the provider.
func NewRefreshingSource(path string, opts ...SourceOption) (*RefreshingSource, error) {
	credential, err := ReadMachineCredential(path)
	if err != nil {
		return nil, err
	}
	s := &RefreshingSource{
		path:      path,
		machineID: credential.MachineID,
		client:    &http.Client{Timeout: defaultHTTPTimeout},
		now:       time.Now,
		fileLock:  flock.New(path + ".lock"),
		renewing:  make(chan struct{}, 1),
		state:     &sourceState{credential: credential, inFile: credential.RefreshToken},
	}
	for _, opt := range opts {
		opt(s)
	}
	client := *s.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s.client = &client
	return s, nil
}

// Format prints the machine and nothing secret, for every verb, for the
// source and a pointer to it.
func (s RefreshingSource) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "transportauth.RefreshingSource{machine %s}", s.machineID)
}

// MachineID returns the machine the credential is for, as the enrolment
// command recorded it. The hub decides the machine from the credential
// itself; this is what the worker names itself with.
func (s *RefreshingSource) MachineID() string { return s.machineID }

// Unsaved returns why a rotated refresh token is held only in memory, or nil
// when the credential file is current. While it is not nil, a restart loses
// the machine's credential; the worker should report it.
func (s *RefreshingSource) Unsaved() error {
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	return s.state.unsaved
}

// Token implements TokenSource. It returns a token only while it is
// unexpired, by the clock read when it returns.
func (s *RefreshingSource) Token(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if token, done, err := s.cached(); done {
		return token, err
	}
	select {
	case s.renewing <- struct{}{}:
	case <-ctx.Done():
		return s.unexpiredOr(ctx.Err())
	}
	defer func() { <-s.renewing }()

	lockCtx, cancel := context.WithTimeout(ctx, fileLockWait)
	locked, err := s.fileLock.TryLockContext(lockCtx, fileLockRetryDelay)
	cancel()
	if err != nil || !locked {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return s.unexpiredOr(ctxErr)
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return s.unexpiredOr(fmt.Errorf("%w: another worker process holds the machine credential", ErrProviderUnavailable))
		}
		return s.unexpiredOr(fmt.Errorf("transportauth: the machine credential cannot be locked for renewal: %w", err))
	}
	defer func() {
		// While a rotated refresh token is unsaved, this source keeps the
		// lock, so no other process presents the token it rotated away from.
		if s.Unsaved() == nil {
			_ = s.fileLock.Unlock()
		}
	}()

	// The file is settled first: a rotation this source could not save, or
	// one another process made, decides which refresh token is presented.
	if err := s.reconcile(); err != nil {
		return s.unexpiredOr(err)
	}
	// Another caller may have renewed while this one waited, or only a save
	// was due.
	if token, done, err := s.cached(); done {
		return token, err
	}
	s.state.mu.Lock()
	credential := s.state.credential
	s.state.mu.Unlock()

	startedAt := s.now()
	answer, err := s.exchange(ctx, credential)
	return s.install(startedAt, answer, err)
}

// cached returns the held token when no renewal is due. done is false when
// the caller must renew, or retry a save.
func (s *RefreshingSource) cached() (token string, done bool, err error) {
	st := s.state
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.revoked {
		return "", true, ErrRevoked
	}
	if st.replaced {
		return "", true, errCredentialReplaced
	}
	now := s.now()
	if st.unsaved != nil && !now.Before(st.saveAfter) {
		return "", false, nil
	}
	if st.access != "" && now.Add(RenewBefore).Before(st.expires) {
		return st.access, true, nil
	}
	return "", false, nil
}

// unexpiredOr returns the held token while it is unexpired, and err
// otherwise.
func (s *RefreshingSource) unexpiredOr(err error) (string, error) {
	st := s.state
	st.mu.Lock()
	defer st.mu.Unlock()
	if !st.revoked && !st.replaced && st.access != "" && s.now().Before(st.expires) {
		return st.access, nil
	}
	return "", err
}

// reconcile brings this source and the credential file into agreement. The
// caller holds the renewal slot and the file lock; the file is read and
// written without state.mu held.
//
//   - The file holds this source's refresh token: if it was recorded as
//     unsaved, the rename landed, and only the directory sync is retried.
//   - The file holds the refresh token this source last knew to be there,
//     and this source holds a newer one it could not save: the save is
//     retried.
//   - The file holds any other refresh token of the same enrolment: another
//     process rotated it, and this source adopts it. Nothing is written.
//   - The file holds another enrolment, or cannot be read: it is refused
//     and kept. Only a file that does not exist is written anew.
func (s *RefreshingSource) reconcile() error {
	st := s.state
	st.mu.Lock()
	held, inFile, unsaved := st.credential, st.inFile, st.unsaved != nil
	st.mu.Unlock()

	onDisk, readErr := ReadMachineCredential(s.path)
	switch {
	case readErr != nil && unsaved && errors.Is(readErr, fs.ErrNotExist):
		s.save(held)
	case readErr != nil:
		return readErr
	case !onDisk.sameEnrolment(held):
		// This source can no longer make progress. Nothing is written over
		// the new enrolment, and the pending save is dropped so the file
		// lock is released.
		st.mu.Lock()
		st.replaced = true
		st.access, st.expires = "", time.Time{}
		st.unsaved, st.saveAfter = nil, time.Time{}
		st.mu.Unlock()
		return errCredentialReplaced
	case onDisk.RefreshToken == held.RefreshToken:
		st.mu.Lock()
		st.inFile = held.RefreshToken
		st.mu.Unlock()
		if unsaved {
			s.recordSave(held.RefreshToken, false, syncCredentialDir(filepath.Dir(s.path)))
		}
	case unsaved && onDisk.RefreshToken == inFile:
		s.save(held)
	default:
		st.mu.Lock()
		st.credential, st.inFile = onDisk, onDisk.RefreshToken
		st.unsaved, st.saveAfter = nil, time.Time{}
		st.mu.Unlock()
	}
	return nil
}

// save writes credential, the held one, to the file and records the outcome.
func (s *RefreshingSource) save(credential MachineCredential) {
	renamed, err := writeMachineCredential(s.path, credential)
	s.recordSave(credential.RefreshToken, renamed, err)
}

// recordSave records the outcome of saving refresh, the held refresh token:
// whether it was renamed into the file, and whether the save is complete.
func (s *RefreshingSource) recordSave(refresh string, renamed bool, err error) {
	st := s.state
	st.mu.Lock()
	defer st.mu.Unlock()
	if renamed {
		st.inFile = refresh
	}
	if err != nil {
		st.unsaved = fmt.Errorf("transportauth: a renewed refresh token could not be saved: %w", err)
		st.saveAfter = s.now().Add(saveRetryInterval)
		return
	}
	st.unsaved, st.saveAfter = nil, time.Time{}
}

// install records the outcome of a renewal and decides what Token returns.
// The caller holds the renewal slot and the file lock.
func (s *RefreshingSource) install(startedAt time.Time, answer renewal, err error) (string, error) {
	st := s.state
	var rotated *MachineCredential
	st.mu.Lock()
	if err == nil {
		// The expiry is counted from before the request was sent, so it is
		// never later than the provider's.
		st.access, st.expires = answer.access, startedAt.Add(answer.lifetime)
	}
	if answer.refresh != "" && answer.refresh != st.credential.RefreshToken {
		// The provider may already have retired the old refresh token, so
		// the new one is kept, in memory even when it cannot be saved, and
		// also when the access token of the same answer is refused.
		st.credential.RefreshToken = answer.refresh
		next := st.credential
		rotated = &next
	}
	st.mu.Unlock()
	if rotated != nil {
		s.save(*rotated)
	}

	st.mu.Lock()
	defer st.mu.Unlock()
	now := s.now()
	switch {
	case err == nil:
		if now.Before(st.expires) {
			return st.access, nil
		}
		st.access, st.expires = "", time.Time{}
		return "", fmt.Errorf("%w: the renewed token expired before it could be used", ErrProviderUnavailable)
	case errors.Is(err, ErrRevoked):
		// A revoked credential has nothing left to save; dropping the
		// pending save releases the file lock to other processes.
		st.revoked = true
		st.access, st.expires = "", time.Time{}
		st.unsaved, st.saveAfter = nil, time.Time{}
		return "", err
	default:
		// The provider gave no verdict. A token that has not expired is
		// still what the hub would accept; one that has is never used.
		if st.access != "" && now.Before(st.expires) {
			return st.access, nil
		}
		st.access, st.expires = "", time.Time{}
		return "", err
	}
}

// renewal is a token endpoint's usable answer.
type renewal struct {
	access   string
	lifetime time.Duration
	refresh  string
}

// tokenResponse is the provider's answer to a refresh.
type tokenResponse struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	ExpiresIn    json.RawMessage `json:"expires_in"`
	RefreshToken string          `json:"refresh_token"`
	Error        *string         `json:"error"`
}

// exchange asks the provider for a new access token.
func (s *RefreshingSource) exchange(ctx context.Context, credential MachineCredential) (renewal, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {credential.ClientID},
		"refresh_token": {credential.RefreshToken},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, credential.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return renewal{}, fmt.Errorf("%w: the token request could not be built", ErrProviderUnavailable)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return renewal{}, fmt.Errorf("%w: the token endpoint could not be reached", ErrProviderUnavailable)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes+1))
	if err != nil || len(body) > maxTokenResponseBytes {
		return renewal{}, fmt.Errorf("%w: the token endpoint's answer could not be read", ErrProviderUnavailable)
	}

	var answer tokenResponse
	isJSON := jsonContent(resp.Header.Get("Content-Type")) && json.Unmarshal(body, &answer) == nil

	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
		// A refusal is a verdict only when the provider names one of the
		// revoking codes in an OAuth error body. Anything else, a proxy's
		// page or a transient OAuth error included, says nothing about the
		// credential.
		if isJSON && answer.Error != nil && revokingErrors[*answer.Error] {
			return renewal{}, fmt.Errorf("%w (%s)", ErrRevoked, *answer.Error)
		}
		if isJSON && answer.Error != nil && *answer.Error != "" {
			return renewal{}, fmt.Errorf("%w: HTTP %d with OAuth error %s", ErrProviderUnavailable, resp.StatusCode, oauthErrorCode(*answer.Error))
		}
		return renewal{}, fmt.Errorf("%w: HTTP %d without an OAuth error", ErrProviderUnavailable, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return renewal{}, fmt.Errorf("%w: HTTP %d", ErrProviderUnavailable, resp.StatusCode)
	}
	if !isJSON {
		return renewal{}, fmt.Errorf("%w: the token endpoint's answer is not a bearer token", ErrProviderUnavailable)
	}
	// A successful answer may rotate the refresh token even when its access
	// token cannot be used; the rotation is kept either way.
	rotated := renewal{refresh: answer.RefreshToken}
	if answer.AccessToken == "" || !strings.EqualFold(answer.TokenType, "Bearer") {
		return rotated, fmt.Errorf("%w: the token endpoint's answer is not a bearer token", ErrProviderUnavailable)
	}
	lifetime, ok := expiresIn(answer.ExpiresIn)
	if !ok || lifetime <= 0 {
		return rotated, fmt.Errorf("%w: the token endpoint's answer has no usable expiry", ErrProviderUnavailable)
	}
	if lifetime > authn.MaxTokenLifetime {
		// The hub refuses such a token; holding it would only fail later.
		return rotated, fmt.Errorf("%w: the provider issued a token living longer than %s; the machine's client must be limited to it",
			ErrProviderUnavailable, authn.MaxTokenLifetime)
	}
	return renewal{access: answer.AccessToken, lifetime: lifetime, refresh: answer.RefreshToken}, nil
}

func jsonContent(contentType string) bool {
	media, _, err := mime.ParseMediaType(contentType)
	return err == nil && (media == "application/json" || strings.HasSuffix(media, "+json"))
}

// expiresIn reads "expires_in", a number of seconds that some providers send
// as a string.
func expiresIn(raw json.RawMessage) (time.Duration, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	text := strings.Trim(string(raw), `"`)
	seconds, err := strconv.ParseInt(text, 10, 64)
	if err != nil || seconds <= 0 || seconds > maxExpiresInSeconds {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

// oauthErrorCode returns an OAuth error code fit to show: the code if it is
// one of the registered shape, otherwise a placeholder.
func oauthErrorCode(code string) string {
	if len(code) > 64 {
		return "provider_error"
	}
	for _, r := range code {
		if (r < 'a' || r > 'z') && r != '_' {
			return "provider_error"
		}
	}
	return code
}
