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
)

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

// Validate checks that the credential is complete and usable by a worker.
func (c MachineCredential) Validate() error {
	if c.Schema != CredentialSchema {
		return fmt.Errorf("transportauth: machine credential schema %d is not %d", c.Schema, CredentialSchema)
	}
	if c.Class != authn.ClassWorker {
		return fmt.Errorf("transportauth: machine credential class %q is not %q", c.Class, authn.ClassWorker)
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
// file that only its owner can read or write.
func ReadMachineCredential(path string) (MachineCredential, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return MachineCredential{}, fmt.Errorf("transportauth: read machine credential: %w", err)
	}
	if !info.Mode().IsRegular() {
		return MachineCredential{}, errors.New("transportauth: the machine credential is not a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
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

// WriteMachineCredential replaces a credential file atomically, readable by
// its owner only.
func WriteMachineCredential(path string, credential MachineCredential) error {
	if err := credential.Validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(credential, "", "  ") //nolint:gosec // writing the refresh token to its owner-only file is the point
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("transportauth: write machine credential: %w", err)
	}
	tmpName := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		_ = tmp.Close()
		return fmt.Errorf("transportauth: write machine credential: %w", err)
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("transportauth: write machine credential: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("transportauth: write machine credential: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("transportauth: write machine credential: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("transportauth: write machine credential: %w", err)
	}
	committed = true
	return nil
}

// RefreshingSource gives a worker machine's access token, renewing it from
// the machine's refresh token at the provider. It is safe for concurrent
// use; one renewal runs at a time.
type RefreshingSource struct {
	path   string
	client *http.Client
	now    func() time.Time

	mu         sync.Mutex
	credential MachineCredential
	access     string
	expires    time.Time
	revoked    bool
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
		path:       path,
		client:     &http.Client{Timeout: defaultHTTPTimeout},
		now:        time.Now,
		credential: credential,
	}
	for _, opt := range opts {
		opt(s)
	}
	client := *s.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s.client = &client
	return s, nil
}

// MachineID returns the machine the credential is for, as the enrolment
// command recorded it. The hub decides the machine from the credential
// itself; this is what the worker names itself with.
func (s *RefreshingSource) MachineID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.credential.MachineID
}

// Token implements TokenSource.
func (s *RefreshingSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked {
		return "", ErrRevoked
	}
	now := s.now()
	if s.access != "" && now.Add(RenewBefore).Before(s.expires) {
		return s.access, nil
	}
	err := s.renew(ctx, now)
	switch {
	case err == nil:
		return s.access, nil
	case errors.Is(err, ErrRevoked):
		s.revoked = true
		s.access, s.expires = "", time.Time{}
		return "", err
	default:
		// The provider gave no verdict. A token that has not expired is
		// still what the hub would accept; one that has is never used.
		if s.access != "" && now.Before(s.expires) {
			return s.access, nil
		}
		s.access, s.expires = "", time.Time{}
		return "", err
	}
}

// tokenResponse is the provider's answer to a refresh.
type tokenResponse struct {
	AccessToken  string          `json:"access_token"`
	TokenType    string          `json:"token_type"`
	ExpiresIn    json.RawMessage `json:"expires_in"`
	RefreshToken string          `json:"refresh_token"`
	Error        *string         `json:"error"`
}

// renew asks the provider for a new access token. It is called with s.mu
// held.
func (s *RefreshingSource) renew(ctx context.Context, startedAt time.Time) error {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {s.credential.ClientID},
		"refresh_token": {s.credential.RefreshToken},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.credential.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("%w: %s", ErrProviderUnavailable, "the token request could not be built")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: the token endpoint could not be reached", ErrProviderUnavailable)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseBytes+1))
	if err != nil || len(body) > maxTokenResponseBytes {
		return fmt.Errorf("%w: the token endpoint's answer could not be read", ErrProviderUnavailable)
	}

	var answer tokenResponse
	isJSON := jsonContent(resp.Header.Get("Content-Type")) && json.Unmarshal(body, &answer) == nil

	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
		// A refusal is a verdict only when the provider says so in an
		// OAuth error body. Anything else, a proxy's page included, says
		// nothing about the credential.
		if isJSON && answer.Error != nil && *answer.Error != "" {
			return fmt.Errorf("%w (%s)", ErrRevoked, oauthErrorCode(*answer.Error))
		}
		return fmt.Errorf("%w: HTTP %d without an OAuth error", ErrProviderUnavailable, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: HTTP %d", ErrProviderUnavailable, resp.StatusCode)
	}
	if !isJSON || answer.AccessToken == "" || !strings.EqualFold(answer.TokenType, "Bearer") {
		return fmt.Errorf("%w: the token endpoint's answer is not a bearer token", ErrProviderUnavailable)
	}
	lifetime, ok := expiresIn(answer.ExpiresIn)
	if !ok || lifetime <= 0 {
		return fmt.Errorf("%w: the token endpoint's answer has no usable expiry", ErrProviderUnavailable)
	}
	if lifetime > authn.MaxTokenLifetime {
		// The hub refuses such a token; holding it would only fail later.
		return fmt.Errorf("%w: the provider issued a token living longer than %s; the machine's client must be limited to it",
			ErrProviderUnavailable, authn.MaxTokenLifetime)
	}

	if answer.RefreshToken != "" && answer.RefreshToken != s.credential.RefreshToken {
		next := s.credential
		next.RefreshToken = answer.RefreshToken
		if err := WriteMachineCredential(s.path, next); err != nil {
			// The provider may already have retired the old refresh token.
			// Keep the new one in memory so this process keeps working,
			// and report that the file is stale.
			s.credential = next
			s.access, s.expires = answer.AccessToken, startedAt.Add(lifetime)
			return fmt.Errorf("transportauth: a renewed refresh token could not be saved: %w", err)
		}
		s.credential = next
	}
	// The expiry is counted from before the request was sent, so it is never
	// later than the provider's.
	s.access, s.expires = answer.AccessToken, startedAt.Add(lifetime)
	return nil
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
