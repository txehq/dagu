// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/spf13/cobra"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/cliauth"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
)

var (
	txeEnrolClientFlag = commandLineFlag{name: "client-id",
		usage: "This machine's own worker client at the identity provider, as the hub's administrator created it"}
	txeEnrolIssuerFlag = commandLineFlag{name: "issuer",
		usage: "Identity provider issuer URL, exactly as the provider states it (default: the hub's)"}
	txeEnrolFileFlag = commandLineFlag{name: "credential-file",
		usage: "Where the worker's credential is written (default: worker-credential.json in the TXE home)"}
	txeEnrolWaitFlag = commandLineFlag{name: "wait", defaultValue: "0",
		usage: `How long to keep the application live, re-applying each minute, until a person of the owner approves it (for example "15m"; 0 applies once)`}
	txeEnrolResumeFlag = commandLineFlag{name: "resume", isBool: true,
		usage: "Apply again with the credential already written, without signing in"}
)

// txeEnrolCredentialFile is the worker credential's default name in the TXE
// home.
const txeEnrolCredentialFile = "worker-credential.json" //nolint:gosec // a file name, not a credential

// txeEnrolLockWait bounds the wait for a worker that holds the credential's
// lock: longer than one of its renewals takes.
var txeEnrolLockWait = 45 * time.Second

// txeEnrolInterval is how often a waiting enrolment applies again. The hub
// takes an application at most once a minute.
var txeEnrolInterval = time.Minute

func init() {
	txeSubcommands = append(txeSubcommands, txeEnrolCommand)
}

func txeEnrolCommand() *cobra.Command {
	cmd := NewCommand(&cobra.Command{
		Use:   "enrol",
		Short: "Enrol this machine's worker with the hub through its owner's browser sign-in",
		Long: `Give this machine's worker its own credential, then apply to the hub to enrol it.

A person of the machine's owner signs in through the system browser at the
machine's own worker client (authorization code with PKCE, as "dagu txe login"
does). The provider's offline refresh token is written to the credential file,
readable by this user only. The worker reads it from worker.auth.credential_file
and renews its access tokens from it; the hub never sees it. The provider must
issue access tokens living at most 5 minutes: a longer one is refused and the
sign-in revoked.

The command then applies to the hub with the worker's own token. The
application grants nothing: a person of the machine's owner approves it in the
hub, naming the class, client, issuer and subject this command prints. An
application is live only while its token is, so --wait keeps applying each
minute until the hub reports the machine enrolled. --resume applies again with
the credential already written, without signing in. "dagu txe enrol check"
only loads the credential file the way the worker does.

A worker that is renewing holds the credential's lock; the credential is
written only once the lock is free. Not on Windows, where the worker cannot
check that only its owner reads the file.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeEnrolClientFlag, txeEnrolIssuerFlag, txeEnrolFileFlag, txeEnrolWaitFlag, txeEnrolResumeFlag,
		txeLoginPromptFlag, txeLoginNoBrowser, txeJSONFlag}, runTXEEnrol)
	cmd.AddCommand(txeEnrolCheckCommand())
	return cmd
}

func txeEnrolCheckCommand() *cobra.Command {
	return NewCommand(&cobra.Command{
		Use:   "check",
		Short: "Check that the worker can load this machine's credential file",
		Long: `Load the credential file exactly as the worker does (an owner-only regular file
holding a machine credential with a usable token endpoint) and require it to be
this machine's (machine.json). It signs in nowhere and contacts nothing. The
worker installer runs it with the binary it built before it passes the file to
the worker.`,
		Args:        cobra.NoArgs,
		Annotations: map[string]string{txeLocalAnnotation: "true"},
	}, []commandLineFlag{txeEnrolFileFlag, txeJSONFlag}, runTXEEnrolCheck)
}

func runTXEEnrolCheck(ctx *Context, _ []string) error {
	home, err := txepkg.DefaultHome()
	if err != nil {
		return err
	}
	machine, err := home.Machine()
	if err != nil {
		return err
	}
	path, err := txeEnrolPath(ctx, home)
	if err != nil {
		return err
	}
	return txeEnrolCheck(ctx, machine.MachineID, path)
}

// txeEnrolView is what enrol shows. It never holds a token.
type txeEnrolView struct {
	MachineID      string               `json:"machine_id"`
	OwnerID        string               `json:"owner_id"`
	ClientID       string               `json:"client_id"`
	Issuer         string               `json:"issuer"`
	Subject        string               `json:"subject,omitempty"`
	CredentialFile string               `json:"credential_file"`
	Application    *txeEnrolApplication `json:"application,omitempty"`
	// ApproveURL is the hub page where a person of the owner approves the
	// application.
	ApproveURL string `json:"approve_url,omitempty"`
	// State is "applied" (awaiting a person's approval) or "enrolled".
	State string `json:"state"`
	// resume is the command that keeps the application live.
	resume string
}

// txeEnrolApplication is the part of the hub's TxeEnrolmentApplication
// shown.
type txeEnrolApplication struct {
	Class             string    `json:"class"`
	Issuer            string    `json:"issuer"`
	Subject           string    `json:"subject"`
	ClientID          string    `json:"client_id"`
	ReceivedAt        time.Time `json:"received_at"`
	CredentialExpires time.Time `json:"credential_expires"`
}

func runTXEEnrol(ctx *Context, _ []string) error {
	if runtime.GOOS == "windows" {
		return errors.New("a machine credential cannot be kept on Windows: the worker cannot check there that only its owner reads it")
	}
	home, err := txepkg.DefaultHome()
	if err != nil {
		return err
	}
	machine, err := home.Machine()
	if err != nil {
		return err
	}
	path, err := txeEnrolPath(ctx, home)
	if err != nil {
		return err
	}
	if txeInDAGStep() {
		return errors.New("enrolment needs a person at a browser; it never runs as a DAG step")
	}
	clientID, err := ctx.StringParam("client-id")
	if err != nil {
		return err
	}
	if clientID == "" {
		return errors.New("--client-id is required: this machine's own worker client at the identity provider")
	}
	remote, err := txeRemoteContext(ctx)
	if err != nil {
		return err
	}
	waitText, err := ctx.StringParam("wait")
	if err != nil {
		return err
	}
	wait, err := time.ParseDuration(waitText)
	if err != nil || wait < 0 {
		return fmt.Errorf("--wait %q: give a duration such as 15m, or 0", waitText)
	}
	resume, err := ctx.Command.Flags().GetBool("resume")
	if err != nil {
		return err
	}

	view := txeEnrolView{MachineID: machine.MachineID, OwnerID: machine.OwnerID, ClientID: clientID, CredentialFile: path,
		resume: "dagu txe enrol --client-id " + txeShellQuote(clientID)}
	if path != filepath.Join(home.Root, txeEnrolCredentialFile) {
		view.resume += " --credential-file " + txeShellQuote(path)
	}
	view.resume += " --resume --wait 15m"
	if !resume {
		if err := txeEnrolMachineKnown(ctx, remote, machine.MachineID); err != nil {
			return err
		}
	}
	var token string
	if resume {
		credential, err := transportauth.ReadMachineCredential(path)
		if err != nil {
			return err
		}
		if credential.Class != authn.ClassWorker {
			return fmt.Errorf("%s holds a %s credential, not this machine's worker credential: enrol again without --resume", path, credential.Class)
		}
		if credential.MachineID != machine.MachineID || credential.ClientID != clientID {
			return fmt.Errorf("%s is for machine %s and client %s, not machine %s and client %s: enrol again without --resume",
				path, credential.MachineID, credential.ClientID, machine.MachineID, clientID)
		}
		view.Issuer = credential.Issuer
	} else {
		issuer, err := txeEnrolIssuer(ctx, remote)
		if err != nil {
			return err
		}
		view.Issuer = issuer
		tokens, err := txeEnrolSignIn(ctx, cliauth.Provider{Issuer: issuer, ClientID: clientID, Scopes: []string{"offline_access"}},
			machine.MachineID, path)
		if err != nil {
			return err
		}
		view.Subject = tokens.Identity.Subject
		token = tokens.AccessToken
	}

	hub := txeEnrolHub{base: remote.baseURL, client: txeEnrolClient(remote.client), machineID: machine.MachineID}
	if token == "" || wait > 0 {
		if err := hub.await(ctx, path, wait, &view); err != nil {
			return err
		}
	} else {
		application, err := hub.apply(ctx, token)
		if err != nil {
			return err
		}
		view.Application, view.State = application, "applied"
	}
	if view.Application != nil {
		view.ApproveURL = txeEnrolApproveURL(remote.baseURL, machine.MachineID, clientID)
	}
	return txeOutput(ctx, view, func(p *txePrinter) { printEnrol(p, view) })
}

// txeEnrolApproveURL is the hub page that lists the machine's applications,
// with this one preselected: the hub's address without its API root.
func txeEnrolApproveURL(apiBase, machineID, clientID string) string {
	base := strings.TrimSuffix(strings.TrimRight(apiBase, "/"), "/api/v1")
	q := url.Values{"class": {string(authn.ClassWorker)}, "client_id": {clientID}}
	return base + "/txe/machines/" + url.PathEscape(machineID) + "?" + q.Encode()
}

// txeEnrolMachineKnown asks the hub, before anyone signs in for the
// machine, whether it knows this machine for the CLI's owner. Only a
// signed-in CLI asks: the hub answers its sign-in by owner, and 404 is
// another owner's machine or none. Without a sign-in nothing is asked.
func txeEnrolMachineKnown(ctx *Context, remote *remoteClient, machineID string) error {
	authed, err := txeHubAuth(ctx, remote)
	if err != nil {
		return err
	}
	if authed == remote {
		return nil
	}
	var out struct {
		MachineID string `json:"machine_id"`
	}
	err = authed.do(ctx, http.MethodGet, "/txe/machines/"+url.PathEscape(machineID), nil, &out, nil)
	var rerr *remoteError
	if errors.As(err, &rerr) && rerr.NotFound() {
		return fmt.Errorf("the hub has no machine %s of this sign-in's owner: run the worker installer, or sign in as a person of its owner", machineID)
	}
	if err != nil {
		return fmt.Errorf("ask the hub about machine %s: %w", machineID, err)
	}
	return nil
}

// txeEnrolChecked is what --check shows. It never holds a token.
type txeEnrolChecked struct {
	CredentialFile string `json:"credential_file"`
	MachineID      string `json:"machine_id"`
	ClientID       string `json:"client_id"`
	Issuer         string `json:"issuer"`
}

// txeEnrolCheck loads the credential exactly as the worker does
// (transportauth.ReadMachineCredential: owner-only regular file, known
// fields, a usable token endpoint) and requires it to be this machine's.
func txeEnrolCheck(ctx *Context, machineID, path string) error {
	credential, err := transportauth.ReadMachineCredential(path)
	if err != nil {
		return err
	}
	// The worker loads only a worker's credential (TXE-4733).
	if credential.Class != authn.ClassWorker {
		return fmt.Errorf("%s holds a %s credential; the worker loads only this machine's worker credential", path, credential.Class)
	}
	if credential.MachineID != machineID {
		return fmt.Errorf("%s is for machine %s, but this machine is %s", path, credential.MachineID, machineID)
	}
	view := txeEnrolChecked{CredentialFile: path, MachineID: credential.MachineID, ClientID: credential.ClientID, Issuer: credential.Issuer}
	return txeOutput(ctx, view, func(p *txePrinter) {
		p.f("credential %s: the worker can load it (machine %s, client %s at %s)\n", path, view.MachineID, view.ClientID, view.Issuer)
	})
}

// txeEnrolPath is the credential file: the flag, made absolute, or the TXE
// home's default.
func txeEnrolPath(ctx *Context, home txepkg.Home) (string, error) {
	path, err := ctx.StringParam("credential-file")
	if err != nil {
		return "", err
	}
	if path == "" {
		return filepath.Join(home.Root, txeEnrolCredentialFile), nil
	}
	return filepath.Abs(path)
}

// txeEnrolIssuer is --issuer, or the issuer the hub names for its CLI.
func txeEnrolIssuer(ctx *Context, remote *remoteClient) (string, error) {
	issuer, err := ctx.StringParam("issuer")
	if err != nil {
		return "", err
	}
	if issuer != "" {
		return issuer, nil
	}
	cfg, err := cliauth.DiscoverHub(ctx, remote.baseURL, remote.client)
	if errors.Is(err, cliauth.ErrHubNoSignIn) {
		return "", errors.New("the hub does not name its identity provider: give --issuer")
	}
	if err != nil {
		return "", err
	}
	return cfg.Issuer, nil
}

// txeEnrolSignIn signs the owner's person in at the worker client and writes
// the worker credential. A sign-in that cannot become the credential is
// revoked at the provider.
func txeEnrolSignIn(ctx *Context, p cliauth.Provider, machineID, path string) (*cliauth.Tokens, error) {
	prompt, err := ctx.StringParam("prompt")
	if err != nil {
		return nil, err
	}
	noBrowser, err := ctx.Command.Flags().GetBool("no-browser")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	opts := cliauth.AuthorizeOptions{Out: ctx.Command.ErrOrStderr(), Prompt: prompt}
	if !noBrowser {
		opts.OpenBrowser = txeOpenBrowser
	}
	tokens, err := cliauth.Authorize(ctx, p, opts)
	if err != nil {
		return nil, err
	}
	written := false
	defer func() {
		if !written {
			_, _ = revokeQuietly(ctx, &cliauth.Entry{Provider: p, RefreshToken: tokens.RefreshToken})
		}
	}()
	// The worker refuses a token living longer than the hub accepts; this
	// says so now rather than at the worker's first renewal.
	if left := time.Until(tokens.Expiry); left > authn.MaxTokenLifetime {
		return nil, fmt.Errorf("the identity provider issued an access token living %s; the worker client must be limited to %s",
			left.Round(time.Second), authn.MaxTokenLifetime)
	}
	endpoints, err := cliauth.Discover(ctx, p, nil)
	if err != nil {
		return nil, err
	}
	credential := transportauth.MachineCredential{
		Schema: transportauth.CredentialSchema, Issuer: p.Issuer, TokenEndpoint: endpoints.Token,
		ClientID: p.ClientID, Class: authn.ClassWorker, MachineID: machineID, RefreshToken: tokens.RefreshToken,
	}
	if err := txeEnrolWrite(ctx, path, credential); err != nil {
		return nil, err
	}
	written = true
	return tokens, nil
}

// txeEnrolWrite writes the credential while holding the lock a worker holds
// over its renewals, so a renewal in flight cannot save its rotated token
// over this one.
func txeEnrolWrite(ctx context.Context, path string, credential transportauth.MachineCredential) error {
	lock := flock.New(path + ".lock")
	lockCtx, cancel := context.WithTimeout(ctx, txeEnrolLockWait)
	defer cancel()
	locked, err := lock.TryLockContext(lockCtx, 50*time.Millisecond)
	if err != nil || !locked {
		if ctx.Err() == nil && (err == nil || errors.Is(err, context.DeadlineExceeded)) {
			return fmt.Errorf("a worker holds %s.lock: stop this machine's worker and enrol again", path)
		}
		return fmt.Errorf("lock %s: %w", path, err)
	}
	defer func() { _ = lock.Unlock() }()
	return transportauth.WriteMachineCredential(path, credential)
}

// txeEnrolClient is client without redirects: the worker's token goes to
// the hub's own address only.
func txeEnrolClient(client *http.Client) *http.Client {
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

// txeEnrolHub calls the hub with the worker's own token.
type txeEnrolHub struct {
	base      string
	client    *http.Client
	machineID string
}

func (h txeEnrolHub) apply(ctx context.Context, token string) (*txeEnrolApplication, error) {
	var out txeEnrolApplication
	path := "/txe/machines/" + url.PathEscape(h.machineID) + "/enrolment-applications"
	if err := h.call(ctx, http.MethodPost, path, token, &out); err != nil {
		return nil, fmt.Errorf("apply to enrol: %w", err)
	}
	return &out, nil
}

// enrolled reports whether the hub takes the worker's token as this
// machine, enrolled.
func (h txeEnrolHub) enrolled(ctx context.Context, token string) (bool, error) {
	var out struct {
		State string `json:"state"`
		Scope struct {
			MachineID string `json:"machine_id"`
		} `json:"scope"`
	}
	if err := h.call(ctx, http.MethodGet, cliauth.HubIdentityPath, token, &out); err != nil {
		return false, fmt.Errorf("ask the hub whether the machine is enrolled: %w", err)
	}
	return out.State == "bound" && out.Scope.MachineID == h.machineID, nil
}

func (h txeEnrolHub) call(ctx context.Context, method, path, token string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(h.base, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return txeEnrolError(resp.StatusCode, body)
	}
	return json.Unmarshal(body, out)
}

// txeEnrolError explains the hub's refusal.
func txeEnrolError(status int, body []byte) error {
	var e struct {
		Message string `json:"message"`
		Details struct {
			Code string `json:"code"`
		} `json:"details"`
	}
	_ = json.Unmarshal(body, &e)
	why := ""
	switch {
	case status == http.StatusUnauthorized:
		why = "the hub refused the worker's token: is this client in the hub's txe.authn.clients as a worker?"
	case status == http.StatusServiceUnavailable:
		why = "the hub could not reach the identity provider; try again shortly"
	case status == http.StatusNotFound:
		why = "the hub knows no such machine of this identity's owner: sign in as a person of the machine's owner"
	case e.Details.Code == "unbound":
		why = "this identity is bound to no owner: a person of the machine's owner must sign in"
	case e.Details.Code == "credential_stale":
		why = "the application's token expired before it was approved: apply again"
	}
	msg := fmt.Sprintf("HTTP %d", status)
	if e.Details.Code != "" {
		msg += " " + e.Details.Code
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if why != "" {
		msg += " (" + why + ")"
	}
	return errors.New(msg)
}

// await applies with tokens renewed from the credential file, until the hub
// reports the machine enrolled or wait runs out; with no wait it applies
// once. Renewal goes through the worker's own source, so a rotated refresh
// token is saved as the worker would save it.
func (h txeEnrolHub) await(ctx context.Context, path string, wait time.Duration, view *txeEnrolView) error {
	source, err := transportauth.NewRefreshingSource(path, transportauth.WithHTTPClient(&http.Client{Timeout: defaultRemoteTimeout}))
	if err != nil {
		return err
	}
	deadline := time.Now().Add(wait)
	for {
		err := h.round(ctx, source, path, view)
		if errors.Is(err, errTxeEnrolled) {
			return nil
		}
		var renewal *txeEnrolRenewalError
		if err != nil && !errors.As(err, &renewal) {
			return err
		}
		// A renewal the provider did not answer is retried while time is
		// left; the last round's failure is the outcome.
		if !time.Now().Add(txeEnrolInterval).Before(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(txeEnrolInterval):
		}
	}
}

// errTxeEnrolled ends a waiting enrolment: the hub reports it enrolled.
var errTxeEnrolled = errors.New("enrolled")

// txeEnrolRenewalError is a renewal the provider gave no verdict on; it may
// be tried again.
type txeEnrolRenewalError struct{ err error }

func (e *txeEnrolRenewalError) Error() string { return e.err.Error() }
func (e *txeEnrolRenewalError) Unwrap() error { return e.err }

// round renews the worker's token, then asks the hub whether the machine is
// enrolled and, if not, applies.
func (h txeEnrolHub) round(ctx context.Context, source *transportauth.RefreshingSource, path string, view *txeEnrolView) error {
	token, err := source.Token(ctx)
	if errors.Is(err, transportauth.ErrRevoked) {
		return fmt.Errorf("%w; run dagu txe enrol again without --resume", err)
	}
	if err != nil {
		return &txeEnrolRenewalError{err: err}
	}
	// The provider may have retired the refresh token on file; one that
	// lives only in this process is lost when it exits.
	if unsaved := source.Unsaved(); unsaved != nil {
		return fmt.Errorf("%w; %s no longer holds a usable credential: make its directory writable and run dagu txe enrol again without --resume",
			unsaved, path)
	}
	done, err := h.enrolled(ctx, token)
	if err != nil {
		return err
	}
	if done {
		view.State, view.Application = "enrolled", nil
		return errTxeEnrolled
	}
	application, err := h.apply(ctx, token)
	if err != nil {
		return err
	}
	view.Application, view.State, view.Subject = application, "applied", application.Subject
	return nil
}

// txeShellQuote quotes s for a POSIX shell when it needs it.
func txeShellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune("-_./:@", r)
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func printEnrol(p *txePrinter, v txeEnrolView) {
	p.f("machine:  %s (owner %s)\n", v.MachineID, v.OwnerID)
	p.f("client:   %s at %s\n", v.ClientID, v.Issuer)
	p.f("credential: %s\n", v.CredentialFile)
	switch {
	case v.State == "enrolled":
		p.f("Enrolled: the hub takes this machine's worker credential.\n")
	case v.Application != nil:
		a := v.Application
		p.f("Applied; the application is live until %s.\n", a.CredentialExpires.Format(time.RFC3339))
		p.f("A person of owner %s approves it in the hub: class %s, client %s, issuer %s, subject %s.\n",
			v.OwnerID, a.Class, a.ClientID, a.Issuer, a.Subject)
		p.f("Approve at %s\n", v.ApproveURL)
		p.f("Until then, keep it live with: %s\n", v.resume)
	}
	p.f("The worker reads it from worker.auth.credential_file: %s (or DAGU_WORKER_AUTH_CREDENTIAL_FILE).\n", v.CredentialFile)
}
