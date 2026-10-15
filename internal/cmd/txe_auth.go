// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"github.com/spf13/cobra"

	"github.com/dagucloud/dagu/v2/internal/cmn/crypto"
	"github.com/dagucloud/dagu/v2/internal/cmn/runenv"
	"github.com/dagucloud/dagu/v2/internal/txe/cliauth"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

var (
	txeLoginIssuerFlag = commandLineFlag{name: "issuer", usage: "Identity provider issuer URL, exactly as the provider states it (default: the hub's, or the one this hub was last signed in with)"}
	txeLoginClientFlag = commandLineFlag{name: "client-id", usage: "Provider client the CLI signs in as (default: the hub's, or the one this hub was last signed in with)"}
	txeLoginScopeFlag  = commandLineFlag{name: "scope", usage: "Extra scope to request besides openid; repeatable", isStringArray: true}
	txeLoginPromptFlag = commandLineFlag{name: "prompt", usage: `Ask the provider to show its sign-in page ("login") or account chooser ("select_account") even when a browser session exists`}
	txeLoginNoBrowser  = commandLineFlag{name: "no-browser", usage: "Print the sign-in address instead of opening the browser; it must still be opened on this machine", isBool: true}
)

// txeSignInDir is where sign-ins are kept, in the TXE home.
const txeSignInDir = "signin"

func init() {
	txeSubcommands = append(txeSubcommands, txeLoginCommand, txeLogoutCommand, txeWhoamiCommand)
}

func txeLoginCommand() *cobra.Command {
	return NewCommand(&cobra.Command{
		Use:   "login",
		Short: "Sign in to the hub's identity provider through the browser",
		Long: `Sign in through the system browser and keep the sign-in for this hub.

The provider's own page asks for the password, never this command, and no
code or token is ever pasted: the browser hands the result to a listener on
127.0.0.1 that exists only for this sign-in (authorization code with PKCE).
The browser must therefore run on this machine.

The sign-in is kept in the TXE home, readable only by this user, one per hub,
and renewed without asking while the provider allows it. Signing in as another
account replaces it: the previous account's sign-in is revoked at the provider
where possible and nothing of it is kept.

Who you are is the provider's issuer and subject. Email and username are
shown, never used to decide anything. Signing in grants nothing by itself: the
hub's administrator binds an identity to an owner.

The provider and client come from the hub (GET /api/v1/txe/auth/cli). A hub
that does not publish them needs --issuer and --client-id; a flag that
disagrees with what the hub publishes is refused.

Other txe commands carry the sign-in on the routes the hub takes it on (the
same answer names them: every /txe route, or also /dags, /dag-runs and
/queues). Every other route, and every request inside a DAG step, keeps the
context's API key. When the hub refuses the sign-in, the token is renewed once
and the request sent once more; a second refusal says to sign in again.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeLoginIssuerFlag, txeLoginClientFlag, txeLoginScopeFlag, txeLoginPromptFlag, txeLoginNoBrowser, txeJSONFlag}, runTXELogin)
}

func txeLogoutCommand() *cobra.Command {
	return NewCommand(&cobra.Command{
		Use:   "logout",
		Short: "End this hub's sign-in on this machine",
		Long: `Delete this hub's sign-in from this machine, then ask the provider to
revoke its refresh token. The local sign-in is gone either way; the output
says whether the provider confirmed the revocation.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeJSONFlag}, runTXELogout)
}

func txeWhoamiCommand() *cobra.Command {
	return NewCommand(&cobra.Command{
		Use:   "whoami",
		Short: "Show who this machine is signed in to the hub as",
		Long: `Show this hub's sign-in on this machine: the provider's issuer and subject,
the username for reference, and when the current access token expires. No
token is shown.

When the hub accepts CLI sign-in, it is also asked who the sign-in is
(GET /api/v1/txe/identity, sent with the sign-in, never the API key): unbound,
pending or bound, and to which owner.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeJSONFlag}, runTXEWhoami)
}

// txeSignIns opens this machine's sign-in store and names the hub of the
// command's context.
func txeSignIns(ctx *Context) (*cliauth.Store, string, error) {
	remote, err := txeRemoteContext(ctx)
	if err != nil {
		return nil, "", err
	}
	return txeSignInStore(ctx, remote)
}

// txeSignInStoreDir is where this machine keeps its sign-ins.
func txeSignInStoreDir() (string, error) {
	home, err := txepkg.DefaultHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home.Root, txeSignInDir), nil
}

// txeSignInStore opens the sign-in store and names remote's hub.
func txeSignInStore(ctx *Context, remote *remoteClient) (*cliauth.Store, string, error) {
	hub, err := cliauth.NormalizeHub(remote.baseURL)
	if err != nil {
		return nil, "", err
	}
	dir, err := txeSignInStoreDir()
	if err != nil {
		return nil, "", err
	}
	key, err := crypto.ResolveKey(ctx.Config.Paths.DataDir)
	if err != nil {
		return nil, "", err
	}
	enc, err := crypto.NewEncryptor(key)
	if err != nil {
		return nil, "", err
	}
	store, err := cliauth.NewStore(dir, enc)
	if err != nil {
		return nil, "", err
	}
	return store, hub, nil
}

// txeInDAGStep reports whether this command runs as a step of a DAG run. A
// step is unattended: it never uses a person's interactive sign-in, and
// keeps the context's API key until machines hold their own credential.
func txeInDAGStep() bool {
	return os.Getenv(runenv.EnvKeyDAGRunID) != "" && os.Getenv(runenv.EnvKeyDAGRunStepName) != ""
}

// txeHubAuth decides what remote's calls carry.
//
// With no sign-in for the hub on this machine, or inside a DAG step, nothing
// changes: the context's API key, and no extra request. With a sign-in, the
// hub is asked which routes take it (GET /txe/auth/cli):
//   - the hub does not accept CLI sign-in: the API key;
//   - the hub names another provider or client than the sign-in was made
//     at: an error; the sign-in is never sent there;
//   - otherwise the routes its use names ("txe": every /txe route; "all":
//     /txe, /dags, /dag-runs and /queues; "identity", or a use this CLI does
//     not know: /txe/identity) carry the sign-in, and every other route the
//     API key.
//
// The choice is made before any call and never changes on an error: a
// refused sign-in is reported, not replaced by the API key.
func txeHubAuth(ctx *Context, remote *remoteClient) (*remoteClient, error) {
	if txeInDAGStep() {
		return remote, nil
	}
	hub, err := cliauth.NormalizeHub(remote.baseURL)
	if err != nil {
		return nil, err
	}
	dir, err := txeSignInStoreDir()
	if err != nil {
		return nil, err
	}
	if signedIn, err := cliauth.HasEntry(dir, hub); err != nil || !signedIn {
		return remote, err
	}
	store, _, err := txeSignInStore(ctx, remote)
	if err != nil {
		return nil, err
	}
	entry, err := store.Load(hub)
	if errors.Is(err, cliauth.ErrNotSignedIn) {
		return remote, nil
	}
	if err != nil {
		return nil, fmt.Errorf("this hub's sign-in cannot be read (%w): run \"dagu txe login\" or \"dagu txe logout\"", err)
	}
	cfg, err := cliauth.DiscoverHub(ctx, remote.baseURL, remote.client)
	if errors.Is(err, cliauth.ErrHubNoSignIn) {
		return remote, nil
	}
	if err != nil {
		return nil, err
	}
	if !cfg.Matches(entry) {
		return nil, fmt.Errorf("this machine signed in to the hub at %s as client %s, but the hub now names %s and client %s: run \"dagu txe login\"",
			entry.Provider.Issuer, entry.Provider.ClientID, cfg.Issuer, cfg.ClientID)
	}
	return remote.withSignIn(store, hub, cfg.Use), nil
}

// txeSignInView is what login and whoami show. It never holds a token.
type txeSignInView struct {
	Hub          string    `json:"hub"`
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	ClientID     string    `json:"client_id"`
	Username     string    `json:"username,omitempty"`
	AccessExpiry time.Time `json:"access_token_expires"`
	SignedInAt   time.Time `json:"signed_in_at"`
	RenewedAt    time.Time `json:"renewed_at,omitzero"`
	// Replaced is the identity this sign-in replaced, when login switched
	// accounts.
	Replaced *cliauth.Identity `json:"replaced,omitempty"`
	// PreviousRevoked says whether the provider confirmed revoking the
	// replaced sign-in.
	PreviousRevoked *bool `json:"previous_revoked,omitempty"`
	// HubIdentity is the hub's own account of this sign-in, from GET /txe/identity,
	// when the hub accepts it; HubError says why there is none.
	HubIdentity *txeHubIdentity `json:"hub_identity,omitempty"`
	HubError    string          `json:"hub_identity_error,omitempty"`
}

// txeHubIdentity is the part of GET /txe/identity whoami shows.
type txeHubIdentity struct {
	AuthzMode string `json:"authz_mode"`
	Principal struct {
		Class    string `json:"class"`
		Issuer   string `json:"issuer,omitempty"`
		Subject  string `json:"subject,omitempty"`
		ClientID string `json:"client_id,omitempty"`
	} `json:"principal"`
	State  string `json:"state"`
	Owners []struct {
		OwnerID     string `json:"owner_id"`
		DisplayName string `json:"display_name,omitempty"`
	} `json:"owners"`
	Scope struct {
		Kind          string `json:"kind,omitempty"`
		UnboundReason string `json:"unbound_reason,omitempty"`
	} `json:"scope"`
	PlatformAdmin bool `json:"platform_admin"`
	IsPerson      bool `json:"is_person"`
}

func signInView(e *cliauth.Entry) txeSignInView {
	return txeSignInView{
		Hub: e.Hub, Issuer: e.Identity.Issuer, Subject: e.Identity.Subject, ClientID: e.Provider.ClientID,
		Username: e.Username, AccessExpiry: e.Expiry.UTC(), SignedInAt: e.SignedInAt.UTC(), RenewedAt: e.RenewedAt.UTC(),
	}
}

func printSignIn(p *txePrinter, v txeSignInView) {
	p.f("hub:      %s\n", v.Hub)
	p.f("issuer:   %s\n", v.Issuer)
	p.f("subject:  %s\n", v.Subject)
	if v.Username != "" {
		p.f("username: %s (shown only; never used to decide access)\n", v.Username)
	}
	p.f("client:   %s\n", v.ClientID)
	p.f("access token expires: %s (renewed when needed)\n", v.AccessExpiry.Format(time.RFC3339))
}

func runTXELogin(ctx *Context, _ []string) error {
	remote, err := txeRemoteContext(ctx)
	if err != nil {
		return err
	}
	store, hub, err := txeSignInStore(ctx, remote)
	if err != nil {
		return err
	}
	advertised, discoverErr := cliauth.DiscoverHub(ctx, remote.baseURL, remote.client)
	provider, err := txeLoginProvider(ctx, store, hub, advertised, discoverErr)
	if err != nil {
		return err
	}
	prompt, err := ctx.StringParam("prompt")
	if err != nil {
		return err
	}
	noBrowser, err := ctx.Command.Flags().GetBool("no-browser")
	if err != nil {
		return err
	}
	opts := cliauth.AuthorizeOptions{Out: ctx.Command.ErrOrStderr(), Prompt: prompt}
	if !noBrowser {
		opts.OpenBrowser = txeOpenBrowser
	}
	tokens, err := cliauth.Authorize(ctx, provider, opts)
	if err != nil {
		return err
	}
	now := time.Now()
	entry := &cliauth.Entry{
		Hub: hub, Provider: provider, Identity: tokens.Identity, Username: tokens.Username,
		AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken, Expiry: tokens.Expiry,
		SignedInAt: now,
	}
	previous, err := store.Replace(ctx, entry)
	if err != nil {
		return err
	}
	view := signInView(entry)
	var revokeErr error
	// The previous sign-in of the same identity is only dropped: it may share
	// the provider session the new one was issued from, which revoking would
	// end too. Another identity's is revoked.
	if previous != nil && previous.Identity != entry.Identity {
		replaced := previous.Identity
		view.Replaced = &replaced
		var revoked bool
		revoked, revokeErr = revokeQuietly(ctx, previous)
		view.PreviousRevoked = &revoked
	}
	return txeOutput(ctx, view, func(p *txePrinter) {
		p.f("Signed in.\n")
		printSignIn(p, view)
		if view.Replaced != nil {
			p.f("replaced: %s at %s", view.Replaced.Subject, view.Replaced.Issuer)
			switch {
			case *view.PreviousRevoked:
				p.f(" (revoked at the provider)\n")
			case revokeErr != nil:
				p.f(" (removed here; the provider did not confirm revocation: %v)\n", revokeErr)
			default:
				p.f(" (removed here; the provider offers no revocation)\n")
			}
		}
		p.f("Signing in grants nothing by itself: access follows the hub's binding of this identity to an owner.\n")
	})
}

// txeLoginProvider decides the provider to sign in at.
//
// A hub that publishes its CLI client decides it: --issuer and --client-id
// may only repeat it, and --scope adds to its scopes. A hub that does not
// publish one (or cannot be asked, when both flags are given) takes the
// flags, or the hub's current sign-in for any flag not given.
func txeLoginProvider(ctx *Context, store *cliauth.Store, hub string, advertised *cliauth.HubConfig, discoverErr error) (cliauth.Provider, error) {
	issuer, err := ctx.StringParam("issuer")
	if err != nil {
		return cliauth.Provider{}, err
	}
	clientID, err := ctx.StringParam("client-id")
	if err != nil {
		return cliauth.Provider{}, err
	}
	scopes, err := ctx.Command.Flags().GetStringArray("scope")
	if err != nil {
		return cliauth.Provider{}, err
	}
	if advertised != nil {
		if issuer != "" && issuer != advertised.Issuer {
			return cliauth.Provider{}, fmt.Errorf("the hub signs its CLI in at %s, not %s", advertised.Issuer, issuer)
		}
		if clientID != "" && clientID != advertised.ClientID {
			return cliauth.Provider{}, fmt.Errorf("the hub's CLI client is %s, not %s", advertised.ClientID, clientID)
		}
		p := advertised.Provider()
		p.Scopes = mergeScopes(p.Scopes, scopes)
		return p, p.Validate()
	}
	p := cliauth.Provider{Issuer: issuer, ClientID: clientID, Scopes: scopes}
	needed := issuer == "" || clientID == ""
	if discoverErr != nil && !errors.Is(discoverErr, cliauth.ErrHubNoSignIn) && needed {
		return cliauth.Provider{}, fmt.Errorf("%w; give --issuer and --client-id to sign in without it", discoverErr)
	}
	if !needed && ctx.Command.Flags().Changed("scope") {
		return p, p.Validate()
	}
	current, err := store.Load(hub)
	if err != nil && !errors.Is(err, cliauth.ErrNotSignedIn) && needed {
		return cliauth.Provider{}, err
	}
	// An unreadable sign-in supplies nothing; signing in again with every
	// value given is how one recovers from it.
	if err != nil {
		current = nil
	}
	if current == nil {
		if needed {
			return cliauth.Provider{}, errors.New("this hub does not publish its CLI client and has no sign-in yet: give --issuer and --client-id")
		}
		return p, p.Validate()
	}
	if issuer == "" {
		p.Issuer = current.Provider.Issuer
	}
	if clientID == "" {
		p.ClientID = current.Provider.ClientID
	}
	if !ctx.Command.Flags().Changed("scope") && p.Issuer == current.Provider.Issuer {
		p.Scopes = current.Provider.Scopes
	}
	return p, p.Validate()
}

// mergeScopes is base followed by each of extra that base lacks.
func mergeScopes(base, extra []string) []string {
	out := slices.Clone(base)
	for _, s := range extra {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// txeRevokeTimeout bounds a best-effort revocation.
const txeRevokeTimeout = 10 * time.Second

func revokeQuietly(ctx context.Context, e *cliauth.Entry) (bool, error) {
	revokeCtx, cancel := context.WithTimeout(ctx, txeRevokeTimeout)
	defer cancel()
	return cliauth.Revoke(revokeCtx, e.Provider, e.RefreshToken, nil)
}

// txeLogoutResult is what logout did.
type txeLogoutResult struct {
	Hub        string `json:"hub"`
	Issuer     string `json:"issuer"`
	Subject    string `json:"subject"`
	Revoked    bool   `json:"revoked_at_provider"`
	Revocation string `json:"revocation,omitempty"`
}

func runTXELogout(ctx *Context, _ []string) error {
	store, hub, err := txeSignIns(ctx)
	if err != nil {
		return err
	}
	removed, err := store.Remove(ctx, hub)
	if err != nil {
		return err
	}
	res := txeLogoutResult{Hub: hub}
	if removed == nil {
		// The entry could not be read; it is gone, and there is no token to
		// revoke.
		res.Revocation = "the sign-in could not be read, so nothing was sent to the provider"
	} else {
		res.Issuer, res.Subject = removed.Identity.Issuer, removed.Identity.Subject
		revoked, err := revokeQuietly(ctx, removed)
		res.Revoked = revoked
		switch {
		case err != nil:
			res.Revocation = fmt.Sprintf("the provider did not confirm: %v", err)
		case !revoked:
			res.Revocation = "the provider offers no revocation; the refresh token stays valid there until it expires"
		}
	}
	return txeOutput(ctx, res, func(p *txePrinter) {
		p.f("Signed out of %s on this machine.\n", res.Hub)
		if res.Revoked {
			p.f("The provider revoked the sign-in.\n")
		} else {
			p.f("%s.\n", res.Revocation)
		}
	})
}

func runTXEWhoami(ctx *Context, _ []string) error {
	remote, err := txeRemoteContext(ctx)
	if err != nil {
		return err
	}
	store, hub, err := txeSignInStore(ctx, remote)
	if err != nil {
		return err
	}
	e, err := store.Load(hub)
	if err != nil {
		return err
	}
	view := signInView(e)
	view.HubIdentity, err = txeAskHubIdentity(ctx, remote)
	if err != nil {
		view.HubError = err.Error()
	}
	return txeOutput(ctx, view, func(p *txePrinter) {
		printSignIn(p, view)
		switch {
		case view.HubIdentity != nil:
			h := view.HubIdentity
			p.f("hub sees: %s %s at %s (client %s), %s", h.Principal.Class, h.Principal.Subject, h.Principal.Issuer, h.Principal.ClientID, h.State)
			for _, o := range h.Owners {
				p.f(", owner %s", o.OwnerID)
				if o.DisplayName != "" {
					p.f(" (%s)", o.DisplayName)
				}
			}
			if h.Scope.UnboundReason != "" {
				p.f(", %s", h.Scope.UnboundReason)
			}
			p.f("; authorization %s\n", h.AuthzMode)
		case view.HubError != "":
			p.f("hub: %s\n", view.HubError)
		}
	})
}

// errHubIdentityNotAsked reports a hub that does not accept this sign-in on
// GET /txe/identity, so there is nothing to ask it.
var errHubIdentityNotAsked = errors.New("the hub does not accept CLI sign-in, so it was not asked who this is")

// txeAskHubIdentity asks the hub who this sign-in is, with the sign-in
// itself. It never asks with the API key: that would describe the key.
func txeAskHubIdentity(ctx *Context, remote *remoteClient) (*txeHubIdentity, error) {
	authed, err := txeHubAuth(ctx, remote)
	if err != nil {
		return nil, err
	}
	if authed == remote {
		return nil, errHubIdentityNotAsked
	}
	var out txeHubIdentity
	if err := authed.do(ctx, http.MethodGet, cliauth.HubIdentityPath, nil, &out, nil); err != nil {
		return nil, err
	}
	return &out, nil
}

// txeOpenBrowser is openBrowser, replaceable in tests.
var txeOpenBrowser = openBrowser

// openBrowser opens url in the system browser. The URL is one argument to
// the opener, never part of a shell command.
func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url) //nolint:gosec // the provider's authorization URL, passed as one argument
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url) //nolint:gosec // as above
	default:
		cmd = exec.Command("xdg-open", url) //nolint:gosec // as above
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
