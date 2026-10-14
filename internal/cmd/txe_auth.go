// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/spf13/cobra"

	"github.com/dagucloud/dagu/v2/internal/cmn/crypto"
	"github.com/dagucloud/dagu/v2/internal/txe/cliauth"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

var (
	txeLoginIssuerFlag = commandLineFlag{name: "issuer", usage: "Identity provider issuer URL, exactly as the provider states it (default: the one this hub was last signed in with)"}
	txeLoginClientFlag = commandLineFlag{name: "client-id", usage: "Provider client the CLI signs in as (default: the one this hub was last signed in with)"}
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

Other txe commands still use the context's API key until the hub accepts
sign-ins.`,
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
the username for reference, and when the current access token expires.
Nothing is sent anywhere; no token is shown.`,
		Args: cobra.NoArgs,
	}, []commandLineFlag{txeJSONFlag}, runTXEWhoami)
}

// txeSignIns opens this machine's sign-in store and names the hub of the
// command's context.
func txeSignIns(ctx *Context) (*cliauth.Store, string, error) {
	remote, err := txeRemote(ctx)
	if err != nil {
		return nil, "", err
	}
	hub, err := cliauth.NormalizeHub(remote.baseURL)
	if err != nil {
		return nil, "", err
	}
	home, err := txepkg.DefaultHome()
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
	store, err := cliauth.NewStore(filepath.Join(home.Root, txeSignInDir), enc)
	if err != nil {
		return nil, "", err
	}
	return store, hub, nil
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
	store, hub, err := txeSignIns(ctx)
	if err != nil {
		return err
	}
	provider, err := txeLoginProvider(ctx, store, hub)
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

// txeLoginProvider takes the provider from the flags, or from the hub's
// current sign-in when they are not given. A flag that differs from the
// current sign-in is a deliberate change of provider.
func txeLoginProvider(ctx *Context, store *cliauth.Store, hub string) (cliauth.Provider, error) {
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
	p := cliauth.Provider{Issuer: issuer, ClientID: clientID, Scopes: scopes}
	if issuer == "" || clientID == "" {
		current, err := store.Load(hub)
		if err != nil && !errors.Is(err, cliauth.ErrNotSignedIn) {
			return cliauth.Provider{}, err
		}
		if current == nil {
			return cliauth.Provider{}, errors.New("this hub has no sign-in yet: give --issuer and --client-id")
		}
		if issuer == "" {
			p.Issuer = current.Provider.Issuer
		}
		if clientID == "" {
			p.ClientID = current.Provider.ClientID
		}
		if !ctx.Command.Flags().Changed("scope") {
			p.Scopes = current.Provider.Scopes
		}
	}
	return p, p.Validate()
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
	store, hub, err := txeSignIns(ctx)
	if err != nil {
		return err
	}
	e, err := store.Load(hub)
	if err != nil {
		return err
	}
	view := signInView(e)
	return txeOutput(ctx, view, func(p *txePrinter) { printSignIn(p, view) })
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
