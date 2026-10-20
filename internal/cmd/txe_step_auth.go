// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/cliauth"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
)

// txeStepClass is the credential class a step's command needs: a reviewer's
// commands need the reviewer class, and every other step, a job's, the
// worker class.
func txeStepClass(cmd *cobra.Command) authn.Class {
	for current := cmd; current != nil; current = current.Parent() {
		if current.Name() == "review" && current.Parent() != nil && current.Parent().Name() == "txe" {
			return authn.ClassReviewer
		}
	}
	return authn.ClassWorker
}

// txeStepRemote decides what a DAG step's calls to the hub carry.
//
// A step never presents a person's sign-in. When the machine is enrolled for
// the step's class (StepAuth names the class), the step presents the class's
// machine credential, and only it:
//   - the step must reach the hub the enrolment was made with;
//   - the credential file must load as the worker loads it, be this
//     machine's, and be from the identity provider the hub names;
//   - every call carries its access token, renewed from the file as the
//     worker renews it, and only to that hub: a redirect is not followed;
//   - a refusal is reported, never retried with the context's API key.
//
// Anything missing or mismatched fails before a call is made. A class the
// machine is not enrolled for keeps the context's API key. A txe command
// prints its class and mode on standard error in either case, for whoever
// reads the run's log.
//
// txe commands always come here (txeHubAuth). Any other command a step runs
// against a context comes here too (NewContext), and is changed only when its
// context reaches the hub the machine is enrolled with: a context for another
// hub keeps its own key.
func txeStepRemote(ctx context.Context, cmd *cobra.Command, remote *remoteClient) (*remoteClient, error) {
	class := txeStepClass(cmd)
	txeCommand := isTXECommand(cmd)
	home, err := txepkg.DefaultHome()
	if err != nil {
		return nil, err
	}
	auth, err := home.StepAuth()
	if err != nil {
		return nil, fmt.Errorf("this step cannot tell how this machine reaches the hub: %w", err)
	}
	entry, enrolled := auth.Enrolled(string(class))
	hub, err := txeHubKey(remote.baseURL)
	if err != nil {
		return nil, err
	}
	enrolledHub := ""
	if enrolled {
		if enrolledHub, err = txeHubKey(entry.Hub); err != nil {
			return nil, fmt.Errorf("this machine's %s enrolment names an invalid hub: %w", class, err)
		}
	}
	if !txeCommand && (!enrolled || hub != enrolledHub) {
		return remote, nil
	}
	if !enrolled {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "txe: step class=%s mode=api_key (this machine is not enrolled for the %s class)\n", class, class)
		return remote, nil
	}
	if hub != enrolledHub {
		return nil, fmt.Errorf("this machine's %s credential is enrolled with the hub at %s, but this step reaches %s: enrol with the store this machine's jobs use; nothing was sent",
			class, entry.Hub, hub)
	}
	if class != authn.ClassWorker {
		return nil, fmt.Errorf("this machine is enrolled for the %s class, but this build reads only worker credentials; nothing was sent", class)
	}
	machine, err := home.Machine()
	if err != nil {
		return nil, err
	}
	credential, err := transportauth.ReadMachineCredential(entry.CredentialFile)
	if err != nil {
		return nil, fmt.Errorf("this machine is enrolled for the %s class, and its credential %s cannot be used (%w); nothing was sent", class, entry.CredentialFile, err)
	}
	if credential.MachineID != machine.MachineID {
		return nil, fmt.Errorf("the %s credential %s is for machine %s, but this machine is %s; nothing was sent", class, entry.CredentialFile, credential.MachineID, machine.MachineID)
	}
	cfg, err := cliauth.DiscoverHub(ctx, remote.baseURL, remote.client)
	if errors.Is(err, cliauth.ErrHubNoSignIn) {
		return nil, fmt.Errorf("the hub at %s names no identity provider, so the %s credential cannot be matched to it; nothing was sent", remote.baseURL, class)
	}
	if err != nil {
		return nil, err
	}
	if cfg.Issuer != credential.Issuer {
		return nil, fmt.Errorf("the %s credential is from %s, but the hub at %s names %s; nothing was sent", class, credential.Issuer, remote.baseURL, cfg.Issuer)
	}
	source, err := transportauth.NewRefreshingSource(entry.CredentialFile, transportauth.WithHTTPClient(&http.Client{Timeout: defaultRemoteTimeout}))
	if err != nil {
		return nil, err
	}
	stepRemote, err := remote.withMachineCredential(source, credential)
	if err != nil {
		return nil, err
	}
	if txeCommand {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "txe: step class=%s mode=credential\n", class)
	}
	return stepRemote, nil
}

// withMachineCredential returns a copy of c whose calls carry the machine's
// access token from source, never the context's API key, and only where the
// hub takes a machine's token:
//   - to c's own scheme and host; redirects are returned, not followed;
//   - on the hub's /txe, /dags, /dag-runs and /queues routes; any other path
//     is sent with no credential at all;
//   - only a token from the credential that was checked: its issuer, client
//     and machine are compared with it each time one is presented.
//
// Any answer outside 2xx (an error, or a redirect, which is not followed) has
// the token, and any other bearer value in it, replaced, so a hub that echoes
// a request's credential does not print it.
func (c *remoteClient) withMachineCredential(source *transportauth.RefreshingSource, credential transportauth.MachineCredential) (*remoteClient, error) {
	base, err := url.Parse(c.baseURL)
	if err != nil || base.Host == "" {
		return nil, fmt.Errorf("the hub address %q is not an absolute URL", c.baseURL)
	}
	httpClient := *c.client
	httpClient.Transport = &txeMachineTransport{
		base: c.client.Transport, source: source, scheme: base.Scheme, host: base.Host,
		root: strings.TrimRight(base.Path, "/"), issuer: credential.Issuer, clientID: credential.ClientID, machineID: credential.MachineID,
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &remoteClient{baseURL: c.baseURL, client: &httpClient}, nil
}

// txeMachineRoutes are the hub routes, under its API root, that take a
// machine's token.
var txeMachineRoutes = []string{"/txe", "/dags", "/dag-runs", "/queues"}

// txeMachineTransport sets the machine's access token on each request to
// the enrolled hub's machine routes, and refuses any other destination.
type txeMachineTransport struct {
	base         http.RoundTripper
	source       *transportauth.RefreshingSource
	scheme, host string
	// root is the hub's API root path, such as /api/v1.
	root string
	// issuer, clientID and machineID are the checked credential's.
	issuer, clientID, machineID string
}

func (t *txeMachineTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	fail := func(err error) (*http.Response, error) {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, err
	}
	if req.URL.Scheme != t.scheme || req.URL.Host != t.host {
		return fail(fmt.Errorf("refusing to send this machine's credential to %s://%s, which is not the hub", req.URL.Scheme, req.URL.Host))
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	out := req.Clone(req.Context())
	out.Header.Del("Authorization")
	if !t.machineRoute(req.URL.Path) {
		return base.RoundTrip(out)
	}
	token, err := t.source.Token(req.Context())
	if err != nil {
		return fail(fmt.Errorf("renew this machine's access token: %w", err))
	}
	// A renewal may have rotated the refresh token. Unless the file holds
	// the new one, the next step and the worker would present a retired one.
	if unsaved := t.source.Unsaved(); unsaved != nil {
		return fail(fmt.Errorf("this machine's renewed credential could not be saved, so the step stops: %w", unsaved))
	}
	if err := t.checkToken(token); err != nil {
		return fail(err)
	}
	out.Header.Set("Authorization", "Bearer "+token)
	resp, err := base.RoundTrip(out)
	if err != nil || (resp.StatusCode >= 200 && resp.StatusCode < 300) {
		return resp, err
	}
	// Every other answer, a redirect included, is shown as an error.
	return txeRedactBearer(resp, token)
}

// machineRoute reports whether path is one of the hub's machine routes.
func (t *txeMachineTransport) machineRoute(path string) bool {
	for _, route := range txeMachineRoutes {
		prefix := t.root + route
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return true
		}
	}
	return false
}

// checkToken compares the token about to be presented with the credential
// that was checked: the file is read again for each renewal, and what it
// holds then is what is sent.
func (t *txeMachineTransport) checkToken(token string) error {
	if machine := t.source.MachineID(); machine != t.machineID {
		return fmt.Errorf("the machine credential now names machine %s, not %s; nothing was sent", machine, t.machineID)
	}
	claims, err := txeTokenClaims(token)
	if err != nil {
		return fmt.Errorf("this machine's access token cannot be read (%w); nothing was sent", err)
	}
	client := claims.Azp
	if client == "" {
		client = claims.ClientID
	}
	if claims.Iss != t.issuer || client != t.clientID {
		return fmt.Errorf("this machine's access token is from %s for client %s, not %s for %s; nothing was sent", claims.Iss, client, t.issuer, t.clientID)
	}
	return nil
}

// txeTokenClaimSet is the part of an access token's claims checked before
// it is sent.
type txeTokenClaimSet struct {
	Iss      string `json:"iss"`
	Azp      string `json:"azp"`
	ClientID string `json:"client_id"`
}

// txeTokenClaims reads, without verifying them, the claims of a JWT access
// token: the hub verifies it; this only checks what is about to be sent.
func txeTokenClaims(token string) (txeTokenClaimSet, error) {
	var claims txeTokenClaimSet
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims, errors.New("it is not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims, errors.New("its payload is not base64url")
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return claims, errors.New("its payload is not JSON")
	}
	return claims, nil
}

// txeBearerPattern is a bearer value as an echoed header would show it.
var txeBearerPattern = regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]+`)

// txeRedactBearer replaces the token, and any bearer value, in an error
// answer's body before anything reads it.
func txeRedactBearer(resp *http.Response, token string) (*http.Response, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if err != nil {
		return nil, err
	}
	text := strings.ReplaceAll(string(body), token, "[redacted]")
	text = txeBearerPattern.ReplaceAllString(text, "Bearer [redacted]")
	resp.Body = io.NopCloser(strings.NewReader(text))
	resp.ContentLength = int64(len(text))
	resp.Header.Del("Content-Length")
	return resp, nil
}

// txeHubKey is a hub's API root as compared for a step's credential: the
// normalized URL with a scheme's default port left out, so two spellings of
// one destination compare equal.
func txeHubKey(raw string) (string, error) {
	normalized, err := cliauth.NormalizeHub(raw)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(normalized)
	if err != nil {
		return "", err
	}
	if port := u.Port(); (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		host := u.Hostname()
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		u.Host = host
	}
	return u.String(), nil
}

// newCommandRemoteClient is newRemoteClient for a command's context. During
// a DAG step, a command other than txe goes through txeStepRemote, so a
// context for the hub the machine is enrolled with presents the machine's
// credential; txe commands decide in txeHubAuth.
func newCommandRemoteClient(ctx context.Context, cmd *cobra.Command, c *cliContext) (*remoteClient, error) {
	remote, err := newRemoteClient(c)
	if err != nil || !txeInDAGStep() || isTXECommand(cmd) {
		return remote, err
	}
	return txeStepRemote(ctx, cmd, remote)
}
