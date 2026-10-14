// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cliauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultAuthorizeTimeout bounds how long a sign-in waits for the browser.
const DefaultAuthorizeTimeout = 5 * time.Minute

// Prompt values a sign-in may ask the provider for.
const (
	PromptNone          = ""
	PromptLogin         = "login"
	PromptSelectAccount = "select_account"
)

// AuthorizeOptions configures one browser sign-in.
type AuthorizeOptions struct {
	// OpenBrowser opens url in the system browser. When it is nil or fails,
	// the URL is written to Out for a browser on this machine to open: the
	// redirect goes to a listener on this machine's loopback address.
	OpenBrowser func(url string) error
	// Out receives instructions for the person. Nil discards them.
	Out io.Writer
	// Prompt is passed to the provider: "" (reuse its session), "login" or
	// "select_account".
	Prompt string
	// Timeout bounds the wait for the browser. Zero means
	// DefaultAuthorizeTimeout.
	Timeout time.Duration
	// HTTP is used for every call to the provider. Nil means
	// http.DefaultClient. Redirects are never followed.
	HTTP *http.Client
}

// Authorize signs a person in through the system browser: an
// authorization-code flow with PKCE S256 on a public client, the redirect
// taken by a one-shot listener on 127.0.0.1.
//
// The listener answers only GET /callback with this attempt's state and the
// Host it was given; any other request is answered and ignored, so it can
// neither end the attempt nor substitute a code. The ID token is verified,
// including its nonce, and the identity is the issuer and subject it names.
func Authorize(ctx context.Context, p Provider, opts AuthorizeOptions) (*Tokens, error) {
	switch opts.Prompt {
	case PromptNone, PromptLogin, PromptSelectAccount:
	default:
		return nil, fmt.Errorf("unknown prompt %q: use %q or %q", opts.Prompt, PromptLogin, PromptSelectAccount)
	}
	client := providerClient(opts.HTTP)
	e, err := discover(ctx, p, client)
	if err != nil {
		return nil, err
	}
	state, err := randomToken()
	if err != nil {
		return nil, err
	}
	nonce, err := randomToken()
	if err != nil {
		return nil, err
	}
	verifier, err := randomToken()
	if err != nil {
		return nil, err
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultAuthorizeTimeout
	}
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cb, err := listenLoopback(state, p.Issuer)
	if err != nil {
		return nil, err
	}
	defer cb.close()

	authURL, err := authorizationURL(e.authURL, p, cb.redirectURI, state, nonce, challengeS256(verifier), opts.Prompt)
	if err != nil {
		return nil, err
	}
	out := opts.Out
	if out == nil {
		out = io.Discard
	}
	opened := false
	if opts.OpenBrowser != nil {
		opened = opts.OpenBrowser(authURL) == nil
	}
	if opened {
		_, _ = fmt.Fprintf(out, "Sign in in the browser window that opened. If none did, open this address in a browser on this machine:\n\n%s\n\n", authURL)
	} else {
		_, _ = fmt.Fprintf(out, "Open this address in a browser on this machine to sign in:\n\n%s\n\n", authURL)
	}

	code, err := cb.wait(waitCtx)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	resp, err := postToken(ctx, client, e.tokenURL, "sign-in", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {p.ClientID},
		"code":          {code},
		"redirect_uri":  {cb.redirectURI},
		"code_verifier": {verifier},
	})
	if err != nil {
		if refused, ok := errors.AsType[*RefusedError](err); ok {
			return nil, fmt.Errorf("the identity provider refused the sign-in (%d %s)", refused.Status, refused.Code)
		}
		return nil, err
	}
	if resp.IDToken == "" {
		return nil, errors.New("the identity provider returned no ID token: the client must allow the openid scope")
	}
	if resp.RefreshToken == "" {
		return nil, errors.New("the identity provider returned no refresh token, so the sign-in could not be renewed")
	}
	claims, err := verifyIDToken(ctx, e, p, client, resp.IDToken, nonce)
	if err != nil {
		return nil, err
	}
	if claims.identity.Issuer != p.Issuer {
		return nil, ErrIdentityChanged
	}
	if err := checkAccessTokenIdentity(resp.AccessToken, claims.identity); err != nil {
		return nil, err
	}
	return &Tokens{
		Identity:     claims.identity,
		Username:     claims.username,
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		Expiry:       expiry(now, resp.ExpiresIn, resp.AccessToken),
	}, nil
}

func authorizationURL(endpoint string, p Provider, redirectURI, state, nonce, challenge, prompt string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("provider's authorization endpoint: %w", err)
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(p.scopes(), " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	if prompt != "" {
		q.Set("prompt", prompt)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// randomToken returns 32 random bytes, base64url without padding: a state,
// a nonce or a PKCE verifier (43 characters, inside RFC 7636's 43 to 128).
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func challengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func constantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// The browser tab shows fixed text only, never anything from the request.
const (
	pageReceived   = "<!doctype html><title>Dagu</title><p>Sign-in received. Return to the terminal.</p>"
	pageUnfinished = "<!doctype html><title>Dagu</title><p>Sign-in did not finish. Return to the terminal.</p>"
	pageIgnored    = "<!doctype html><title>Dagu</title><p>This request is not part of the sign-in.</p>"
)

// callbackResult is what the one accepted callback carried.
type callbackResult struct {
	code string
	err  error
}

// loopback is the one-shot redirect listener.
type loopback struct {
	redirectURI string
	host        string
	state       string
	issuer      string
	server      *http.Server
	result      chan callbackResult
	once        sync.Once
	closeOnce   sync.Once
}

// listenLoopback listens on 127.0.0.1 with a port the system chooses. It
// never listens on another address: a redirect to "localhost" could resolve
// elsewhere, and any other interface is reachable from outside.
func listenLoopback(state, issuer string) (*loopback, error) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen for the browser's redirect: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	l := &loopback{
		host:   "127.0.0.1:" + strconv.Itoa(port),
		state:  state,
		issuer: issuer,
		result: make(chan callbackResult, 1),
	}
	l.redirectURI = "http://" + l.host + "/callback"
	l.server = &http.Server{
		Handler:           http.HandlerFunc(l.serve),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() { _ = l.server.Serve(ln) }()
	return l, nil
}

func (l *loopback) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	ignore := func(status int) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, pageIgnored)
	}
	// Host is checked so that a page in the browser cannot reach the
	// listener through a name it controls (DNS rebinding).
	if r.Host != l.host {
		ignore(http.StatusMisdirectedRequest)
		return
	}
	if r.URL.Path != "/callback" {
		ignore(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet {
		ignore(http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	// A callback without this attempt's state is not part of it: answered
	// and ignored, so it can neither end the attempt nor supply a code.
	if !constantTimeEqual(q.Get("state"), l.state) || len(q["state"]) != 1 {
		ignore(http.StatusBadRequest)
		return
	}
	res := l.accept(q)
	accepted := false
	l.once.Do(func() {
		l.result <- res
		accepted = true
	})
	if !accepted {
		ignore(http.StatusConflict)
		return
	}
	if res.err != nil {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, pageUnfinished)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, pageReceived)
}

// accept reads a callback that carries this attempt's state.
func (l *loopback) accept(q url.Values) callbackResult {
	// RFC 9207: when the provider names itself, it must be this issuer.
	if iss, ok := q["iss"]; ok && (len(iss) != 1 || iss[0] != l.issuer) {
		return callbackResult{err: errors.New("the sign-in answer came from another issuer")}
	}
	if code := q.Get("error"); code != "" {
		return callbackResult{err: fmt.Errorf("the identity provider did not sign you in: %s", authorizationErrorCode(code))}
	}
	if len(q["code"]) != 1 || q.Get("code") == "" {
		return callbackResult{err: errors.New("the sign-in answer carried no code")}
	}
	return callbackResult{code: q.Get("code")}
}

// authorizationErrorCode names a standard RFC 6749 4.1.2.1 or OIDC error
// code, and nothing else from the callback.
func authorizationErrorCode(code string) string {
	switch code {
	case "invalid_request", "unauthorized_client", "access_denied", "unsupported_response_type",
		"invalid_scope", "server_error", "temporarily_unavailable",
		"interaction_required", "login_required", "account_selection_required", "consent_required":
		return code
	default:
		return "other error"
	}
}

func (l *loopback) wait(ctx context.Context) (string, error) {
	select {
	case res := <-l.result:
		return res.code, res.err
	case <-ctx.Done():
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "", errors.New("the sign-in timed out waiting for the browser")
		}
		return "", fmt.Errorf("the sign-in was cancelled: %w", ctx.Err())
	}
}

// close stops the listener. A request already being read is cut off: the
// attempt is over and nothing more is answered.
func (l *loopback) close() {
	l.closeOnce.Do(func() {
		l.once.Do(func() {})
		_ = l.server.Close()
	})
}
