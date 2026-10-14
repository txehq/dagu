// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cliauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/cliauth/cliauthtest"
)

func providerOf(f *cliauthtest.Provider) Provider {
	return Provider{Issuer: f.Issuer(), ClientID: f.ClientID}
}

func authorize(t *testing.T, f *cliauthtest.Provider, opts AuthorizeOptions) (*Tokens, error) {
	t.Helper()
	if opts.OpenBrowser == nil {
		opts.OpenBrowser = f.Browser(t)
	}
	if opts.Timeout == 0 {
		opts.Timeout = 10 * time.Second
	}
	return Authorize(context.Background(), providerOf(f), opts)
}

func TestAuthorizeSignsInWithPKCEAndNonce(t *testing.T) {
	f := cliauthtest.New(t)
	var out bytes.Buffer
	tokens, err := authorize(t, f, AuthorizeOptions{Out: &out, Prompt: PromptSelectAccount})
	require.NoError(t, err)

	assert.Equal(t, Identity{Issuer: f.Issuer(), Subject: f.Subject}, tokens.Identity)
	assert.Equal(t, "alice", tokens.Username)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.WithinDuration(t, time.Now().Add(5*time.Minute), tokens.Expiry, 5*time.Second)

	q := f.LastAuth()
	assert.Equal(t, "code", q.Get("response_type"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Equal(t, "openid", q.Get("scope"))
	assert.Equal(t, "select_account", q.Get("prompt"))
	assert.Len(t, q.Get("state"), 43)
	assert.Len(t, q.Get("nonce"), 43)
	assert.NotEqual(t, q.Get("state"), q.Get("nonce"))
	redirect, err := url.Parse(q.Get("redirect_uri"))
	require.NoError(t, err)
	assert.Equal(t, "http", redirect.Scheme)
	assert.Equal(t, "127.0.0.1", redirect.Hostname())
	assert.Equal(t, "/callback", redirect.Path)
	// The person is told where to sign in; no token is ever printed.
	assert.Contains(t, out.String(), "browser")
	assert.NotContains(t, out.String(), tokens.AccessToken)
	assert.NotContains(t, out.String(), tokens.RefreshToken)
}

func TestAuthorizeRequestsExtraScopesOnce(t *testing.T) {
	f := cliauthtest.New(t)
	p := providerOf(f)
	p.Scopes = []string{"openid", "offline_access", "offline_access"}
	_, err := Authorize(context.Background(), p, AuthorizeOptions{OpenBrowser: f.Browser(t), Timeout: 10 * time.Second})
	require.NoError(t, err)
	assert.Equal(t, "openid offline_access", f.LastAuth().Get("scope"))
}

// sendCallback plays a request to the listener that did not come from the
// provider's redirect.
func sendCallback(t *testing.T, redirectURI string, query url.Values, host string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, redirectURI+"?"+query.Encode(), nil)
	require.NoError(t, err)
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	assert.NotContains(t, string(body), "forged", "the listener must not echo the request")
	return resp.StatusCode
}

func TestAuthorizeIgnoresForgedCallbacks(t *testing.T) {
	f := cliauthtest.New(t)
	real := f.Browser(t)
	tokens, err := authorize(t, f, AuthorizeOptions{OpenBrowser: func(raw string) error {
		u, _ := url.Parse(raw)
		redirect := u.Query().Get("redirect_uri")
		state := u.Query().Get("state")
		host := strings.TrimPrefix(redirect, "http://")
		host = strings.TrimSuffix(host, "/callback")
		// Wrong state, no state, repeated state: answered and ignored.
		assert.Equal(t, http.StatusBadRequest, sendCallback(t, redirect, url.Values{"code": {"forged"}, "state": {"forged"}}, ""))
		assert.Equal(t, http.StatusBadRequest, sendCallback(t, redirect, url.Values{"code": {"forged"}}, ""))
		assert.Equal(t, http.StatusBadRequest, sendCallback(t, redirect, url.Values{"code": {"forged"}, "state": {state, state}}, ""))
		// Right state through another host name (DNS rebinding): ignored.
		assert.Equal(t, http.StatusMisdirectedRequest, sendCallback(t, redirect, url.Values{"code": {"forged"}, "state": {state}}, "attacker.example:"+strings.Split(host, ":")[1]))
		// Another path or method: ignored.
		assert.Equal(t, http.StatusNotFound, sendCallback(t, "http://"+host+"/other", url.Values{"state": {state}}, ""))
		resp, err := http.Post(redirect+"?"+url.Values{"state": {state}, "code": {"forged"}}.Encode(), "text/plain", nil) //nolint:noctx // test
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
		return real(raw)
	}})
	require.NoError(t, err)
	assert.Equal(t, f.Subject, tokens.Identity.Subject)
}

func TestAuthorizeAcceptsOneCallbackOnly(t *testing.T) {
	f := cliauthtest.New(t)
	real := f.Browser(t)
	var redirect, state string
	_, err := authorize(t, f, AuthorizeOptions{OpenBrowser: func(raw string) error {
		u, _ := url.Parse(raw)
		redirect, state = u.Query().Get("redirect_uri"), u.Query().Get("state")
		return real(raw)
	}})
	require.NoError(t, err)
	// After the attempt the listener is closed.
	resp, err := http.Get(redirect + "?" + url.Values{"state": {state}, "code": {"late"}}.Encode()) //nolint:noctx // test
	if err == nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err)
}

func TestAuthorizeRefusals(t *testing.T) {
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	cases := []struct {
		name  string
		setup func(f *cliauthtest.Provider)
		want  string
	}{
		{"nonce mismatch", func(f *cliauthtest.Provider) { f.IDNonce = func(string) string { return "another" } }, "nonce"},
		{"no nonce", func(f *cliauthtest.Provider) { f.IDNonce = func(string) string { return "" } }, "nonce"},
		{"ID token for another client", func(f *cliauthtest.Provider) { f.IDAudience = "other-client" }, "not valid"},
		{"ID token signed by another key", func(f *cliauthtest.Provider) { f.SignWith = other }, "not valid"},
		{"access token for another subject", func(f *cliauthtest.Provider) { f.AccessSubject = "someone-else" }, "another identity"},
		{"callback from another issuer", func(f *cliauthtest.Provider) { f.CallbackIssuer = "https://evil.example" }, "another issuer"},
		{"provider denied", func(f *cliauthtest.Provider) { f.CallbackError = "access_denied" }, "access_denied"},
		{"no refresh token", func(f *cliauthtest.Provider) { f.OmitRefresh = true }, "no refresh token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := cliauthtest.New(t)
			tc.setup(f)
			_, err := authorize(t, f, AuthorizeOptions{})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestAuthorizeAcceptsMatchingIssParameter(t *testing.T) {
	f := cliauthtest.New(t)
	f.CallbackIssuer = f.Issuer()
	_, err := authorize(t, f, AuthorizeOptions{})
	require.NoError(t, err)
}

func TestAuthorizeTimesOut(t *testing.T) {
	f := cliauthtest.New(t)
	start := time.Now()
	_, err := authorize(t, f, AuthorizeOptions{OpenBrowser: func(string) error { return nil }, Timeout: 200 * time.Millisecond})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out")
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestAuthorizePrintsURLWhenBrowserFails(t *testing.T) {
	f := cliauthtest.New(t)
	var out bytes.Buffer
	_, err := authorize(t, f, AuthorizeOptions{
		Out:         &out,
		OpenBrowser: func(string) error { return errors.New("no browser") },
		Timeout:     200 * time.Millisecond,
	})
	require.Error(t, err)
	assert.Contains(t, out.String(), f.Issuer()+"/auth?")
	assert.Contains(t, out.String(), "on this machine")
}

func TestProviderValidation(t *testing.T) {
	for _, issuer := range []string{"", "http://idp.example/realms/x", "ftp://idp.example", "https://u:p@idp.example", "https://idp.example?x=1", "relative"} {
		err := Provider{Issuer: issuer, ClientID: "c"}.Validate()
		assert.Error(t, err, issuer)
	}
	for _, issuer := range []string{"https://account.example/realms/master", "http://127.0.0.1:8080/realms/test", "http://localhost:8080"} {
		assert.NoError(t, Provider{Issuer: issuer, ClientID: "c"}.Validate(), issuer)
	}
	assert.Error(t, Provider{Issuer: "https://idp.example"}.Validate())
	_, err := Authorize(context.Background(), Provider{Issuer: "https://idp.example", ClientID: "c"}, AuthorizeOptions{Prompt: "none"})
	assert.ErrorContains(t, err, "unknown prompt")
}

func TestDiscoveryRequiresExactIssuer(t *testing.T) {
	f := cliauthtest.New(t)
	f.IssuerOverride = f.Issuer() + "/"
	_, err := authorize(t, f, AuthorizeOptions{})
	require.Error(t, err)
	var unverifiable *UnverifiableError
	assert.False(t, errors.As(err, &unverifiable), "a provider naming another issuer is not an outage: %v", err)
	assert.Contains(t, err.Error(), "does not say it is that issuer")
}

func TestDiscoveryRequiresSecureSigningKeys(t *testing.T) {
	f := cliauthtest.New(t)
	f.JWKSURI = "http://keys.example/jwks"
	_, err := authorize(t, f, AuthorizeOptions{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signing keys endpoint")
	assert.Contains(t, err.Error(), "https")
}

func TestAuthorizeDeadlineCoversDiscovery(t *testing.T) {
	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer hung.Close()
	defer close(release)
	start := time.Now()
	_, err := Authorize(context.Background(), Provider{Issuer: hung.URL, ClientID: "c"}, AuthorizeOptions{
		OpenBrowser: func(string) error { return nil },
		Timeout:     300 * time.Millisecond,
	})
	require.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestProviderClientIsBounded(t *testing.T) {
	c := providerClient(nil)
	assert.Equal(t, providerRequestTimeout, c.Timeout)
	assert.Zero(t, http.DefaultClient.Timeout, "the shared client is not changed")
	assert.Equal(t, time.Second, providerClient(&http.Client{Timeout: time.Second}).Timeout)

	for _, n := range []int{0, maxProviderResponse} {
		b := &limitedBody{body: io.NopCloser(bytes.NewReader(make([]byte, n))), left: maxProviderResponse}
		got, err := io.ReadAll(b)
		require.NoError(t, err)
		assert.Len(t, got, n)
	}
	b := &limitedBody{body: io.NopCloser(bytes.NewReader(make([]byte, maxProviderResponse+1))), left: maxProviderResponse}
	_, err := io.ReadAll(b)
	assert.ErrorIs(t, err, errResponseTooLarge)
}

func TestProviderAnswersAreBounded(t *testing.T) {
	chunk := bytes.Repeat([]byte("a"), 64<<10)
	streamed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"issuer":"`))
		for range 2 * maxProviderResponse / len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer streamed.Close()
	declared := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(2*maxProviderResponse))
		_, _ = w.Write(chunk)
	}))
	defer declared.Close()
	for _, issuer := range []string{streamed.URL, declared.URL} {
		_, err := Refresh(context.Background(), Provider{Issuer: issuer, ClientID: "c"}, Identity{Issuer: issuer, Subject: "s"}, "rt", nil)
		var unverifiable *UnverifiableError
		require.ErrorAs(t, err, &unverifiable, issuer)
		// go-oidc keeps only the text of the cause.
		assert.Contains(t, err.Error(), errResponseTooLarge.Error(), issuer)
	}
}

// RFC 7519 allows a fractional exp; it must not hide the token's subject.
func TestAuthorizeRefusesAccessTokenForAnotherIdentityWithFractionalExpiry(t *testing.T) {
	f := cliauthtest.New(t)
	f.AccessClaims = map[string]any{"sub": "someone-else", "exp": float64(time.Now().Add(time.Minute).Unix()) + 0.5}
	_, err := authorize(t, f, AuthorizeOptions{})
	assert.ErrorIs(t, err, ErrIdentityChanged)
}

func TestUnverifiedClaims(t *testing.T) {
	jwtOf := func(payload string) string {
		return "e30." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
	}
	want := Identity{Issuer: "https://idp.example", Subject: "s"}
	cases := []struct {
		payload string
		changed bool
	}{
		{`{"iss":"https://idp.example","sub":"s","exp":1791979200.5}`, false},
		{`{"iss":"https://idp.example","sub":"other","exp":1791979200.5}`, true},
		{`{"iss":"https://other.example","exp":"soon"}`, true},
		{`{"sub":42}`, true},
		{`{"exp":1791979200}`, false},
		{`[1,2]`, false},
	}
	for _, tc := range cases {
		err := checkTokenIdentity(jwtOf(tc.payload), want)
		if tc.changed {
			assert.ErrorIs(t, err, ErrIdentityChanged, tc.payload)
		} else {
			assert.NoError(t, err, tc.payload)
		}
	}
	assert.NoError(t, checkTokenIdentity("opaque-token", want))

	sent := time.Unix(1791970000, 0)
	assert.Equal(t, time.Unix(1791979200, 0), expiry(sent, 0, jwtOf(`{"exp":1791979200.9}`)))
	assert.Equal(t, sent.Add(time.Minute), expiry(sent, 60, jwtOf(`{"exp":1e300}`)))
	assert.Equal(t, sent, expiry(sent, 0, jwtOf(`{"exp":"never"}`)))
}
