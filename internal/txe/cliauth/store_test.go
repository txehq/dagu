// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cliauth

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/cmn/crypto"
	"github.com/dagucloud/dagu/v2/internal/txe/cliauth/cliauthtest"
)

const testHub = "http://127.0.0.1:18080"

func signIn(t *testing.T, f *cliauthtest.Provider) *Tokens {
	t.Helper()
	tokens, err := authorize(t, f, AuthorizeOptions{})
	require.NoError(t, err)
	return tokens
}

func TestRefreshVerdicts(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		refused bool
	}{
		{"invalid_grant", 400, `{"error":"invalid_grant","error_description":"User disabled"}`, true},
		{"not_allowed", 400, `{"error":"not_allowed"}`, true},
		{"invalid_client", 401, `{"error":"invalid_client"}`, true},
		{"server error with OAuth body", 503, `{"error":"temporarily_unavailable"}`, false},
		{"internal error", 500, `oops`, false},
		{"rate limited", 429, `{"error":"slow_down"}`, false},
		{"400 not JSON", 400, `<html>bad gateway</html>`, false},
		{"400 JSON without error", 400, `{"message":"no"}`, false},
		{"200 not JSON", 200, `<html>login</html>`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := cliauthtest.New(t)
			tokens := signIn(t, f)
			f.RefreshHandler = func(w http.ResponseWriter) bool {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
				return true
			}
			_, err := Refresh(context.Background(), providerOf(f), tokens.Identity, tokens.RefreshToken, nil)
			require.Error(t, err)
			var refused *RefusedError
			var unverifiable *UnverifiableError
			if tc.refused {
				require.ErrorAs(t, err, &refused)
				assert.Contains(t, err.Error(), "dagu txe login")
				assert.False(t, errors.As(err, &unverifiable))
			} else {
				require.ErrorAs(t, err, &unverifiable)
				assert.Contains(t, err.Error(), "did not answer")
				assert.False(t, errors.As(err, &refused))
			}
		})
	}
}

func TestRefreshUnreachableProviderIsUnverifiable(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	_, err = Refresh(context.Background(), Provider{Issuer: "http://" + addr, ClientID: "c"}, Identity{Issuer: "http://" + addr, Subject: "s"}, "rt", nil)
	var unverifiable *UnverifiableError
	require.ErrorAs(t, err, &unverifiable)
}

func TestRefreshKeepsIdentity(t *testing.T) {
	t.Run("same identity", func(t *testing.T) {
		f := cliauthtest.New(t)
		f.RefreshIDToken = true
		f.Rotate = true
		tokens := signIn(t, f)
		renewed, err := Refresh(context.Background(), providerOf(f), tokens.Identity, tokens.RefreshToken, nil)
		require.NoError(t, err)
		assert.Equal(t, tokens.Identity, renewed.Identity)
		assert.NotEqual(t, tokens.RefreshToken, renewed.RefreshToken, "rotated")
	})
	t.Run("kept refresh token when not rotated", func(t *testing.T) {
		f := cliauthtest.New(t)
		tokens := signIn(t, f)
		renewed, err := Refresh(context.Background(), providerOf(f), tokens.Identity, tokens.RefreshToken, nil)
		require.NoError(t, err)
		assert.Equal(t, tokens.RefreshToken, renewed.RefreshToken)
	})
	t.Run("ID token for another subject", func(t *testing.T) {
		f := cliauthtest.New(t)
		tokens := signIn(t, f)
		f.RefreshIDToken = true
		f.IDSubject = "someone-else"
		_, err := Refresh(context.Background(), providerOf(f), tokens.Identity, tokens.RefreshToken, nil)
		assert.ErrorIs(t, err, ErrIdentityChanged)
	})
	t.Run("access token for another subject", func(t *testing.T) {
		f := cliauthtest.New(t)
		tokens := signIn(t, f)
		f.AccessSubject = "someone-else"
		_, err := Refresh(context.Background(), providerOf(f), tokens.Identity, tokens.RefreshToken, nil)
		assert.ErrorIs(t, err, ErrIdentityChanged)
	})
	t.Run("identity at another issuer", func(t *testing.T) {
		f := cliauthtest.New(t)
		tokens := signIn(t, f)
		want := Identity{Issuer: "https://other.example", Subject: tokens.Identity.Subject}
		_, err := Refresh(context.Background(), providerOf(f), want, tokens.RefreshToken, nil)
		assert.ErrorIs(t, err, ErrIdentityChanged)
	})
}

func TestRevoke(t *testing.T) {
	f := cliauthtest.New(t)
	tokens := signIn(t, f)
	ok, err := Revoke(context.Background(), providerOf(f), tokens.RefreshToken, nil)
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, []string{tokens.RefreshToken}, f.Revoked())
	_, err = Refresh(context.Background(), providerOf(f), tokens.Identity, tokens.RefreshToken, nil)
	var refused *RefusedError
	assert.ErrorAs(t, err, &refused)

	f.NoRevocation = true
	ok, err = Revoke(context.Background(), providerOf(f), "x", nil)
	require.NoError(t, err)
	assert.False(t, ok)
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	enc, err := crypto.NewEncryptor("test-key-0123456789abcdef0123456789")
	require.NoError(t, err)
	s, err := NewStore(filepath.Join(t.TempDir(), "signin"), enc)
	require.NoError(t, err)
	return s
}

func entryFor(f *cliauthtest.Provider, tokens *Tokens) *Entry {
	return &Entry{
		Hub: testHub, Provider: providerOf(f), Identity: tokens.Identity, Username: tokens.Username,
		AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken, Expiry: tokens.Expiry,
		SignedInAt: time.Now(),
	}
}

func TestStoreKeepsTokensPrivateAndEncrypted(t *testing.T) {
	f := cliauthtest.New(t)
	tokens := signIn(t, f)
	s := newTestStore(t)
	previous, err := s.Replace(context.Background(), entryFor(f, tokens))
	require.NoError(t, err)
	assert.Nil(t, previous)

	file, _, err := s.paths(testHub)
	require.NoError(t, err)
	data, err := os.ReadFile(file)
	require.NoError(t, err)
	assert.NotContains(t, string(data), tokens.AccessToken)
	assert.NotContains(t, string(data), tokens.RefreshToken)
	assert.Contains(t, string(data), tokens.Identity.Subject)

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(file)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
		di, err := os.Stat(s.dir)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o700), di.Mode().Perm())

		require.NoError(t, os.Chmod(file, 0o644))
		_, err = s.Load(testHub)
		assert.ErrorContains(t, err, "other users")
	}
}

func TestStoreDirectoryIsClosedToOthers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits")
	}
	dir := filepath.Join(t.TempDir(), "signin")
	require.NoError(t, os.Mkdir(dir, 0o755))
	require.NoError(t, os.Chmod(dir, 0o755))
	enc, err := crypto.NewEncryptor("k")
	require.NoError(t, err)
	_, err = NewStore(dir, enc)
	require.NoError(t, err)
	di, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), di.Mode().Perm())

	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(dir, link))
	_, err = NewStore(link, enc)
	assert.ErrorContains(t, err, "symbolic link")
}

func TestStoreKeysByHubAndReplacesAccount(t *testing.T) {
	f := cliauthtest.New(t)
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.Load(testHub)
	assert.ErrorIs(t, err, ErrNotSignedIn)

	first := signIn(t, f)
	_, err = s.Replace(ctx, entryFor(f, first))
	require.NoError(t, err)

	// The same hub written another way is the same entry; another hub is not.
	got, err := s.Load("HTTP://127.0.0.1:18080/")
	require.NoError(t, err)
	assert.Equal(t, first.Identity, got.Identity)
	_, err = s.Load("http://127.0.0.1:18081")
	assert.ErrorIs(t, err, ErrNotSignedIn)

	// Signing in as someone else replaces the entry and hands back the old one.
	f.Subject = "subject-b"
	f.Username = "bob"
	second := signIn(t, f)
	previous, err := s.Replace(ctx, entryFor(f, second))
	require.NoError(t, err)
	require.NotNil(t, previous)
	assert.Equal(t, first.Identity, previous.Identity)
	assert.Equal(t, first.RefreshToken, previous.RefreshToken)
	got, err = s.Load(testHub)
	require.NoError(t, err)
	assert.Equal(t, "subject-b", got.Identity.Subject)
	assert.Equal(t, second.RefreshToken, got.RefreshToken)

	removed, err := s.Remove(ctx, testHub)
	require.NoError(t, err)
	assert.Equal(t, "subject-b", removed.Identity.Subject)
	_, err = s.Remove(ctx, testHub)
	assert.ErrorIs(t, err, ErrNotSignedIn)
}

func TestStoreRefusesEntryForAnotherIssuer(t *testing.T) {
	f := cliauthtest.New(t)
	tokens := signIn(t, f)
	e := entryFor(f, tokens)
	e.Identity.Issuer = "https://other.example"
	_, err := newTestStore(t).Replace(context.Background(), e)
	assert.Error(t, err)
}

// expire makes the stored access token due for renewal.
func expire(t *testing.T, s *Store, by time.Duration) {
	t.Helper()
	e, err := s.Load(testHub)
	require.NoError(t, err)
	file, _, _ := s.paths(testHub)
	e.Expiry = time.Now().Add(by)
	require.NoError(t, s.write(file, e))
}

func TestStoreAccessTokenRenewal(t *testing.T) {
	ctx := context.Background()

	t.Run("fresh token is used as it is", func(t *testing.T) {
		f := cliauthtest.New(t)
		s := newTestStore(t)
		tokens := signIn(t, f)
		_, err := s.Replace(ctx, entryFor(f, tokens))
		require.NoError(t, err)
		got, err := s.AccessToken(ctx, testHub, nil)
		require.NoError(t, err)
		assert.Equal(t, tokens.AccessToken, got)
		assert.Equal(t, 0, f.Refreshes())
	})

	t.Run("due token is renewed and saved", func(t *testing.T) {
		f := cliauthtest.New(t)
		f.Rotate = true
		s := newTestStore(t)
		tokens := signIn(t, f)
		_, err := s.Replace(ctx, entryFor(f, tokens))
		require.NoError(t, err)
		expire(t, s, 10*time.Second)
		got, err := s.AccessToken(ctx, testHub, nil)
		require.NoError(t, err)
		assert.NotEqual(t, tokens.AccessToken, got)
		e, err := s.Load(testHub)
		require.NoError(t, err)
		assert.Equal(t, got, e.AccessToken)
		assert.NotEqual(t, tokens.RefreshToken, e.RefreshToken)
		assert.False(t, e.RenewedAt.IsZero())
		assert.Equal(t, 1, f.Refreshes())
	})

	t.Run("refusal ends the sign-in", func(t *testing.T) {
		f := cliauthtest.New(t)
		s := newTestStore(t)
		_, err := s.Replace(ctx, entryFor(f, signIn(t, f)))
		require.NoError(t, err)
		expire(t, s, -time.Second)
		f.RefreshHandler = func(w http.ResponseWriter) bool {
			cliauthtest.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return true
		}
		_, err = s.AccessToken(ctx, testHub, nil)
		var refused *RefusedError
		require.ErrorAs(t, err, &refused)
		_, err = s.Load(testHub)
		assert.ErrorIs(t, err, ErrNotSignedIn)
	})

	t.Run("another identity ends the sign-in", func(t *testing.T) {
		f := cliauthtest.New(t)
		s := newTestStore(t)
		_, err := s.Replace(ctx, entryFor(f, signIn(t, f)))
		require.NoError(t, err)
		expire(t, s, -time.Second)
		f.AccessSubject = "someone-else"
		_, err = s.AccessToken(ctx, testHub, nil)
		require.ErrorIs(t, err, ErrIdentityChanged)
		_, err = s.Load(testHub)
		assert.ErrorIs(t, err, ErrNotSignedIn)
	})

	t.Run("no verdict keeps the sign-in and a still valid token", func(t *testing.T) {
		f := cliauthtest.New(t)
		s := newTestStore(t)
		tokens := signIn(t, f)
		_, err := s.Replace(ctx, entryFor(f, tokens))
		require.NoError(t, err)
		f.RefreshHandler = func(w http.ResponseWriter) bool {
			w.WriteHeader(http.StatusServiceUnavailable)
			return true
		}
		expire(t, s, 10*time.Second)
		got, err := s.AccessToken(ctx, testHub, nil)
		require.NoError(t, err)
		assert.Equal(t, tokens.AccessToken, got)

		expire(t, s, -time.Second)
		_, err = s.AccessToken(ctx, testHub, nil)
		var unverifiable *UnverifiableError
		require.ErrorAs(t, err, &unverifiable)
		e, err := s.Load(testHub)
		require.NoError(t, err, "an outage is not a sign-out")
		assert.Equal(t, tokens.RefreshToken, e.RefreshToken)
	})

	t.Run("not signed in", func(t *testing.T) {
		_, err := newTestStore(t).AccessToken(ctx, testHub, nil)
		assert.ErrorIs(t, err, ErrNotSignedIn)
	})
}

func TestStoreRenewAfterHubRefusal(t *testing.T) {
	ctx := context.Background()
	f := cliauthtest.New(t)
	f.Rotate = true
	s := newTestStore(t)
	tokens := signIn(t, f)
	_, err := s.Replace(ctx, entryFor(f, tokens))
	require.NoError(t, err)

	// The hub refused the token we sent: renew even though it looks fresh.
	renewed, err := s.Renew(ctx, testHub, tokens.AccessToken, nil)
	require.NoError(t, err)
	assert.NotEqual(t, tokens.AccessToken, renewed)
	assert.Equal(t, 1, f.Refreshes())

	// A second caller still holding the old token gets the newer one
	// without another renewal.
	again, err := s.Renew(ctx, testHub, tokens.AccessToken, nil)
	require.NoError(t, err)
	assert.Equal(t, renewed, again)
	assert.Equal(t, 1, f.Refreshes())
}

func TestStoreConcurrentRenewalHappensOnce(t *testing.T) {
	ctx := context.Background()
	f := cliauthtest.New(t)
	f.Rotate = true // a reused refresh token would be refused
	s := newTestStore(t)
	_, err := s.Replace(ctx, entryFor(f, signIn(t, f)))
	require.NoError(t, err)
	expire(t, s, -time.Second)

	// Several stores over one directory stand for separate CLI processes.
	var calls atomic.Int32
	const n = 8
	results := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		peer := &Store{dir: s.dir, enc: s.enc, now: time.Now, renew: func(ctx context.Context, p Provider, want Identity, rt string, c *http.Client) (*Tokens, error) {
			calls.Add(1)
			time.Sleep(20 * time.Millisecond)
			return Refresh(ctx, p, want, rt, c)
		}}
		wg.Go(func() {
			results[i], errs[i] = peer.AccessToken(ctx, testHub, nil)
		})
	}
	wg.Wait()
	for i := range n {
		require.NoError(t, errs[i])
		assert.Equal(t, results[0], results[i])
	}
	assert.Equal(t, int32(1), calls.Load())
	assert.Equal(t, 1, f.Refreshes())
}

func TestNormalizeHub(t *testing.T) {
	got, err := NormalizeHub(" HTTPS://Hub.Example:8443/api/v1/?x=1#f ")
	require.NoError(t, err)
	assert.Equal(t, "https://hub.example:8443/api/v1", got)
	for _, bad := range []string{"", "ftp://hub", "hub.example", "https://u:p@hub"} {
		_, err := NormalizeHub(bad)
		assert.Error(t, err, bad)
	}
	assert.False(t, strings.Contains(got, "?"))
}

func TestRefreshIDTokenAtAnotherIssuerEndsSignIn(t *testing.T) {
	ctx := context.Background()
	f := cliauthtest.New(t)
	s := newTestStore(t)
	_, err := s.Replace(ctx, entryFor(f, signIn(t, f)))
	require.NoError(t, err)
	// Still valid, so a renewal without a verdict would keep using it.
	expire(t, s, 10*time.Second)
	f.RefreshIDToken = true
	f.IDIssuer = "https://other.example"
	_, err = s.AccessToken(ctx, testHub, nil)
	require.ErrorIs(t, err, ErrIdentityChanged)
	_, err = s.Load(testHub)
	assert.ErrorIs(t, err, ErrNotSignedIn)
}

func TestRefreshFailuresWithoutVerdictAreUnverifiable(t *testing.T) {
	cases := map[string]func(t *testing.T, f *cliauthtest.Provider){
		"not a bearer token": func(_ *testing.T, f *cliauthtest.Provider) {
			f.RefreshHandler = func(w http.ResponseWriter) bool {
				cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"access_token": "a", "token_type": "mac", "expires_in": 60})
				return true
			}
		},
		"discovery names another issuer": func(_ *testing.T, f *cliauthtest.Provider) {
			f.IssuerOverride = f.Issuer() + "/"
		},
		"signing keys unreachable": func(t *testing.T, f *cliauthtest.Provider) {
			ln, err := net.Listen("tcp4", "127.0.0.1:0")
			require.NoError(t, err)
			addr := ln.Addr().String()
			require.NoError(t, ln.Close())
			f.RefreshIDToken = true
			f.JWKSURI = "http://" + addr + "/jwks"
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			f := cliauthtest.New(t)
			tokens := signIn(t, f)
			breakIt(t, f)
			_, err := Refresh(context.Background(), providerOf(f), tokens.Identity, tokens.RefreshToken, nil)
			var unverifiable *UnverifiableError
			require.ErrorAs(t, err, &unverifiable)
			var refused *RefusedError
			assert.False(t, errors.As(err, &refused))
			assert.NotErrorIs(t, err, ErrIdentityChanged)
		})
	}
}

func TestStoreRefusesEditedBinding(t *testing.T) {
	ctx := context.Background()
	f := cliauthtest.New(t)
	for _, field := range []string{"issuer", "client_id", "subject", "hub"} {
		t.Run(field, func(t *testing.T) {
			s := newTestStore(t)
			_, err := s.Replace(ctx, entryFor(f, signIn(t, f)))
			require.NoError(t, err)
			file, _, err := s.paths(testHub)
			require.NoError(t, err)
			data, err := os.ReadFile(file)
			require.NoError(t, err)
			var raw map[string]any
			require.NoError(t, json.Unmarshal(data, &raw))
			raw[field] = "https://attacker.example"
			if field == "hub" {
				raw[field] = testHub + "/x"
			}
			edited, err := json.Marshal(raw)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(file, edited, 0o600))

			before := f.Refreshes()
			_, err = s.AccessToken(ctx, testHub, nil)
			require.Error(t, err)
			_, err = s.Renew(ctx, testHub, "stale", nil)
			require.Error(t, err)
			assert.Equal(t, before, f.Refreshes(), "an edited entry sends its refresh token nowhere")

			// Signing in again replaces it.
			_, err = s.Replace(ctx, entryFor(f, signIn(t, f)))
			require.NoError(t, err)
			_, err = s.Load(testHub)
			require.NoError(t, err)
		})
	}
}

func TestStoreRenewalHasDeadline(t *testing.T) {
	ctx := context.Background()
	f := cliauthtest.New(t)
	s := newTestStore(t)
	_, err := s.Replace(ctx, entryFor(f, signIn(t, f)))
	require.NoError(t, err)
	expire(t, s, -time.Second)
	var deadline time.Time
	var bounded bool
	s.renew = func(ctx context.Context, _ Provider, _ Identity, _ string, _ *http.Client) (*Tokens, error) {
		deadline, bounded = ctx.Deadline()
		return nil, &UnverifiableError{Op: "renewal", Err: ctx.Err()}
	}
	start := time.Now()
	_, err = s.AccessToken(ctx, testHub, nil)
	var unverifiable *UnverifiableError
	require.ErrorAs(t, err, &unverifiable)
	require.True(t, bounded)
	assert.WithinRange(t, deadline, start, time.Now().Add(renewTimeout))
	assert.Less(t, renewTimeout, lockTimeout, "a waiting process outlasts a renewal")
}
