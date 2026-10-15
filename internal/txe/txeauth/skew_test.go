// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
)

// The cause of the refusals seen on the K3 and K4 rigs (TXE-4363). A
// provider stamps iat in whole seconds by its own clock. When that clock is a
// little ahead of the hub's, a token used at once is stamped a second the hub
// has not reached yet. With every other claim valid, the hub refuses it as
// not yet valid.
func TestAFreshTokenFromAProviderAheadIsRefusedWithoutIssuedAtTolerance(t *testing.T) {
	w := newWorld(t)
	keys := authn.StaticKeys{testKeyID: {Public: &testRSAKey().PublicKey, Algorithm: "RS256"}}
	second := time.Unix(w.now.Unix(), 0)
	// The hub is at T+0.9 s; the provider, 0.3 s ahead, at T+1.2 s, which it
	// stamps as T+1.
	w.now = second.Add(900 * time.Millisecond)
	issued := second.Add(time.Second)
	svc := skewService(t, w, keys, 0)

	_, err := svc.Verify(w.ctx, token(t, issued, nil))
	require.Equal(t, authn.ReasonNotYetValid, authn.ReasonOf(err), "refused for its issue time alone")

	// The same token a moment later, once the hub reaches T+1, is accepted:
	// nothing else about it was wrong.
	w.now = issued
	_, err = svc.Verify(w.ctx, token(t, issued, nil))
	require.NoError(t, err)
}

// skewService is tokenService with an issued-at tolerance.
func skewService(t *testing.T, w *world, keys authn.KeySource, skew time.Duration) *Service {
	t.Helper()
	svc, err := NewService(config.TXEConfig{Authn: config.TXEAuthnConfig{
		Issuer: testIssuer, Audience: testAudience, JWKSURL: "https://issuer.example/certs",
		Clients:      []config.TXEAuthnClient{{ID: testCLI, Class: "cli"}, {ID: testWorker, Class: "worker"}},
		IssuedAtSkew: skew,
	}}, w.dataDir, w.reg, WithKeySource(keys), WithClock(func() time.Time { return w.now }))
	require.NoError(t, err)
	return svc
}

// With the default tolerance the same token is accepted. The tolerance is
// bounded at both claims it covers, and moves nothing else: expiry is exact
// and the lifetime cap holds. The coordinator verifies with this same
// service, so it accepts and refuses exactly the same tokens.
func TestTheIssuedAtToleranceIsBoundedAndLeavesExpiryExact(t *testing.T) {
	w := newWorld(t)
	keys := authn.StaticKeys{testKeyID: {Public: &testRSAKey().PublicKey, Algorithm: "RS256"}}
	second := time.Unix(w.now.Unix(), 0)
	w.now = second.Add(900 * time.Millisecond)
	skew := config.TXEAuthnDefaultIssuedAtSkew
	svc := skewService(t, w, keys, skew)

	// The token of the rigs is accepted.
	issued := second.Add(time.Second)
	_, err := svc.Verify(w.ctx, token(t, issued, nil))
	require.NoError(t, err)

	// iat or nbf up to now+skew is accepted; one whole second past it is not.
	edge := w.now.Add(skew).Truncate(time.Second)
	_, err = svc.Verify(w.ctx, token(t, edge, nil))
	require.NoError(t, err, "iat within the tolerance")
	past := w.now.Add(skew + time.Second)
	_, err = svc.Verify(w.ctx, token(t, past, nil))
	require.Equal(t, authn.ReasonNotYetValid, authn.ReasonOf(err), "iat past the tolerance")
	_, err = svc.Verify(w.ctx, token(t, second, map[string]any{"nbf": past.Unix()}))
	require.Equal(t, authn.ReasonNotYetValid, authn.ReasonOf(err), "nbf past the tolerance")
	_, err = svc.Verify(w.ctx, token(t, second, map[string]any{"nbf": edge.Unix()}))
	require.NoError(t, err, "nbf within the tolerance")

	// Expiry is exact: a token at its expiry is refused, whatever the
	// tolerance.
	expiring := token(t, second.Add(-time.Minute), map[string]any{"exp": second.Add(time.Second).Unix()})
	w.now = second.Add(time.Second)
	_, err = svc.Verify(w.ctx, expiring)
	require.Equal(t, authn.ReasonExpired, authn.ReasonOf(err))

	// The lifetime cap is measured from iat as before.
	_, err = svc.Verify(w.ctx, token(t, w.now, map[string]any{"exp": w.now.Add(authn.MaxTokenLifetime + time.Second).Unix()}))
	require.Equal(t, authn.ReasonLifetime, authn.ReasonOf(err))
}

// A tolerance over the verifier's bound is refused when the service is built.
func TestTheIssuedAtToleranceIsCapped(t *testing.T) {
	w := newWorld(t)
	keys := authn.StaticKeys{testKeyID: {Public: &testRSAKey().PublicKey, Algorithm: "RS256"}}
	_, err := NewService(config.TXEConfig{Authn: config.TXEAuthnConfig{
		Issuer: testIssuer, Audience: testAudience, JWKSURL: "https://issuer.example/certs",
		Clients:      []config.TXEAuthnClient{{ID: testCLI, Class: "cli"}},
		IssuedAtSkew: authn.MaxIssuedAtSkew + time.Second,
	}}, w.dataDir, w.reg, WithKeySource(keys))
	require.Error(t, err)
}
