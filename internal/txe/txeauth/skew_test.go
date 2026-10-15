// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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
	svc := tokenService(t, w, keys)

	_, err := svc.Verify(w.ctx, token(t, issued, nil))
	require.Equal(t, authn.ReasonNotYetValid, authn.ReasonOf(err), "refused for its issue time alone")

	// The same token a moment later, once the hub reaches T+1, is accepted:
	// nothing else about it was wrong.
	w.now = issued
	_, err = svc.Verify(w.ctx, token(t, issued, nil))
	require.NoError(t, err)
}
