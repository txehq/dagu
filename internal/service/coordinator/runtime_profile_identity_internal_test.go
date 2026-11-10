// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	profilepkg "github.com/dagucloud/dagu/v2/internal/profile"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// The identity crosses the wire with the values it was read with; a
// response from a coordinator that predates the field decodes as unknown,
// so the worker's run can never pass a check against an expected identity
// (TXE-6145).
func TestRuntimeProfileIdentityOverTheWire(t *testing.T) {
	t.Parallel()

	decode := func(t *testing.T, resp *coordinatorv1.ResolveRuntimeProfileResponse) *profilepkg.RuntimeResolved {
		t.Helper()
		wire, err := proto.Marshal(resp)
		require.NoError(t, err)
		var got coordinatorv1.ResolveRuntimeProfileResponse
		require.NoError(t, proto.Unmarshal(wire, &got))
		resolved, err := runtimeProfileFromProto(&got)
		require.NoError(t, err)
		return resolved
	}

	current := runtimeProfileToProto(&profilepkg.RuntimeResolved{
		Selected: &profilepkg.Resolved{Name: "prod", Variables: map[string]string{}, Secrets: map[string]string{}},
		Identity: "rp1:abc",
	})
	assert.Equal(t, "rp1:abc", decode(t, current).Identity)

	// What an older coordinator sends: the same layers, no field 3.
	older := &coordinatorv1.ResolveRuntimeProfileResponse{Selected: current.GetSelected()}
	resolved := decode(t, older)
	assert.Equal(t, "prod", resolved.Selected.Name)
	assert.Empty(t, resolved.Identity)
}
