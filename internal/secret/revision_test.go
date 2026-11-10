// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package secret_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/cmn/crypto"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	"github.com/dagucloud/dagu/v2/internal/secret"
	secretref "github.com/dagucloud/dagu/v2/internal/secret/ref"
)

func newRevisionStore(t *testing.T) *store.SecretStore {
	t.Helper()
	enc, err := crypto.NewEncryptor("revision-test")
	require.NoError(t, err)
	secrets, err := store.NewSecretStore(testutil.NewMemoryBackend().Collection("secrets"), enc)
	require.NoError(t, err)
	return secrets
}

func createManaged(t *testing.T, secrets secret.Store, workspace, ref, value string, now time.Time) *secret.Secret {
	t.Helper()
	sec, err := secret.New(secret.CreateInput{Workspace: workspace, Ref: ref, ProviderType: secret.ProviderDaguManaged}, now)
	require.NoError(t, err)
	require.NoError(t, secrets.Create(context.Background(), sec, &secret.WriteValueInput{Value: value, CreatedAt: now}))
	return sec
}

// The revision a resolve reads its value from is the one metadata names
// before it, and each change of the stored state names another, with the
// clock frozen (TXE-6222).
func TestReferenceRevisionFollowsTheStoredState(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	secrets := newRevisionStore(t)
	global := createManaged(t, secrets, secret.GlobalWorkspace, "team/token", "v1", now)
	ref := secretref.Ref{Name: "TOKEN", Ref: "team/token"}
	resolver := secret.NewReferenceResolver(secrets, "payments")

	first, err := resolver.Revision(ctx, ref)
	require.NoError(t, err)
	value, read, err := resolver.ResolveReferenceRevision(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, "v1", value)
	assert.Equal(t, first, read, "the value is read from the revision metadata names")
	assert.Equal(t, secretref.Revision{SecretID: global.ID, Version: 1}, read)

	// A new value at the same instant.
	_, err = secrets.WriteValue(ctx, global.ID, secret.WriteValueInput{Value: "v2", CreatedAt: now})
	require.NoError(t, err)
	rotated, err := resolver.Revision(ctx, ref)
	require.NoError(t, err)
	assert.NotEqual(t, first, rotated, "a rotation")
	value, read, err = resolver.ResolveReferenceRevision(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, "v2", value)
	assert.Equal(t, rotated, read)

	// The same value written again is still another version.
	_, err = secrets.WriteValue(ctx, global.ID, secret.WriteValueInput{Value: "v2", CreatedAt: now})
	require.NoError(t, err)
	rewritten, err := resolver.Revision(ctx, ref)
	require.NoError(t, err)
	assert.NotEqual(t, rotated, rewritten)

	// A secret of the workspace shadows the global one.
	shadow := createManaged(t, secrets, "payments", "team/token", "v2", now)
	shadowed, err := resolver.Revision(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, secretref.Revision{SecretID: shadow.ID, Version: 1}, shadowed)

	// Deleted and created again under the same ref: another secret.
	require.NoError(t, secrets.Delete(ctx, shadow.ID))
	recreated := createManaged(t, secrets, "payments", "team/token", "v2", now)
	again, err := resolver.Revision(ctx, ref)
	require.NoError(t, err)
	assert.NotEqual(t, shadowed, again)
	assert.Equal(t, recreated.ID, again.SecretID)
}

// A secret that cannot be resolved has no revision. Disabling keeps the
// stored value and its version: enabled again, the secret names the same
// revision, since no new value was written.
func TestReferenceRevisionOfAnUnresolvableSecret(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Now()
	secrets := newRevisionStore(t)
	sec := createManaged(t, secrets, secret.GlobalWorkspace, "team/token", "v1", now)
	ref := secretref.Ref{Name: "TOKEN", Ref: "team/token"}
	resolver := secret.NewReferenceResolver(secrets, "")

	before, err := resolver.Revision(ctx, ref)
	require.NoError(t, err)

	_, err = resolver.Revision(ctx, secretref.Ref{Name: "TOKEN", Ref: "team/missing"})
	require.ErrorIs(t, err, secret.ErrNotFound)

	disabled, err := secrets.GetByID(ctx, sec.ID)
	require.NoError(t, err)
	require.NoError(t, disabled.SetStatus(secret.StatusDisabled, "alice", now))
	require.NoError(t, secrets.Update(ctx, disabled))
	_, err = resolver.Revision(ctx, ref)
	require.ErrorIs(t, err, secret.ErrDisabled)
	_, _, err = resolver.ResolveReferenceRevision(ctx, ref)
	require.ErrorIs(t, err, secret.ErrDisabled)

	enabled, err := secrets.GetByID(ctx, sec.ID)
	require.NoError(t, err)
	require.NoError(t, enabled.SetStatus(secret.StatusActive, "alice", now))
	require.NoError(t, secrets.Update(ctx, enabled))
	after, err := resolver.Revision(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, before, after)
}
