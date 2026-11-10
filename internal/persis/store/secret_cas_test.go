// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package store_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/cmn/crypto"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	"github.com/dagucloud/dagu/v2/internal/secret"
)

// interleavingCollection runs a write of another process once, right after
// a read of a record has been handed out and before the reader replaces it:
// the window in which a plain replace lost that write (TXE-6145).
type interleavingCollection struct {
	persis.Collection
	once      sync.Once
	armed     bool
	meanwhile func()
}

func (c *interleavingCollection) Get(ctx context.Context, id string) (*persis.Record, error) {
	rec, err := c.Collection.Get(ctx, id)
	if err == nil && c.armed {
		c.once.Do(func() {
			c.armed = false
			c.meanwhile()
		})
	}
	return rec, err
}

// interleaved is a store whose next read is followed by a write of another
// store on the same records, that other store, and a secret both hold.
type interleaved struct {
	store, other *store.SecretStore
	col          *interleavingCollection
	id           string
}

func newInterleavedStores(t *testing.T) interleaved {
	t.Helper()
	ctx := context.Background()
	enc, err := crypto.NewEncryptor("test-key")
	require.NoError(t, err)
	shared := testutil.NewMemoryBackend().Collection("secrets")
	other, err := store.NewSecretStore(shared, enc)
	require.NoError(t, err)
	col := &interleavingCollection{Collection: shared}
	reader, err := store.NewSecretStore(col, enc)
	require.NoError(t, err)

	sec := newSecret(secret.GlobalWorkspace, "runtime-profiles/prod/key-544f4b454e")
	require.NoError(t, other.Create(ctx, sec, &secret.WriteValueInput{Value: "v1"}))
	return interleaved{store: reader, other: other, col: col, id: sec.ID}
}

// A read's stamp never puts back the record it read over a value written
// since: the newer version survives, and the read names the version whose
// value it returned.
func TestSecretResolveKeepsAWriteThatLandedSinceItsRead(t *testing.T) {
	ctx := context.Background()
	rig := newInterleavedStores(t)
	reader, other, col, id := rig.store, rig.other, rig.col, rig.id
	col.armed = true
	col.meanwhile = func() {
		_, err := other.WriteValue(ctx, id, secret.WriteValueInput{Value: "v2"})
		require.NoError(t, err)
	}

	value, version, err := reader.ResolveValue(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "v1", value)
	assert.Equal(t, 1, version.Version, "the version comes with its value")

	value, version, err = other.ReadValue(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "v2", value, "the write that landed meanwhile is kept")
	assert.Equal(t, 2, version.Version)
}

// Two writers never give one version number two values.
func TestSecretWriteNeverReusesAVersionNumber(t *testing.T) {
	ctx := context.Background()
	rig := newInterleavedStores(t)
	writer, other, col, id := rig.store, rig.other, rig.col, rig.id
	col.armed = true
	col.meanwhile = func() {
		_, err := other.WriteValue(ctx, id, secret.WriteValueInput{Value: "from-other"})
		require.NoError(t, err)
	}

	_, err := writer.WriteValue(ctx, id, secret.WriteValueInput{Value: "from-writer"})
	require.NoError(t, err)

	value, version, err := other.ReadValue(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, 3, version.Version, "both writes are versions of their own")
	assert.Equal(t, "from-writer", value)
}

// A metadata update never drops a version written since its read.
func TestSecretUpdateKeepsAWriteThatLandedSinceItsRead(t *testing.T) {
	ctx := context.Background()
	rig := newInterleavedStores(t)
	updater, other, col, id := rig.store, rig.other, rig.col, rig.id
	current, err := other.GetByID(ctx, id)
	require.NoError(t, err)
	col.armed = true
	col.meanwhile = func() {
		_, err := other.WriteValue(ctx, id, secret.WriteValueInput{Value: "v2"})
		require.NoError(t, err)
	}

	desc := "described"
	current.Description = desc
	require.NoError(t, updater.Update(ctx, current))

	value, version, err := other.ReadValue(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, "v2", value)
	assert.Equal(t, 2, version.Version)
	got, err := other.GetByID(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, desc, got.Description)
}

// Without any race: an update from a copy read before a write keeps that
// write current, and the next write takes a new number.
func TestSecretUpdateFromAnOlderCopyKeepsTheCurrentVersion(t *testing.T) {
	ctx := context.Background()
	s := newSecretStore(t)
	sec := newSecret(secret.GlobalWorkspace, "runtime-profiles/prod/key-41")
	require.NoError(t, s.Create(ctx, sec, &secret.WriteValueInput{Value: "v1"}))
	stale, err := s.GetByID(ctx, sec.ID)
	require.NoError(t, err)
	_, err = s.WriteValue(ctx, sec.ID, secret.WriteValueInput{Value: "v2"})
	require.NoError(t, err)

	stale.Description = "described"
	require.NoError(t, s.Update(ctx, stale))
	value, version, err := s.ReadValue(ctx, sec.ID)
	require.NoError(t, err)
	assert.Equal(t, "v2", value)
	assert.Equal(t, 2, version.Version)

	_, err = s.WriteValue(ctx, sec.ID, secret.WriteValueInput{Value: "v3"})
	require.NoError(t, err)
	value, version, err = s.ReadValue(ctx, sec.ID)
	require.NoError(t, err)
	assert.Equal(t, "v3", value)
	assert.Equal(t, 3, version.Version)
}
