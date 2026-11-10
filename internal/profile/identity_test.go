// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package profile_test

import (
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/cmn/crypto"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	"github.com/dagucloud/dagu/v2/internal/profile"
	"github.com/dagucloud/dagu/v2/internal/secret"
)

type identityRig struct {
	profiles *store.ProfileStore
	col      persis.Collection
	secrets  *store.SecretStore
	manager  *profile.Manager
	resolver *profile.Resolver
}

func newIdentityRig(t *testing.T) identityRig {
	t.Helper()
	col := testutil.NewMemoryBackend().Collection("profiles")
	profiles, err := store.NewProfileStore(col)
	require.NoError(t, err)
	enc, err := crypto.NewEncryptor("test-key")
	require.NoError(t, err)
	secrets, err := store.NewSecretStore(testutil.NewMemoryBackend().Collection("secrets"), enc)
	require.NoError(t, err)
	return identityRig{
		profiles: profiles,
		col:      col,
		secrets:  secrets,
		manager:  profile.NewManager(profiles, secrets),
		resolver: profile.NewResolver(profiles, secrets),
	}
}

// identity reads the identity both ways: from the values' own resolve, and
// from metadata alone. The two must agree for an unchanged state.
func (r identityRig) identity(t *testing.T, req profile.RuntimeRequest) string {
	t.Helper()
	ctx := context.Background()
	resolved, err := r.resolver.ResolveRuntime(ctx, req)
	require.NoError(t, err)
	prospective, err := r.resolver.RuntimeIdentity(ctx, req)
	require.NoError(t, err)
	require.Equal(t, resolved.Identity, prospective, "the metadata read and the resolve name one state")
	return resolved.Identity
}

func (r identityRig) get(t *testing.T, name string) *profile.Profile {
	t.Helper()
	p, err := r.profiles.GetByName(context.Background(), name)
	require.NoError(t, err)
	return p
}

func (r identityRig) create(t *testing.T, name string) *profile.Profile {
	t.Helper()
	p, err := profile.New(profile.CreateInput{Name: name, CreatedBy: "alice"}, time.Now())
	require.NoError(t, err)
	require.NoError(t, r.profiles.Create(context.Background(), p))
	return r.get(t, name)
}

// The negative control: with the clock stopped, two different variable sets
// are two identities. A time-based revision would call them the same.
func TestRuntimeIdentityDiffersForDifferentValuesAtTheSameInstant(t *testing.T) {
	rig := newIdentityRig(t)
	ctx := context.Background()
	frozen := time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC)
	req := profile.RuntimeRequest{ProfileName: "prod"}

	p, err := profile.New(profile.CreateInput{Name: "prod"}, frozen)
	require.NoError(t, err)
	require.NoError(t, p.SetVariable("REGION", "eu", "alice", frozen))
	require.NoError(t, rig.profiles.Create(ctx, p))
	first := rig.identity(t, req)

	p = rig.get(t, "prod")
	require.NoError(t, p.SetVariable("REGION", "us", "alice", frozen))
	require.NoError(t, rig.profiles.Update(ctx, p))
	second := rig.identity(t, req)

	require.Equal(t, frozen, rig.get(t, "prod").UpdatedAt, "the clock did not move")
	assert.NotEmpty(t, first)
	assert.NotEqual(t, first, second)
}

func TestRuntimeIdentityChangesOnEveryManagedMutation(t *testing.T) {
	ctx := context.Background()
	req := profile.RuntimeRequest{ProfileName: "prod"}

	cases := map[string]func(t *testing.T, rig identityRig){
		"variable added": func(t *testing.T, rig identityRig) {
			_, err := rig.manager.SetVariable(ctx, rig.get(t, "prod"), "NEW", "1", "alice")
			require.NoError(t, err)
		},
		"variable changed": func(t *testing.T, rig identityRig) {
			_, err := rig.manager.SetVariable(ctx, rig.get(t, "prod"), "REGION", "us", "alice")
			require.NoError(t, err)
		},
		"variable set to the same value": func(t *testing.T, rig identityRig) {
			_, err := rig.manager.SetVariable(ctx, rig.get(t, "prod"), "REGION", "eu", "alice")
			require.NoError(t, err)
		},
		"variable deleted": func(t *testing.T, rig identityRig) {
			require.NoError(t, rig.manager.DeleteEntry(ctx, rig.get(t, "prod"), "REGION", "alice"))
		},
		"secret added": func(t *testing.T, rig identityRig) {
			_, err := rig.manager.SetSecret(ctx, rig.get(t, "prod"), "OTHER", "s3cr3t", "alice")
			require.NoError(t, err)
		},
		// The profile document does not change: only the secret's version.
		"secret value rewritten": func(t *testing.T, rig identityRig) {
			before := rig.get(t, "prod").Generation
			_, err := rig.manager.SetSecret(ctx, rig.get(t, "prod"), "TOKEN", "rotated", "alice")
			require.NoError(t, err)
			require.Equal(t, before, rig.get(t, "prod").Generation)
		},
		"secret deleted": func(t *testing.T, rig identityRig) {
			require.NoError(t, rig.manager.DeleteEntry(ctx, rig.get(t, "prod"), "TOKEN", "alice"))
		},
		"description changed": func(t *testing.T, rig identityRig) {
			p := rig.get(t, "prod")
			desc := "other"
			p.ApplyUpdate(profile.UpdateInput{Description: &desc, UpdatedBy: "alice"}, time.Now())
			require.NoError(t, rig.profiles.Update(ctx, p))
		},
		"disabled and enabled again": func(t *testing.T, rig identityRig) {
			p := rig.get(t, "prod")
			require.NoError(t, p.SetStatus(profile.StatusDisabled, "alice", time.Now()))
			require.NoError(t, rig.profiles.Update(ctx, p))
			_, err := rig.resolver.RuntimeIdentity(ctx, req)
			require.ErrorIs(t, err, profile.ErrDisabled, "a disabled profile has no identity to reuse under")
			p = rig.get(t, "prod")
			require.NoError(t, p.SetStatus(profile.StatusActive, "alice", time.Now()))
			require.NoError(t, rig.profiles.Update(ctx, p))
		},
		"deleted and created again with the same entries": func(t *testing.T, rig identityRig) {
			old := rig.get(t, "prod")
			require.NoError(t, rig.profiles.Delete(ctx, "prod"))
			p := rig.create(t, "prod")
			for _, entry := range old.Entries {
				if entry.Kind == profile.EntryKindVariable {
					_, err := rig.manager.SetVariable(ctx, p, entry.Key, entry.Value, "alice")
					require.NoError(t, err)
				}
			}
		},
		"rewritten unchanged": func(t *testing.T, rig identityRig) {
			require.NoError(t, rig.profiles.Update(ctx, rig.get(t, "prod")))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			rig := newIdentityRig(t)
			p := rig.create(t, "prod")
			_, err := rig.manager.SetVariable(ctx, p, "REGION", "eu", "alice")
			require.NoError(t, err)
			_, err = rig.manager.SetSecret(ctx, rig.get(t, "prod"), "TOKEN", "s3cr3t", "alice")
			require.NoError(t, err)
			before := rig.identity(t, req)
			require.Equal(t, before, rig.identity(t, req), "reading changes nothing")

			mutate(t, rig)

			assert.NotEqual(t, before, rig.identity(t, req))
		})
	}
}

func TestRuntimeIdentityCoversTheDefaultLayers(t *testing.T) {
	ctx := context.Background()
	rig := newIdentityRig(t)
	ref, err := profile.WorkspaceInheritedRef("ops")
	require.NoError(t, err)
	inWorkspace := profile.RuntimeRequest{Workspace: "ops"}

	none := rig.identity(t, inWorkspace)
	assert.NotEmpty(t, none, "no layers is a known state")

	global, err := profile.NewInherited(profile.GlobalInheritedRef(), profile.InheritedCreateInput{}, time.Now())
	require.NoError(t, err)
	require.NoError(t, rig.profiles.Create(ctx, global))
	withGlobal := rig.identity(t, inWorkspace)
	assert.NotEqual(t, none, withGlobal)

	layer, err := profile.NewInherited(ref, profile.InheritedCreateInput{}, time.Now())
	require.NoError(t, err)
	require.NoError(t, rig.profiles.Create(ctx, layer))
	withWorkspace := rig.identity(t, inWorkspace)
	assert.NotEqual(t, withGlobal, withWorkspace)
	assert.Equal(t, withGlobal, rig.identity(t, profile.RuntimeRequest{Workspace: "other"}), "another workspace takes only the global layer")

	stored, err := rig.profiles.GetInherited(ctx, ref)
	require.NoError(t, err)
	_, err = rig.manager.SetVariable(ctx, stored, "STAGE", "1", "alice")
	require.NoError(t, err)
	assert.NotEqual(t, withWorkspace, rig.identity(t, inWorkspace))

	stored, err = rig.profiles.GetInherited(ctx, profile.GlobalInheritedRef())
	require.NoError(t, err)
	before := rig.identity(t, inWorkspace)
	_, err = rig.manager.SetSecret(ctx, stored, "SHARED", "v1", "alice")
	require.NoError(t, err)
	assert.NotEqual(t, before, rig.identity(t, inWorkspace))
}

func TestRuntimeIdentityTellsTheSelectedProfileApart(t *testing.T) {
	ctx := context.Background()
	rig := newIdentityRig(t)
	for _, name := range []string{"prod", "staging"} {
		p := rig.create(t, name)
		_, err := rig.manager.SetVariable(ctx, p, "REGION", "eu", "alice")
		require.NoError(t, err)
	}
	none := rig.identity(t, profile.RuntimeRequest{})
	prod := rig.identity(t, profile.RuntimeRequest{ProfileName: "prod"})
	staging := rig.identity(t, profile.RuntimeRequest{ProfileName: "staging"})
	assert.NotEqual(t, none, prod)
	assert.NotEqual(t, prod, staging, "same keys and values, another profile")

	_, err := rig.resolver.RuntimeIdentity(ctx, profile.RuntimeRequest{ProfileName: "gone"})
	require.ErrorIs(t, err, profile.ErrNotFound)
}

// A record from before generations existed, or one rewritten by a build that
// drops the field, has no generation: its state is unknown, never "same".
func TestRuntimeIdentityIsUnknownForARecordWithoutGeneration(t *testing.T) {
	ctx := context.Background()
	rig := newIdentityRig(t)
	p := rig.create(t, "prod")
	p.Generation = ""
	data, err := json.Marshal(map[string]any{"profile": p})
	require.NoError(t, err)
	require.NoError(t, rig.col.Put(ctx, &persis.Record{ID: "prod", Data: data, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}))

	assert.Empty(t, rig.identity(t, profile.RuntimeRequest{ProfileName: "prod"}))
	assert.NotEmpty(t, rig.identity(t, profile.RuntimeRequest{}), "a run that takes no such layer is unaffected")

	// The next write through the store gives it a generation.
	require.NoError(t, rig.profiles.Update(ctx, rig.get(t, "prod")))
	assert.NotEmpty(t, rig.identity(t, profile.RuntimeRequest{ProfileName: "prod"}))
}

// The store, not the caller, names a stored state.
func TestProfileStoreAssignsTheGeneration(t *testing.T) {
	ctx := context.Background()
	rig := newIdentityRig(t)
	p, err := profile.New(profile.CreateInput{Name: "prod"}, time.Now())
	require.NoError(t, err)
	p.Generation = "chosen-by-caller"
	require.NoError(t, rig.profiles.Create(ctx, p))
	created := rig.get(t, "prod").Generation
	assert.NotEqual(t, "chosen-by-caller", created)
	assert.Equal(t, created, p.Generation, "the caller sees what was stored")

	// A caller holding an older copy, with its old generation, still gets
	// a new one: every write is a new state.
	stale := rig.get(t, "prod")
	seen := map[string]bool{created: true}
	for range 3 {
		require.NoError(t, rig.profiles.Update(ctx, stale))
		assert.False(t, seen[stale.Generation], "a write never repeats a generation")
		seen[stale.Generation] = true
	}
}

// Every way to write a profile goes through these methods. A new method on
// the profile, its manager or its store must be classified here, and a write
// must have a case in TestRuntimeIdentityChangesOnEveryManagedMutation.
func TestEveryProfileWriterIsCoveredByTheIdentity(t *testing.T) {
	classified := map[reflect.Type][]string{
		reflect.TypeFor[*profile.Profile](): {
			// In-memory edits; persisted only through the store below.
			"ApplyUpdate", "Clone", "DeleteEntry", "SetSecret", "SetStatus", "SetVariable",
		},
		reflect.TypeFor[*profile.Manager](): {
			// Writers: through ProfileStore.Update, or a secret version.
			"DeleteEntry", "SetSecret", "SetVariable",
			// Readers.
			"EnsureRunnable", "Resolve",
		},
		reflect.TypeFor[*store.ProfileStore](): {
			// Writers: Create and Update assign a generation; Delete
			// removes the ID, which a new Create never reuses.
			"Create", "Delete", "Update",
			// Readers.
			"GetByName", "GetInherited", "List",
		},
	}
	for typ, names := range classified {
		var methods []string
		for method := range typ.Methods() {
			methods = append(methods, method.Name)
		}
		slices.Sort(names)
		assert.Equal(t, names, methods, "%s: classify each new method for the runtime identity (TXE-6145)", typ)
	}
}

// Writes from separate processes (here: separate stores on one collection)
// never lose a version, so a version number names one value.
func TestSecretVersionsAreUniqueUnderConcurrentWriters(t *testing.T) {
	ctx := context.Background()
	col := testutil.NewMemoryBackend().Collection("secrets")
	enc, err := crypto.NewEncryptor("test-key")
	require.NoError(t, err)
	stores := make([]*store.SecretStore, 3)
	for i := range stores {
		stores[i], err = store.NewSecretStore(col, enc)
		require.NoError(t, err)
	}
	sec, err := secret.New(secret.CreateInput{
		Workspace: secret.GlobalWorkspace, Ref: "runtime-profiles/prod/key-544f4b454e",
		ProviderType: secret.ProviderDaguManaged,
	}, time.Now())
	require.NoError(t, err)
	require.NoError(t, stores[0].Create(ctx, sec, &secret.WriteValueInput{Value: "v0"}))

	const writes = 20
	done := make(chan struct{})
	for w := range 2 {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := range writes {
				_, err := stores[w].WriteValue(ctx, sec.ID, secret.WriteValueInput{Value: string(rune('a'+w)) + string(rune('0'+i%10))})
				assert.NoError(t, err)
			}
		}()
	}
	go func() {
		defer func() { done <- struct{}{} }()
		for range writes {
			_, _, err := stores[2].ResolveValue(ctx, sec.ID)
			assert.NoError(t, err)
		}
	}()
	for range 3 {
		<-done
	}

	current, err := stores[0].GetCurrentVersion(ctx, sec.ID)
	require.NoError(t, err)
	assert.Equal(t, 1+2*writes, current.Version, "no write was lost")
}
