// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package providers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretref "github.com/dagucloud/dagu/v2/internal/secret/ref"
)

// revisionedReferenceResolver names a revision for each reference it
// resolves, and none for the ref "team/unversioned".
type revisionedReferenceResolver struct{ mockReferenceResolver }

func (revisionedReferenceResolver) ResolveReferenceRevision(_ context.Context, ref secretref.Ref) (string, secretref.Revision, error) {
	if ref.Ref == "team/unversioned" {
		return "value-" + ref.Name, secretref.Revision{}, nil
	}
	return "value-" + ref.Name, secretref.Revision{SecretID: "id-" + ref.Ref, Version: 7}, nil
}

// Only a registry reference whose resolver names the revision it read has
// one; an external provider never has (TXE-6222).
func TestResolveAllRevisions(t *testing.T) {
	t.Setenv("REVISION_TEST_PROVIDER_SECRET", "from-env")
	refs := []secretref.Ref{
		{Name: "A", Ref: "team/a"},
		{Name: "B", Ref: "team/unversioned"},
		{Name: "C", Provider: "env", Key: "REVISION_TEST_PROVIDER_SECRET"},
	}

	envs, revisions, err := NewRegistryWithReferenceResolver(&revisionedReferenceResolver{}).ResolveAllRevisions(context.Background(), refs)
	require.NoError(t, err)
	assert.Equal(t, []string{"A=value-A", "B=value-B", "C=from-env"}, envs)
	assert.Equal(t, map[string]secretref.Revision{"A": {SecretID: "id-team/a", Version: 7}}, revisions)

	envs, revisions, err = NewRegistryWithReferenceResolver(&mockReferenceResolver{}).ResolveAllRevisions(context.Background(), refs[:1])
	require.NoError(t, err)
	assert.Equal(t, []string{"A=mock-reference-value"}, envs)
	assert.Empty(t, revisions, "a resolver that names no revision")

	envs, revisions, err = NewRegistry().ResolveAllRevisions(context.Background(), nil)
	require.NoError(t, err)
	assert.Nil(t, envs)
	assert.Nil(t, revisions)
}
