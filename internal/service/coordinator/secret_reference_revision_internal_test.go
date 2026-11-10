// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/secret/providers"
	secretref "github.com/dagucloud/dagu/v2/internal/secret/ref"
	"github.com/dagucloud/dagu/v2/internal/serviceregistry"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// A response names a revision only with a secret ID and a version in range:
// an older coordinator sends neither, and its run's identity is unknown
// (TXE-6222).
func TestSecretReferenceRevisionOfAResponse(t *testing.T) {
	t.Parallel()

	assert.Equal(t, secretref.Revision{SecretID: "s", Version: 3},
		secretReferenceRevision(&coordinatorv1.ResolveSecretReferenceResponse{Value: "v", SecretId: "s", Version: 3}))
	for name, resp := range map[string]*coordinatorv1.ResolveSecretReferenceResponse{
		"an older coordinator": {Value: "v"},
		"no secret ID":         {Value: "v", Version: 3},
		"no version":           {Value: "v", SecretId: "s"},
		"a negative version":   {Value: "v", SecretId: "s", Version: -1},
		"out of range":         {Value: "v", SecretId: "s", Version: math.MaxInt32 + 1},
	} {
		assert.False(t, secretReferenceRevision(resp).Known(), name)
	}
}

// valueOnlyClient resolves values and names no revision: a client of an
// older build.
type valueOnlyClient struct{}

func (valueOnlyClient) ResolveSecretReference(context.Context, serviceregistry.HostInfo, secretref.Ref, string, bool, SecretReferenceRun) (string, error) {
	return "value", nil
}

// revisionClient names the revision it read each value from.
type revisionClient struct{ valueOnlyClient }

func (revisionClient) ResolveSecretReferenceRevision(context.Context, serviceregistry.HostInfo, secretref.Ref, string, SecretReferenceRun) (string, secretref.Revision, error) {
	return "value", secretref.Revision{SecretID: "s", Version: 2}, nil
}

func TestSecretReferenceResolverNamesTheClientsRevision(t *testing.T) {
	t.Parallel()

	ref := secretref.Ref{Name: "TOKEN", Ref: "team/token"}
	for name, tc := range map[string]struct {
		client SecretReferenceClient
		want   secretref.Revision
	}{
		"a client that names revisions": {client: revisionClient{}, want: secretref.Revision{SecretID: "s", Version: 2}},
		"an older client":               {client: valueOnlyClient{}},
	} {
		resolver, ok := NewSecretReferenceResolver(tc.client, "", serviceregistry.HostInfo{}, SecretReferenceRun{}).(providers.RevisionedReferenceResolver)
		require.True(t, ok, name)
		value, revision, err := resolver.ResolveReferenceRevision(context.Background(), ref)
		require.NoError(t, err, name)
		assert.Equal(t, "value", value, name)
		assert.Equal(t, tc.want, revision, name)
	}
}
