// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	secretref "github.com/dagucloud/dagu/v2/internal/secret/ref"
	"github.com/dagucloud/dagu/v2/internal/spec"
)

func TestRecordedRuntimeIdentity(t *testing.T) {
	t.Parallel()

	plain := &ir.DAG{Steps: []ir.Step{{Name: "a"}}}
	x := spec.RunRuntimeIdentity(plain, "rp1:x")
	require.NotEmpty(t, x)
	carrying := func(identity string) *ir.DAGRunStatus {
		return &ir.DAGRunStatus{RuntimeIdentity: identity, Nodes: []*ir.Node{{Status: ir.NodeSucceeded}}}
	}

	assert.Equal(t, x, recordedRuntimeIdentity(plain, "rp1:x", nil, nil), "a first run takes its own")
	defaultBase := &ir.DAG{BaseConfigData: []byte("# Base DAG Configuration\ntype: graph\noverlap_policy: skip\nhist_retention_days: 30\nmax_output_size: 1048576\n")}
	assert.Equal(t, spec.RunRuntimeIdentity(defaultBase, "rp1:x"), recordedRuntimeIdentity(defaultBase, "rp1:x", nil, nil), "a new hub's base configuration sets no runtime context")
	assert.NotEmpty(t, recordedRuntimeIdentity(defaultBase, "rp1:x", nil, nil))
	assert.Equal(t, x, recordedRuntimeIdentity(plain, "rp1:x", nil, &ir.DAGRunStatus{Nodes: []*ir.Node{{Status: ir.NodeNotStarted}}}), "a queued run carries nothing")
	assert.Equal(t, x, recordedRuntimeIdentity(plain, "rp1:x", nil, carrying(x)), "a retry of the same state")
	assert.Empty(t, recordedRuntimeIdentity(plain, "rp1:x", nil, carrying("rp1:y")), "nodes of another state")
	assert.Empty(t, recordedRuntimeIdentity(plain, "rp1:x", nil, carrying("")), "nodes of an unknown state")
	assert.Empty(t, recordedRuntimeIdentity(plain, "", nil, nil), "an unknown resolve")

	for name, dag := range map[string]*ir.DAG{
		"DAG secrets": {Secrets: []secretref.Ref{{Name: "TOKEN"}}},
		"base env":    {BaseConfigData: []byte("env:\n  - A: 1\n")},
		"base type":   {BaseConfigData: []byte("type: chain\n")},
		"sub-DAG":     {Steps: []ir.Step{{Name: "child", SubDAG: &ir.SubDAG{Name: "other"}}}},
	} {
		assert.Empty(t, recordedRuntimeIdentity(dag, "rp1:x", nil, nil), "%s has no server-side version", name)
		assert.ErrorIs(t, checkExpectedRuntimeIdentity(dag, "rp1:x", nil, &ir.DAGRunStatus{ExpectedRuntimeIdentity: spec.RunRuntimeIdentity(plain, "rp1:x")}), ErrRuntimeIdentityChanged, name)
	}
}

func TestADotenvFileReadMakesTheIdentityUnknown(t *testing.T) {
	t.Parallel()

	dag := &ir.DAG{Dotenv: []string{".env"}}
	x := spec.RunRuntimeIdentity(dag, "rp1:x")
	assert.Equal(t, x, recordedRuntimeIdentity(dag, "rp1:x", nil, nil), "a named .env that is not there adds nothing")
	assert.Empty(t, recordedRuntimeIdentity(dag, "rp1:x", []string{"/work/.env"}, nil))
	assert.ErrorIs(t, checkExpectedRuntimeIdentity(dag, "rp1:x", []string{"/work/.env"}, &ir.DAGRunStatus{ExpectedRuntimeIdentity: x}), ErrRuntimeIdentityChanged)
}

func TestCheckExpectedRuntimeIdentity(t *testing.T) {
	t.Parallel()

	dag := &ir.DAG{}
	expecting := &ir.DAGRunStatus{ExpectedRuntimeIdentity: spec.RunRuntimeIdentity(dag, "rp1:x")}
	assert.NoError(t, checkExpectedRuntimeIdentity(dag, "", nil, nil), "no seed, no check")
	assert.NoError(t, checkExpectedRuntimeIdentity(dag, "", nil, &ir.DAGRunStatus{}), "nothing reused automatically")
	assert.NoError(t, checkExpectedRuntimeIdentity(dag, "rp1:x", nil, expecting))
	assert.ErrorIs(t, checkExpectedRuntimeIdentity(dag, "rp1:y", nil, expecting), ErrRuntimeIdentityChanged)
	assert.ErrorIs(t, checkExpectedRuntimeIdentity(dag, "", nil, expecting), ErrRuntimeIdentityChanged)
}

// The output limit bounds what a step outputs: another one is another state.
func TestRunRuntimeIdentityCoversTheOutputLimit(t *testing.T) {
	t.Parallel()

	small := &ir.DAG{MaxOutputSize: 1024}
	large := &ir.DAG{MaxOutputSize: 2048}
	assert.NotEqual(t, spec.RunRuntimeIdentity(small, "rp1:x"), spec.RunRuntimeIdentity(large, "rp1:x"))
	assert.Empty(t, spec.RunRuntimeIdentity(small, ""), "an unknown profile state stays unknown")
}
