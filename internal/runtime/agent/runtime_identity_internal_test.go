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
	x := spec.RunRuntimeIdentity(plain, "rp1:x", nil)
	require.NotEmpty(t, x)
	carrying := func(identity string) *ir.DAGRunStatus {
		return &ir.DAGRunStatus{RuntimeIdentity: identity, Nodes: []*ir.Node{{Status: ir.NodeSucceeded}}}
	}

	assert.Equal(t, x, recordedRuntimeIdentity(plain, runtimeInputs{profileIdentity: "rp1:x"}, nil), "a first run takes its own")
	defaultBase := &ir.DAG{BaseConfigData: []byte("# Base DAG Configuration\ntype: graph\noverlap_policy: skip\nhist_retention_days: 30\nmax_output_size: 1048576\n")}
	assert.Equal(t, spec.RunRuntimeIdentity(defaultBase, "rp1:x", nil), recordedRuntimeIdentity(defaultBase, runtimeInputs{profileIdentity: "rp1:x"}, nil), "a new hub's base configuration sets no runtime context")
	assert.NotEmpty(t, recordedRuntimeIdentity(defaultBase, runtimeInputs{profileIdentity: "rp1:x"}, nil))
	assert.Equal(t, x, recordedRuntimeIdentity(plain, runtimeInputs{profileIdentity: "rp1:x"}, &ir.DAGRunStatus{Nodes: []*ir.Node{{Status: ir.NodeNotStarted}}}), "a queued run carries nothing")
	assert.Equal(t, x, recordedRuntimeIdentity(plain, runtimeInputs{profileIdentity: "rp1:x"}, carrying(x)), "a retry of the same state")
	assert.Empty(t, recordedRuntimeIdentity(plain, runtimeInputs{profileIdentity: "rp1:x"}, carrying("rp1:y")), "nodes of another state")
	assert.Empty(t, recordedRuntimeIdentity(plain, runtimeInputs{profileIdentity: "rp1:x"}, carrying("")), "nodes of an unknown state")
	assert.Empty(t, recordedRuntimeIdentity(plain, runtimeInputs{}, nil), "an unknown resolve")

	for name, dag := range map[string]*ir.DAG{
		"DAG secrets": {Secrets: []secretref.Ref{{Name: "TOKEN"}}},
		"base env":    {BaseConfigData: []byte("env:\n  - A: 1\n")},
		"base type":   {BaseConfigData: []byte("type: chain\n")},
		"sub-DAG":     {Steps: []ir.Step{{Name: "child", SubDAG: &ir.SubDAG{Name: "other"}}}},
	} {
		assert.Empty(t, recordedRuntimeIdentity(dag, runtimeInputs{profileIdentity: "rp1:x"}, nil), "%s has no server-side version", name)
		assert.ErrorIs(t, checkExpectedRuntimeIdentity(dag, runtimeInputs{profileIdentity: "rp1:x"}, &ir.DAGRunStatus{ExpectedRuntimeIdentity: spec.RunRuntimeIdentity(plain, "rp1:x", nil)}), ErrRuntimeIdentityChanged, name)
	}
}

func TestADotenvFileReadMakesTheIdentityUnknown(t *testing.T) {
	t.Parallel()

	dag := &ir.DAG{Dotenv: []string{".env"}}
	x := spec.RunRuntimeIdentity(dag, "rp1:x", nil)
	assert.Equal(t, x, recordedRuntimeIdentity(dag, runtimeInputs{profileIdentity: "rp1:x"}, nil), "a named .env that is not there adds nothing")
	assert.Empty(t, recordedRuntimeIdentity(dag, runtimeInputs{profileIdentity: "rp1:x", dotenvFiles: []string{"/work/.env"}}, nil))
	assert.ErrorIs(t, checkExpectedRuntimeIdentity(dag, runtimeInputs{profileIdentity: "rp1:x", dotenvFiles: []string{"/work/.env"}}, &ir.DAGRunStatus{ExpectedRuntimeIdentity: x}), ErrRuntimeIdentityChanged)
}

func TestCheckExpectedRuntimeIdentity(t *testing.T) {
	t.Parallel()

	dag := &ir.DAG{}
	expecting := &ir.DAGRunStatus{ExpectedRuntimeIdentity: spec.RunRuntimeIdentity(dag, "rp1:x", nil)}
	assert.NoError(t, checkExpectedRuntimeIdentity(dag, runtimeInputs{}, nil), "no seed, no check")
	assert.NoError(t, checkExpectedRuntimeIdentity(dag, runtimeInputs{}, &ir.DAGRunStatus{}), "nothing reused automatically")
	assert.NoError(t, checkExpectedRuntimeIdentity(dag, runtimeInputs{profileIdentity: "rp1:x"}, expecting))
	assert.ErrorIs(t, checkExpectedRuntimeIdentity(dag, runtimeInputs{profileIdentity: "rp1:y"}, expecting), ErrRuntimeIdentityChanged)
	assert.ErrorIs(t, checkExpectedRuntimeIdentity(dag, runtimeInputs{}, expecting), ErrRuntimeIdentityChanged)
}

// The output limit bounds what a step outputs: another one is another state.
func TestRunRuntimeIdentityCoversTheOutputLimit(t *testing.T) {
	t.Parallel()

	small := &ir.DAG{MaxOutputSize: 1024}
	large := &ir.DAG{MaxOutputSize: 2048}
	assert.NotEqual(t, spec.RunRuntimeIdentity(small, "rp1:x", nil), spec.RunRuntimeIdentity(large, "rp1:x", nil))
	assert.Empty(t, spec.RunRuntimeIdentity(small, "", nil), "an unknown profile state stays unknown")
}
