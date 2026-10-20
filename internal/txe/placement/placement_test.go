// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package placement

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
)

// A base configuration's "worker_selector: local" survives a document's own
// selector, so the DAG would run on the hub and not on the machine it names:
// such a DAG's placement cannot be verified. Local with no machine is a
// placement on no machine (TXE-4717).
func TestForceLocalWithAMachineIsUnverified(t *testing.T) {
	_, err := Of(&ir.DAG{Name: "d", ForceLocal: true, WorkerSelector: map[string]string{MachineLabel: "mch_A"}})
	require.ErrorIs(t, err, ErrUnverified)

	got, err := Of(&ir.DAG{Name: "d", ForceLocal: true})
	require.NoError(t, err)
	assert.Equal(t, []Placement{{Name: "d"}}, got)
}

// A called DAG, or a tool, is looked up exactly as written: a name the
// runtime would read differently from this check is unverified.
func TestCalledNamesAreLiteral(t *testing.T) {
	for _, name := range []string{" helper", "helper ", "${X}", "`x`"} {
		_, err := Of(&ir.DAG{Name: "d", Steps: []ir.Step{{Name: "s", SubDAG: &ir.SubDAG{Name: name}}}})
		assert.ErrorIs(t, err, ErrUnverified, "call %q", name)
		_, err = Of(&ir.DAG{Name: "d", Steps: []ir.Step{{Name: "s", LLM: &ir.LLMConfig{Tools: []string{name}}}}})
		assert.ErrorIs(t, err, ErrUnverified, "tool %q", name)
	}
	got, err := Of(&ir.DAG{Name: "d", Steps: []ir.Step{{Name: "s", SubDAG: &ir.SubDAG{Name: "helper"}}}})
	require.NoError(t, err)
	assert.Equal(t, []Placement{{Name: "d"}, {Name: "helper", Step: true, Document: "d"}}, got)
}
