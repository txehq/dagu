// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package transform_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/runtime/transform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// reusableNodesFixture holds the server's decision of which nodes may stand
// in for a step of another run (transform.Reusable), with what the UI sees of
// each node: its API status, whether it has a finish, and whether the run's
// reusedInputs record names it. The UI's availability rule (runHoldsOutputs)
// is checked against the same file (reuseSource.test.ts): it must never hold
// a node the server would not carry, and must hold every carried node the
// server records. A new node status, or a change to the server's rule, makes
// this file stale here and fails until the UI agrees.
const reusableNodesFixture = "../../../ui/src/features/visual-editor/run/__tests__/testdata/reusable-nodes.json"

type reusableNodeCase struct {
	Name           string `json:"name"`
	Status         int    `json:"status"`
	SkippedByRetry bool   `json:"skippedByRetry"`
	// Finished is a node with a finish time and a done count, as a node that
	// ran or a carried one has; a precondition skip has them too.
	Finished bool `json:"finished"`
	// Recorded is a run whose reusedInputs names the node. The server
	// records each step it carries; a run of an older server records none.
	Recorded bool `json:"recorded"`
	Reusable bool `json:"reusable"`
}

func reusableNodeCases() []reusableNodeCase {
	var cases []reusableNodeCase
	for status := ir.NodeStatus(0); status < 64; status++ {
		if status.String() == "unknown" {
			continue
		}
		for _, carried := range []bool{false, true} {
			for _, finished := range []bool{false, true} {
				recordings := []bool{false}
				if carried && status == ir.NodeSkipped {
					// A carried skip is recorded by this server and not by
					// an older one.
					recordings = []bool{true, false}
				}
				for _, recorded := range recordings {
					node := &ir.Node{Status: status}
					node.SkippedByRetry = carried
					cases = append(cases, reusableNodeCase{
						Name:           caseName(status, carried, finished, recorded),
						Status:         int(status),
						SkippedByRetry: carried,
						Finished:       finished,
						Recorded:       recorded,
						Reusable:       transform.Reusable(node),
					})
				}
			}
		}
	}
	return cases
}

func caseName(status ir.NodeStatus, carried, finished, recorded bool) string {
	name := status.String()
	if carried {
		name += ", carried"
	}
	if finished {
		name += ", finished"
	}
	if recorded {
		name += ", recorded"
	}
	return name
}

// The fixture is the server's own rule over every node status. Set
// DAGU_UPDATE_REUSABLE_NODES=1 to rewrite it after the rule or the statuses
// change.
func TestReusableNodesFixtureIsTheServersOwn(t *testing.T) {
	want := reusableNodeCases()
	path := filepath.FromSlash(reusableNodesFixture)
	if os.Getenv("DAGU_UPDATE_REUSABLE_NODES") != "" {
		out, err := json.MarshalIndent(want, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, append(out, '\n'), 0o600))
		return
	}
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var got []reusableNodeCase
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, want, got, "the fixture says what transform.Reusable decides; DAGU_UPDATE_REUSABLE_NODES=1 rewrites it")
}
