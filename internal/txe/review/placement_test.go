// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package review_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/dagucloud/dagu/v2/internal/spec"
	"github.com/dagucloud/dagu/v2/internal/txe/review"
)

// The rendered pair satisfies the hub's native-write placement rules for a
// machine's own DAGs (TXE-4412, TXE-4417). Loaded as the hub loads a spec,
// each is one document pinned by a literal worker_selector to its machine
// alone, declares no name of its own, holds no local DAG, and has no step
// with a selector of its own or a call to another DAG.
func TestRenderedDAGsArePinnedToTheirMachine(t *testing.T) {
	const machine = "mch_01JREV000000000000000000ZZ"
	dags, err := review.RenderDAGs(review.DAGConfig{MachineID: machine, StateDir: "/var/txe/state", AgentModel: "claude-test"})
	require.NoError(t, err)
	for name, doc := range map[string]string{dags.ReviewerName: dags.Reviewer, dags.DecideName: dags.Decide} {
		t.Run(name, func(t *testing.T) {
			dag, err := spec.LoadYAML(t.Context(), []byte(doc), spec.WithName(""), spec.WithoutEval())
			require.NoError(t, err)
			assert.Equal(t, map[string]string{"txe.machine": machine}, dag.WorkerSelector)
			assert.Empty(t, dag.LocalDAGs)
			// A step's selector would have to name the same machine, and a
			// call may name only this machine's DAGs: the pair has neither.
			require.NotEmpty(t, dag.Steps)
			for _, step := range dag.Steps {
				assert.Empty(t, step.WorkerSelector, "step %s", step.Name)
				assert.Nil(t, step.SubDAG, "step %s calls another DAG", step.Name)
			}
			for k, v := range dag.WorkerSelector {
				assert.False(t, strings.ContainsAny(k+v, "$`"), "a literal selector")
			}

			var top map[string]any
			require.NoError(t, yaml.Unmarshal([]byte(doc), &top))
			assert.NotContains(t, top, "name", "the DAG takes its file's name")
			assert.Len(t, strings.Split(doc, "\n---"), 1, "one document")
		})
	}
}
