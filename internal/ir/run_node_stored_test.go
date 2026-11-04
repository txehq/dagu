// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package ir_test

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Upstream Dagu v2.25.2 (commit 8ced76f9e5961fc2d36e4ef286ba3d31800e304d)
// stores a step output that is repeated under a node's other output fields
// once per status line: the repeating field is dropped and outputsValueFrom
// or stepOutputsValueFrom names the field that holds the text. The fork's
// writer never does this, but a fork build must read such lines without
// losing the repeated values, or it is not a safe rollback target.
//
// testdata/upstream_v2.25.2_stored_status.jsonl holds status lines encoded by
// that version's own writer (json.Marshal(ir.StoredStatus(status)) at the
// commit above), one {"case": name, "status": line} object per line.

const (
	storedFixturePath = "testdata/upstream_v2.25.2_stored_status.jsonl"

	diffOutput = "{\"diff\":\"+a\\n+b\\n\"}"
	jsonOutput = `{"result":"ok"}`
	textOutput = "plain text"
	ownOutput  = `{"step":"own"}`
)

// outputs is the expected value of a node's three output fields; nil means
// the field is unset.
type outputs struct {
	output, outputs, step *string
}

// storedStatusFixtures returns the upstream status lines by case name.
func storedStatusFixtures(t testing.TB) map[string]string {
	t.Helper()
	f, err := os.Open(storedFixturePath)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	fixtures := map[string]string{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(nil, 4<<20)
	for scanner.Scan() {
		var entry struct {
			Case   string          `json:"case"`
			Status json.RawMessage `json:"status"`
		}
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &entry))
		fixtures[entry.Case] = string(entry.Status)
	}
	require.NoError(t, scanner.Err())
	return fixtures
}

func assertOutputs(t *testing.T, want outputs, node *ir.Node, name string) {
	t.Helper()
	require.NotNil(t, node, name)
	assert.Equal(t, want.output, node.OutputValue, "%s outputValue", name)
	assert.Equal(t, want.outputs, node.OutputsValue, "%s outputsValue", name)
	assert.Equal(t, want.step, node.StepOutputsValue, "%s stepOutputsValue", name)
}

func TestUpstreamStoredStatusLinesRestoreEveryOutput(t *testing.T) {
	t.Parallel()

	fixtures := storedStatusFixtures(t)
	same := outputs{new(diffOutput), new(diffOutput), new(diffOutput)}
	tests := []struct {
		name  string
		nodes map[string]outputs
	}{
		{"all_same", map[string]outputs{"fetch": same}},
		{"step_repeats_outputs", map[string]outputs{"fetch": {new(textOutput), new(jsonOutput), new(jsonOutput)}}},
		{"outputs_repeats_output", map[string]outputs{"fetch": {new(diffOutput), new(diffOutput), new(ownOutput)}}},
		{"step_repeats_output", map[string]outputs{"fetch": {new(diffOutput), new(jsonOutput), new(diffOutput)}}},
		{"all_differ", map[string]outputs{"fetch": {new(textOutput), new(jsonOutput), new(ownOutput)}}},
		{"only_outputs", map[string]outputs{"fetch": {nil, new(jsonOutput), nil}}},
		{"only_output", map[string]outputs{"fetch": {new(textOutput), nil, nil}}},
		{"empty_repeated", map[string]outputs{"fetch": {new(""), new(""), new("")}}},
		{"empty_output_set_outputs", map[string]outputs{"fetch": {new(""), new(jsonOutput), new("")}}},
		{"none_set", map[string]outputs{"fetch": {}}},
		{"several_nodes", map[string]outputs{
			"a": same,
			"b": {new(textOutput), new(jsonOutput), new(jsonOutput)},
			"c": {},
			"d": {new(diffOutput), new(diffOutput), new(ownOutput)},
		}},
		{"subdag_parent", map[string]outputs{"call-child": same}},
		{"subdag_child", map[string]outputs{"child-step": same}},
		{"agent_state", map[string]outputs{"agent": same}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			line, ok := fixtures[tt.name]
			require.True(t, ok, "fixture %s", tt.name)
			status, err := ir.StatusFromJSON(line)
			require.NoError(t, err)
			require.Len(t, status.Nodes, len(tt.nodes))
			for _, node := range status.Nodes {
				want, ok := tt.nodes[node.Step.Name]
				require.True(t, ok, "unexpected node %s", node.Step.Name)
				assertOutputs(t, want, node, node.Step.Name)
			}
		})
	}
}

func TestUpstreamStoredHandlerNodesRestoreEveryOutput(t *testing.T) {
	t.Parallel()

	status, err := ir.StatusFromJSON(storedStatusFixtures(t)["handlers"])
	require.NoError(t, err)
	same := outputs{new(diffOutput), new(diffOutput), new(diffOutput)}
	assertOutputs(t, same, status.Nodes[0], "fetch")
	assertOutputs(t, same, status.OnInit, "onInit")
	assertOutputs(t, same, status.OnExit, "onExit")
	assertOutputs(t, outputs{new(textOutput), new(jsonOutput), new(jsonOutput)}, status.OnSuccess, "onSuccess")
	assertOutputs(t, same, status.OnFailure, "onFailure")
	assertOutputs(t, same, status.OnAbort, "onAbort")
	assertOutputs(t, outputs{new(diffOutput), new(diffOutput), new(ownOutput)}, status.OnWait, "onWait")
}

// The other node fields of an upstream line still read as before.
func TestUpstreamStoredLinesKeepOtherNodeFields(t *testing.T) {
	t.Parallel()

	fixtures := storedStatusFixtures(t)

	parent, err := ir.StatusFromJSON(fixtures["subdag_parent"])
	require.NoError(t, err)
	node := parent.Nodes[0]
	assert.Equal(t, []ir.SubDAGRun{{DAGRunID: "run-child", Params: "x=1", DAGName: "child"}}, node.SubRuns)
	assert.Equal(t, []ir.SubDAGRun{{DAGRunID: "run-child-r1", DAGName: "child"}}, node.SubRunsRepeated)
	assert.Equal(t, ir.NodeSucceeded, node.Status)
	assert.Equal(t, "/logs/call-child.out", node.Stdout)

	agent, err := ir.StatusFromJSON(fixtures["agent_state"])
	require.NoError(t, err)
	assert.JSONEq(t, `{"tasks":[{"id":"t1","done":true}]}`, string(agent.Nodes[0].AgentState))
}

// A fork build reads every stored line of a run, so a line of a run that
// began under the fork and continued under the upstream writer reads too.
func TestStatusLinesWrittenBeforeStoringOutputsOnceStillRead(t *testing.T) {
	t.Parallel()

	line := `{"name":"review","dagRunId":"run-1","nodes":[{"step":{"name":"fetch"},"status":4,` +
		`"outputValue":"{\"diff\":\"x\"}","outputsValue":"{\"diff\":\"x\"}","stepOutputsValue":"{\"diff\":\"x\"}"}]}`
	read, err := ir.StatusFromJSON(line)
	require.NoError(t, err)
	assertOutputs(t, outputs{new(`{"diff":"x"}`), new(`{"diff":"x"}`), new(`{"diff":"x"}`)}, read.Nodes[0], "fetch")
}

// These lines are written by hand: the upstream writer never produces them,
// but the reader's rules for them are the upstream reader's.
func TestStoredOutputReferenceRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		node string
		want outputs
	}{
		{
			name: "inline value wins over a reference",
			node: `{"outputValue":"a","outputsValue":"b","outputsValueFrom":"outputValue","stepOutputsValue":"c","stepOutputsValueFrom":"outputValue"}`,
			want: outputs{new("a"), new("b"), new("c")},
		},
		{
			name: "inline empty string wins over a reference",
			node: `{"outputValue":"a","outputsValue":"","outputsValueFrom":"outputValue","stepOutputsValue":"","stepOutputsValueFrom":"outputsValue"}`,
			want: outputs{new("a"), new(""), new("")},
		},
		{
			name: "explicit null is absent and restores",
			node: `{"outputValue":"a","outputsValue":null,"outputsValueFrom":"outputValue","stepOutputsValue":null,"stepOutputsValueFrom":"outputValue"}`,
			want: outputs{new("a"), new("a"), new("a")},
		},
		{
			name: "reference to a missing field restores nothing",
			node: `{"outputsValueFrom":"outputValue","stepOutputsValueFrom":"outputsValue"}`,
			want: outputs{},
		},
		{
			name: "step reference to outputs that is itself a reference",
			node: `{"outputValue":"a","outputsValueFrom":"outputValue","stepOutputsValueFrom":"outputsValue"}`,
			want: outputs{new("a"), new("a"), new("a")},
		},
		{
			name: "unknown reference names restore nothing",
			node: `{"outputValue":"a","outputsValue":"b","outputsValueFrom":"stepOutputsValue","stepOutputsValueFrom":"bogus"}`,
			want: outputs{new("a"), new("b"), nil},
		},
		{
			name: "self reference restores nothing",
			node: `{"outputValue":"a","outputsValueFrom":"outputsValue","stepOutputsValueFrom":"stepOutputsValue"}`,
			want: outputs{new("a"), nil, nil},
		},
		{
			name: "empty reference names restore nothing",
			node: `{"outputValue":"a","outputsValueFrom":"","stepOutputsValueFrom":""}`,
			want: outputs{new("a"), nil, nil},
		},
		{
			name: "step reference to empty output",
			node: `{"outputValue":"","outputsValue":"b","stepOutputsValueFrom":"outputValue"}`,
			want: outputs{new(""), new("b"), new("")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var node ir.Node
			require.NoError(t, json.Unmarshal([]byte(tt.node), &node))
			assertOutputs(t, tt.want, &node, "node")
		})
	}
}

func TestRestoredOutputsAreCopies(t *testing.T) {
	t.Parallel()

	var node ir.Node
	require.NoError(t, json.Unmarshal([]byte(`{"outputValue":"a","outputsValueFrom":"outputValue","stepOutputsValueFrom":"outputValue"}`), &node))
	*node.OutputValue = "changed"
	assert.Equal(t, "a", *node.OutputsValue)
	assert.Equal(t, "a", *node.StepOutputsValue)
	*node.OutputsValue = "changed again"
	assert.Equal(t, "a", *node.StepOutputsValue)
}

// Legacy status fields the fork reads (tags, onCancel, controllerState) keep
// working on a line that also stores an output once.
func TestLegacyStatusFieldsAndStoredOutputsReadTogether(t *testing.T) {
	t.Parallel()

	line := `{"name":"legacy","dagRunId":"run-legacy","status":4,"tags":["env=prod"],` +
		`"nodes":[{"step":{"name":"agent"},"status":4,"outputValue":"a","outputsValueFrom":"outputValue","stepOutputsValueFrom":"outputValue",` +
		`"controllerState":{"tasks":[{"id":"t1"}]}}],` +
		`"onCancel":{"step":{"name":"onCancel"},"status":4,"outputValue":"c","outputsValue":"d","stepOutputsValueFrom":"outputsValue"}}`
	status, err := ir.StatusFromJSON(line)
	require.NoError(t, err)
	assert.Equal(t, []string{"env=prod"}, status.Labels)
	assertOutputs(t, outputs{new("a"), new("a"), new("a")}, status.Nodes[0], "agent")
	assert.JSONEq(t, `{"tasks":[{"id":"t1"}]}`, string(status.Nodes[0].AgentState))
	require.NotNil(t, status.OnAbort)
	assert.Equal(t, "onAbort", status.OnAbort.Step.Name)
	assertOutputs(t, outputs{new("c"), new("d"), new("d")}, status.OnAbort, "onAbort")
}

// The fork's writer is unchanged: a node, and a status, marshal every output
// field inline and never the reference fields, so a line the fork writes is
// read by any older fork build.
func TestForkWritesEveryOutputFieldInline(t *testing.T) {
	t.Parallel()

	status, err := ir.StatusFromJSON(storedStatusFixtures(t)["all_same"])
	require.NoError(t, err)

	data, err := json.Marshal(status)
	require.NoError(t, err)
	assert.Equal(t, 3, strings.Count(string(data), `+a\\n+b\\n`))
	assert.NotContains(t, string(data), "outputsValueFrom")
	assert.NotContains(t, string(data), "stepOutputsValueFrom")

	node, err := json.Marshal(status.Nodes[0])
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(node, &fields))
	for _, name := range []string{"outputValue", "outputsValue", "stepOutputsValue"} {
		assert.JSONEq(t, `"`+strings.ReplaceAll(strings.ReplaceAll(diffOutput, `\`, `\\`), `"`, `\"`)+`"`, string(fields[name]), name)
	}
	assert.NotContains(t, fields, "outputsValueFrom")
	assert.NotContains(t, fields, "stepOutputsValueFrom")

	// Rewritten by the fork, the line reads back whole.
	again, err := ir.StatusFromJSON(string(data))
	require.NoError(t, err)
	assertOutputs(t, outputs{new(diffOutput), new(diffOutput), new(diffOutput)}, again.Nodes[0], "fetch")
}
