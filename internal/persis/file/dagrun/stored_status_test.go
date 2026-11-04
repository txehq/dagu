// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// upstreamStoredStatusLines returns status lines as the upstream v2.25.2
// writer stored them, by case name (see internal/ir/testdata).
func upstreamStoredStatusLines(t *testing.T) map[string]string {
	t.Helper()
	f, err := os.Open("../../../ir/testdata/upstream_v2.25.2_stored_status.jsonl")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	lines := map[string]string{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(nil, 4<<20)
	for scanner.Scan() {
		var entry struct {
			Case   string          `json:"case"`
			Status json.RawMessage `json:"status"`
		}
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &entry))
		lines[entry.Case] = string(entry.Status)
	}
	require.NoError(t, scanner.Err())
	return lines
}

// withLargeOutput returns the line with its first node's outputValue replaced
// by a large output, as an upstream writer stores a step whose three output
// fields all hold that text.
func withLargeOutput(t *testing.T, line, large string) string {
	t.Helper()
	var status map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &status))
	node, ok := status["nodes"].([]any)[0].(map[string]any)
	require.True(t, ok)
	node["outputValue"] = large
	require.Equal(t, "outputValue", node["outputsValueFrom"])
	require.Equal(t, "outputValue", node["stepOutputsValueFrom"])
	data, err := json.Marshal(status)
	require.NoError(t, err)
	return string(data)
}

func outputFields(n *ir.Node) []*string {
	return []*string{n.OutputValue, n.OutputsValue, n.StepOutputsValue}
}

// A status file left by the upstream v2.25.2 writer loads through the attempt
// with every output restored; the fork appends the status inline and compacts
// the file on close, and the file reloads with the same values after each.
func TestUpstreamStoredStatusFileLoadsRewritesAndReloads(t *testing.T) {
	th := setupTestRepository(t)
	lines := upstreamStoredStatusLines(t)
	large := `{"diff":"` + strings.Repeat("+added line\n", 20000) + `end of diff"}`

	diff := "{\"diff\":\"+a\\n+b\\n\"}"
	tests := []struct {
		name   string
		line   string
		value  string // the first node's output, held by all three of its fields
		marker string // a part of it as the line encodes it
		stored int    // times the upstream line holds the marked output
		inline int    // times the fork's line holds it
	}{
		{name: "all_same", line: lines["all_same"], value: diff, marker: `+a\\n+b\\n`, stored: 1, inline: 3},
		{name: "handlers", line: lines["handlers"], value: diff, marker: `+a\\n+b\\n`, stored: 6, inline: 17},
		{name: "large", line: withLargeOutput(t, lines["all_same"], large), value: large, marker: "end of diff", stored: 1, inline: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dagRunID := uuid.Must(uuid.NewV7()).String()
			attempt := th.CreateAttempt(t, time.Now(), dagRunID, ir.Running)
			// The file as the upstream writer left it: one stored line.
			require.NoError(t, os.WriteFile(attempt.file, []byte(tt.line+"\n"), 0o600))
			require.Equal(t, tt.stored, strings.Count(tt.line, tt.marker))

			expected, err := ir.StatusFromJSON(tt.line)
			require.NoError(t, err)
			first := expected.Nodes[0]
			for _, value := range outputFields(first) {
				require.NotNil(t, value)
				assert.Equal(t, tt.value, *value)
			}

			loaded, err := attempt.ReadStatus(th.Context)
			require.NoError(t, err)
			uncached, err := attempt.ReadStatusUncached(th.Context)
			require.NoError(t, err)
			assertSameOutputs(t, expected, loaded)
			assertSameOutputs(t, expected, uncached)

			// The fork appends the status as it always has: every value inline.
			require.NoError(t, attempt.Open(th.Context))
			require.NoError(t, attempt.Write(th.Context, *loaded))
			appended := statusLines(t, attempt.file)
			require.Len(t, appended, 2)
			assertInline(t, appended[1], tt.marker, tt.inline)
			assertSameOutputs(t, expected, readStatus(t, attempt))

			// Close compacts the file to its last status.
			require.NoError(t, attempt.Close(th.Context))
			compacted := statusLines(t, attempt.file)
			require.Len(t, compacted, 1)
			assertInline(t, compacted[0], tt.marker, tt.inline)
			assertSameOutputs(t, expected, readStatus(t, attempt))
		})
	}
}

func readStatus(t *testing.T, attempt *Attempt) *ir.DAGRunStatus {
	t.Helper()
	status, err := attempt.ReadStatusUncached(context.Background())
	require.NoError(t, err)
	return status
}

func statusLines(t *testing.T, file string) []string {
	t.Helper()
	data, err := os.ReadFile(file)
	require.NoError(t, err)
	return strings.Split(strings.TrimRight(string(data), "\n"), "\n")
}

// assertInline checks a line the fork wrote: no reference field, and the
// marked output held once per field that has it.
func assertInline(t *testing.T, line, marker string, count int) {
	t.Helper()
	assert.NotContains(t, line, "outputsValueFrom")
	assert.NotContains(t, line, "stepOutputsValueFrom")
	assert.Equal(t, count, strings.Count(line, marker))
}

func assertSameOutputs(t *testing.T, want, got *ir.DAGRunStatus) {
	t.Helper()
	wantNodes, gotNodes := allNodes(want), allNodes(got)
	require.Len(t, gotNodes, len(wantNodes))
	for i := range wantNodes {
		assert.Equal(t, wantNodes[i].Step.Name, gotNodes[i].Step.Name)
		assert.Equal(t, outputFields(wantNodes[i]), outputFields(gotNodes[i]), wantNodes[i].Step.Name)
	}
}

// allNodes lists a status's step nodes and set handler nodes.
func allNodes(st *ir.DAGRunStatus) []*ir.Node {
	nodes := append([]*ir.Node{}, st.Nodes...)
	for _, handler := range []*ir.Node{st.OnInit, st.OnExit, st.OnSuccess, st.OnFailure, st.OnAbort, st.OnWait} {
		if handler != nil {
			nodes = append(nodes, handler)
		}
	}
	return nodes
}
