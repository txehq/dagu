// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package ir

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Negative control: before this fork restored stored outputs, Node.UnmarshalJSON
// decoded the line into nodeJSON and kept what it found. On a line the upstream
// v2.25.2 writer stored, that decoder keeps outputValue and loses the two
// fields that reference it; Node.UnmarshalJSON now gets them back.
func TestOldReaderLosesStoredOutputs(t *testing.T) {
	t.Parallel()

	f, err := os.Open("testdata/upstream_v2.25.2_stored_status.jsonl")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	var line string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(nil, 4<<20)
	for scanner.Scan() {
		var entry struct {
			Case   string          `json:"case"`
			Status json.RawMessage `json:"status"`
		}
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &entry))
		if entry.Case == "all_same" {
			line = string(entry.Status)
		}
	}
	require.NoError(t, scanner.Err())
	require.NotEmpty(t, line)

	var raw struct {
		Nodes []json.RawMessage `json:"nodes"`
	}
	require.NoError(t, json.Unmarshal([]byte(line), &raw))
	require.Len(t, raw.Nodes, 1)

	var old nodeJSON
	require.NoError(t, json.Unmarshal(raw.Nodes[0], &old))
	require.NotNil(t, old.OutputValue)
	assert.Nil(t, old.OutputsValue, "the old decoder loses outputsValue")
	assert.Nil(t, old.StepOutputsValue, "the old decoder loses stepOutputsValue")

	var node Node
	require.NoError(t, json.Unmarshal(raw.Nodes[0], &node))
	require.NotNil(t, node.OutputsValue)
	require.NotNil(t, node.StepOutputsValue)
	assert.Equal(t, *old.OutputValue, *node.OutputsValue)
	assert.Equal(t, *old.OutputValue, *node.StepOutputsValue)
}
