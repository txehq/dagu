// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package workflowtriggers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRepositoryWorkflows fails when a workflow on this branch would start a
// second run of itself on a pull request's unchanged head.
func TestRepositoryWorkflows(t *testing.T) {
	t.Parallel()
	dir := filepath.Join("..", "..", "..", ".github", "workflows")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var read []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml")) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err)
		findings, err := Check(name, data)
		require.NoError(t, err)
		assert.Empty(t, findings)
		read = append(read, name)
	}
	// A wrong path or an empty read must not pass as a clean result.
	assert.Contains(t, read, "ci.yaml")
	assert.Contains(t, read, gateWorkflow)
}

func TestCheck(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, file, src string
		want            []string // substrings, one per expected finding
	}{
		{
			name: "default types",
			file: "x.yaml",
			src:  "on:\n  pull_request:\n    paths: [a]\njobs:\n  a:\n    runs-on: x\n",
		},
		{
			name: "explicit head-changing types",
			file: "x.yaml",
			src:  "on:\n  pull_request:\n    types: [opened, reopened, synchronize]\njobs:\n  a:\n    runs-on: x\n",
		},
		{
			name: "event as a string and as a list",
			file: "x.yaml",
			src:  "on: [push, pull_request]\njobs:\n  a:\n    runs-on: x\n",
		},
		{
			// PR #279's shape: the draft ran every job, and ready_for_review ran them again.
			name: "ready_for_review re-runs what the draft ran",
			file: "ci.yaml",
			src: "on:\n  pull_request:\n    types:\n      - opened\n      - synchronize\n      - ready_for_review\n" +
				"concurrency:\n  group: ci-${{ github.event.pull_request.number }}\n  cancel-in-progress: true\n" +
				"jobs:\n  test:\n    runs-on: x\n  lint:\n    if: github.event_name == 'pull_request'\n    runs-on: x\n",
			want: []string{"ci.yaml: pull_request type ready_for_review re-runs jobs a draft already ran on the same head (lint, test)"},
		},
		{
			name: "ready_for_review as a scalar type",
			file: "x.yaml",
			src:  "on:\n  pull_request:\n    types: ready_for_review\njobs:\n  a:\n    runs-on: x\n",
			want: []string{"type ready_for_review"},
		},
		{
			name: "ready_for_review with one job not gated on draft",
			file: "x.yaml",
			src: "on:\n  pull_request:\n    types: [opened, ready_for_review]\n" +
				"jobs:\n  a:\n    if: ${{ !github.event.pull_request.draft }}\n    runs-on: x\n  b:\n    runs-on: x\n",
			want: []string{"(b)"},
		},
		{
			// The draft's run skipped every job, so ready_for_review starts the work once.
			name: "ready_for_review with every job gated on draft",
			file: "x.yaml",
			src: "on:\n  pull_request_target:\n    types: [opened, synchronize, ready_for_review]\n" +
				"jobs:\n  a:\n    if: ${{ !github.event.pull_request.draft }}\n    runs-on: x\n",
		},
		{
			name: "edited and labeled outside the gate",
			file: "x.yaml",
			src:  "on:\n  pull_request_target:\n    types: [opened, edited, labeled]\njobs:\n  a:\n    runs-on: x\n",
			want: []string{"pull_request_target type edited", "pull_request_target type labeled"},
		},
		{
			name: "the review gate's re-check types",
			file: gateWorkflow,
			src: "on:\n  pull_request_target:\n    types: [opened, reopened, synchronize, ready_for_review, edited, labeled, unlabeled]\n" +
				"jobs:\n  check:\n    if: ${{ !github.event.pull_request.draft }}\n    runs-on: x\n",
		},
		{
			name: "no pull_request trigger",
			file: "x.yaml",
			src:  "on:\n  push:\n    branches: [main]\njobs:\n  a:\n    runs-on: x\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings, err := Check(tc.file, []byte(tc.src))
			require.NoError(t, err)
			require.Len(t, findings, len(tc.want), "findings: %q", findings)
			for i, w := range tc.want {
				assert.Contains(t, findings[i], w)
			}
		})
	}
}

func TestCheckRefusesUnreadableTriggers(t *testing.T) {
	t.Parallel()
	_, err := Check("x.yaml", []byte("on:\n  pull_request:\n    types: {a: b}\n"))
	require.Error(t, err)
	_, err = Check("x.yaml", []byte("on: [\n"))
	require.Error(t, err)
}
