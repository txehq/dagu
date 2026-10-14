// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/continuity/fixture"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

func runTXEContinuity(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, _, err := runTXEContinuityStreams(t, args...)
	return out, err
}

func runTXEContinuityStreams(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	keepDaguEnvironment(t)
	t.Setenv("TXE_DAGU_HOME", t.TempDir())
	root := &cobra.Command{Use: "dagu", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(TXE())
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"txe", "continuity"}, args...))
	err := root.Execute()
	return out.String(), errOut.String(), err
}

// The freeze workflow from the command line: inventory, validate, take a
// second inventory of the unchanged store, compare clean; then a lost record
// blocks the comparison.
func TestTXEContinuityCommands(t *testing.T) {
	l, f, err := fixture.Build(t.Context(), filepath.Join(t.TempDir(), "root"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = fixture.Unseal(l.Root) })
	dir := t.TempDir()
	scans := []string{
		"--scan", "hub-data=hub-data=" + l.DataDir + "=" + l.HubMount,
		"--scan", "dags=hub-dags=" + l.DAGsDir,
		"--scan", "machine-home=laptop-home=" + l.MachineHome,
		"--scan", "logs=hub-logs=" + l.LogsDir,
	}
	inventory := func(name string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		out, err := runTXEContinuity(t, append([]string{"inventory", "--label", name, "--owner", fixture.StableOwner, "--out", p}, scans...)...)
		require.NoError(t, err, out)
		assert.Contains(t, out, "written to "+p)
		return p
	}
	first := inventory("before.json")
	_, err = runTXEContinuity(t, append([]string{"inventory", "--out", first}, scans...)...)
	assert.Error(t, err, "an existing inventory is not replaced")

	out, err := runTXEContinuity(t, "validate", first)
	require.NoError(t, err, out)
	assert.Contains(t, out, "0 blocking")

	second := inventory("after.json")
	out, err = runTXEContinuity(t, "compare", first, second)
	require.NoError(t, err, out)
	assert.Contains(t, out, "0 blocking")

	out, err = runTXEContinuity(t, "compare", first, second, "--json")
	require.NoError(t, err, out)
	var rep map[string]any
	require.NoError(t, json.Unmarshal([]byte(out), &rep))

	// The progress report names what was added and changed.
	require.NoError(t, os.WriteFile(filepath.Join(l.DataDir, "dag-runs", "new-run.jsonl"), []byte("{}\n"), 0o600))
	later := inventory("later.json")
	out, err = runTXEContinuity(t, "compare", "--progress", first, later)
	require.NoError(t, err, out)
	assert.Contains(t, out, "added   hub-data/dag-runs/new-run.jsonl")

	require.NoError(t, os.Remove(filepath.Join(registry.Dir(l.DataDir), "jobs", f.Jobs["validation"]+".json")))
	// Written to standard output, the inventory stays decodable and its
	// findings go to standard error.
	stdout, stderr, err := runTXEContinuityStreams(t, append([]string{"inventory"}, scans...)...)
	require.Error(t, err)
	var inv map[string]any
	require.NoError(t, json.Unmarshal([]byte(stdout), &inv))
	assert.Contains(t, stderr, "dangling_ref")
	third := inventoryExpectingIssues(t, dir, scans)
	out, err = runTXEContinuity(t, "compare", first, third)
	require.Error(t, err)
	assert.Contains(t, out, "record_missing")
}

// inventoryExpectingIssues takes an inventory that is expected to have blocking issues:
// the command writes it and fails.
func inventoryExpectingIssues(t *testing.T, dir string, scans []string) string {
	t.Helper()
	p := filepath.Join(dir, "broken.json")
	out, err := runTXEContinuity(t, append([]string{"inventory", "--out", p}, scans...)...)
	require.Error(t, err, out)
	assert.FileExists(t, p)
	return p
}

// A malformed --scan value is refused before anything is read.
func TestTXEContinuityScanValue(t *testing.T) {
	_, err := runTXEContinuity(t, "inventory", "--scan", "hub-data=/only-two")
	assert.ErrorContains(t, err, "want <area>=<label>=<path>")
	_, err = runTXEContinuity(t, "inventory")
	assert.ErrorContains(t, err, "--scan")
}
