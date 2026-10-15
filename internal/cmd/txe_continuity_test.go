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
		// The printer escapes what it prints, so a Windows path is not
		// shown verbatim; the file itself is the evidence.
		assert.Contains(t, out, "written to")
		assert.FileExists(t, p)
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

// --keep reads a strict keep manifest: a malformed one is refused before
// anything is scanned, and an unpinned entry blocks with its digest.
func TestTXEContinuityKeep(t *testing.T) {
	l, _, err := fixture.Build(t.Context(), filepath.Join(t.TempDir(), "root"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = fixture.Unseal(l.Root) })
	require.NoError(t, os.WriteFile(filepath.Join(l.MachineHome, "base.yaml"), []byte("x\n"), 0o600))
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte(`{"format":"txe.continuity.keep/v1","entries":[{"root":"laptop-home","path":"../x","provenance":"p"}]}`), 0o600))
	scan := "machine-home=laptop-home=" + l.MachineHome
	_, err = runTXEContinuity(t, "inventory", "--scan", scan, "--keep", bad)
	assert.ErrorContains(t, err, "not a clean relative path")

	keep := filepath.Join(dir, "keep.json")
	require.NoError(t, os.WriteFile(keep, []byte(`{"format":"txe.continuity.keep/v1","entries":[{"root":"laptop-home","path":"base.yaml","provenance":"fixture"}]}`), 0o600))
	out, err := runTXEContinuity(t, "inventory", "--scan", scan, "--keep", keep, "--out", filepath.Join(dir, "inv.json"))
	require.Error(t, err)
	assert.Contains(t, out, "kept_unpinned")
	assert.NotContains(t, out, "unclassified_area")
}

// The freeze from the command line: the hub and the machine are
// inventoried apart, reconciled into one joint inventory that validates,
// and joint inventories compare.
func TestTXEContinuityReconcile(t *testing.T) {
	l, _, err := fixture.Build(t.Context(), filepath.Join(t.TempDir(), "root"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = fixture.Unseal(l.Root) })
	dir := t.TempDir()
	hub := filepath.Join(dir, "hub.json")
	out, err := runTXEContinuity(t, "inventory", "--label", "freeze", "--out", hub,
		"--scan", "hub-data=hub-data="+l.DataDir+"="+l.HubMount, "--scan", "dags=hub-dags="+l.DAGsDir, "--scan", "logs=hub-logs="+l.LogsDir)
	require.NoError(t, err, out)
	laptop := filepath.Join(dir, "laptop.json")
	out, err = runTXEContinuity(t, "inventory", "--label", "freeze", "--out", laptop, "--scan", "machine-home=laptop-home="+l.MachineHome)
	require.NoError(t, err, out)

	joint := filepath.Join(dir, "joint.json")
	out, err = runTXEContinuity(t, "reconcile", hub, laptop, "--out", joint)
	require.NoError(t, err, out)
	assert.Contains(t, out, "of 2 parts written to")
	assert.Contains(t, out, "0 blocking")
	out, err = runTXEContinuity(t, "validate", joint)
	require.NoError(t, err, out)
	assert.NotContains(t, out, "not_checked")
	out, err = runTXEContinuity(t, "compare", joint, joint)
	require.NoError(t, err, out)

	_, err = runTXEContinuity(t, "reconcile", hub, "--out", filepath.Join(dir, "one.json"))
	require.Error(t, err)
	_, err = runTXEContinuity(t, "reconcile", hub, hub, "--out", filepath.Join(dir, "twice.json"))
	require.ErrorContains(t, err, "given twice")
	assert.NoFileExists(t, filepath.Join(dir, "twice.json"))
	data, err := os.ReadFile(laptop)
	require.NoError(t, err)
	altered := filepath.Join(dir, "altered.json")
	require.NoError(t, os.WriteFile(altered, bytes.Replace(data, []byte(`"label": "freeze"`), []byte(`"label": "other"`), 1), 0o600))
	_, err = runTXEContinuity(t, "reconcile", hub, altered, "--out", filepath.Join(dir, "altered-joint.json"))
	require.ErrorContains(t, err, "digest")
}
