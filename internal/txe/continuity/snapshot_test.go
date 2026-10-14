// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"context"
	"encoding/json"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity/fixture"
)

var update = flag.Bool("update", false, "rewrite testdata/retained-v1 from a freshly built fixture")

const snapshotDir = "testdata/retained-v1"

// snapshotFacts is what the committed snapshot records about itself.
type snapshotFacts struct {
	// HubMount is the data directory path the snapshot's hub wrote, which
	// its stored paths name.
	HubMount string         `json:"hub_mount"`
	Counts   map[string]int `json:"counts"`
}

func snapshotRoots(hubMount string) []continuity.Root {
	return []continuity.Root{
		{Area: continuity.AreaHubData, Path: filepath.Join(snapshotDir, "hub", "data"), Label: "hub-data", Mount: hubMount},
		{Area: continuity.AreaDAGs, Path: filepath.Join(snapshotDir, "hub", "dags"), Label: "hub-dags"},
		{Area: continuity.AreaMachineHome, Path: filepath.Join(snapshotDir, "machine", "txe-dagu"), Label: "laptop-home"},
	}
}

// The committed snapshot is a phase-one store in the format this registry
// writes today. It must stay readable: a change to the registry that makes
// these records unreadable, or relationships unresolvable, needs a migration
// and support here before any retained store is upgraded.
func TestSnapshotStaysReadable(t *testing.T) {
	if *update {
		writeSnapshot(t)
	}
	data, err := os.ReadFile(filepath.Join(snapshotDir, "facts.json"))
	require.NoError(t, err, "run go test -run TestSnapshotStaysReadable -update to create the snapshot")
	var facts snapshotFacts
	require.NoError(t, json.Unmarshal(data, &facts))

	inv, err := continuity.Scan(context.Background(), continuity.Options{Roots: snapshotRoots(facts.HubMount), ExpectedOwner: fixture.StableOwner})
	require.NoError(t, err)
	for _, i := range continuity.Blocking(continuity.Validate(inv, continuity.Policy{})) {
		t.Errorf("the phase-one snapshot no longer validates: %s %s: %s", i.Code, i.ID, i.Detail)
	}
	assert.Equal(t, facts.Counts, inv.Counts, "the snapshot's records are all still recognized")
}

func writeSnapshot(t *testing.T) {
	t.Helper()
	l, _ := build(t)
	require.NoError(t, os.RemoveAll(snapshotDir))
	// Lock files are operational and excluded from every inventory.
	copyTree(t, l.DataDir, filepath.Join(snapshotDir, "hub", "data"), func(rel string) bool { return !strings.HasPrefix(rel, "txe/locks/") })
	copyTree(t, l.MachineHome, filepath.Join(snapshotDir, "machine", "txe-dagu"), nil)
	// Only the jobs' DAGs: the rest of the DAG directory is upstream's
	// examples, which a new DAG store writes.
	copyTree(t, l.DAGsDir, filepath.Join(snapshotDir, "hub", "dags"), func(rel string) bool { return strings.HasPrefix(rel, "job_") })
	inv, err := continuity.Scan(context.Background(), continuity.Options{Roots: snapshotRoots(l.HubMount), ExpectedOwner: fixture.StableOwner})
	require.NoError(t, err)
	out, err := json.MarshalIndent(snapshotFacts{HubMount: l.HubMount, Counts: inv.Counts}, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(snapshotDir, "facts.json"), append(out, '\n'), 0o600))
}

func copyTree(t *testing.T, from, to string, keep func(rel string) bool) {
	t.Helper()
	require.NoError(t, filepath.WalkDir(from, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(from, p)
		if err != nil {
			return err
		}
		if d.IsDir() || (keep != nil && !keep(filepath.ToSlash(rel))) {
			return nil
		}
		data, err := os.ReadFile(p) //nolint:gosec // test fixture path
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		dst := filepath.Join(to, rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return err
		}
		return os.WriteFile(dst, data, info.Mode().Perm()|0o600)
	}))
}
