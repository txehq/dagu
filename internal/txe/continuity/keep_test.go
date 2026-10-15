// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity/fixture"
)

// strayEntries writes what a Dagu run whose DAGU_HOME is the TXE home leaves
// there, and a smoke package outside the package store's layout.
func strayEntries(t *testing.T, l *fixture.Layout) {
	t.Helper()
	for rel, data := range map[string]string{
		"base.yaml":                             "# Base DAG Configuration\n",
		".base-config-created":                  "# Marker\n",
		"dags/example-01-basic-sequential.yaml": "steps: []\n",
		"dags/.examples-created":                "# Marker\n",
		"data/auth/encryption_key":              "fixture-stray-key-placeholder",
		"packages/txe-smoke/v1/files/smoke.sh":  "#!/bin/sh\necho smoke\n",
	} {
		p := homePath(l, rel)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, []byte(data), 0o600))
	}
	for _, dir := range []string{"data/contexts", "logs/admin/events/inbox", "logs/admin/events/quarantine"} {
		require.NoError(t, os.MkdirAll(homePath(l, dir), 0o750))
	}
	if runtime.GOOS != "windows" {
		// The key cannot be read at all, so a scan that opened it would fail.
		p := homePath(l, "data/auth")
		require.NoError(t, os.Chmod(p, 0o000))
		t.Cleanup(func() { _ = os.Chmod(p, 0o750) }) //nolint:gosec // restore for cleanup
	}
}

func strayManifest() *continuity.KeepManifest {
	const p = "a dagu run with DAGU_HOME at the TXE home wrote Dagu's first-run defaults (fixture)"
	return &continuity.KeepManifest{Format: continuity.KeepFormatV1, Entries: []continuity.KeepEntry{
		{Root: "laptop-home", Path: "base.yaml", Provenance: p},
		{Root: "laptop-home", Path: ".base-config-created", Provenance: p},
		{Root: "laptop-home", Path: "dags", Provenance: p},
		{Root: "laptop-home", Path: "data", Provenance: p, Exclude: []string{"auth", "contexts"}},
		{Root: "laptop-home", Path: "logs/admin", Provenance: p},
		{Root: "laptop-home", Path: "packages/txe-smoke", Provenance: "a hand-made smoke package (fixture)"},
	}}
}

func scanKeep(t *testing.T, l *fixture.Layout, m *continuity.KeepManifest) *continuity.Inventory {
	t.Helper()
	data, err := json.Marshal(m)
	require.NoError(t, err)
	decoded, err := continuity.DecodeKeep(data)
	require.NoError(t, err)
	inv, err := continuity.Scan(context.Background(), continuity.Options{Roots: roots(l), ExpectedOwner: fixture.StableOwner,
		Label: "test", Now: func() time.Time { return scanTime }, Keep: decoded})
	require.NoError(t, err)
	return inv
}

var treeDigest = regexp.MustCompile(`sha256:[0-9a-f]{64}`)

// pin copies the digests a scan reported for unpinned entries into the
// manifest.
func pin(t *testing.T, m *continuity.KeepManifest, inv *continuity.Inventory) {
	t.Helper()
	found := map[string]string{}
	for _, i := range inv.Issues {
		if i.Code == "kept_unpinned" {
			found[i.ID] = treeDigest.FindString(i.Detail)
		}
	}
	for k := range m.Entries {
		e := &m.Entries[k]
		require.NotEmpty(t, found[e.Root+"/"+e.Path], e.Path)
		e.Digest = found[e.Root+"/"+e.Path]
	}
}

// An entry no TXE writer owns is kept exactly as it is once it is
// attributed and pinned: unpinned it blocks and reports its digest, pinned
// it is a warning carrying its provenance, every file under it is
// inventoried as immutable, and its excluded key is never opened. A change
// or a loss afterwards blocks the scan and the freeze comparison.
func TestKeepPinsAttributedEntries(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	strayEntries(t, l)
	m := strayManifest()

	got := codes(continuity.Validate(scanKeep(t, l, m), continuity.Policy{}), continuity.SeverityBlock)
	assert.Equal(t, map[string]int{"kept_unpinned": 6}, got)

	pin(t, m, scanKeep(t, l, m))
	before := scanKeep(t, l, m)
	issues := continuity.Validate(before, continuity.Policy{})
	assert.Empty(t, continuity.Blocking(issues))
	assert.Equal(t, 6, codes(issues, continuity.SeverityWarn)["kept_unclassified"])
	for _, i := range issues {
		if i.Code == "kept_unclassified" {
			assert.Contains(t, i.Detail, "(fixture)")
		}
	}
	files := map[string]continuity.File{}
	for _, f := range before.Files {
		if f.Root == "laptop-home" {
			files[f.Path] = f
		}
	}
	for _, p := range []string{"base.yaml", ".base-config-created", "dags/example-01-basic-sequential.yaml", "packages/txe-smoke/v1/files/smoke.sh"} {
		assert.Equal(t, continuity.PolicyImmutable, files[p].Policy, p)
	}
	for p := range files {
		assert.False(t, strings.HasPrefix(p, "data/auth"), p)
	}
	excluded := map[string]bool{}
	for _, e := range before.Excluded {
		excluded[e.Root+"/"+e.Path] = true
	}
	assert.True(t, excluded["laptop-home/data/auth"])
	assert.True(t, excluded["laptop-home/data/contexts"])

	// Empty directories are part of the pinned tree.
	require.NoError(t, os.Remove(homePath(l, "logs/admin/events/quarantine")))
	require.NoError(t, os.WriteFile(homePath(l, "dags/example-01-basic-sequential.yaml"), []byte("steps: [changed]\n"), 0o600))
	require.NoError(t, os.Remove(homePath(l, "base.yaml")))
	after := scanKeep(t, l, m)
	got = codes(continuity.Validate(after, continuity.Policy{}), continuity.SeverityBlock)
	assert.Equal(t, map[string]int{"kept_changed": 2, "kept_missing": 1}, got)
	got = compareCodes(continuity.Compare(before, after, continuity.CompareOptions{}))
	assert.Equal(t, 1, got["file_changed"], "%v", got)
	assert.Equal(t, 1, got["file_missing"], "%v", got)
}

// A kept entry that is, or holds, a path under which writers keep
// credentials is refused without being read unless the manifest excludes
// it.
func TestKeepRefusesCredentialPaths(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	strayEntries(t, l)
	require.NoError(t, os.MkdirAll(homePath(l, "auth"), 0o750))
	m := &continuity.KeepManifest{Format: continuity.KeepFormatV1, Entries: []continuity.KeepEntry{
		{Root: "laptop-home", Path: "data", Provenance: "fixture"},
		{Root: "laptop-home", Path: "auth", Provenance: "fixture"},
	}}
	inv := scanKeep(t, l, m)
	got := codes(continuity.Validate(inv, continuity.Policy{}), continuity.SeverityBlock)
	assert.Equal(t, 2, got["kept_credential"], "%v", got)
	for _, f := range inv.Files {
		assert.False(t, strings.HasPrefix(f.Path, "data/auth"), f.Path)
	}
}

// The manifest only takes over an entry nothing classifies: an entry that is
// classified or excluded is scanned as before, and its manifest entry blocks
// as never found.
func TestKeepNeverOverridesClassification(t *testing.T) {
	t.Parallel()
	l, f := build(t)
	require.NoError(t, os.MkdirAll(filepath.Join(l.DataDir, "users"), 0o750))
	m := &continuity.KeepManifest{Format: continuity.KeepFormatV1, Entries: []continuity.KeepEntry{
		{Root: "laptop-home", Path: "tunnel", Provenance: "fixture"},
		{Root: "laptop-home", Path: "receipts", Provenance: "fixture"},
		{Root: "laptop-home", Path: "packages/" + f.Jobs["validation"], Provenance: "fixture"},
		{Root: "hub-data", Path: "users", Provenance: "fixture"},
	}}
	inv := scanKeep(t, l, m)
	got := codes(continuity.Validate(inv, continuity.Policy{}), continuity.SeverityBlock)
	assert.Equal(t, map[string]int{"kept_missing": 4}, got)
	excluded := map[string]bool{}
	for _, e := range inv.Excluded {
		excluded[e.Root+"/"+e.Path] = true
	}
	assert.True(t, excluded["laptop-home/tunnel"])
	assert.True(t, excluded["hub-data/users"])
	for _, file := range inv.Files {
		if file.Root == "laptop-home" && strings.HasPrefix(file.Path, "receipts/") {
			assert.Equal(t, continuity.PolicyMutable, file.Policy)
		}
	}
}

func TestDecodeKeepIsStrict(t *testing.T) {
	t.Parallel()
	valid := `{"format":"txe.continuity.keep/v1","entries":[{"root":"laptop-home","path":"data","provenance":"p","exclude":["auth"],` +
		`"digest":"sha256:` + strings.Repeat("a", 64) + `"}]}`
	_, err := continuity.DecodeKeep([]byte(valid))
	require.NoError(t, err)
	entry := func(fields string) string {
		return `{"format":"txe.continuity.keep/v1","entries":[{` + fields + `}]}`
	}
	for name, doc := range map[string]string{
		"an unknown field":         entry(`"root":"r","path":"p","provenance":"x","accept":"all"`),
		"another format":           `{"format":"txe.continuity.keep/v2","entries":[]}`,
		"no provenance":            entry(`"root":"r","path":"p","provenance":" "`),
		"a path out of the root":   entry(`"root":"r","path":"../p","provenance":"x"`),
		"an absolute path":         entry(`"root":"r","path":"/p","provenance":"x"`),
		"an unclean path":          entry(`"root":"r","path":"a/../b","provenance":"x"`),
		"a backslash":              entry(`"root":"r","path":"a\\b","provenance":"x"`),
		"the root itself":          entry(`"root":"r","path":".","provenance":"x"`),
		"a root that is a path":    entry(`"root":"r/s","path":"p","provenance":"x"`),
		"a digest that is not one": entry(`"root":"r","path":"p","provenance":"x","digest":"sha256:abc"`),
		"an unclean exclusion":     entry(`"root":"r","path":"p","provenance":"x","exclude":["../q"]`),
		"an entry kept twice": `{"format":"txe.continuity.keep/v1","entries":[{"root":"r","path":"p","provenance":"x"},` +
			`{"root":"r","path":"p","provenance":"y"}]}`,
	} {
		_, err := continuity.DecodeKeep([]byte(doc))
		assert.Error(t, err, name)
	}
}
