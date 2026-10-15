// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dagrun"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity/fixture"
)

// runStore opens the fixture's run store as the hub does, journal and all.
func runStore(l *fixture.Layout) *dagrun.Store {
	return dagrun.NewStore(filepath.Join(l.DataDir, "dag-runs"))
}

func filesByKey(inv *continuity.Inventory) map[string]continuity.File {
	out := map[string]continuity.File{}
	for _, f := range inv.Files {
		out[f.Root+"/"+f.Path] = f
	}
	return out
}

// The preparation journal a coordinator leaves behind when it stops between
// preparing attempts and publishing them is retained: each entry is in the
// inventory, to be present after the transition, and nothing blocks.
func TestPreparationJournalIsRetained(t *testing.T) {
	t.Parallel()
	l, f := build(t)
	pending, err := runStore(l).ListAttemptPreparations(context.Background())
	require.NoError(t, err)
	require.Len(t, pending, 2, "the fixture leaves a journal the coordinator would act on")

	inv := scan(t, l)
	assert.Empty(t, continuity.Blocking(continuity.Validate(inv, continuity.Policy{})))
	files := filesByKey(inv)
	for _, p := range f.Preparations {
		file, ok := files["hub-data/"+p]
		require.True(t, ok, "%s is inventoried", p)
		assert.Equal(t, continuity.PolicyMutable, file.Policy, p)
		assert.NotEmpty(t, file.SHA256, p)
	}
}

// Taken apart and reconciled, the hub's and the machine's inventories keep
// the journal and every record and owner relationship, and an entry lost
// across the transition blocks. A temporary file the journal's writer left
// may go.
func TestPreparationJournalLossBlocks(t *testing.T) {
	t.Parallel()
	l, f := build(t)
	journal := filepath.Join(l.DataDir, "dag-runs.preparations")
	// An interrupted write leaves the temporary file fileutil.WriteFileAtomic
	// makes, named by os.CreateTemp as it names it.
	created, err := os.CreateTemp(journal, path.Base(f.Preparations[0])+".tmp.*")
	require.NoError(t, err)
	_, err = created.WriteString("{")
	require.NoError(t, err)
	require.NoError(t, created.Close())
	tmp := created.Name()

	before, err := continuity.Reconcile(hubAndMachine(t, l))
	require.NoError(t, err)
	assert.Empty(t, continuity.Blocking(continuity.Validate(before, continuity.Policy{})))
	whole := scanRoots(t, "freeze", roots(l)...)
	assert.Empty(t, continuity.Compare(whole, before, continuity.CompareOptions{}).Issues, "the joint inventory is the inventory of one scan")
	files := filesByKey(before)
	for _, p := range f.Preparations {
		assert.Equal(t, continuity.PolicyMutable, files["hub-data/"+p].Policy, p)
	}
	assert.Equal(t, continuity.PolicyOperational, files["hub-data/dag-runs.preparations/"+filepath.Base(tmp)].Policy)

	// Nothing changed: the joint inventories compare clean.
	same, err := continuity.Reconcile(hubAndMachine(t, l))
	require.NoError(t, err)
	assert.Empty(t, continuity.Compare(before, same, continuity.CompareOptions{}).Issues)

	// The coordinator's own removal of one entry, and the temporary file
	// gone.
	pending, err := runStore(l).ListAttemptPreparations(context.Background())
	require.NoError(t, err)
	require.Len(t, pending, 2)
	lost := pending[0]
	require.NoError(t, runStore(l).EndAttemptPreparation(context.Background(), lost))
	require.NoError(t, os.Remove(tmp))
	after, err := continuity.Reconcile(hubAndMachine(t, l))
	require.NoError(t, err)
	rep := continuity.Compare(before, after, continuity.CompareOptions{})
	var missing []string
	for _, i := range rep.Issues {
		require.Equal(t, "file_missing", i.Code, "%s %s", i.ID, i.Detail)
		missing = append(missing, i.ID)
	}
	assert.Equal(t, []string{"hub-data/dag-runs.preparations/" + dagrun.PreparationEntryName(lost)}, missing)
}

// The journal holds only what its writer writes. Any other name, type or
// content blocks, and is not inventoried as an entry.
func TestPreparationJournalShapesBlock(t *testing.T) {
	journalPath := func(l *fixture.Layout, rel string) string {
		return filepath.Join(l.DataDir, "dag-runs.preparations", filepath.FromSlash(rel))
	}
	entry := func(t *testing.T, l *fixture.Layout, f *fixture.Facts, i int) (string, []byte) {
		t.Helper()
		p := filepath.Join(l.DataDir, filepath.FromSlash(f.Preparations[i]))
		data, err := os.ReadFile(p) //nolint:gosec // test fixture path
		require.NoError(t, err)
		return p, data
	}
	rewrite := func(fn func(m map[string]any)) func(*testing.T, *fixture.Layout, *fixture.Facts) string {
		return func(t *testing.T, l *fixture.Layout, f *fixture.Facts) string {
			p, data := entry(t, l, f, 0)
			var m map[string]any
			require.NoError(t, json.Unmarshal(data, &m))
			fn(m)
			out, err := json.Marshal(m)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(p, out, 0o600))
			return f.Preparations[0]
		}
	}
	otherName := strings.Repeat("a", 64) + ".json"
	cases := []struct {
		name   string
		break_ func(t *testing.T, l *fixture.Layout, f *fixture.Facts) string
	}{
		{"a file of another name", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) string {
			require.NoError(t, os.WriteFile(journalPath(l, "notes.json"), []byte(`{}`), 0o600))
			return "dag-runs.preparations/notes.json"
		}},
		{"an entry stored under another attempt's name", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) string {
			_, data := entry(t, l, f, 0)
			require.NoError(t, os.WriteFile(journalPath(l, otherName), data, 0o600))
			return "dag-runs.preparations/" + otherName
		}},
		{"an execution's entry without its marker", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) string {
			for i := range f.Preparations {
				p, data := entry(t, l, f, i)
				if strings.Contains(path.Base(f.Preparations[i]), "-") {
					continue
				}
				// A new attempt's entry renamed as one of its executions.
				name := strings.TrimSuffix(filepath.Base(p), ".json") + "-" + strings.Repeat("b", 32) + ".json"
				require.NoError(t, os.WriteFile(journalPath(l, name), data, 0o600))
				return "dag-runs.preparations/" + name
			}
			t.Fatal("no new attempt's entry")
			return ""
		}},
		{"an entry that is not JSON", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) string {
			p, _ := entry(t, l, f, 0)
			require.NoError(t, os.WriteFile(p, []byte("not json"), 0o600))
			return f.Preparations[0]
		}},
		{"an entry of another schema", rewrite(func(m map[string]any) { m["schema"] = persis.AttemptPreparationSchema + 1 })},
		{"an entry naming another attempt", rewrite(func(m map[string]any) { m["attemptId"] = "att_planted" })},
		{"an entry without its time", rewrite(func(m map[string]any) { delete(m, "preparedAt") })},
		{"a directory with an entry's name", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) string {
			require.NoError(t, os.MkdirAll(journalPath(l, otherName), 0o750))
			require.NoError(t, os.WriteFile(journalPath(l, otherName+"/held.json"), []byte(`{}`), 0o600))
			return "dag-runs.preparations/" + otherName
		}},
		{"a subdirectory", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) string {
			require.NoError(t, os.MkdirAll(journalPath(l, ".dagu_lock"), 0o750))
			return "dag-runs.preparations/.dagu_lock"
		}},
		{"a temporary file of another name", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) string {
			require.NoError(t, os.WriteFile(journalPath(l, "x.json.tmp.1"), []byte(`{}`), 0o600))
			return "dag-runs.preparations/x.json.tmp.1"
		}},
		{"the journal as a file", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) string {
			require.NoError(t, os.RemoveAll(journalPath(l, "")))
			require.NoError(t, os.WriteFile(journalPath(l, ""), []byte(`{}`), 0o600))
			return "dag-runs.preparations"
		}},
	}
	if runtime.GOOS != "windows" {
		cases = append(cases, struct {
			name   string
			break_ func(t *testing.T, l *fixture.Layout, f *fixture.Facts) string
		}{"a link with an entry's name", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) string {
			require.NoError(t, os.Symlink(filepath.Join(l.DataDir, "dag-runs"), journalPath(l, otherName)))
			return "dag-runs.preparations/" + otherName
		}})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, f := build(t)
			rel := tc.break_(t, l, f)
			inv := scan(t, l)
			blocked := false
			for _, i := range continuity.Blocking(continuity.Validate(inv, continuity.Policy{})) {
				if i.ID == "hub-data/"+rel {
					blocked = true
				}
			}
			assert.True(t, blocked, "%s blocks: %v", rel, inv.Issues)
			for _, file := range inv.Files {
				assert.False(t, file.Root == "hub-data" && (file.Path == rel || strings.HasPrefix(file.Path, rel+"/")), "%s is not inventoried", file.Path)
			}
		})
	}
}
