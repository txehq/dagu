// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity/fixture"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

const impostor = "own_01M4ZZZZZZZZZZZZZZZZZZZZZZ"

func regPath(l *fixture.Layout, id string) string {
	return filepath.Join(registry.Dir(l.DataDir), filepath.FromSlash(id)+".json")
}

// edit rewrites a JSON record through fn.
func edit(t *testing.T, p string, fn func(m map[string]any)) {
	t.Helper()
	data, err := os.ReadFile(p) //nolint:gosec // test fixture path
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	fn(m)
	out, err := json.MarshalIndent(m, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(p, out, 0o600))
}

func job(t *testing.T, l *fixture.Layout, jobID string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(regPath(l, "jobs/"+jobID))
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	return m
}

func blocking(t *testing.T, l *fixture.Layout) map[string]int {
	t.Helper()
	return codes(continuity.Validate(scan(t, l), continuity.Policy{}), continuity.SeverityBlock)
}

// Each break in a retained store is found and blocks. Every case starts from
// a fresh fixture that validates clean.
func TestBreaksAreBlocking(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(t *testing.T, l *fixture.Layout, f *fixture.Facts)
		want   string
	}{
		{"an owner with the owner's display name is another owner", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) {
			o := registry.Owner{Schema: 1, OwnerID: impostor, DisplayName: "Connor Wang"}
			b, _ := json.Marshal(o)
			require.NoError(t, os.WriteFile(regPath(l, "owners/"+impostor), b, 0o600))
		}, "unexpected_owner"},
		{"a job reassigned to another owner", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			edit(t, regPath(l, "jobs/"+f.Jobs["health-check"]), func(m map[string]any) { m["owner_id"] = impostor })
		}, "owner_mismatch"},
		{"a project reassigned to another owner", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			edit(t, regPath(l, "projects/"+f.Projects[0]), func(m map[string]any) { m["owner_id"] = impostor })
		}, "owner_inconsistent"},
		{"a version record lost", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			refs := job(t, l, f.Jobs["health-check"])["version_refs"].([]any)
			require.NoError(t, os.Remove(regPath(l, refs[0].(string))))
		}, "dangling_ref"},
		{"a history record in the middle of a chain lost", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			head := job(t, l, f.Jobs["health-check"])["chains"].(map[string]any)["events"].(string)
			data, err := os.ReadFile(regPath(l, head))
			require.NoError(t, err)
			var e registry.Event
			require.NoError(t, json.Unmarshal(data, &e))
			require.NotEmpty(t, e.Prev)
			require.NoError(t, os.Remove(regPath(l, e.Prev)))
		}, "dangling_ref"},
		{"a decision whose proposal is gone", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			head := job(t, l, f.Jobs["health-check"])["chains"].(map[string]any)["decisions"].(string)
			edit(t, regPath(l, head), func(m map[string]any) { m["proposal_id"] = "prp_01M4ZZZZZZZZZZZZZZZZZZZZZZ" })
		}, "dangling_ref"},
		{"an unreadable record", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			require.NoError(t, os.WriteFile(regPath(l, "jobs/"+f.Jobs["paused"]), []byte("{not json"), 0o600))
		}, "undecodable"},
		{"a record with a field this tool does not know", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			edit(t, regPath(l, "jobs/"+f.Jobs["paused"]), func(m map[string]any) { m["tenant"] = "x" })
		}, "undecodable"},
		{"a record kind this tool does not know", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) {
			p := regPath(l, "workspaces/w1")
			require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
			require.NoError(t, os.WriteFile(p, []byte(`{"id":"w1"}`), 0o600))
		}, "unsupported_record"},
		{"a record of a later schema", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			edit(t, regPath(l, "jobs/"+f.Jobs["paused"]), func(m map[string]any) { m["schema"] = 2 })
		}, "unsupported_schema"},
		{"a job whose current facts are not its latest version's", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			edit(t, regPath(l, "jobs/"+f.Jobs["paused"]), func(m map[string]any) { m["package_digest"] = "sha256:" + strings.Repeat("0", 64) })
		}, "version_mismatch"},
		{"a chain that loops", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			head := job(t, l, f.Jobs["health-check"])["chains"].(map[string]any)["events"].(string)
			edit(t, regPath(l, head), func(m map[string]any) { m["prev"] = head })
		}, "chain_cycle"},
		{"a package file changed", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			p := packageFile(l, f, "validation")
			require.NoError(t, os.Chmod(p, 0o700))
			require.NoError(t, os.WriteFile(p, []byte("#!/bin/sh\necho changed\n"), 0o700))
			require.NoError(t, os.Chmod(p, 0o555))
		}, "package_corrupt"},
		{"a package lost from its machine", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			require.NoError(t, fixture.Unseal(filepath.Join(l.MachineHome, "packages", f.Jobs["manual-retire"])))
			require.NoError(t, os.RemoveAll(filepath.Join(l.MachineHome, "packages", f.Jobs["manual-retire"])))
		}, "package_missing"},
		{"a hub artifact's bytes changed", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			require.NoError(t, os.WriteFile(filepath.Join(l.DataDir, filepath.FromSlash(f.HubArtifacts[0])), []byte("{}"), 0o600))
		}, "artifact_digest"},
		{"a hub artifact lost", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			require.NoError(t, os.Remove(filepath.Join(l.DataDir, filepath.FromSlash(f.HubArtifacts[0]))))
		}, "artifact_missing"},
		{"a machine artifact lost", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			require.NoError(t, os.Remove(filepath.Join(l.MachineHome, filepath.FromSlash(f.MachineArtifacts[1]))))
		}, "artifact_missing"},
		{"an empty machine artifact lost", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			require.NoError(t, os.Remove(filepath.Join(l.MachineHome, filepath.FromSlash(f.MachineArtifacts[0]))))
		}, "artifact_missing"},
		{"an area of the data directory nobody classified", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) {
			require.NoError(t, os.MkdirAll(filepath.Join(l.DataDir, "newfeature"), 0o750))
		}, "unclassified_area"},
		{"an area of a machine home nobody classified", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) {
			require.NoError(t, os.MkdirAll(filepath.Join(l.MachineHome, "cache"), 0o750))
		}, "unclassified_area"},
		{"an identity bound to another owner", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) {
			dir := filepath.Join(l.DataDir, "txe", "authz", "v1", "bindings")
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Len(t, entries, 1)
			edit(t, filepath.Join(dir, entries[0].Name()), func(m map[string]any) { m["owner_id"] = impostor })
		}, "owner_mismatch"},
		{"a binding that names no subject", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) {
			dir := filepath.Join(l.DataDir, "txe", "authz", "v1", "bindings")
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)
			edit(t, filepath.Join(dir, entries[0].Name()), func(m map[string]any) { m["subject"] = "" })
		}, "missing_field"},
		{"a job holding a null proposal", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			edit(t, regPath(l, "jobs/"+f.Jobs["health-check"]), func(m map[string]any) {
				m["proposals"] = map[string]any{"prp_01M4ZZZZZZZZZZZZZZZZZZZZZZ": nil}
			})
		}, "corrupt_entry"},
		{"records in a hidden directory of the store", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) {
			p := regPath(l, ".future/x")
			require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
			require.NoError(t, os.WriteFile(p, []byte(`{}`), 0o600))
		}, "unsupported_record"},
		{"machine.json is a link into the client directory", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) {
			skipWithoutSymlinks(t)
			secret := filepath.Join(l.MachineHome, "client", "token.json")
			require.NoError(t, os.MkdirAll(filepath.Dir(secret), 0o750))
			require.NoError(t, os.WriteFile(secret, []byte(`{"schema":1,"machine_id":"fixture-secret"}`), 0o600))
			p := filepath.Join(l.MachineHome, "machine.json")
			require.NoError(t, os.Remove(p))
			require.NoError(t, os.Symlink(secret, p))
		}, "unsupported_file"},
		{"a package directory is a link", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			skipWithoutSymlinks(t)
			id := f.Jobs["validation"]
			dir := filepath.Join(l.MachineHome, "packages", id)
			require.NoError(t, fixture.Unseal(dir))
			name := digestDir(f.Packages[id][0])
			require.NoError(t, os.Rename(filepath.Join(dir, name), filepath.Join(l.Root, "moved")))
			require.NoError(t, os.Symlink(filepath.Join(l.Root, "moved"), filepath.Join(dir, name)))
		}, "unsupported_file"},
		{"an area of the data directory is a link", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) {
			skipWithoutSymlinks(t)
			require.NoError(t, os.MkdirAll(filepath.Join(l.Root, "elsewhere"), 0o750))
			require.NoError(t, os.Symlink(filepath.Join(l.Root, "elsewhere"), filepath.Join(l.DataDir, "views")))
		}, "unsupported_file"},
		{"a machine home without its identity", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			require.NoError(t, os.Remove(filepath.Join(l.MachineHome, "machine.json")))
			require.NoError(t, fixture.Unseal(filepath.Join(l.MachineHome, "packages", f.Jobs["validation"])))
			require.NoError(t, os.RemoveAll(filepath.Join(l.MachineHome, "packages", f.Jobs["validation"])))
		}, "machine_identity_missing"},
		{"the expected owner's record lost", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) {
			require.NoError(t, os.Remove(regPath(l, "owners/"+fixture.StableOwner)))
		}, "owner_missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, f := build(t)
			require.Empty(t, blocking(t, l), "the fixture starts clean")
			tc.break_(t, l, f)
			got := blocking(t, l)
			assert.Positive(t, got[tc.want], "want %s, got %v", tc.want, got)
		})
	}
}

func digestDir(digest string) string {
	return strings.Replace(digest, ":", "-", 1)
}

// packageFile is the entrypoint of the first package of a fixture job.
func packageFile(l *fixture.Layout, f *fixture.Facts, job string) string {
	id := f.Jobs[job]
	return filepath.Join(l.MachineHome, "packages", id, digestDir(f.Packages[id][0]), "files", "run.sh")
}

// A copy that keeps a package's bytes but not its permissions leaves a
// package the store refuses to run: lost execute bit, or not sealed.
func TestPackagePermissionsAreChecked(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no permission bits")
	}
	for name, mode := range map[string]os.FileMode{"execute bit lost": 0o444, "left writable": 0o755} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			l, f := build(t)
			before := scan(t, l)
			require.NoError(t, os.Chmod(packageFile(l, f, "validation"), mode))
			after := scan(t, l)
			assert.Positive(t, codes(continuity.Validate(after, continuity.Policy{}), continuity.SeverityBlock)["package_corrupt"])
			assert.Positive(t, codes(continuity.CompareProgress(before, after).Issues, continuity.SeverityBlock)["immutable_changed"])
			assert.Positive(t, codes(continuity.Compare(before, after, continuity.CompareOptions{}).Issues, continuity.SeverityBlock)["file_changed"])
		})
	}
}

// Scanning the same store twice gives the same inventory, byte for byte.
func TestInventoryIsDeterministic(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	first := scan(t, l)
	for range 5 {
		assert.Equal(t, first.Digest, scan(t, l).Digest)
	}
}

// A store written on Windows records archive paths with backslashes; they
// are matched to the scanned root and the bytes are checked, not skipped.
func TestWindowsArchivePathsAreChecked(t *testing.T) {
	for name, mount := range map[string]string{"drive": `C:\dagu\data`, "unc": `\\fileserver\share\dagu\data`} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			l, f := build(t)
			dir := filepath.Join(registry.Dir(l.DataDir), "artifacts")
			var manifest string
			require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					manifest = p
				}
				return err
			}))
			edit(t, manifest, func(m map[string]any) {
				rel := strings.TrimPrefix(m["archive_dir"].(string), filepath.ToSlash(l.HubMount))
				m["archive_dir"] = mount + strings.ReplaceAll(rel, "/", `\`)
			})
			rs := roots(l)
			rs[0].Mount = mount
			scanWith := func() map[string]int {
				inv, err := continuity.Scan(context.Background(), continuity.Options{Roots: rs, ExpectedOwner: fixture.StableOwner})
				require.NoError(t, err)
				issues := continuity.Validate(inv, continuity.Policy{})
				assert.Zero(t, codes(issues, continuity.SeverityWarn)["artifact_unverified"])
				return codes(issues, continuity.SeverityBlock)
			}
			assert.Empty(t, scanWith())
			require.NoError(t, os.Remove(filepath.Join(l.DataDir, filepath.FromSlash(f.HubArtifacts[0]))))
			assert.Positive(t, scanWith()["artifact_missing"])
		})
	}
}

// Ownership is only ever an owner_id field. A person who signed in first
// with the owner's name and email has a pending request and nothing else;
// the only binding is the one an administrator approved for the owner's own
// identity.
func TestFirstSignInClaimsNothing(t *testing.T) {
	l, _ := build(t)
	inv := scan(t, l)
	var requests, bindings []continuity.Record
	for _, r := range inv.Records {
		switch r.Class {
		case continuity.ClassBindingRequest:
			requests = append(requests, r)
		case continuity.ClassBinding:
			bindings = append(bindings, r)
		}
	}
	require.Len(t, requests, 2)
	for _, r := range requests {
		assert.Empty(t, r.Owner, "a request names no owner")
	}
	require.Len(t, bindings, 1)
	assert.Equal(t, fixture.StableOwner, bindings[0].Owner)
	assert.Equal(t, fixture.Issuer+"|subject-owner", bindings[0].Attrs["identity"])
	for _, r := range inv.Records {
		if r.Owner != "" {
			assert.Equal(t, fixture.StableOwner, r.Owner, "%s/%s", r.Store, r.ID)
		}
	}
	assert.Empty(t, continuity.Blocking(continuity.Validate(inv, continuity.Policy{})))
}

// Areas that hold credentials are listed as excluded and never read: the
// scan succeeds with them unreadable, and nothing of theirs is in the
// inventory.
func TestCredentialAreasAreNotRead(t *testing.T) {
	l, _ := build(t)
	const secret = "fixture-secret-value-never-read"
	for _, p := range []string{
		filepath.Join(l.DataDir, "users", "admin.json"),
		filepath.Join(l.DataDir, "apikeys", "key.json"),
		filepath.Join(l.DataDir, "contexts", "remote.json"),
		filepath.Join(l.MachineHome, "client", "contexts", "hub.yaml"),
	} {
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, []byte(secret), 0o600))
		require.NoError(t, os.Chmod(filepath.Dir(p), 0o000))
		t.Cleanup(func() { _ = os.Chmod(filepath.Dir(p), 0o750) }) //nolint:gosec // restore for cleanup
	}
	require.NoError(t, os.Chmod(filepath.Join(l.MachineHome, "client"), 0o000))
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(l.MachineHome, "client"), 0o750) }) //nolint:gosec // restore for cleanup

	inv := scan(t, l)
	excluded := map[string]bool{}
	for _, e := range inv.Excluded {
		excluded[e.Root+"/"+e.Path] = true
	}
	for _, p := range []string{"hub-data/users", "hub-data/apikeys", "hub-data/contexts", "laptop-home/client"} {
		assert.True(t, excluded[p], p)
	}
	out, err := json.Marshal(inv)
	require.NoError(t, err)
	assert.NotContains(t, string(out), secret)
	assert.NotContains(t, string(out), "admin.json")
	assert.Empty(t, continuity.Blocking(continuity.Validate(inv, continuity.Policy{})))
}

// Scanning changes nothing: every file's bytes, mode and modification time
// are the same afterwards, and no file is added or removed.
func TestScanIsReadOnly(t *testing.T) {
	l, _ := build(t)
	before := treeState(t, l.Root)
	scan(t, l)
	assert.Equal(t, before, treeState(t, l.Root))
}

func treeState(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	require.NoError(t, filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		line := p + " " + info.Mode().String() + " " + info.ModTime().String()
		if d.Type().IsRegular() {
			data, err := os.ReadFile(p) //nolint:gosec // test fixture path
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			line += " " + hex.EncodeToString(sum[:])
		}
		out = append(out, line)
		return nil
	}))
	sort.Strings(out)
	return out
}

// An inventory written out and read back is the same inventory; one edited
// after it was sealed is refused.
func TestInventoryRoundTrip(t *testing.T) {
	l, _ := build(t)
	inv := scan(t, l)
	data, err := json.Marshal(inv)
	require.NoError(t, err)
	back, err := continuity.Decode(data)
	require.NoError(t, err)
	assert.Equal(t, inv.Digest, back.Digest)
	assert.Equal(t, continuity.Validate(inv, continuity.Policy{}), continuity.Validate(back, continuity.Policy{}))

	var m map[string]any
	require.NoError(t, json.Unmarshal(data, &m))
	m["expected_owner"] = impostor
	tampered, err := json.Marshal(m)
	require.NoError(t, err)
	_, err = continuity.Decode(tampered)
	assert.ErrorContains(t, err, "does not match")

	m["format"] = "txe.continuity.inventory/v9"
	tampered, err = json.Marshal(m)
	require.NoError(t, err)
	_, err = continuity.Decode(tampered)
	assert.ErrorContains(t, err, "format")
}

func skipWithoutSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symbolic links needs a privilege on Windows")
	}
}

// A worker finds packages only under its own home: a package that is only
// on another scanned machine does not count for the job's machine.
func TestPackageOnTheWrongMachine(t *testing.T) {
	t.Parallel()
	l, f := build(t)
	other := filepath.Join(l.Root, "machine2", "txe-dagu")
	require.NoError(t, os.MkdirAll(filepath.Join(other, "packages"), 0o750))
	id, err := json.Marshal(map[string]any{"schema": 1, "machine_id": f.Machine2, "owner_id": fixture.StableOwner})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(other, "machine.json"), id, 0o600))
	// Moved sealed, as it is: only its place changes.
	job := f.Jobs["validation"]
	require.NoError(t, os.Rename(filepath.Join(l.MachineHome, "packages", job), filepath.Join(other, "packages", job)))
	rs := append(roots(l), continuity.Root{Area: continuity.AreaMachineHome, Path: other, Label: "linux-home"})
	inv, err := continuity.Scan(context.Background(), continuity.Options{Roots: rs, ExpectedOwner: fixture.StableOwner})
	require.NoError(t, err)
	var missing, corrupt []string
	for _, i := range continuity.Validate(inv, continuity.Policy{}) {
		switch {
		case i.Code == "package_missing" && strings.Contains(i.ID, "registry/history/"+job+"/versions/"):
			missing = append(missing, i.ID)
		case i.Code == "package_corrupt" && strings.Contains(i.ID, job):
			corrupt = append(corrupt, i.ID)
		}
	}
	assert.NotEmpty(t, missing, "the validation job's version has no package on its own machine")
	assert.Empty(t, corrupt, "the moved package itself verifies")
}
