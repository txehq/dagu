// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package machineauth_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The release proof is two files. The manifest names the builds under test: an
// exact name, the binary's path, its full sha256 and the version it reports.
// The results are what one run of the heavy test recorded: for every build the
// status of every required cell, and for every ordered pair of builds the pair
// cell, with the digests of the binaries that actually ran. verifyResults holds
// the one to the other and fails closed: a missing, unknown, duplicated or failed
// cell, a cell that was not run, a build the manifest does not name, a digest
// that differs from the manifest or from the binary on disk now, or a pair
// without its cell, each make the proof invalid. A result with a cell that was
// not run is partial and is never release acceptance.

// manifest is DAGU_MACHINEAUTH_MATRIX's file.
type manifest struct {
	Builds []manifestBuild `json:"builds"`
	// Long asks for the long cells (issuer revocation, stale attempt at the
	// production lease threshold). A release proof needs them.
	Long bool `json:"long"`
	// ResultsDir is where results are written; the manifest's directory when empty.
	ResultsDir string `json:"results_dir,omitempty"`

	// sha256 is the digest of the manifest file's bytes, set by loadManifest:
	// results name the manifest they ran under, and the gate holds them to it.
	sha256 string
}

type manifestBuild struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Version string `json:"version,omitempty"`
	// Roles and Routes narrow a build's scope; absent, a build runs the full
	// scope. Only the builds listed in narrowedScopes (scope_test.go) may be
	// narrowed, and only to the scope listed there.
	Roles  []string `json:"roles,omitempty"`
	Routes []string `json:"routes,omitempty"`
	// Provenance binds the build's provenance record (provenance_test.go).
	Provenance *provenanceRef `json:"provenance,omitempty"`
}

// results is what the heavy test writes.
type results struct {
	Schema int       `json:"schema"`
	At     time.Time `json:"at"`
	Long   bool      `json:"long"`
	// ManifestSHA256 is the digest of the manifest file the run read; empty for
	// the source mode, which has no file and is never a release proof.
	ManifestSHA256 string        `json:"manifest_sha256"`
	Builds         []resultBuild `json:"builds"`
	Cells          []cellResult  `json:"cells"`
	Partial        bool          `json:"partial"`
}

type resultBuild struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Version string `json:"version"`
	// Scope is what the build ran; Excluded says, in words, what a full build
	// runs and this one did not, and ScopeReason why (narrowedScopes' reason).
	Scope       buildScope `json:"scope"`
	Excluded    []string   `json:"excluded,omitempty"`
	ScopeReason string     `json:"scope_reason,omitempty"`
	// Capability is the binary's own account of itself, read before any cell.
	Capability capability     `json:"capability"`
	Provenance *provenanceRef `json:"provenance,omitempty"`
}

// cellResult is one cell of one build (HubBuild = WorkerBuild), one pair, or
// one cell of a worker-only build under a hub build.
type cellResult struct {
	Name        string            `json:"name"`
	HubBuild    string            `json:"hub_build"`
	WorkerBuild string            `json:"worker_build"`
	Status      string            `json:"status"` // pass, fail, not_run
	Detail      string            `json:"detail,omitempty"`
	Reasons     map[string]int    `json:"reasons,omitempty"`
	Values      map[string]string `json:"values,omitempty"`
}

const (
	statusPass    = "pass"
	statusFail    = "fail"
	statusNotRun  = "not_run"
	resultsSchema = 2
)

// strictUnmarshal refuses a field it does not know: a misspelled scope or
// provenance field is an error, never a silent default.
func strictUnmarshal(raw []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after the JSON document")
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// loadManifest reads and checks a manifest: no unknown field, distinct names,
// absolute paths, full lower-case digests, the version every build must
// report, a bound provenance record, a scope the build may run, and at least
// one build that is a hub.
func loadManifest(path string) (*manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := strictUnmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	m.sha256 = sha256Hex(raw)
	if len(m.Builds) == 0 {
		return nil, errors.New("manifest: no builds")
	}
	seen := map[string]bool{}
	hubs := 0
	for _, b := range m.Builds {
		switch {
		case b.Name == "" || strings.ContainsAny(b.Name, " /\\"):
			return nil, fmt.Errorf("manifest: build name %q must be one word", b.Name)
		case seen[b.Name]:
			return nil, fmt.Errorf("manifest: build %q named twice", b.Name)
		case b.Path == "":
			return nil, fmt.Errorf("manifest: build %q has no path", b.Name)
		case !filepath.IsAbs(b.Path):
			// A relative path would be hashed in one place and run from another
			// (exec resolves a bare name through PATH): the proof must name one file.
			return nil, fmt.Errorf("manifest: build %q needs an absolute path, got %q", b.Name, b.Path)
		case len(b.SHA256) != 64 || strings.ToLower(b.SHA256) != b.SHA256:
			return nil, fmt.Errorf("manifest: build %q needs a full lower-case sha256", b.Name)
		case b.Version == "":
			return nil, fmt.Errorf("manifest: build %q names no version: the binary's own report is held to it", b.Name)
		case b.Provenance == nil || b.Provenance.Record == "" || !filepath.IsAbs(b.Provenance.Record):
			return nil, fmt.Errorf("manifest: build %q needs a provenance record by absolute path", b.Name)
		case len(b.Provenance.SHA256) != 64 || strings.ToLower(b.Provenance.SHA256) != b.Provenance.SHA256:
			return nil, fmt.Errorf("manifest: build %q needs its provenance record's full lower-case sha256", b.Name)
		}
		s, _, err := resolveScope(b)
		if err != nil {
			return nil, fmt.Errorf("manifest: %w", err)
		}
		if s.hub() {
			hubs++
		}
		seen[b.Name] = true
	}
	if hubs == 0 {
		return nil, errors.New("manifest: no build is a hub; a worker-only build runs under a hub build of the manifest")
	}
	return &m, nil
}

// verifyResults holds results to the manifest and the matrix. It returns the
// reasons the proof is not a full release proof; an empty slice is a full pass.
// Every cell of the manifest's scope is required, the long ones included: a
// manifest with long=false describes a smoke, and its results never verify as
// a proof. "Full" is full for the manifest's scope: a narrowed build's
// exclusions are the ones narrowedScopes lists, recorded with the result.
// checkDisk re-reads each binary's digest from its path and each provenance
// record from its path (false for a results file judged without them at hand;
// the recorded digests are still held to the manifest).
func verifyResults(m *manifest, r *results, checkDisk bool) []string {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	if r.Schema != resultsSchema {
		add("results schema %d, this verifier reads %d", r.Schema, resultsSchema)
		return problems
	}
	if r.ManifestSHA256 != m.sha256 {
		add("results ran under manifest sha256 %q, the manifest given is %q", r.ManifestSHA256, m.sha256)
	}
	want := map[string]manifestBuild{}
	scopes := map[string]buildScope{}
	for _, b := range m.Builds {
		want[b.Name] = b
		s, _, err := resolveScope(b)
		if err != nil {
			add("%v", err)
			s = fullScope
		}
		scopes[b.Name] = s
	}
	got := map[string]resultBuild{}
	for _, b := range r.Builds {
		if _, dup := got[b.Name]; dup {
			add("build %s recorded twice", b.Name)
		}
		got[b.Name] = b
		mb, known := want[b.Name]
		if !known {
			add("results hold build %s, which the manifest does not name", b.Name)
			continue
		}
		switch {
		case b.Path != mb.Path:
			add("build %s ran from %s, the manifest names %s", b.Name, b.Path, mb.Path)
		case b.SHA256 != mb.SHA256:
			add("build %s ran as sha256 %s, the manifest names %s", b.Name, b.SHA256, mb.SHA256)
		case b.Version != mb.Version:
			add("build %s reported version %q, the manifest names %q", b.Name, b.Version, mb.Version)
		}
		verifyBuildScope(mb, b, scopes[b.Name], add)
		if checkDisk {
			disk, err := fileSHA256(mb.Path)
			switch {
			case err != nil:
				add("build %s: the binary cannot be read now (%v); a proof is held to the binary it names", b.Name, err)
			case disk != b.SHA256:
				add("build %s: the binary at %s is now sha256 %s, not the %s that ran", b.Name, mb.Path, disk, b.SHA256)
			}
			verifyProvenance(mb, add)
		}
	}
	for name := range want {
		if _, ok := got[name]; !ok {
			add("build %s is in the manifest but not in the results", name)
		}
	}
	if r.Long != m.Long {
		add("results were run with long=%v, the manifest asks for long=%v", r.Long, m.Long)
	}
	if !m.Long {
		add("the manifest asks for long=false: a smoke, never a release proof")
	}
	setOf := func(cells []string) map[string]bool {
		set := map[string]bool{}
		for _, c := range cells {
			set[c] = true
		}
		return set
	}
	fullSet, workerOnlySet := setOf(requiredCells(true)), setOf(requiredWorkerOnlyCells(true))
	type key struct{ name, hub, worker string }
	seen := map[key]bool{}
	notRun := 0
	for _, c := range r.Cells {
		k := key{c.Name, c.HubBuild, c.WorkerBuild}
		if seen[k] {
			add("cell %s (hub %s, worker %s) recorded twice", c.Name, c.HubBuild, c.WorkerBuild)
		}
		seen[k] = true
		_, hubKnown := want[c.HubBuild]
		_, workerKnown := want[c.WorkerBuild]
		if !hubKnown {
			add("cell %s names hub build %q, which the manifest does not", c.Name, c.HubBuild)
		}
		if !workerKnown {
			add("cell %s names worker build %q, which the manifest does not", c.Name, c.WorkerBuild)
		}
		if hubKnown && workerKnown {
			switch {
			case !scopes[c.HubBuild].hub():
				add("cell %s names %s as hub, a worker-only build", c.Name, c.HubBuild)
			case c.Name == pairCell:
				if c.HubBuild == c.WorkerBuild {
					add("pair cell with the same hub and worker build %s", c.HubBuild)
				}
			case !scopes[c.WorkerBuild].hub():
				if !workerOnlySet[c.Name] {
					add("cell %s is not a cell of the worker-only build %s", c.Name, c.WorkerBuild)
				}
			case !fullSet[c.Name]:
				add("cell %s is not a cell of this matrix", c.Name)
			case c.HubBuild != c.WorkerBuild:
				add("cell %s recorded with hub %s and worker %s; a build's cell runs both as the same build", c.Name, c.HubBuild, c.WorkerBuild)
			}
		}
		switch c.Status {
		case statusPass:
		case statusFail:
			add("cell %s (hub %s, worker %s) failed: %s", c.Name, c.HubBuild, c.WorkerBuild, c.Detail)
		case statusNotRun:
			notRun++
			add("cell %s (hub %s, worker %s) was not run: %s", c.Name, c.HubBuild, c.WorkerBuild, c.Detail)
		default:
			add("cell %s (hub %s, worker %s) has status %q, not pass, fail or not_run", c.Name, c.HubBuild, c.WorkerBuild, c.Status)
		}
	}
	for hub := range want {
		if !scopes[hub].hub() {
			continue
		}
		for _, cell := range requiredCells(true) {
			if !seen[key{cell, hub, hub}] {
				add("cell %s missing for build %s", cell, hub)
			}
		}
		for other := range want {
			if other == hub {
				continue
			}
			if !seen[key{pairCell, hub, other}] {
				add("pair cell missing: hub %s with worker %s", hub, other)
			}
			if !scopes[other].hub() {
				for _, cell := range requiredWorkerOnlyCells(true) {
					if !seen[key{cell, hub, other}] {
						add("cell %s missing for worker-only build %s under hub %s", cell, other, hub)
					}
				}
			}
		}
	}
	if r.Partial != (notRun > 0) {
		add("results say partial=%v but %d cells were not run", r.Partial, notRun)
	}
	sort.Strings(problems)
	return problems
}

// verifyBuildScope holds what a build recorded about its scope and itself to
// what the manifest and narrowedScopes allow.
func verifyBuildScope(mb manifestBuild, b resultBuild, s buildScope, add func(string, ...any)) {
	if !slices.Equal(b.Scope.Roles, s.Roles) || !slices.Equal(b.Scope.Routes, s.Routes) {
		add("build %s ran %s, the manifest's scope for it is %s", b.Name, b.Scope, s)
	}
	if !slices.Equal(b.Excluded, excludedCells(s)) {
		add("build %s records exclusions %q, its scope excludes %q", b.Name, b.Excluded, excludedCells(s))
	}
	_, n, _ := resolveScope(mb)
	wantReason := ""
	if n != nil {
		wantReason = n.Reason
	}
	if b.ScopeReason != wantReason {
		add("build %s records the scope reason %q, narrowedScopes says %q", b.Name, b.ScopeReason, wantReason)
	}
	if err := checkCapability(b.Name, mb.Version, s, b.Capability); err != nil {
		add("%v", err)
	}
	if mb.Provenance == nil || b.Provenance == nil || *b.Provenance != *mb.Provenance {
		add("build %s ran with provenance %v, the manifest binds %v", b.Name, b.Provenance, mb.Provenance)
	}
}

// verifyProvenance reads a build's record from disk: it must be the bound
// record, for the build's binary, and a narrowed build's must be a source
// record of the commit narrowedScopes names.
func verifyProvenance(mb manifestBuild, add func(string, ...any)) {
	if mb.Provenance == nil {
		return
	}
	rec, err := readProvenance(mb.Provenance, mb.SHA256)
	if err != nil {
		add("build %s: %v", mb.Name, err)
		return
	}
	_, n, _ := resolveScope(mb)
	if n == nil {
		return
	}
	switch {
	case rec.Kind != "source" || rec.Source.Commit != n.Commit:
		add("build %s runs narrowed as version %s, which needs a source record of commit %s; its record is a %s record%s",
			mb.Name, mb.Version, n.Commit, rec.Kind, commitSuffix(rec))
	case rec.Source.Builder != controlledBuilder:
		add("build %s runs narrowed, which needs a record of the controlled build %s; its record names builder %q",
			mb.Name, controlledBuilder, rec.Source.Builder)
	case rec.Source.Module != n.Module:
		add("build %s runs narrowed, which needs a build of module %s; its record names module %q", mb.Name, n.Module, rec.Source.Module)
	}
}

func commitSuffix(rec *provenanceRecord) string {
	if rec.Source == nil {
		return ""
	}
	return " of commit " + rec.Source.Commit
}

// A fixture that a full run would produce, for the verifier's own tests.
func fullResults(m *manifest) *results {
	r := &results{Schema: resultsSchema, At: time.Now(), Long: m.Long, ManifestSHA256: m.sha256}
	scopes := map[string]buildScope{}
	for _, b := range m.Builds {
		s, n, err := resolveScope(b)
		if err != nil {
			panic(err)
		}
		scopes[b.Name] = s
		rb := resultBuild{Name: b.Name, Path: b.Path, SHA256: b.SHA256, Version: b.Version, Scope: s, Excluded: excludedCells(s),
			Capability: capability{VersionOutput: b.Version, HubURLFlag: s.has(routeChannel) || s.has(routeTLS)}, Provenance: b.Provenance}
		if n != nil {
			rb.ScopeReason = n.Reason
		}
		r.Builds = append(r.Builds, rb)
	}
	for _, b := range m.Builds {
		if !scopes[b.Name].hub() {
			continue
		}
		for _, cell := range requiredCells(m.Long) {
			r.Cells = append(r.Cells, cellResult{Name: cell, HubBuild: b.Name, WorkerBuild: b.Name, Status: statusPass})
		}
		for _, o := range m.Builds {
			if o.Name == b.Name {
				continue
			}
			r.Cells = append(r.Cells, cellResult{Name: pairCell, HubBuild: b.Name, WorkerBuild: o.Name, Status: statusPass})
			if !scopes[o.Name].hub() {
				for _, cell := range requiredWorkerOnlyCells(m.Long) {
					r.Cells = append(r.Cells, cellResult{Name: cell, HubBuild: b.Name, WorkerBuild: o.Name, Status: statusPass})
				}
			}
		}
	}
	return r
}

func fakeProvenance(c string) *provenanceRef {
	return &provenanceRef{Record: "/nonexistent/provenance-" + c + ".json", SHA256: strings.Repeat(c, 64)}
}

func testManifest(long bool) *manifest {
	return &manifest{Long: long, sha256: strings.Repeat("9", 64), Builds: []manifestBuild{
		{Name: "old", Path: "/nonexistent/old/dagu", SHA256: strings.Repeat("a", 64), Version: "0.0.0-txe.19", Provenance: fakeProvenance("1")},
		{Name: "new", Path: "/nonexistent/new/dagu", SHA256: strings.Repeat("b", 64), Version: "0.0.20-txe.main", Provenance: fakeProvenance("2")},
	}}
}

// testManifestWithWorker adds the one narrowed build narrowedScopes lists.
func testManifestWithWorker(long bool) *manifest {
	m := testManifest(long)
	m.Builds = append(m.Builds, manifestBuild{Name: "w18", Path: "/nonexistent/w18/dagu", SHA256: strings.Repeat("e", 64),
		Version: "2.18.2-txe.18", Roles: []string{roleWorker}, Routes: []string{routeNative}, Provenance: fakeProvenance("3")})
	return m
}

func TestVerifyAcceptsAFullRun(t *testing.T) {
	t.Parallel()
	m := testManifest(true)
	assert.Empty(t, verifyResults(m, fullResults(m), false))
}

// Each way a result can fall short is a reason, and none is waived.
func TestVerifyFailsClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(m *manifest, r *results)
		want   string
	}{
		{"a long cell not run", func(_ *manifest, r *results) {
			for i := range r.Cells {
				if r.Cells[i].Name == "stale" && r.Cells[i].HubBuild == "new" {
					r.Cells[i].Status, r.Cells[i].Detail = statusNotRun, "DAGU_MACHINEAUTH_LONG unset"
				}
			}
			r.Partial = true
		}, "cell stale (hub new, worker new) was not run"},
		{"a short run offered as a long proof", func(m *manifest, r *results) {
			*r = *fullResults(testManifest(false))
			m.Long = true
		}, "results were run with long=false, the manifest asks for long=true"},
		{"a complete smoke is still not a proof", func(m *manifest, r *results) {
			*m = *testManifest(false)
			*r = *fullResults(m)
		}, "a smoke, never a release proof"},
		{"a failed refusal", func(_ *manifest, r *results) {
			r.Cells[3].Status, r.Cells[3].Detail = statusFail, "hub logged no_credential 0 times"
		}, "failed: hub logged no_credential 0 times"},
		{"a missing cell", func(_ *manifest, r *results) {
			r.Cells = r.Cells[1:]
		}, "cell setup missing for build old"},
		{"a missing pair", func(_ *manifest, r *results) {
			var kept []cellResult
			for _, c := range r.Cells {
				if c.Name != pairCell || c.HubBuild != "new" || c.WorkerBuild != "old" {
					kept = append(kept, c)
				}
			}
			r.Cells = kept
		}, "pair cell missing: hub new with worker old"},
		{"a duplicated cell", func(_ *manifest, r *results) {
			r.Cells = append(r.Cells, r.Cells[0])
		}, "recorded twice"},
		{"an unknown cell", func(_ *manifest, r *results) {
			r.Cells = append(r.Cells, cellResult{Name: "pos-anything", HubBuild: "old", WorkerBuild: "old", Status: statusPass})
		}, "cell pos-anything is not a cell of this matrix"},
		{"a cell attributed to two builds", func(_ *manifest, r *results) {
			r.Cells[2].WorkerBuild = "new"
		}, "a build's cell runs both as the same build"},
		{"a pair of a build with itself", func(_ *manifest, r *results) {
			r.Cells = append(r.Cells, cellResult{Name: pairCell, HubBuild: "old", WorkerBuild: "old", Status: statusPass})
		}, "pair cell with the same hub and worker build old"},
		{"a malformed status", func(_ *manifest, r *results) {
			r.Cells[5].Status = "PASS"
		}, `has status "PASS", not pass, fail or not_run`},
		{"a build the manifest does not name", func(_ *manifest, r *results) {
			r.Builds = append(r.Builds, resultBuild{Name: "stray", SHA256: strings.Repeat("c", 64)})
		}, "results hold build stray, which the manifest does not name"},
		{"a build missing from the results", func(_ *manifest, r *results) {
			r.Builds = r.Builds[:1]
		}, "build new is in the manifest but not in the results"},
		{"a digest that is not the manifest's", func(_ *manifest, r *results) {
			r.Builds[1].SHA256 = strings.Repeat("d", 64)
		}, "ran as sha256 dddd"},
		{"a path that is not the manifest's", func(_ *manifest, r *results) {
			r.Builds[0].Path = "/elsewhere/dagu"
		}, "ran from /elsewhere/dagu"},
		{"a version that is not the manifest's", func(_ *manifest, r *results) {
			r.Builds[0].Version = "0.0.0-txe.18"
		}, `reported version "0.0.0-txe.18", the manifest names "0.0.0-txe.19"`},
		{"a cell naming an unknown build", func(_ *manifest, r *results) {
			r.Cells[0].HubBuild, r.Cells[0].WorkerBuild = "ghost", "ghost"
		}, `names hub build "ghost"`},
		{"partial flag disagreeing with the cells", func(_ *manifest, r *results) {
			r.Partial = true
		}, "results say partial=true but 0 cells were not run"},
		{"another schema", func(_ *manifest, r *results) {
			r.Schema = 1
		}, "results schema 1"},
		{"results of another manifest", func(_ *manifest, r *results) {
			r.ManifestSHA256 = strings.Repeat("8", 64)
		}, "results ran under manifest sha256"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := testManifest(true)
			r := fullResults(m)
			tc.mutate(m, r)
			problems := verifyResults(m, r, false)
			require.NotEmpty(t, problems, "the verifier accepted it")
			assert.Contains(t, strings.Join(problems, "\n"), tc.want)
		})
	}
}

// writeRecord writes a provenance record for a binary and returns its reference.
func writeRecord(t *testing.T, dir, name string, rec provenanceRecord) *provenanceRef {
	t.Helper()
	raw, err := json.Marshal(rec)
	require.NoError(t, err)
	p := filepath.Join(dir, name+"-provenance.json")
	require.NoError(t, os.WriteFile(p, raw, 0o600))
	return &provenanceRef{Record: p, SHA256: sha256Hex(raw)}
}

func imageRecordFor(name, binarySHA string) provenanceRecord {
	return provenanceRecord{Schema: provenanceSchema, Kind: "image", Name: name, BinarySHA256: binarySHA,
		Image: &imageProvenance{Index: "sha256:" + strings.Repeat("1", 64), Platform: "linux/amd64", Manifest: "sha256:" + strings.Repeat("2", 64)}}
}

// With the binaries at hand, a digest is re-read from disk, so a binary swapped
// after the run is caught.
func TestVerifyHoldsTheProofToTheBinaryOnDisk(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := dir + "/dagu"
	require.NoError(t, os.WriteFile(path, []byte("one build"), 0o600))
	sum, err := fileSHA256(path)
	require.NoError(t, err)
	m := &manifest{Long: true, Builds: []manifestBuild{{Name: "only", Path: path, SHA256: sum, Version: "1.0.0",
		Provenance: writeRecord(t, dir, "only", imageRecordFor("only", sum))}}}
	r := fullResults(m)
	assert.Empty(t, verifyResults(m, r, true))
	require.NoError(t, os.WriteFile(path, []byte("another build"), 0o600))
	problems := verifyResults(m, r, true)
	require.Len(t, problems, 1)
	assert.Contains(t, problems[0], "is now sha256")
	require.NoError(t, os.Remove(path))
	problems = verifyResults(m, r, true)
	require.Len(t, problems, 1)
	assert.Contains(t, problems[0], "cannot be read now")
}

// loadManifest refuses what it cannot hold a proof to.
func TestLoadManifestRefusesBadShapes(t *testing.T) {
	t.Parallel()
	write := func(t *testing.T, body string) string {
		t.Helper()
		path := t.TempDir() + "/manifest.json"
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
		return path
	}
	// An absolute path of this OS, with forward slashes so it is JSON as is
	// (a drive-letter path with slashes is absolute on Windows too).
	abs := filepath.ToSlash(t.TempDir())
	prov := `"provenance":{"record":"` + abs + `/p.json","sha256":"` + strings.Repeat("7", 64) + `"}`
	build := func(name, extra string) string {
		return `{"name":"` + name + `","path":"` + abs + `/` + name + `","sha256":"` + strings.Repeat("0", 64) + `","version":"1.0.0",` + prov + extra + `}`
	}
	good := `{"builds":[` + build("a", "") + `]}`
	path := write(t, good)
	m, err := loadManifest(path)
	require.NoError(t, err)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, sha256Hex(raw), m.sha256, "the manifest's digest is its bytes'")
	for name, body := range map[string]string{
		"no builds":           `{"builds":[]}`,
		"short digest":        `{"builds":[{"name":"a","path":"` + abs + `/x","sha256":"abc","version":"1",` + prov + `}]}`,
		"upper digest":        `{"builds":[{"name":"a","path":"` + abs + `/x","sha256":"` + strings.Repeat("A", 64) + `","version":"1",` + prov + `}]}`,
		"twice":               `{"builds":[` + build("a", "") + `,` + build("a", "") + `]}`,
		"name with path":      `{"builds":[` + build("a/b", "") + `]}`,
		"no path":             `{"builds":[{"name":"a","sha256":"` + strings.Repeat("0", 64) + `","version":"1",` + prov + `}]}`,
		"relative path":       `{"builds":[{"name":"a","path":"dagu","sha256":"` + strings.Repeat("0", 64) + `","version":"1",` + prov + `}]}`,
		"no version":          `{"builds":[{"name":"a","path":"` + abs + `/a","sha256":"` + strings.Repeat("0", 64) + `",` + prov + `}]}`,
		"no provenance":       `{"builds":[{"name":"a","path":"` + abs + `/a","sha256":"` + strings.Repeat("0", 64) + `","version":"1"}]}`,
		"unknown field":       `{"builds":[` + build("a", `,"route":["native"]`) + `]}`,
		"a reason of its own": `{"builds":[` + build("a", `,"scope_reason":"the caller says so"`) + `]}`,
		"no hub":              `{"builds":[{"name":"w","path":"` + abs + `/w","sha256":"` + strings.Repeat("0", 64) + `","version":"2.18.2-txe.18","roles":["worker"],"routes":["native"],` + prov + `}]}`,
	} {
		_, err := loadManifest(write(t, body))
		assert.Error(t, err, name)
	}
}

// cellStatus turns a subtest's outcome into a cell status. t.Run reports true
// for a subtest the -run filter excluded or that skipped itself, so a body that
// did not run to its end is never a pass.
func cellStatus(passed, ran bool, detail string) (string, string) {
	switch {
	case passed && ran:
		return statusPass, detail
	case passed:
		return statusNotRun, "the subtest did not run to its end (excluded by the test filter, or skipped)"
	default:
		return statusFail, "see the subtest output"
	}
}

// A subtest the -run filter excluded, or that skipped itself, reports true
// from t.Run without having run; the cell is then not run, never a pass.
func TestCellStatusNeverPassesWhatDidNotRun(t *testing.T) {
	t.Parallel()
	status, _ := cellStatus(true, true, "ok")
	assert.Equal(t, statusPass, status)
	status, detail := cellStatus(true, false, "")
	assert.Equal(t, statusNotRun, status)
	assert.Contains(t, detail, "did not run")
	status, _ = cellStatus(false, false, "")
	assert.Equal(t, statusFail, status)
	status, _ = cellStatus(false, true, "")
	assert.Equal(t, statusFail, status)
}

// DAGU_MACHINEAUTH_VERIFY=<results.json> with DAGU_MACHINEAUTH_MATRIX=<manifest>
// judges a recorded run against the binaries on disk now. It is the command a
// release gate runs; it fails on any problem the verifier finds.
func TestMachineAuthVerify(t *testing.T) {
	resultsPath := os.Getenv("DAGU_MACHINEAUTH_VERIFY")
	manifestPath := os.Getenv("DAGU_MACHINEAUTH_MATRIX")
	if resultsPath == "" {
		t.Skip("set DAGU_MACHINEAUTH_VERIFY=<results.json> and DAGU_MACHINEAUTH_MATRIX=<manifest.json> to verify a recorded run")
	}
	require.NotEmpty(t, manifestPath, "DAGU_MACHINEAUTH_MATRIX names the manifest the results are held to")
	approved := os.Getenv("DAGU_MACHINEAUTH_MANIFEST_SHA256")
	require.NotEmpty(t, approved, "DAGU_MACHINEAUTH_MANIFEST_SHA256 names the digest of the manifest that was approved: the gate holds the proof to that manifest, not to whichever file is given")
	m, err := loadManifest(manifestPath)
	require.NoError(t, err)
	require.Equal(t, approved, m.sha256, "the manifest given is not the approved one")
	raw, err := os.ReadFile(resultsPath)
	require.NoError(t, err)
	var r results
	require.NoError(t, json.Unmarshal(raw, &r))
	problems := verifyResults(m, &r, true)
	if len(problems) > 0 {
		t.Fatalf("not a release proof (%d problems):\n  %s", len(problems), strings.Join(problems, "\n  "))
	}
	t.Logf("release proof holds for manifest %s: %d builds, %d cells, long=%v, recorded %s", m.sha256, len(r.Builds), len(r.Cells), r.Long, r.At.UTC().Format(time.RFC3339))
	for _, line := range scopeSummary(&r) {
		t.Log(line)
	}
	for _, b := range m.Builds {
		rec, err := readProvenance(b.Provenance, b.SHA256)
		require.NoError(t, err)
		t.Logf("PROVENANCE %s: %s record; %s", b.Name, rec.Kind, rec.Scope)
	}
}
