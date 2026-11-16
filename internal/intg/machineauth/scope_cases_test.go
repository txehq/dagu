// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package machineauth_test

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The matrix can run a narrowed build only as a worker over native gRPC; an
// entry of another shape would be accepted by the manifest and then have no
// cells to run.
func TestNarrowedScopesAreRunnable(t *testing.T) {
	t.Parallel()
	commit := regexp.MustCompile(`^[0-9a-f]{40}$`)
	seen := map[string]bool{}
	for _, n := range narrowedScopes {
		assert.False(t, seen[n.Version], "version %s listed twice", n.Version)
		seen[n.Version] = true
		assert.Equal(t, []string{roleWorker}, n.Scope.Roles, "%s: only worker-only builds have cells", n.Version)
		assert.Equal(t, []string{routeNative}, n.Scope.Routes, "%s: a worker-only build runs over native gRPC", n.Version)
		assert.Regexp(t, commit, n.Commit, "%s: a full commit id", n.Version)
		assert.NotEmpty(t, n.Reason, "%s: the reason is shown with every result", n.Version)
	}
}

// A caller cannot narrow a build narrowedScopes does not list, nor narrow a
// listed one differently: candidate C and -19 keep every role and route.
func TestResolveScopeRefusesWhatIsNotListed(t *testing.T) {
	t.Parallel()
	c := manifestBuild{Name: "c", Version: "2.25.8-txe.1"}
	p19 := manifestBuild{Name: "p19", Version: "2.18.2-txe.19"}
	w18 := manifestBuild{Name: "w18", Version: "2.18.2-txe.18"}
	with := func(b manifestBuild, roles, routes []string) manifestBuild {
		b.Roles, b.Routes = roles, routes
		return b
	}
	for name, tc := range map[string]struct {
		b    manifestBuild
		want string
	}{
		"C without its hub role":                   {with(c, []string{roleWorker}, nil), "only the builds listed in narrowedScopes"},
		"C without its worker role":                {with(c, []string{roleHub}, nil), "only the builds listed in narrowedScopes"},
		"C without the TLS route":                  {with(c, nil, []string{routeNative, routeChannel}), "only the builds listed in narrowedScopes"},
		"C as the -18 scope":                       {with(c, []string{roleWorker}, []string{routeNative}), "only the builds listed in narrowedScopes"},
		"-19 without the channel":                  {with(p19, nil, []string{routeNative}), "only the builds listed in narrowedScopes"},
		"-18 declaring a channel it does not have": {with(w18, []string{roleWorker}, []string{routeNative, routeChannel}), "the only narrowed scope listed for that version"},
		"-18 as a hub":                             {with(w18, []string{roleHub, roleWorker}, []string{routeNative}), "the only narrowed scope listed for that version"},
		"an unknown role":                          {with(c, []string{"reviewer"}, nil), `unknown role "reviewer"`},
		"an unknown route":                         {with(c, nil, []string{"quic"}), `unknown route "quic"`},
		"a route named twice":                      {with(w18, []string{roleWorker}, []string{routeNative, routeNative}), `route "native" named twice`},
		"an empty role list":                       {with(c, []string{}, nil), "an empty role list"},
	} {
		_, _, err := resolveScope(tc.b)
		if assert.Error(t, err, name) {
			assert.Contains(t, err.Error(), tc.want, name)
		}
	}
	s, n, err := resolveScope(with(w18, []string{roleWorker}, []string{routeNative}))
	require.NoError(t, err)
	require.NotNil(t, n)
	assert.Equal(t, "5b011eba3a30e224be14a5c81bd15cd9ab90c956", n.Commit)
	assert.False(t, s.hub())
	s, n, err = resolveScope(with(c, []string{roleWorker, roleHub}, []string{routeTLS, routeNative, routeChannel}))
	require.NoError(t, err, "the full scope in any order is the full scope")
	assert.Nil(t, n)
	assert.True(t, s.full())
}

// The binary's own account corroborates its scope; it never narrows one.
func TestCheckCapability(t *testing.T) {
	t.Parallel()
	narrow := buildScope{Roles: []string{roleWorker}, Routes: []string{routeNative}}
	ok := func(s buildScope, flag bool) error {
		return checkCapability("b", "1.0", s, capability{VersionOutput: "1.0", HubURLFlag: flag})
	}
	require.NoError(t, ok(fullScope, true))
	require.NoError(t, ok(narrow, false))
	err := ok(fullScope, false)
	require.Error(t, err, "a full build whose worker cannot take the channel fails; it is not narrowed")
	assert.Contains(t, err.Error(), "cannot take the channel")
	err = ok(narrow, true)
	require.Error(t, err, "a build narrowed to native whose worker can take the channel must prove the channel")
	assert.Contains(t, err.Error(), "the channel routes must be proven")
	err = checkCapability("b", "1.0", fullScope, capability{VersionOutput: "1.0-other", HubURLFlag: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `dagu version says "1.0-other"`)
}

func TestVerifyAcceptsAFullRunWithAWorkerOnlyBuild(t *testing.T) {
	t.Parallel()
	m := testManifestWithWorker(true)
	r := fullResults(m)
	assert.Empty(t, verifyResults(m, r, false))
	// 2 full builds × 28 + 2 hubs × 9 worker-only cells + pairs (old→new,
	// old→w18, new→old, new→w18): the stage-1 shape of TXE-7523.
	assert.Len(t, r.Cells, 2*len(requiredCells(true))+2*len(requiredWorkerOnlyCells(true))+4)
	summary := strings.Join(scopeSummary(r), "\n")
	assert.Contains(t, summary, "SCOPE w18 (2.18.2-txe.18): NARROWED to roles worker, routes native. EXCLUDED: every hub-side cell")
	assert.Contains(t, summary, "route channel; route tls")
	assert.Contains(t, summary, "SCOPE old (0.0.0-txe.19): full")
}

// Every way a run with a worker-only build can fall short is a reason.
func TestVerifyFailsClosedOnScope(t *testing.T) {
	t.Parallel()
	build := func(r *results, name string) *resultBuild {
		for i := range r.Builds {
			if r.Builds[i].Name == name {
				return &r.Builds[i]
			}
		}
		panic(name)
	}
	cases := []struct {
		name   string
		mutate func(m *manifest, r *results)
		want   string
	}{
		{"a worker-only cell missing", func(_ *manifest, r *results) {
			r.Cells = slices.DeleteFunc(r.Cells, func(c cellResult) bool {
				return c.Name == "revoke-issuer" && c.HubBuild == "new" && c.WorkerBuild == "w18"
			})
		}, "cell revoke-issuer missing for worker-only build w18 under hub new"},
		{"a worker-only long cell not run", func(_ *manifest, r *results) {
			for i := range r.Cells {
				if r.Cells[i].Name == "stale" && r.Cells[i].WorkerBuild == "w18" && r.Cells[i].HubBuild == "old" {
					r.Cells[i].Status = statusNotRun
				}
			}
			r.Partial = true
		}, "cell stale (hub old, worker w18) was not run"},
		{"a worker-only build recorded as hub", func(_ *manifest, r *results) {
			r.Cells = append(r.Cells, cellResult{Name: "setup", HubBuild: "w18", WorkerBuild: "w18", Status: statusPass})
		}, "names w18 as hub, a worker-only build"},
		{"a full build's cell offered for the worker-only build", func(_ *manifest, r *results) {
			r.Cells = append(r.Cells, cellResult{Name: "pos-channel-http", HubBuild: "new", WorkerBuild: "w18", Status: statusPass})
		}, "cell pos-channel-http is not a cell of the worker-only build w18"},
		{"the pair with the worker-only build missing", func(_ *manifest, r *results) {
			r.Cells = slices.DeleteFunc(r.Cells, func(c cellResult) bool {
				return c.Name == pairCell && c.HubBuild == "old" && c.WorkerBuild == "w18"
			})
		}, "pair cell missing: hub old with worker w18"},
		{"exclusions dropped from the result", func(_ *manifest, r *results) {
			build(r, "w18").Excluded = nil
		}, "build w18 records exclusions"},
		{"a reason of the caller's own", func(_ *manifest, r *results) {
			build(r, "w18").ScopeReason = "it was easier"
		}, `records the scope reason "it was easier"`},
		{"a narrowed build whose worker can take the channel", func(_ *manifest, r *results) {
			build(r, "w18").Capability.HubURLFlag = true
		}, "the channel routes must be proven"},
		{"a full build recorded narrowed", func(_ *manifest, r *results) {
			b := build(r, "new")
			b.Scope = buildScope{Roles: []string{roleWorker}, Routes: []string{routeNative}}
		}, "build new ran roles worker, routes native, the manifest's scope for it is roles hub+worker, routes native+channel+tls"},
		{"a full build without the channel", func(_ *manifest, r *results) {
			build(r, "old").Capability.HubURLFlag = false
		}, "build old declares roles hub+worker, routes native+channel+tls, but its worker has no --worker.hub-url"},
		{"a manifest narrowing a build that is not listed", func(m *manifest, _ *results) {
			m.Builds[1].Roles = []string{roleWorker}
		}, "only the builds listed in narrowedScopes may run narrowed"},
		{"a version the binary did not report", func(_ *manifest, r *results) {
			build(r, "w18").Capability.VersionOutput = "2.18.2-txe.17"
		}, `dagu version says "2.18.2-txe.17"`},
		{"another provenance record", func(_ *manifest, r *results) {
			build(r, "w18").Provenance = fakeProvenance("4")
		}, "build w18 ran with provenance"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := testManifestWithWorker(true)
			r := fullResults(m)
			tc.mutate(m, r)
			problems := verifyResults(m, r, false)
			require.NotEmpty(t, problems, "the verifier accepted it")
			assert.Contains(t, strings.Join(problems, "\n"), tc.want)
		})
	}
}

// With the records at hand, a narrowed build's record must be a source record
// of the commit narrowedScopes names, for the build's binary, and the record
// the manifest binds.
func TestVerifyHoldsNarrowedBuildsToTheirSourceCommit(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeBinary := func(name string) (string, string) {
		p := dir + "/" + name
		require.NoError(t, os.WriteFile(p, []byte("binary "+name), 0o600))
		sum, err := fileSHA256(p)
		require.NoError(t, err)
		return p, sum
	}
	fullPath, fullSum := writeBinary("full")
	wPath, wSum := writeBinary("w18")
	source := func(commit string) provenanceRecord {
		return provenanceRecord{Schema: provenanceSchema, Kind: "source", Name: "w18", BinarySHA256: wSum,
			Source: &sourceProvenance{Tag: "txe-v2.18.2-18", Commit: commit, GOOS: "linux", GOARCH: "amd64"}}
	}
	n := 0
	mk := func(wRec provenanceRecord) *manifest {
		n++
		return &manifest{Long: true, Builds: []manifestBuild{
			{Name: "full", Path: fullPath, SHA256: fullSum, Version: "9.9.9", Provenance: writeRecord(t, dir, "full", imageRecordFor("full", fullSum))},
			{Name: "w18", Path: wPath, SHA256: wSum, Version: "2.18.2-txe.18", Roles: []string{roleWorker}, Routes: []string{routeNative},
				Provenance: writeRecord(t, dir, fmt.Sprintf("w18-%d", n), wRec)},
		}}
	}
	good := mk(source(narrowedScopes[0].Commit))
	assert.Empty(t, verifyResults(good, fullResults(good), true))

	for name, tc := range map[string]struct {
		m    *manifest
		want string
	}{
		"another commit":  {mk(source(strings.Repeat("f", 40))), "needs a source record of commit 5b011eba"},
		"an image record": {mk(imageRecordFor("w18", wSum)), "its record is a image record"},
		"another binary": {mk(func() provenanceRecord {
			r := source(narrowedScopes[0].Commit)
			r.BinarySHA256 = strings.Repeat("0", 64)
			return r
		}()), "is for binary sha256 0000"},
	} {
		problems := verifyResults(tc.m, fullResults(tc.m), true)
		assert.Contains(t, strings.Join(problems, "\n"), tc.want, name)
	}
	// A record changed after the manifest bound it.
	m := mk(source(narrowedScopes[0].Commit))
	require.NoError(t, os.WriteFile(m.Builds[1].Provenance.Record, []byte(`{"schema":1}`), 0o600))
	assert.Contains(t, strings.Join(verifyResults(m, fullResults(m), true), "\n"), "the manifest binds")
}
