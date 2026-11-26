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

// The matrix can run a narrowed build only as a worker over native gRPC, or as
// a hub and worker over native gRPC; an entry of another shape would be
// accepted by the manifest and then have no cells to run. Each entry binds
// its provenance by one kind, with exactly that kind's fields.
func TestNarrowedScopesAreRunnable(t *testing.T) {
	t.Parallel()
	commit := regexp.MustCompile(`^[0-9a-f]{40}$`)
	seen := map[string]bool{}
	for _, n := range narrowedScopes {
		assert.False(t, seen[n.Version], "version %s listed twice", n.Version)
		seen[n.Version] = true
		assert.Equal(t, []string{routeNative}, n.Scope.Routes, "%s: a narrowed build runs over native gRPC", n.Version)
		assert.Contains(t, [][]string{{roleWorker}, allRoles}, n.Scope.Roles, "%s: worker-only, or hub and worker", n.Version)
		assert.Regexp(t, commit, n.Commit, "%s: a full commit id", n.Version)
		assert.NotEmpty(t, n.Reason, "%s: the reason is shown with every result", n.Version)
		switch n.Provenance {
		case provenanceSource:
			assert.NotEmpty(t, n.Module, "%s: the module its controlled build must build", n.Version)
			assert.Empty(t, n.Index, "%s: a source entry names no image", n.Version)
		case provenanceImage:
			assert.Regexp(t, digestRE, n.Index, "%s: the image index it is read out of", n.Version)
			assert.Empty(t, n.Module, "%s: an image entry names no module", n.Version)
		default:
			t.Errorf("%s: provenance kind %q, not %s or %s", n.Version, n.Provenance, provenanceSource, provenanceImage)
		}
		if n.Scope.hub() {
			assert.NotEmpty(t, n.HubConfigKeys, "%s: a narrowed hub lists the configuration keys its source reads", n.Version)
			assert.True(t, slices.IsSorted(n.HubConfigKeys), "%s: the keys are listed sorted", n.Version)
		} else {
			assert.Empty(t, n.HubConfigKeys, "%s: a worker-only build has no hub configuration", n.Version)
		}
	}
}

// The two entries are the ones TXE-7523's R9 run binds: -18 by a source
// record of its tag, -17 by an image record of the hub's fallback index.
func TestNarrowedScopesBindTheR9Builds(t *testing.T) {
	t.Parallel()
	w18, _, err := resolveScope(manifestBuild{Name: "w18", Version: "2.18.2-txe.18", Roles: []string{roleWorker}, Routes: []string{routeNative}})
	require.NoError(t, err)
	assert.Equal(t, buildScope{Roles: []string{roleWorker}, Routes: []string{routeNative}}, w18)
	_, n18, _ := resolveScope(manifestBuild{Name: "w18", Version: "2.18.2-txe.18", Roles: []string{roleWorker}, Routes: []string{routeNative}})
	assert.Equal(t, provenanceSource, n18.Provenance)
	assert.Equal(t, "5b011eba3a30e224be14a5c81bd15cd9ab90c956", n18.Commit)
	assert.Equal(t, "github.com/dagucloud/dagu/v2", n18.Module)
	s, n17, err := resolveScope(manifestBuild{Name: "f17", Version: "2.18.2-txe.17", Routes: []string{routeNative}})
	require.NoError(t, err)
	assert.Equal(t, buildScope{Roles: allRoles, Routes: []string{routeNative}}, s)
	assert.Equal(t, provenanceImage, n17.Provenance)
	assert.Equal(t, "4d164866b07195346610588a37390a38960e5bb7", n17.Commit)
	assert.Equal(t, "sha256:d625b509af2a8fdbfb771c7d3dcb89b8b4a345680fcf2c2e91d62c5e66f33d9b", n17.Index)
	assert.NotContains(t, n17.HubConfigKeys, "coordinator.worker_channel.enabled")
}

// A caller cannot narrow a build narrowedScopes does not list, nor narrow a
// listed one differently: candidate C and -19 keep every role and route.
func TestResolveScopeRefusesWhatIsNotListed(t *testing.T) {
	t.Parallel()
	c := manifestBuild{Name: "c", Version: "2.25.8-txe.1"}
	p19 := manifestBuild{Name: "p19", Version: "2.18.2-txe.19"}
	w18 := manifestBuild{Name: "w18", Version: "2.18.2-txe.18"}
	f17 := manifestBuild{Name: "f17", Version: "2.18.2-txe.17"}
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
		"-17 declared full":                        {f17, "the only narrowed scope listed for that version"},
		"-17 declaring the channel":                {with(f17, nil, []string{routeNative, routeChannel}), "the only narrowed scope listed for that version"},
		"-17 declaring TLS":                        {with(f17, nil, []string{routeNative, routeTLS}), "the only narrowed scope listed for that version"},
		"-17 as a worker only":                     {with(f17, []string{roleWorker}, []string{routeNative}), "the only narrowed scope listed for that version"},
		"-17 as a hub only":                        {with(f17, []string{roleHub}, []string{routeNative}), "the only narrowed scope listed for that version"},
		"-18 declared full":                        {w18, "the only narrowed scope listed for that version"},
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
			Source: &sourceProvenance{Builder: controlledBuilder, Tag: "txe-v2.18.2-18", Commit: commit, Module: narrowedScopes[0].Module,
				GOOS: "linux", GOARCH: "amd64"}}
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
		"a record not written by the controlled build": {mk(func() provenanceRecord {
			r := source(narrowedScopes[0].Commit)
			r.Source.Builder = ""
			return r
		}()), "needs a record of the controlled build"},
		"a build of another module with the right stamp": {mk(func() provenanceRecord {
			r := source(narrowedScopes[0].Commit)
			r.Source.Module = "evil"
			return r
		}()), `needs a build of module github.com/dagucloud/dagu/v2; its record names module "evil"`},
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

// testManifestR9 is the shape of TXE-7523's R9 run: candidate c′ full, f17
// (txe-v2.18.2-17) as a native-only hub and worker, w18 worker-only.
func testManifestR9(long bool) *manifest {
	return &manifest{Long: long, sha256: strings.Repeat("9", 64), Builds: []manifestBuild{
		{Name: "cprime", Path: "/nonexistent/cprime/dagu", SHA256: strings.Repeat("a", 64), Version: "2.25.8-txe.2", Provenance: fakeProvenance("1")},
		{Name: "f17", Path: "/nonexistent/f17/dagu", SHA256: strings.Repeat("b", 64), Version: "2.18.2-txe.17",
			Routes: []string{routeNative}, Provenance: fakeProvenance("2")},
		{Name: "w18", Path: "/nonexistent/w18/dagu", SHA256: strings.Repeat("e", 64), Version: "2.18.2-txe.18",
			Roles: []string{roleWorker}, Routes: []string{routeNative}, Provenance: fakeProvenance("3")},
	}}
}

// Stage 1 of TXE-7523 (manifest 86a5274a…: c and p19 full, w18 worker-only)
// still derives exactly 78 cells: 2 × 28 + 2 × 9 + 4 pairs.
func TestStageOneShapeStillDerives78Cells(t *testing.T) {
	t.Parallel()
	m := &manifest{Long: true, sha256: strings.Repeat("9", 64), Builds: []manifestBuild{
		{Name: "c", Path: "/nonexistent/c/dagu", SHA256: strings.Repeat("a", 64), Version: "2.25.8-txe.1", Provenance: fakeProvenance("1")},
		{Name: "p19", Path: "/nonexistent/p19/dagu", SHA256: strings.Repeat("b", 64), Version: "2.18.2-txe.19", Provenance: fakeProvenance("2")},
		{Name: "w18", Path: "/nonexistent/w18/dagu", SHA256: strings.Repeat("e", 64), Version: "2.18.2-txe.18",
			Roles: []string{roleWorker}, Routes: []string{routeNative}, Provenance: fakeProvenance("3")},
	}}
	r := fullResults(m)
	assert.Len(t, r.Cells, 78)
	assert.Empty(t, verifyResults(m, r, false))
	for _, b := range r.Builds {
		if b.Name == "w18" {
			assert.Equal(t, []string{"every hub-side cell with this build as hub (setup, the refusal probes, pos-two-owners, pos-probe-control, pair-native as hub)",
				"route channel", "route tls"}, b.Excluded, "-18's exclusions are unchanged")
		}
	}
}

// The R9 shape derives 28 for c′, 26 for f17 (no channel positives), 9 for
// w18 under each hub and the 4 pairs: 76, which the verifier accepts.
func TestVerifyAcceptsANativeOnlyHub(t *testing.T) {
	t.Parallel()
	m := testManifestR9(true)
	r := fullResults(m)
	assert.Empty(t, verifyResults(m, r, false))
	assert.Len(t, r.Cells, 28+26+2*9+4)
	for _, c := range r.Cells {
		if c.HubBuild == "f17" {
			assert.NotContains(t, []string{"pos-channel-http", "pos-channel-tls"}, c.Name)
		}
	}
	summary := strings.Join(scopeSummary(r), "\n")
	assert.Contains(t, summary, "SCOPE f17 (2.18.2-txe.17): NARROWED to roles hub+worker, routes native. EXCLUDED: route channel; route tls; hub cells pos-channel-http, pos-channel-tls; "+
		"with this build as hub, pos-probe-control and every neg- probe run over grpc only, and setup's enrol check does not take the channel. Why: txe-v2.18.2-17 predates")
	assert.Contains(t, summary, "SCOPE cprime (2.25.8-txe.2): full")
}

// Every way a run with the native-only hub can fall short is a reason.
func TestVerifyFailsClosedOnANativeOnlyHub(t *testing.T) {
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
		{"a derived cell missing", func(_ *manifest, r *results) {
			r.Cells = slices.DeleteFunc(r.Cells, func(c cellResult) bool {
				return c.Name == "pos-probe-control" && c.HubBuild == "f17"
			})
		}, "cell pos-probe-control missing for build f17"},
		{"a refusal class missing", func(_ *manifest, r *results) {
			r.Cells = slices.DeleteFunc(r.Cells, func(c cellResult) bool {
				return c.Name == "neg-no-credential" && c.HubBuild == "f17"
			})
		}, "cell neg-no-credential missing for build f17"},
		{"a channel cell recorded", func(_ *manifest, r *results) {
			r.Cells = append(r.Cells, cellResult{Name: "pos-channel-http", HubBuild: "f17", WorkerBuild: "f17", Status: statusPass})
		}, "cell pos-channel-http is not a cell of hub build f17, whose scope is roles hub+worker, routes native"},
		{"a TLS cell recorded", func(_ *manifest, r *results) {
			r.Cells = append(r.Cells, cellResult{Name: "pos-channel-tls", HubBuild: "f17", WorkerBuild: "f17", Status: statusPass})
		}, "cell pos-channel-tls is not a cell of hub build f17"},
		{"a channel cell recorded as not run", func(_ *manifest, r *results) {
			r.Cells = append(r.Cells, cellResult{Name: "pos-channel-tls", HubBuild: "f17", WorkerBuild: "f17", Status: statusNotRun})
			r.Partial = true
		}, "cell pos-channel-tls is not a cell of hub build f17"},
		{"the full hub's channel cell missing", func(_ *manifest, r *results) {
			r.Cells = slices.DeleteFunc(r.Cells, func(c cellResult) bool {
				return c.Name == "pos-channel-http" && c.HubBuild == "cprime"
			})
		}, "cell pos-channel-http missing for build cprime"},
		{"a worker-only cell missing under the native-only hub", func(_ *manifest, r *results) {
			r.Cells = slices.DeleteFunc(r.Cells, func(c cellResult) bool {
				return c.Name == "reenrol" && c.HubBuild == "f17" && c.WorkerBuild == "w18"
			})
		}, "cell reenrol missing for worker-only build w18 under hub f17"},
		{"a pair missing", func(_ *manifest, r *results) {
			r.Cells = slices.DeleteFunc(r.Cells, func(c cellResult) bool {
				return c.Name == pairCell && c.HubBuild == "cprime" && c.WorkerBuild == "f17"
			})
		}, "pair cell missing: hub cprime with worker f17"},
		{"-17's worker listing --worker.hub-url", func(_ *manifest, r *results) {
			build(r, "f17").Capability.HubURLFlag = true
		}, "the channel routes must be proven"},
		{"-17 recorded with the full scope", func(_ *manifest, r *results) {
			build(r, "f17").Scope = fullScope
		}, "build f17 ran roles hub+worker, routes native+channel+tls, the manifest's scope for it is roles hub+worker, routes native"},
		{"-17's exclusions dropped", func(_ *manifest, r *results) {
			build(r, "f17").Excluded = []string{"route channel", "route tls"}
		}, "build f17 records exclusions"},
		{"-17 declared full in the manifest", func(m *manifest, _ *results) {
			m.Builds[1].Routes = nil
		}, "the only narrowed scope listed for that version is roles hub+worker, routes native"},
		{"-17 declared worker-only in the manifest", func(m *manifest, _ *results) {
			m.Builds[1].Roles = []string{roleWorker}
		}, "the only narrowed scope listed for that version is roles hub+worker, routes native"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := testManifestR9(true)
			r := fullResults(m)
			tc.mutate(m, r)
			problems := verifyResults(m, r, false)
			require.NotEmpty(t, problems, "the verifier accepted it")
			assert.Contains(t, strings.Join(problems, "\n"), tc.want)
		})
	}
}

// A narrowed hub is started only with configuration keys its source reads:
// -17's configuration has no worker channel, and the full template, which
// has one, is refused for -17 before any cell.
func TestNativeOnlyHubConfigHoldsToItsSource(t *testing.T) {
	t.Parallel()
	_, n17, err := resolveScope(manifestBuild{Name: "f17", Version: "2.18.2-txe.17", Routes: []string{routeNative}})
	require.NoError(t, err)
	in := hubConfigInput{Scope: n17.Scope, HubPort: 1, CoordPort: 2, IssuerURL: "http://127.0.0.1:3", MachineIDs: []string{"mch_a", "mch_b"}}
	native := renderHubConfig(in)
	assert.NotContains(t, native, "worker_channel")
	require.NoError(t, checkHubConfigKeys("f17", n17, native))
	paths, err := configKeyPaths(native)
	require.NoError(t, err)
	assert.Equal(t, n17.HubConfigKeys, paths, "-17's list is exactly what the native-only template writes")

	in.Scope = fullScope
	full := renderHubConfig(in)
	assert.Contains(t, full, "worker_channel:\n    enabled: true")
	err = checkHubConfigKeys("f17", n17, full)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "coordinator.worker_channel.enabled")
	fullPaths, err := configKeyPaths(full)
	require.NoError(t, err)
	want := append(slices.Clone(paths), "coordinator.worker_channel.enabled")
	slices.Sort(want)
	assert.Equal(t, want, fullPaths, "the full template writes -17's keys and the worker channel, nothing else")

	// A full build is not held to a list; a narrowed hub without one is refused.
	require.NoError(t, checkHubConfigKeys("c", nil, full))
	bare := *n17
	bare.HubConfigKeys = nil
	err = checkHubConfigKeys("f17", &bare, native)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lists no configuration keys")
	// A worker-only entry has no hub configuration to check.
	_, n18, err := resolveScope(manifestBuild{Name: "w18", Version: "2.18.2-txe.18", Roles: []string{roleWorker}, Routes: []string{routeNative}})
	require.NoError(t, err)
	require.NoError(t, checkHubConfigKeys("w18", n18, full))
}

func TestConfigKeyPaths(t *testing.T) {
	t.Parallel()
	paths, err := configKeyPaths("a: 1\nb:\n  c: [x, y]\n  d:\n    - id: p\n      class: q\n    - id: r\n")
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b.c", "b.d[].class", "b.d[].id"}, paths)
	_, err = configKeyPaths("a:\n  - x\n  - k: v\n")
	require.Error(t, err)
	_, err = configKeyPaths("a: [")
	require.Error(t, err)
}
