// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package machineauth_test

import (
	"fmt"
	"slices"
	"strings"
)

// A build's scope is the roles it runs (hub, worker) and the routes its worker
// takes (native gRPC, the worker channel over HTTP, the channel through a TLS
// edge). Every build runs the full scope unless this file names it: a manifest
// can ask for a narrower scope only for a build whose version and source commit
// are listed in narrowedScopes, with exactly the scope listed there. The reason
// is this file's, reviewed with it; a manifest carries no reason of its own, and
// a caller cannot narrow a build that is not listed (TXE-7524).

const (
	roleHub    = "hub"
	roleWorker = "worker"

	routeNative  = "native"
	routeChannel = "channel"
	routeTLS     = "tls"
)

type buildScope struct {
	Roles  []string `json:"roles"`
	Routes []string `json:"routes"`
}

var (
	allRoles  = []string{roleHub, roleWorker}
	allRoutes = []string{routeNative, routeChannel, routeTLS}
	fullScope = buildScope{Roles: allRoles, Routes: allRoutes}
)

func (s buildScope) full() bool {
	return slices.Equal(s.Roles, allRoles) && slices.Equal(s.Routes, allRoutes)
}

func (s buildScope) hub() bool { return slices.Contains(s.Roles, roleHub) }

func (s buildScope) has(route string) bool { return slices.Contains(s.Routes, route) }

func (s buildScope) String() string {
	return fmt.Sprintf("roles %s, routes %s", strings.Join(s.Roles, "+"), strings.Join(s.Routes, "+"))
}

// A narrowed build's provenance record must be of the kind its entry lists.
const (
	// provenanceSource: a record of the controlled build of Commit from a fresh
	// clone of its tag (controlledBuilder), for Module.
	provenanceSource = "source"
	// provenanceImage: a record of the binary read out of the published image
	// index Index (index → the platform's manifest → config and layers → the
	// file, every link checked by digest), as candidate C and -19 are. Commit is
	// the source the index was built from, shown with the result; the record
	// itself names no commit, so the index digest is what binds it.
	provenanceImage = "image"
)

// narrowedScope is one build that may run with less than the full scope.
type narrowedScope struct {
	// Version is what the binary reports (dagu version) and the manifest names.
	Version string
	// Commit is the source commit of the build: the commit a source record must
	// name, and the commit an image's index was built from.
	Commit string
	// Provenance is the kind of record the build must have: provenanceSource or
	// provenanceImage.
	Provenance string
	// Module is the main module a source record's controlled build must have
	// built (source only).
	Module string
	// Index is the image index digest an image record must name (image only).
	Index string
	Scope buildScope
	// HubConfigKeys are, for a build that is a hub, every key of the hub's
	// configuration the build's own source reads, as rendered by
	// renderHubConfig (rig_test.go): one dotted path per leaf, "[]" for a list
	// of entries. The rig refuses to start the hub, before any cell, when its
	// configuration writes a key outside this list: a build older than the
	// template ignores a key it does not know rather than refusing it.
	HubConfigKeys []string
	// Reason says why, from the source: shown with every result of the build.
	Reason string
}

// narrowedScopes are the only builds a manifest may narrow. Both predate the
// worker channel, which arrived in -19 (TXE-5598 #197 the hub's channel,
// TXE-5602 #198 worker.hub_url, TXE-5665 #213 the channel check).
//
//   - txe-v2.18.2-18 is the worker the Mac runs (TXE-5506): a worker over
//     native gRPC under every hub of the manifest, never a hub, bound by a
//     source record of its tag's commit.
//   - txe-v2.18.2-17 is the hub's fallback (TXE-7523 R9, TXE-8590): the hub
//     image 2.18.2-txe.17@sha256:d625b509…. It runs as a hub and a worker, over
//     native gRPC only, bound by an image record of that index. Its source has
//     no --worker.hub-url and no coordinator.worker_channel, so a hub rolled
//     back to -17 serves native-gRPC workers only.
var narrowedScopes = []narrowedScope{
	{
		Version:    "2.18.2-txe.18",
		Commit:     "5b011eba3a30e224be14a5c81bd15cd9ab90c956",
		Provenance: provenanceSource,
		Module:     "github.com/dagucloud/dagu/v2",
		Scope:      buildScope{Roles: []string{roleWorker}, Routes: []string{routeNative}},
		Reason: "txe-v2.18.2-18 predates the worker channel (#197, #198 and #213 landed in -19): " +
			"it runs as a worker over native gRPC under every hub build, never as a hub",
	},
	{
		Version:    "2.18.2-txe.17",
		Commit:     "4d164866b07195346610588a37390a38960e5bb7",
		Provenance: provenanceImage,
		Index:      "sha256:d625b509af2a8fdbfb771c7d3dcb89b8b4a345680fcf2c2e91d62c5e66f33d9b",
		Scope:      buildScope{Roles: []string{roleHub, roleWorker}, Routes: []string{routeNative}},
		// Read from 4d164866's source: internal/cmn/config/definition.go (host,
		// port, auth, auth.builtin.initial_admin, auth.oidc, license.fork_policy,
		// coordinator), transport_auth.go (coordinator.auth: mode, hub_key_file)
		// and txe.go (txe.authn, txe.authz, an authn client's id and class).
		HubConfigKeys: []string{
			"auth.builtin.initial_admin.username",
			"auth.mode",
			"auth.oidc.allowed_domains",
			"auth.oidc.auto_signup",
			"auth.oidc.client_id",
			"auth.oidc.client_url",
			"auth.oidc.issuer",
			"auth.oidc.pkce",
			"auth.oidc.scopes",
			"coordinator.advertise",
			"coordinator.auth.mode",
			"coordinator.host",
			"coordinator.port",
			"host",
			"license.fork_policy.features",
			"port",
			"txe.authn.audience",
			"txe.authn.cli_client",
			"txe.authn.clients[].class",
			"txe.authn.clients[].id",
			"txe.authn.issuer",
			"txe.authn.jwks_url",
			"txe.authz.mode",
		},
		Reason: "txe-v2.18.2-17 predates the worker channel (#197, #198 and #213 landed in -19; its source has no " +
			"--worker.hub-url and no coordinator.worker_channel): it runs as a hub and a worker over native gRPC only, " +
			"so the channel routes are not proven for it and a hub rolled back to -17 serves native-gRPC workers only",
	},
}

// normalizeScope fills the defaults and puts the lists in their canonical
// order. It refuses an unknown or repeated role or route.
func normalizeScope(roles, routes []string) (buildScope, error) {
	pick := func(what string, given, known []string) ([]string, error) {
		if given == nil {
			return slices.Clone(known), nil
		}
		if len(given) == 0 {
			return nil, fmt.Errorf("an empty %s list", what)
		}
		var out []string
		for _, k := range known {
			n := 0
			for _, g := range given {
				if g == k {
					n++
				}
			}
			if n > 1 {
				return nil, fmt.Errorf("%s %q named twice", what, k)
			}
			if n == 1 {
				out = append(out, k)
			}
		}
		for _, g := range given {
			if !slices.Contains(known, g) {
				return nil, fmt.Errorf("unknown %s %q (known: %s)", what, g, strings.Join(known, ", "))
			}
		}
		return out, nil
	}
	ro, err := pick("role", roles, allRoles)
	if err != nil {
		return buildScope{}, err
	}
	rt, err := pick("route", routes, allRoutes)
	if err != nil {
		return buildScope{}, err
	}
	return buildScope{Roles: ro, Routes: rt}, nil
}

// resolveScope is the scope a manifest build may run with: the full scope, or
// the narrowed scope listed for its version, exactly.
func resolveScope(b manifestBuild) (buildScope, *narrowedScope, error) {
	s, err := normalizeScope(b.Roles, b.Routes)
	if err != nil {
		return buildScope{}, nil, fmt.Errorf("build %q: %w", b.Name, err)
	}
	for i := range narrowedScopes {
		n := &narrowedScopes[i]
		if n.Version != b.Version {
			continue
		}
		// A listed version runs exactly its listed scope, never the full one:
		// its source lacks what the full scope proves.
		if !slices.Equal(n.Scope.Roles, s.Roles) || !slices.Equal(n.Scope.Routes, s.Routes) {
			return buildScope{}, nil, fmt.Errorf("build %q (version %s) declares %s; the only narrowed scope listed for that version is %s",
				b.Name, b.Version, s, n.Scope)
		}
		return s, n, nil
	}
	if s.full() {
		return s, nil, nil
	}
	return buildScope{}, nil, fmt.Errorf("build %q (version %q) declares %s, but only the builds listed in narrowedScopes may run narrowed; every other build runs %s",
		b.Name, b.Version, s, fullScope)
}

// capability is what a binary says about itself before any cell runs.
type capability struct {
	// VersionOutput is dagu version's output, trimmed.
	VersionOutput string `json:"version_output"`
	// HubURLFlag says whether dagu worker --help lists --worker.hub-url, the
	// flag a worker takes the channel with.
	HubURLFlag bool `json:"hub_url_flag"`
}

// checkCapability holds a binary's own account to its declared scope and
// version. The probe only corroborates: the scope itself comes from
// narrowedScopes, never from help text, so a binary that lacks a route can
// make a full-scope build fail but can never narrow one.
func checkCapability(name, version string, s buildScope, c capability) error {
	if c.VersionOutput != version {
		return fmt.Errorf("build %s: dagu version says %q, the manifest names %q", name, c.VersionOutput, version)
	}
	channel := s.has(routeChannel) || s.has(routeTLS)
	switch {
	case channel && !c.HubURLFlag:
		return fmt.Errorf("build %s declares %s, but its worker has no --worker.hub-url: it cannot take the channel", name, s)
	case !channel && c.HubURLFlag:
		return fmt.Errorf("build %s declares %s, but its worker lists --worker.hub-url: it can take the channel, so the channel routes must be proven", name, s)
	}
	return nil
}

// workerOnlyCells are the cells a worker-only build runs under each hub build,
// on a machine of its own enrolled through its own CLI.
var workerOnlyCells = []string{
	"w-setup",           // the build's own CLI: txe login, machine create, txe enrol (worker and reviewer), txe enrol check
	"pos-native",        // a pinned run on its machine over native gRPC
	"neg-worker-start",  // it refuses to start with a reviewer credential, another machine's id or label
	"neg-worker-nocred", // without a credential it is refused and never handed a task
	"cancel",            // a run stopped through the hub is aborted on it
	"revoke-owner",      // the owner revokes it during a step: the step stops within the bound, late writes refused
	"reenrol",           // its own CLI enrols again: a new generation, the revoked one stays
}

// workerOnlyLongCells run with long=true.
var workerOnlyLongCells = []string{"stale", "revoke-issuer"}

func requiredWorkerOnlyCells(long bool) []string {
	cells := slices.Clone(workerOnlyCells)
	if long {
		cells = append(cells, workerOnlyLongCells...)
	}
	return cells
}

// excludedCells names, for a narrowed build, what it does not run compared
// with a full build: shown with the result so a reader sees the exclusion.
func excludedCells(s buildScope) []string {
	if s.full() {
		return nil
	}
	var out []string
	if !s.hub() {
		out = append(out, "every hub-side cell with this build as hub (setup, the refusal probes, pos-two-owners, pos-probe-control, pair-native as hub)")
	}
	for _, r := range allRoutes {
		if !s.has(r) {
			out = append(out, "route "+r)
		}
	}
	if s.hub() {
		required := requiredHubCells(s, true)
		var dropped []string
		for _, c := range requiredCells(true) {
			if !slices.Contains(required, c) {
				dropped = append(dropped, c)
			}
		}
		if len(dropped) > 0 {
			out = append(out, "hub cells "+strings.Join(dropped, ", "))
		}
		if routes := probeRoutes(s); len(routes) < len(probeRoutes(fullScope)) {
			out = append(out, "with this build as hub, pos-probe-control and every neg- probe run over "+strings.Join(routes, "+")+
				" only, and setup's enrol check does not take the channel")
		}
	}
	return out
}

// scopeSummary says, one line per build, what "full" covered for it: shown
// by the matrix and the gate at the end, so a narrowed build's exclusions
// are never read past.
func scopeSummary(r *results) []string {
	var lines []string
	for _, b := range r.Builds {
		if len(b.Excluded) == 0 {
			lines = append(lines, fmt.Sprintf("SCOPE %s (%s): full, %s", b.Name, b.Version, b.Scope))
			continue
		}
		lines = append(lines, fmt.Sprintf("SCOPE %s (%s): NARROWED to %s. EXCLUDED: %s. Why: %s",
			b.Name, b.Version, b.Scope, strings.Join(b.Excluded, "; "), b.ScopeReason))
	}
	return lines
}
