// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package machineauth_test is the machine-authentication release check: the
// matrix a dagu build must pass as real processes (a hub in enforce, workers, the
// CLI) against a synthetic identity provider, and the guards that keep the
// matrix complete.
//
// The light tests run everywhere and need no process: they hold the matrix to
// the transport contract (every refusal reason and every coordinator method is
// either exercised or named as not exercised, with the reason) and check the
// result verifier. The heavy test runs only when asked for by environment; see
// README.md in this directory.
package machineauth_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// refusalClass is one way a caller is refused, and how the matrix provokes it
// with the probe: a credential (or none), the worker id and label the request
// names, and the method. Each class is sent over both routes (native gRPC and
// the worker channel), and the hub's decision log must show the reason.
type refusalClass struct {
	// Name is the cell name, cell "neg-" + Name.
	Name string
	// Reason is what the hub logs.
	Reason transportauth.Reason
	// Token says which credential the probe presents: see probeTokens.
	Token string
	// Scheme is the authorization scheme; Bearer unless the class is about it.
	Scheme string
	// OtherMachine names B's id or label in the request instead of A's.
	OtherID, OtherLabel bool
	// Method is heartbeat unless the class is about a hub-only method.
	Method string
	// Note says what the class stands for.
	Note string
}

// refusalClasses are the refusals the matrix exercises. The guard below makes
// sure they, with unreachableReasons, name every reason the contract has.
var refusalClasses = []refusalClass{
	{Name: "no-credential", Reason: transportauth.ReasonNoCredential, Token: "", Note: "a call with no authorization at all"},
	{Name: "hub-scheme-with-token", Reason: transportauth.ReasonMalformed, Token: "worker-a", Scheme: "Hub", Note: "a provider token under the hub's own scheme is not a hub key: malformed, and answered as if no credential were given"},
	{Name: "garbage-token", Reason: transportauth.ReasonTokenRefused, Token: "garbage", Note: "a bearer value that is not a token is refused by the verifier"},
	{Name: "cli-token", Reason: transportauth.ReasonNotMachine, Token: "cli", Note: "a person's CLI token is not a worker's"},
	{Name: "reviewer-token", Reason: transportauth.ReasonNotMachine, Token: "reviewer-a", Note: "a reviewer-class credential is not accepted by the coordinator"},
	{Name: "other-machine-id", Reason: transportauth.ReasonWorkerID, Token: "worker-a", OtherID: true, Note: "A's credential naming B's worker id"},
	{Name: "other-machine-label", Reason: transportauth.ReasonMachineLabel, Token: "worker-a", OtherLabel: true, Note: "A's credential carrying B's txe.machine label"},
	{Name: "expired-token", Reason: transportauth.ReasonTokenRefused, Token: "expired", Note: "an access token past its exp"},
	{Name: "not-yet-valid-token", Reason: transportauth.ReasonTokenRefused, Token: "future", Note: "an access token issued ahead of the hub's clock beyond the skew"},
	{Name: "wrong-audience", Reason: transportauth.ReasonTokenRefused, Token: "audience", Note: "an access token for another audience"},
	{Name: "unknown-client", Reason: transportauth.ReasonTokenRefused, Token: "unknown-client", Note: "an access token of a client the hub does not list"},
	{Name: "long-lifetime", Reason: transportauth.ReasonTokenRefused, Token: "long", Note: "an access token living longer than the cap"},
	{Name: "other-identity-on-client", Reason: transportauth.ReasonNotEnrolled, Token: "bob-on-a", Note: "A's worker client, but another bound person's subject: no enrolment"},
	{Name: "dispatch-as-machine", Reason: transportauth.ReasonHubOnly, Token: "worker-a", Method: "dispatch", Note: "a hub-only method with a machine credential"},
	{Name: "cancel-as-machine", Reason: transportauth.ReasonHubOnly, Token: "worker-a", Method: "cancel", Note: "RequestCancel with a machine credential"},
}

// unreachableReasons are the contract's reasons the matrix does not provoke,
// each with why. A reason added to the contract must be put in one of the two
// lists before the guard passes again.
var unreachableReasons = map[transportauth.Reason]string{
	transportauth.ReasonAllowed:          "not a refusal",
	transportauth.ReasonUnknownMethod:    "every method of the service is listed (TestEveryCoordinatorMethodHasASurface); an unlisted method cannot be sent through the generated client",
	transportauth.ReasonBadHubKey:        "needs the hub's own key file to be wrong; the hub's processes share one file, exercised by transportauth's unit tests",
	transportauth.ReasonProviderDown:     "the hub refuses while its key set is unavailable; a process-level cell would need the issuer to vanish mid-run, covered by authn's unit tests",
	transportauth.ReasonExpired:          "an enrolment with an expired credential record; the store refuses it on enrolment, covered by authz's unit tests",
	transportauth.ReasonStoreUnavailable: "a broken owner store; not a protocol property",
	transportauth.ReasonNoResourceCheck:  "GetWorkspaceBundle (the scoped surface) needs a workspace bundle; its authorization is covered by transportauth's unit tests",
	transportauth.ReasonBadRequest:       "a request of the wrong type for its method; cannot be produced through the generated client",
}

// surfaceCoverage says how each surface of the contract is exercised by the
// matrix: by which cells, or why not.
var surfaceCoverage = map[transportauth.Surface]string{
	transportauth.SurfacePublic: "the health service answers the probe without a credential (cell pos-native, worker health check) and is the only public surface",
	transportauth.SurfaceWorker: "every positive cell drives the worker methods with the enrolled credential; neg-other-machine-id and neg-other-machine-label refuse them for another machine; neg-no-credential refuses them bare",
	transportauth.SurfaceScoped: "GetWorkspaceBundle: not exercised as a process (needs a workspace bundle); covered by transportauth's unit tests",
	transportauth.SurfaceHub:    "neg-dispatch-as-machine and neg-cancel-as-machine refuse a machine on hub-only methods; the hub's own processes drive them in every positive cell",
}

// positiveCells are the cells a build must pass besides the refusals.
var positiveCells = []string{
	"setup",             // the real enrolment protocol for two owners and two machines
	"pos-native",        // a pinned run over native gRPC on loopback
	"pos-channel-http",  // the same over the worker channel on HTTP loopback
	"pos-channel-tls",   // the same over the worker channel through a TLS edge with a private CA the worker trusts
	"pos-two-owners",    // A's job on A and B's on B, both workers up
	"pos-probe-control", // the probe with A's own credential, id and label is accepted on both routes
	"neg-worker-start",  // the worker binary refuses to start with a reviewer credential, another machine's id, another machine's label
	"neg-worker-nocred", // a credential-less worker is refused and never handed a task
	"cancel",            // a run stopped through the hub is aborted on the pinned worker
	"revoke-owner",      // the owner revokes the enrolment during a step: refused within seconds, the step stops within the bound, late writes refused
	"reenrol",           // enrolling again is a new generation; the revoked one stays revoked
}

// longCells need minutes each and run only with DAGU_MACHINEAUTH_LONG=1.
var longCells = []string{
	"revoke-issuer", // the provider refuses the refresh: the worker presents nothing more
	"stale",         // a frozen worker's attempt expires at the production lease threshold; its late writes are refused as stale
}

// requiredCells lists what a complete result holds for one build.
func requiredCells(long bool) []string {
	cells := append([]string{}, positiveCells...)
	for _, c := range refusalClasses {
		cells = append(cells, "neg-"+c.Name)
	}
	if long {
		cells = append(cells, longCells...)
	}
	return cells
}

// pairCell is the cell every hub×worker pair of different builds runs.
const pairCell = "pair-native"

// contractReasons reads the Reason constants from the transportauth package's
// source, so a new reason is seen here before anyone remembers to list it.
// go test runs a package's tests in the package directory, which is how the
// source is found (a trimmed build path would not do).
func contractReasons(t *testing.T) []string {
	t.Helper()
	cwd, err := os.Getwd()
	require.NoError(t, err)
	dir := filepath.Join(cwd, "..", "..", "txe", "transportauth")
	entries, err := os.ReadDir(dir)
	require.NoError(t, err, "the transportauth source is read relative to this package's directory")
	var names []string
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".go" || len(name) > 8 && name[len(name)-8:] == "_test.go" {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		require.NoError(t, err)
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				if ident, ok := vs.Type.(*ast.Ident); !ok || ident.Name != "Reason" {
					continue
				}
				for _, n := range vs.Names {
					names = append(names, n.Name)
				}
			}
		}
	}
	sort.Strings(names)
	return names
}

// reasonValues maps the contract's constant names to their values, from the
// package itself, so the source read above and the compiled contract agree.
var reasonValues = map[string]transportauth.Reason{
	"ReasonAllowed":          transportauth.ReasonAllowed,
	"ReasonUnknownMethod":    transportauth.ReasonUnknownMethod,
	"ReasonNoCredential":     transportauth.ReasonNoCredential,
	"ReasonMalformed":        transportauth.ReasonMalformed,
	"ReasonBadHubKey":        transportauth.ReasonBadHubKey,
	"ReasonTokenRefused":     transportauth.ReasonTokenRefused,
	"ReasonProviderDown":     transportauth.ReasonProviderDown,
	"ReasonNotMachine":       transportauth.ReasonNotMachine,
	"ReasonNotEnrolled":      transportauth.ReasonNotEnrolled,
	"ReasonExpired":          transportauth.ReasonExpired,
	"ReasonStoreUnavailable": transportauth.ReasonStoreUnavailable,
	"ReasonHubOnly":          transportauth.ReasonHubOnly,
	"ReasonNoResourceCheck":  transportauth.ReasonNoResourceCheck,
	"ReasonWorkerID":         transportauth.ReasonWorkerID,
	"ReasonMachineLabel":     transportauth.ReasonMachineLabel,
	"ReasonBadRequest":       transportauth.ReasonBadRequest,
}

// Every reason the contract has is either provoked by a refusal class or
// named as unreachable with why, and the matrix names no reason the contract
// lacks.
func TestMatrixNamesEveryRefusalReason(t *testing.T) {
	t.Parallel()
	names := contractReasons(t)
	require.NotEmpty(t, names)
	exercised := map[transportauth.Reason]bool{}
	for _, c := range refusalClasses {
		exercised[c.Reason] = true
	}
	for _, name := range names {
		value, known := reasonValues[name]
		require.True(t, known, "transportauth gained %s: add it to reasonValues and to refusalClasses or unreachableReasons", name)
		_, unreachable := unreachableReasons[value]
		assert.True(t, exercised[value] || unreachable, "reason %s (%q) is neither exercised nor named as unreachable", name, value)
		assert.False(t, exercised[value] && unreachable, "reason %s (%q) is both exercised and named as unreachable", name, value)
		if unreachable {
			assert.NotEmpty(t, unreachableReasons[value], "unreachable reason %s needs a note", name)
		}
	}
	for name := range reasonValues {
		assert.Contains(t, names, name, "reasonValues names %s, which transportauth no longer has", name)
	}
	seen := map[string]bool{}
	for _, c := range refusalClasses {
		assert.False(t, seen[c.Name], "refusal class %s is listed twice", c.Name)
		seen[c.Name] = true
		assert.NotEmpty(t, c.Note, "refusal class %s needs a note", c.Name)
	}
}

// Every method the coordinator serves has a surface (the contract's own rule),
// and every surface is covered by the matrix or named as not exercised.
func TestMatrixCoversEverySurface(t *testing.T) {
	t.Parallel()
	methods := []string{
		grpc_health_v1.Health_Check_FullMethodName,
		grpc_health_v1.Health_Watch_FullMethodName,
		grpc_health_v1.Health_List_FullMethodName,
	}
	desc := coordinatorv1.CoordinatorService_ServiceDesc
	for _, m := range desc.Methods {
		methods = append(methods, "/"+desc.ServiceName+"/"+m.MethodName)
	}
	for _, s := range desc.Streams {
		methods = append(methods, "/"+desc.ServiceName+"/"+s.StreamName)
	}
	surfaces := map[transportauth.Surface][]string{}
	for _, method := range methods {
		surface, ok := transportauth.SurfaceOf(method)
		require.True(t, ok, "%s has no surface in transportauth; a new method is refused to everyone until it is classified", method)
		surfaces[surface] = append(surfaces[surface], method)
	}
	for surface, members := range surfaces {
		assert.NotEmpty(t, surfaceCoverage[surface], "surface %q (%v) is not covered or named by the matrix", surface, members)
	}
	for surface := range surfaceCoverage {
		assert.Contains(t, surfaces, surface, "the matrix names surface %q, which no method has", surface)
	}
	// The hub-only probes name methods of the hub surface.
	for _, c := range refusalClasses {
		if c.Reason != transportauth.ReasonHubOnly {
			continue
		}
		full := map[string]string{"dispatch": coordinatorv1.CoordinatorService_Dispatch_FullMethodName, "cancel": coordinatorv1.CoordinatorService_RequestCancel_FullMethodName}[c.Method]
		surface, _ := transportauth.SurfaceOf(full)
		assert.Equal(t, transportauth.SurfaceHub, surface, "class %s probes %s, which is not hub-only", c.Name, full)
	}
}

// The required cell list is stable, has no repeats, and the long cells are
// extra, never a replacement.
func TestRequiredCellsAreDistinct(t *testing.T) {
	t.Parallel()
	for _, long := range []bool{false, true} {
		cells := requiredCells(long)
		seen := map[string]bool{}
		for _, c := range cells {
			assert.False(t, seen[c], "cell %s listed twice (long=%v)", c, long)
			seen[c] = true
		}
		assert.Contains(t, cells, "setup")
		assert.Contains(t, cells, "pos-channel-tls")
		assert.Equal(t, long, seen["stale"])
	}
	assert.Len(t, requiredCells(true), len(requiredCells(false))+len(longCells))
}
