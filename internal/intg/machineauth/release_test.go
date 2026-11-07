// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package machineauth_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/test"
)

// TestMachineAuthReleaseMatrix runs the matrix as real processes. It is opt-in:
//
//	DAGU_MACHINEAUTH_MATRIX=<manifest.json>  the builds to prove (see README.md)
//	DAGU_MACHINEAUTH_MATRIX=source           the current source, built by the harness
//	DAGU_MACHINEAUTH_LONG=1                  in source mode: also the long cells
//	DAGU_MACHINEAUTH_RESULTS=<dir>           in source mode: where results go
//
// Each build is run as hub and worker through every cell; with several builds,
// every ordered pair runs the pair cell. Each cell's result is recorded, and
// the results file is written whatever happens. The test fails on any failed
// cell. A cell that was not run (the long cells with long off) makes the result
// partial, which the test says in words: a partial result is a smoke, never a
// release proof — TestMachineAuthVerify refuses it.
func TestMachineAuthReleaseMatrix(t *testing.T) {
	spec := os.Getenv("DAGU_MACHINEAUTH_MATRIX")
	if spec == "" {
		t.Skip("set DAGU_MACHINEAUTH_MATRIX=<manifest.json> or =source to run the matrix as real processes")
	}
	if runtime.GOOS != "linux" {
		t.Skip("the matrix runs on Linux (the channel's TLS cell trusts its CA through SSL_CERT_FILE); cross-compile the test with go test -c and run it in a Linux container")
	}
	m, resultsDir := loadMatrixSpec(t, spec)
	require.NoError(t, checkBinaries(m), "a build's binary is not the one the manifest names")

	res := &results{Schema: resultsSchema, At: time.Now().UTC(), Long: m.Long}
	record := func(c cellResult) {
		res.Cells = append(res.Cells, c)
		mark := "PASS"
		if c.Status != statusPass {
			mark = strings.ToUpper(c.Status)
		}
		t.Logf("%-28s hub=%-8s worker=%-8s %s %s", c.Name, c.HubBuild, c.WorkerBuild, mark, truncate(c.Detail, 160))
	}
	builds := map[string]build{}
	for _, mb := range m.Builds {
		builds[mb.Name] = build{name: mb.Name, path: mb.Path, sha256: mb.SHA256}
	}
	for _, mb := range m.Builds {
		b := builds[mb.Name]
		run := newMatrixRun(t, b, record)
		res.Builds = append(res.Builds, resultBuild{Name: b.name, Path: b.path, SHA256: b.sha256, Version: run.version})
		run.cells(m.Long)
		for _, other := range m.Builds {
			if other.Name != b.name {
				run.pair(builds[other.Name])
			}
		}
		run.close()
	}
	for _, c := range res.Cells {
		if c.Status == statusNotRun {
			res.Partial = true
		}
	}
	path := filepath.Join(resultsDir, "machineauth-results-"+res.At.Format("20060102T150405Z")+".json")
	raw, err := json.MarshalIndent(res, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	t.Logf("results written to %s", path)
	var failed []string
	for _, c := range res.Cells {
		if c.Status == statusFail {
			failed = append(failed, fmt.Sprintf("%s (hub %s, worker %s): %s", c.Name, c.HubBuild, c.WorkerBuild, c.Detail))
		}
	}
	require.Empty(t, failed, "cells failed")
	if res.Partial {
		t.Logf("PARTIAL: the long cells were not run; this result is a smoke of %d build(s), not a release proof", len(res.Builds))
	} else if problems := verifyResults(m, res, true); len(problems) > 0 {
		t.Fatalf("the run passed its cells but the verifier does not hold it as a proof:\n  %s", strings.Join(problems, "\n  "))
	} else {
		t.Logf("FULL: %d build(s), %d cells, a release proof the verifier holds", len(res.Builds), len(res.Cells))
	}
}

// checkBinaries makes sure every build's binary is the one the manifest names.
func checkBinaries(m *manifest) error {
	for _, b := range m.Builds {
		got, err := fileSHA256(b.Path)
		if err != nil {
			return fmt.Errorf("build %s: %w", b.Name, err)
		}
		if got != b.SHA256 {
			return fmt.Errorf("build %s: the binary at its path has sha256 %s, the manifest says %s", b.Name, got, b.SHA256)
		}
	}
	return nil
}

// loadMatrixSpec reads the manifest, or makes one for the current source.
func loadMatrixSpec(t *testing.T, spec string) (*manifest, string) {
	t.Helper()
	if spec != "source" {
		m, err := loadManifest(spec)
		require.NoError(t, err)
		dir := m.ResultsDir
		if dir == "" {
			dir = filepath.Dir(spec)
		}
		return m, dir
	}
	helper := test.Setup(t, test.WithBuiltExecutable())
	path := helper.Config.Paths.Executable
	sum, err := fileSHA256(path)
	require.NoError(t, err)
	dir := os.Getenv("DAGU_MACHINEAUTH_RESULTS")
	if dir == "" {
		dir = t.TempDir()
	}
	return &manifest{Builds: []manifestBuild{{Name: "source", Path: path, SHA256: sum}}, Long: os.Getenv("DAGU_MACHINEAUTH_LONG") == "1"}, dir
}

// matrixRun is one build's run: its own rig, hub and store.
type matrixRun struct {
	t       *testing.T
	b       build
	r       *rig
	version string
	record  func(cellResult)
	// ok is false once setup failed; later cells are then not run.
	ok bool
}

func newMatrixRun(t *testing.T, b build, record func(cellResult)) *matrixRun {
	t.Helper()
	run := &matrixRun{t: t, b: b, r: newRig(t), record: record, ok: true}
	run.cell("setup", run.setup)
	return run
}

func (run *matrixRun) close() {
	run.r.stopAll()
}

// cell runs one cell and records it, catching the test failure as the cell's
// failure so the rest of the matrix still runs and is recorded.
func (run *matrixRun) cell(name string, body func() string) {
	run.cellAs(name, run.b, body)
}

func (run *matrixRun) cellAs(name string, worker build, body func() string) {
	c := cellResult{Name: name, HubBuild: run.b.name, WorkerBuild: worker.name}
	if !run.ok {
		c.Status, c.Detail = statusNotRun, "setup failed"
		run.record(c)
		return
	}
	run.r.markLog()
	var detail string
	passed := run.t.Run(fmt.Sprintf("%s/%s/%s", run.b.name, worker.name, name), func(t *testing.T) {
		saved := run.r.t
		run.r.t = t
		defer func() { run.r.t = saved }()
		detail = body()
	})
	c.Reasons = run.r.refusalsSinceMark()
	if passed {
		c.Status, c.Detail = statusPass, detail
	} else {
		c.Status, c.Detail = statusFail, "see the subtest output"
		if name == "setup" {
			run.ok = false
		}
	}
	run.record(c)
}

func (run *matrixRun) notRun(name, why string) {
	run.record(cellResult{Name: name, HubBuild: run.b.name, WorkerBuild: run.b.name, Status: statusNotRun, Detail: why})
}

// cells runs every cell of one build, the long ones only when asked.
func (run *matrixRun) cells(long bool) {
	run.cell("pos-native", func() string { return run.pinnedRun("a-native", run.b, "native") })
	run.cell("pos-channel-http", func() string { return run.pinnedRun("a-channel", run.b, "channel") })
	run.cell("pos-channel-tls", func() string { return run.pinnedRun("a-tls", run.b, "tls") })
	run.cell("pos-two-owners", run.twoOwners)
	run.cell("pos-probe-control", run.probeControl)
	for _, class := range refusalClasses {
		run.cell("neg-"+class.Name, func() string { return run.probeClass(class) })
	}
	run.cell("neg-worker-start", run.workerRefusesToStart)
	run.cell("neg-worker-nocred", run.workerWithoutCredential)
	run.cell("cancel", run.cancelFromHub)
	run.cell("revoke-owner", run.revokeOwner)
	run.cell("reenrol", run.reenrol)
	if !long {
		for _, name := range longCells {
			run.notRun(name, "long cells are off (manifest long=false / DAGU_MACHINEAUTH_LONG unset): a smoke, not a release proof")
		}
		return
	}
	run.cell("stale", run.staleAttempt)
	run.cell("revoke-issuer", run.revokeAtIssuer) // last: it refuses A's client at the issuer for good
}

// pair runs the pair cell: this hub with a worker of another build.
func (run *matrixRun) pair(worker build) {
	run.cellAs(pairCell, worker, func() string { return run.pinnedRun("a-"+worker.name, worker, "native") })
}

// ── setup: the real enrolment protocol ───────────────────────────────────────

func (run *matrixRun) setup() string {
	r := run.r
	t := r.t
	r.startHub(run.b)
	run.version = r.hubVersion()
	require.True(t, r.hubSaysEnforce(), "the hub did not log that it authenticates its callers in enforce mode:\n%s", r.logTail(r.hub, 20))
	r.adminLogin()
	me := r.apiOK(http.MethodGet, "/auth/me", r.tokens["admin"], nil)
	user, _ := me["user"].(map[string]any)
	require.Equal(t, "admin", user["role"], "the builtin administrator")
	cli := r.apiOK(http.MethodGet, "/txe/auth/cli", "", nil)
	require.Equal(t, cliClient, cli["client_id"], "the hub advertises the CLI client")
	require.Equal(t, r.issuer.url(), cli["issuer"])
	for _, name := range []string{"A", "B"} {
		m := r.machines[name]
		r.apiOK(http.MethodPost, "/txe/owners", r.tokens["admin"], map[string]any{"owner_id": m.owner, "display_name": "Owner " + name + " (synthetic)",
			"actor": map[string]string{"kind": "cli", "id": "machineauth-matrix"}})
		// The person: browser SSO, a binding request, the administrator's approval.
		token := r.hubSignIn(m.person)
		req := r.apiOK(http.MethodPost, "/txe/binding-requests", token, map[string]any{})
		require.Equal(t, "pending", req["state"])
		gen, _ := req["generation"].(float64)
		approved := r.apiOK(http.MethodPost, "/txe/owners/"+m.owner+"/bindings", r.tokens["admin"],
			map[string]any{"issuer": req["issuer"], "subject": req["subject"], "request_generation": int(gen)})
		require.Equal(t, "active", approved["state"], "binding of %s", m.person)
		identity := r.apiOK(http.MethodGet, "/txe/identity", token, nil)
		require.Equal(t, "bound", identity["state"])
		require.Equal(t, true, identity["is_person"])
		// The machine: machine.json first, as the installer writes it; the person's CLI signs in and records it.
		require.NoError(t, os.WriteFile(filepath.Join(m.txe(), "machine.json"),
			[]byte(fmt.Sprintf(`{"schema":1,"machine_id":%q,"owner_id":%q,"display_name":"rig-%s"}`+"\n", m.id, m.owner, name)), 0o600))
		r.cliSignIn(m, m.person, "txe", "login", "--hub", r.hubURL(), "--json")
		who := lastJSON(t, r.cli(m, "txe", "whoami", "--json"))
		hubIdentity, _ := who["hub_identity"].(map[string]any)
		require.Equal(t, "bound", hubIdentity["state"], "whoami of %s: the hub's account of the CLI sign-in (%v)", m.person, who["hub_identity_error"])
		principal, _ := hubIdentity["principal"].(map[string]any)
		require.Equal(t, "cli", principal["class"], "the CLI sign-in is a cli-class token")
		created := lastJSON(t, r.cli(m, "txe", "machine", "create", "--display-name", "rig-"+name, "--json"))
		require.Equal(t, m.id, created["machine_id"])
		require.Equal(t, m.owner, created["owner_id"])
		run.enrol(m, "worker")
		run.enrol(m, "reviewer")
		check := lastJSON(t, r.cli(m, "txe", "enrol", "check", "--json", "--hub-url", r.hubURL()))
		require.Equal(t, "SERVING", check["channel"], "enrol check through the channel")
	}
	r.writeDAG("pin-a", r.A(), `echo "pinned to A"`, "sleep 2", "echo done-a")
	r.writeDAG("pin-b", r.B(), `echo "pinned to B"`, "sleep 2", "echo done-b")
	r.writeDAG("hold-a", r.A(), "echo hold-start", "for i in $(seq 1 300); do echo tick $i; sleep 1; done", "echo hold-end")
	return fmt.Sprintf("hub %s version %s; owners, persons, machines A and B enrolled (worker and reviewer) through the issuer", run.b.name, run.version)
}

// enrol runs dagu txe enrol for class through the issuer and has the person
// approve the application. It returns the enrolment's generation.
func (run *matrixRun) enrol(m *machineHome, class string) int {
	r := run.r
	t := r.t
	client := "dagu-" + class + "-" + m.id
	args := []string{"txe", "enrol", "--client-id", client, "--json"}
	if class != "worker" {
		args = append(args, "--class", class)
	}
	view := lastJSON(t, r.cliSignIn(m, m.person, args...))
	require.Equal(t, "applied", view["state"], "enrol %s %s", m.name, class)
	require.Equal(t, client, view["client_id"])
	approved := r.apiOK(http.MethodPost, "/txe/machines/"+m.id+"/enrolments", r.tokens[m.person],
		map[string]any{"class": class, "client_id": client, "issuer": view["issuer"], "subject": view["subject"]})
	require.Equal(t, "active", approved["state"], "approval of %s %s", m.name, class)
	gen, _ := approved["generation"].(float64)
	info, err := os.Stat(m.credential(class))
	require.NoError(t, err, "the credential file the enrolment wrote")
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the credential file is owner-only")
	return int(gen)
}

// ── positive cells ───────────────────────────────────────────────────────────

// pinnedRun starts a worker of build b for machine A over route and runs A's
// pinned job on it.
func (run *matrixRun) pinnedRun(name string, b build, route string) string {
	r := run.r
	t := r.t
	before := r.issuer.refreshes(r.workerClient(r.A()))
	w := r.startWorker(name, b, r.A(), route, workerOptions{})
	defer r.stop(w, 10*time.Second)
	require.True(t, r.workerHealthy(r.A().id, 30*time.Second), "worker %s not healthy:\n%s", name, r.logTail(w, 15))
	id := r.enqueue("pin-a")
	s := r.waitRun("pin-a", id, 120*time.Second)
	require.Equal(t, "succeeded", s.status, "pin-a %s: %+v\n%s", id, s, r.logTail(w, 15))
	require.Equal(t, r.A().id, s.worker, "pin-a ran on another worker")
	renewed := r.issuer.refreshes(r.workerClient(r.A())) - before
	require.Positive(t, renewed, "the worker renewed its access token at the issuer")
	return fmt.Sprintf("run %s succeeded on %s over %s; %d issuer renewal(s)", id, s.worker, route, renewed)
}

func (run *matrixRun) twoOwners() string {
	r := run.r
	t := r.t
	wa := r.startWorker("a-both", run.b, r.A(), "native", workerOptions{})
	defer r.stop(wa, 10*time.Second)
	wb := r.startWorker("b-both", run.b, r.B(), "native", workerOptions{})
	defer r.stop(wb, 10*time.Second)
	require.True(t, r.workerHealthy(r.A().id, 30*time.Second) && r.workerHealthy(r.B().id, 30*time.Second), "both workers healthy")
	ra, rb := r.enqueue("pin-a"), r.enqueue("pin-b")
	sa, sb := r.waitRun("pin-a", ra, 120*time.Second), r.waitRun("pin-b", rb, 120*time.Second)
	require.Equal(t, "succeeded", sa.status, "pin-a: %+v", sa)
	require.Equal(t, "succeeded", sb.status, "pin-b: %+v", sb)
	require.Equal(t, r.A().id, sa.worker, "A's job went to %s", sa.worker)
	require.Equal(t, r.B().id, sb.worker, "B's job went to %s", sb.worker)
	return "A's run on A, B's run on B"
}

// ── the probe ────────────────────────────────────────────────────────────────

// probeToken is the credential a refusal class presents.
func (run *matrixRun) probeToken(kind string) string {
	r := run.r
	t := r.t
	a := r.A()
	mint := func(client, person string, o mintOptions) string {
		tok, err := r.issuer.accessToken(client, person, o)
		require.NoError(t, err)
		return tok
	}
	switch kind {
	case "":
		return ""
	case "worker-a":
		return mint(r.workerClient(a), a.person, mintOptions{})
	case "cli":
		return mint(cliClient, a.person, mintOptions{})
	case "reviewer-a":
		return mint("dagu-reviewer-"+a.id, a.person, mintOptions{})
	case "expired":
		return mint(r.workerClient(a), a.person, mintOptions{lifetime: 60 * time.Second, iatShift: -120 * time.Second})
	case "future":
		return mint(r.workerClient(a), a.person, mintOptions{lifetime: 60 * time.Second, iatShift: 120 * time.Second})
	case "audience":
		return mint(r.workerClient(a), a.person, mintOptions{audience: "someone-else"})
	case "unknown-client":
		return mint("dagu-worker-mch_UNKNOWN", a.person, mintOptions{})
	case "long":
		return mint(r.workerClient(a), a.person, mintOptions{lifetime: time.Hour})
	case "bob-on-a":
		return mint(r.workerClient(a), r.B().person, mintOptions{})
	case "garbage":
		return "not-a-jwt"
	}
	t.Fatalf("probe token %q", kind)
	return ""
}

// probeControl: the probe with A's own credential, id and label is accepted on
// both routes, so a refusal below is the class's doing.
func (run *matrixRun) probeControl() string {
	r := run.r
	t := r.t
	token := run.probeToken("worker-a")
	code, msg := r.probeCall("grpc", "heartbeat", token, "", r.A().id, r.A().id)
	require.Equal(t, "OK", code, "gRPC heartbeat with A's credential: %s", msg)
	code, msg = r.probeCall("channel", "heartbeat", token, "", r.A().id, r.A().id)
	require.Equal(t, "200", code, "channel heartbeat with A's credential: %s", msg)
	return "A's own credential accepted on both routes"
}

// probeClass sends one refusal class over both routes and requires the hub to
// refuse each and to log the class's reason once per route.
func (run *matrixRun) probeClass(class refusalClass) string {
	r := run.r
	t := r.t
	id, label := r.A().id, r.A().id
	if class.OtherID {
		id = r.B().id
	}
	if class.OtherLabel {
		label = r.B().id
	}
	token := run.probeToken(class.Token)
	var notes []string
	for _, route := range []string{"grpc", "channel"} {
		code, msg := r.probeCall(route, class.Method, token, class.Scheme, id, label)
		if route == "grpc" {
			require.NotEqual(t, "OK", code, "%s over gRPC was accepted", class.Name)
		} else {
			require.NotEqual(t, "200", code, "%s over the channel was accepted", class.Name)
		}
		notes = append(notes, fmt.Sprintf("%s=%s", route, code))
		_ = msg
	}
	counts := r.refusalsSinceMark()
	require.GreaterOrEqualf(t, counts[string(class.Reason)], 2, "the hub logged reason %s %d time(s) for %s (both routes); refusals since mark: %v",
		class.Reason, counts[string(class.Reason)], class.Name, counts)
	return fmt.Sprintf("%s; hub reason %s ×%d", strings.Join(notes, " "), class.Reason, counts[string(class.Reason)])
}

// ── refused workers ──────────────────────────────────────────────────────────

// workerRefusesToStart: the binary itself refuses a reviewer credential,
// another machine's worker id and another machine's label.
func (run *matrixRun) workerRefusesToStart() string {
	r := run.r
	t := r.t
	cases := map[string]workerOptions{
		"a-reviewer-cred": {credential: r.A().credential("reviewer")},
		"a-as-b":          {id: r.B().id},
		"a-label-b":       {label: r.B().id},
	}
	var notes []string
	for name, o := range cases {
		w := r.startWorker(name, run.b, r.A(), "native", o)
		select {
		case <-w.done:
			require.Error(t, w.err, "worker %s exited 0; it must refuse", name)
			tail := r.logTail(w, 3)
			require.Contains(t, tail, "Error:", "worker %s said nothing about why", name)
			notes = append(notes, name+": refused at start")
		case <-time.After(15 * time.Second):
			r.stop(w, 5*time.Second)
			t.Fatalf("worker %s kept running with a wrong credential, id or label", name)
		}
	}
	return strings.Join(notes, "; ")
}

// workerWithoutCredential: a worker that presents nothing is refused on every
// call and never handed a task.
func (run *matrixRun) workerWithoutCredential() string {
	r := run.r
	t := r.t
	w := r.startWorker("a-nocred", run.b, r.A(), "native", workerOptions{noCred: true})
	defer r.stop(w, 10*time.Second)
	id := r.enqueue("pin-a")
	time.Sleep(12 * time.Second)
	require.False(t, r.exited(w), "the credential-less worker should keep trying, not exit")
	s := r.run("pin-a", id)
	require.Equal(t, "queued", s.status, "pin-a was handed to a credential-less worker: %+v", s)
	counts := r.refusalsSinceMark()
	require.Positive(t, counts["no_credential"], "the hub logged no refusal: %v", counts)
	// Leave the queue clean for the next cell: the run is cancelled.
	r.stop(w, 10*time.Second)
	wa := r.startWorker("a-after-nocred", run.b, r.A(), "native", workerOptions{})
	defer r.stop(wa, 10*time.Second)
	final := r.waitRun("pin-a", id, 120*time.Second)
	require.Equal(t, "succeeded", final.status, "the queued run should go to the enrolled worker afterwards: %+v", final)
	return fmt.Sprintf("refused no_credential ×%d; the run stayed queued until an enrolled worker took it", counts["no_credential"])
}

// ── cancel, revocation, re-enrolment ─────────────────────────────────────────

func (run *matrixRun) cancelFromHub() string {
	r := run.r
	t := r.t
	w := r.startWorker("a-cancel", run.b, r.A(), "native", workerOptions{})
	defer r.stop(w, 10*time.Second)
	require.True(t, r.workerHealthy(r.A().id, 30*time.Second))
	id := r.enqueue("hold-a")
	require.True(t, r.waitRunning("hold-a", id, 60*time.Second), "hold-a did not start")
	time.Sleep(3 * time.Second)
	t0 := time.Now()
	code, raw := r.api(http.MethodPost, "/dag-runs/hold-a/"+id+"/stop", r.tokens["admin"], map[string]any{})
	require.Equal(t, http.StatusOK, code, "stop: %s", truncate(string(raw), 200))
	s := r.waitRun("hold-a", id, 90*time.Second)
	require.Equal(t, "aborted", s.status, "hold-a after stop: %+v", s)
	return fmt.Sprintf("aborted on %s %s after the stop", s.worker, time.Since(t0).Round(time.Second))
}

// revokeOwner: the owner revokes A's worker enrolment while a step runs. The
// hub refuses the next call, the worker stops the step within its bound, and
// every late write is refused.
func (run *matrixRun) revokeOwner() string {
	r := run.r
	t := r.t
	w := r.startWorker("a-revoke", run.b, r.A(), "native", workerOptions{})
	defer r.stop(w, 10*time.Second)
	require.True(t, r.workerHealthy(r.A().id, 30*time.Second))
	id := r.enqueue("hold-a")
	require.True(t, r.waitRunning("hold-a", id, 60*time.Second), "hold-a did not start")
	time.Sleep(3 * time.Second)
	r.markLog()
	t0 := time.Now()
	revoked := r.apiOK(http.MethodPost, "/txe/machines/"+r.A().id+"/enrolments/worker/revoke", r.tokens[r.A().person],
		map[string]any{"reason": "machineauth matrix: the owner revokes the worker while a step runs"})
	require.Equal(t, "revoked", revoked["state"])
	s := r.waitRun("hold-a", id, 150*time.Second)
	ended := time.Since(t0).Round(time.Second)
	require.True(t, terminal(s.status), "hold-a still %s %s after the revocation", s.status, ended)
	require.NotEqual(t, "succeeded", s.status, "the revoked worker's run succeeded")
	counts := r.refusalsSinceMark()
	require.Positive(t, counts["not_enrolled"], "no not_enrolled refusal logged: %v", counts)
	tail, err := os.ReadFile(w.log)
	require.NoError(t, err)
	require.Contains(t, string(tail), "refused this worker for the whole bound", "the worker did not report stopping at the bound")
	lateWrites := 0
	for reason, n := range counts {
		if reason == "not_enrolled" {
			lateWrites += n
		}
	}
	return fmt.Sprintf("run %s after %s; %d late calls refused not_enrolled; the worker stopped the step at its bound", s.status, ended, lateWrites)
}

// reenrol: enrolling the revoked machine again is a new generation of the
// machine's worker enrolment (the hub lists one standing record per class),
// and the worker runs again with the credential the new enrolment wrote.
func (run *matrixRun) reenrol() string {
	r := run.r
	t := r.t
	gen := run.enrol(r.A(), "worker")
	require.GreaterOrEqual(t, gen, 2, "the re-enrolment is a new generation")
	list := r.apiOK(http.MethodGet, "/txe/machines/"+r.A().id+"/enrolments", r.tokens[r.A().person], nil)
	items, _ := list["enrolments"].([]any)
	active := 0
	for _, item := range items {
		e, _ := item.(map[string]any)
		if e["class"] == "worker" && e["state"] == "active" {
			active++
			listed, _ := e["generation"].(float64)
			require.Equal(t, gen, int(listed), "the listed worker enrolment is the new generation")
		}
	}
	require.Equal(t, 1, active, "one active worker enrolment")
	return fmt.Sprintf("generation %d active; %s", gen, run.pinnedRun("a-reenrolled", run.b, "native"))
}

// ── long cells ───────────────────────────────────────────────────────────────

// staleAttempt: a frozen worker's attempt expires at the production lease
// threshold; its late status and streams are refused as stale.
func (run *matrixRun) staleAttempt() string {
	r := run.r
	t := r.t
	old := r.startWorker("a-old", run.b, r.A(), "native", workerOptions{id: r.A().id + "@old", maxRuns: 1})
	defer r.stop(old, 10*time.Second)
	require.True(t, r.workerHealthy(r.A().id+"@old", 30*time.Second))
	id := r.enqueue("hold-a")
	require.True(t, r.waitRunning("hold-a", id, 60*time.Second), "hold-a did not start")
	time.Sleep(3 * time.Second)
	r.freeze(old)
	frozenAt := time.Now()
	fresh := r.startWorker("a-new", run.b, r.A(), "native", workerOptions{id: r.A().id + "@new", maxRuns: 1})
	defer r.stop(fresh, 10*time.Second)
	require.True(t, r.workerHealthy(r.A().id+"@new", 30*time.Second))
	r.markLog()
	s := r.waitRun("hold-a", id, 400*time.Second)
	expiredAfter := time.Since(frozenAt).Round(time.Second)
	require.True(t, terminal(s.status), "the frozen attempt did not expire in 400 s: %+v", s)
	require.Contains(t, s.errText, "lease expired", "the run's error names the expired lease: %q", s.errText)
	r.thaw(old)
	time.Sleep(20 * time.Second)
	after := r.run("hold-a", id)
	require.Equal(t, s.status, after.status, "the thawed worker changed the run's state")
	require.Equal(t, s.finished, after.finished, "the thawed worker changed the run's end")
	stale := r.hubLinesSinceMark("stale attempt")
	require.NotEmpty(t, stale, "the hub logged no stale-attempt refusal after the thaw")
	return fmt.Sprintf("attempt expired %s after the freeze (%s); %d stale-attempt refusals after the thaw; final state unchanged", expiredAfter, s.status, len(stale))
}

// revokeAtIssuer: the provider refuses the worker's refresh; the worker ends
// and presents nothing more. Run last: A's client stays refused.
func (run *matrixRun) revokeAtIssuer() string {
	r := run.r
	t := r.t
	w := r.startWorker("a-issuer", run.b, r.A(), "native", workerOptions{})
	defer r.stop(w, 10*time.Second)
	require.True(t, r.workerHealthy(r.A().id, 30*time.Second))
	control := r.waitRun("pin-a", r.enqueue("pin-a"), 120*time.Second)
	require.Equal(t, "succeeded", control.status, "control run before the revocation")
	dropped := r.issuer.revokeClient(r.workerClient(r.A()))
	t0 := time.Now()
	deadline := t0.Add(330 * time.Second)
	noticed := false
	for time.Now().Before(deadline) {
		raw, _ := os.ReadFile(w.log)
		if strings.Contains(string(raw), "invalid_grant") || strings.Contains(string(raw), "refused this machine's credential") {
			noticed = true
			break
		}
		time.Sleep(2 * time.Second)
	}
	require.True(t, noticed, "the worker did not notice the provider's refusal within 330 s")
	noticedAfter := time.Since(t0).Round(time.Second)
	r.markLog()
	id := r.enqueue("pin-a")
	time.Sleep(45 * time.Second)
	s := r.run("pin-a", id)
	require.Equal(t, "queued", s.status, "a run was handed to a worker whose credential the provider refused: %+v", s)
	counts := r.refusalsSinceMark()
	require.Empty(t, counts, "the worker presented a token after the provider refused it: %v", counts)
	return fmt.Sprintf("%d refresh token(s) dropped; the worker noticed at its renewal %s later and presented nothing more; a new run stayed queued", dropped, noticedAfter)
}
