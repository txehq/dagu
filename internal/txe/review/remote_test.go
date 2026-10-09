// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/humantask"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dag"
	"github.com/dagucloud/dagu/v2/internal/runtime"
	apiv1 "github.com/dagucloud/dagu/v2/internal/service/frontend/api/v1"
	"github.com/dagucloud/dagu/v2/internal/txe/decision"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/review"
)

// httpTransport is a minimal review.Transport over the service's HTTP API.
type httpTransport struct {
	base string
	t    *testing.T
}

func (h httpTransport) Do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e struct {
			Message string `json:"message"`
			Details struct {
				Code string `json:"code"`
			} `json:"details"`
		}
		_ = json.Unmarshal(raw, &e)
		return &review.TransportError{Status: resp.StatusCode, Code: e.Details.Code, Message: e.Message}
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// remoteFixture is the real TXE registry and its real HTTP handlers, with one
// registered job, behind the reviewer's Remote adapter.
type remoteFixture struct {
	t      *testing.T
	store  *registry.Store
	remote *runsRemote
	jobID  string
	target apigen.TxeTarget
	fx     *effects
	opener *opener
	tasks  *taskRecorder
	// service is the fake of Dagu's run history that the registry's run
	// control and the reviewer both read.
	service *runs
	// ahead is how far the registry's clock runs ahead of real time. Tests
	// move the registry's time with it; nothing sleeps.
	ahead *time.Duration
}

// runsRemote supplies run evidence, which the real service reads from its
// run history; everything else goes to the real registry.
type runsRemote struct {
	*review.Remote
	runs []review.RunEvidence
}

func (r *runsRemote) RunsAfter(_ context.Context, _ string, cursor string) ([]review.RunEvidence, error) {
	start := 0
	for i, run := range r.runs {
		if run.RunID == cursor {
			start = i + 1
		}
	}
	return r.runs[start:], nil
}

func newRemoteFixture(t *testing.T) *remoteFixture {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	repo := persis.NewDAGRepository(dag.NewStore(filepath.Join(dir, "dags")), persis.DAGRepositoryOptions{})
	service := newRuns()
	control := &runControl{runs: service}
	ahead := new(time.Duration)
	store, err := registry.NewFileStore(filepath.Join(dir, "data"), registry.WithDAGStore(registry.NewDAGStore(repo)), registry.WithRunControl(control),
		registry.WithClock(func() time.Time { return time.Now().Add(*ahead) }))
	require.NoError(t, err)
	cfg := &config.Config{}
	cfg.Server.Permissions = map[config.Permission]bool{config.PermissionWriteDAGs: true, config.PermissionRunDAGs: true}
	a := apiv1.New(repo, nil, nil, nil, runtime.Manager{}, cfg, nil, nil, prometheus.NewRegistry(), nil, apiv1.WithTxeRegistry(store))

	router := chi.NewRouter()
	// The decision endpoint needs an authenticated person, as in production.
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := &auth.User{ID: "u-connor", Username: "connor", Role: auth.RoleAdmin}
			next.ServeHTTP(w, r.WithContext(auth.WithUser(r.Context(), user)))
		})
	})
	strict := apigen.NewStrictHandlerWithOptions(a, nil, apigen.StrictHTTPServerOptions{
		RequestErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		},
		ResponseErrorHandlerFunc: writeAPIError,
	})
	srv := httptest.NewServer(apigen.HandlerFromMux(strict, router))
	t.Cleanup(srv.Close)
	transport := httpTransport{base: srv.URL, t: t}

	mint := func(p registry.Prefix) string {
		id, err := registry.NewID(p, time.Now())
		require.NoError(t, err)
		return id
	}
	owner, machine, jobID := mint(registry.PrefixOwner), mint(registry.PrefixMachine), mint(registry.PrefixJob)
	actor := &apigen.TxeActor{Kind: apigen.TxeActorKindCli, Id: "cc5-test"}
	post := func(path string, in, out any) {
		t.Helper()
		require.NoError(t, transport.Do(ctx, http.MethodPost, path, in, out), path)
	}
	post("/txe/owners", apigen.TxeOwnerCreateRequest{OwnerId: owner, DisplayName: "Connor Wang", Actor: actor}, nil)
	post("/txe/machines", apigen.TxeMachineCreateRequest{MachineId: machine, OwnerId: owner, DisplayName: "laptop", Actor: actor}, nil)
	var project apigen.TxeProject
	post("/txe/projects", apigen.TxeProjectEnsureRequest{OwnerId: owner, Key: "fixture", Actor: actor}, &project)

	target := apigen.TxeTarget{Kind: "fixture.volume", StableId: map[string]string{"cluster_uid": "c-1", "uid": "vol-1"}}
	digest := fmt.Sprintf("sha256:%064x", 7)
	readOnly, none := apigen.TxePermittedActionIdempotency("read_only"), apigen.TxePermittedActionIdempotency("none")
	depthSchema := json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{
		"depth":{"type":"integer","minimum":1,"maximum":5},
		"ratio":{"type":"number","maximum":1},
		"verbose":{"type":"boolean"},
		"label":{"type":"string","maxLength":8}}}`)
	sizeSchema := json.RawMessage(`{"type":"object","properties":{"size_gb":{"type":"string"}}}`)
	spec := fmt.Sprintf("worker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/run.sh\n", machine)
	post("/txe/jobs", apigen.TxeRegisterRequest{
		JobId: jobID, RequestId: "r1", OwnerId: owner, ProjectId: project.ProjectId, MachineId: machine, JobKey: "volume:vol-1",
		Version: apigen.TxeJobVersionInput{
			Title: "Volume monitor", Purpose: "Watch free space on the data volume.",
			Package: apigen.TxePackage{Digest: digest, Path: dir, Entrypoint: "run.sh"},
			Dag:     apigen.TxeDAGRef{Spec: spec},
			Targets: &[]apigen.TxeTarget{target},
			ReviewPolicy: &apigen.TxeReviewPolicy{
				Brief: new("Check usage."), Cadence: new("1h"), MaxAttempts: new(2),
				PermittedActions: &[]apigen.TxePermittedAction{
					{Name: "collect_diagnostics", Routine: true, Command: new("true"), Idempotency: &readOnly, TimeoutSec: 30, ParamSchema: depthSchema},
					{Name: "expand_volume", Routine: false, Command: new("true"), Idempotency: &none, TimeoutSec: 30, ParamSchema: sizeSchema},
					{Name: "notify", Routine: true, Command: new("true"), Idempotency: &none, TimeoutSec: 30},
				},
			},
		},
		Actor: actor,
	}, nil)
	post("/txe/jobs/"+jobID+"/ready", apigen.TxeReadyRequest{
		Package: apigen.TxePackageEvidence{Digest: digest, Path: dir, MachineId: machine}, Actor: actor,
	}, nil)

	remote := &runsRemote{
		Remote: &review.Remote{
			Transport: splitTransport{runs: runsTransport{runs: service}, rest: transport},
			MachineID: machine, RunID: "tick-1", AgentClient: "fixture-agent 1.0",
		},
		runs: []review.RunEvidence{{RunID: "run-1", Status: "failed", Outputs: map[string]string{"free_pct": "12"}}},
	}
	f := &remoteFixture{t: t, store: store, remote: remote, jobID: jobID, target: target, fx: newEffects(), opener: &opener{}, tasks: &taskRecorder{}, service: service, ahead: ahead}
	control.spec = f.job().DAGSpecSHA256
	return f
}

// runControl is the registry's view of Dagu's runs in these tests: the
// same fake of the service's run API the reviewer reads and retries
// through, so both see one run history.
type runControl struct {
	runs *runs
	// spec is the digest of the DAG every run in the fake ran.
	spec string
}

func (c *runControl) ActiveRuns(context.Context, string) ([]registry.RunRef, error) { return nil, nil }
func (c *runControl) StopRun(context.Context, string, registry.RunRef) error        { return nil }
func (c *runControl) IsSuspended(context.Context, string) (bool, error)             { return false, nil }
func (c *runControl) SetSuspended(context.Context, string, bool) error              { return nil }
func (c *runControl) RunFinished(context.Context, string, registry.RunRef) (bool, error) {
	return true, nil
}

func (c *runControl) LatestAttempt(ctx context.Context, job, runID string) (registry.RunAttempt, error) {
	state, err := c.runs.RunState(ctx, job, runID)
	if err != nil {
		return registry.RunAttempt{}, registry.ErrRunNotFound
	}
	return registry.RunAttempt{
		AttemptID: state.AttemptID, QueuedAt: state.QueuedAt, SpecSHA256: c.spec, Status: state.Status,
		Finished: !state.Active, Succeeded: state.Succeeded,
	}, nil
}

func writeAPIError(w http.ResponseWriter, _ *http.Request, err error) {
	status, body := http.StatusInternalServerError, map[string]any{"message": err.Error()}
	if apiErr, ok := errors.AsType[*apiv1.Error](err); ok {
		status = apiErr.HTTPStatus
		body["code"], body["message"], body["details"] = apiErr.Code, apiErr.Message, apiErr.Details
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func (f *remoteFixture) reviewer(holder string) *review.Reviewer {
	return &review.Reviewer{
		Registry: f.remote, Effector: f.fx, Opener: f.opener, Holder: holder,
		AgentClient: "fixture-agent 1.0", DecideDAG: review.DecideDAGName(f.remote.MachineID), ClaimTTL: 10 * time.Minute,
	}
}

// targetID is the reviewer's id of the fixture job's target: the registry's
// canonical identity of it.
func (f *remoteFixture) targetID() string {
	return registry.TargetKey(registry.Target{Kind: f.target.Kind, StableID: f.target.StableId})
}

func (f *remoteFixture) job() *registry.Job {
	f.t.Helper()
	job, err := f.store.GetJob(context.Background(), f.jobID)
	require.NoError(f.t, err)
	return job
}

// The reviewer runs a whole episode against the real registry through its
// HTTP API: claim, packet from the registered version, a routine action
// granted and settled, a proposal filed, the review recorded, the checkpoint
// advanced and the claim released. A replay does nothing.
func TestRemoteReviewEpisodeAgainstTheRealRegistry(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	targetID := f.targetID()

	due, err := f.remote.DueJobs(ctx, f.remote.MachineID, time.Now().Add(time.Minute))
	require.NoError(t, err)
	require.Equal(t, []string{f.jobID}, due)

	prepared, err := f.reviewer("reviewer-a").Prepare(ctx, f.jobID)
	require.NoError(t, err)
	require.Empty(t, prepared.Skipped)
	packet := prepared.Packet
	assert.Equal(t, "Watch free space on the data volume.", packet.Job.Purpose)
	require.Len(t, packet.Job.Targets, 1)
	assert.Equal(t, targetID, packet.Job.Targets[0].StableID)
	require.Len(t, packet.Job.Review.Actions, 3)
	assert.Equal(t, []string{"size_gb"}, packet.Job.Review.Actions[1].Params)
	assert.Equal(t, 3600, packet.Job.Review.CadenceSec)
	assert.Equal(t, []string{"run-1"}, packet.RunIDs())

	// A second reviewer cannot claim the job meanwhile.
	other, err := f.reviewer("reviewer-b").Prepare(ctx, f.jobID)
	require.NoError(t, err)
	assert.Equal(t, review.SkipClaimHeld, other.Skipped)

	decision := review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "run-1 failed; collect and grow.", EvidenceRunIDs: []string{"run-1"},
		Actions: []review.AgentAction{
			{Name: "collect_diagnostics", TargetID: targetID, Reason: "diagnose"},
			{Name: "expand_volume", TargetID: targetID, Params: map[string]string{"size_gb": "200"}, Reason: "grow"},
			{Name: "delete_volume", TargetID: targetID, Reason: "undeclared"},
		},
	}
	applied, err := f.reviewer("reviewer-a").Apply(ctx, prepared, decision)
	require.NoError(t, err)
	require.Len(t, applied.Executed, 1)
	assert.Equal(t, review.ActionSucceeded, applied.Executed[0].State)
	assert.Equal(t, 1, f.fx.count("collect_diagnostics"))
	assert.Equal(t, 0, f.fx.count("expand_volume"))
	assert.Len(t, applied.Proposals, 2)

	job := f.job()
	assert.Equal(t, 1, job.Checkpoint.Version)
	assert.Equal(t, "run-1", job.Checkpoint.RunCursor)
	require.NotNil(t, job.Claim)
	assert.Equal(t, registry.ClaimReleased, job.Claim.State, "the claim is released")
	assert.Len(t, job.Proposals, 2)
	assert.Equal(t, review.LifecycleActive, review.Lifecycle(job.Lifecycle))

	stored, err := f.remote.Review(ctx, f.jobID, packet.ReviewID)
	require.NoError(t, err)
	assert.Equal(t, []string{"run-1"}, stored.CoveredRuns)
	assert.Equal(t, review.OutcomeAct, stored.Outcome)

	actions, err := f.remote.Actions(ctx, f.jobID)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, review.ActionSucceeded, actions[0].State)
	assert.Equal(t, "receipt-collect_diagnostics", actions[0].Receipt)
	assert.Equal(t, targetID, actions[0].TargetID)

	open, err := f.remote.OpenProposals(ctx, f.jobID)
	require.NoError(t, err)
	require.Len(t, open, 2)
	kinds := map[review.ProposalKind]int{}
	for _, p := range open {
		kinds[p.Kind]++
		assert.Equal(t, 1, f.opener.opened[p.NativeTask.RunID])
	}
	assert.Equal(t, map[review.ProposalKind]int{review.ProposalAction: 1, review.ProposalQuestion: 1}, kinds)

	// A replayed completion of the same episode does nothing.
	replay, err := f.reviewer("reviewer-a").Apply(ctx, prepared, decision)
	require.NoError(t, err)
	assert.True(t, replay.Replayed)
	assert.Equal(t, 1, f.fx.count("collect_diagnostics"))

	// Nothing is due right after the review.
	due, err = f.remote.DueJobs(ctx, f.remote.MachineID, time.Now().Add(time.Minute))
	require.NoError(t, err)
	assert.Empty(t, due)
}

// A reviewer that crashes after the effect leaves the action in flight in
// the real registry. The next holder cannot be granted the same action, and
// a late write under the dead claim is refused as stale.
func TestRemoteCrashLeavesTheActionInFlight(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	targetID := f.targetID()
	prepared, err := f.reviewer("reviewer-a").Prepare(ctx, f.jobID)
	require.NoError(t, err)

	action, err := f.remote.BeginAction(ctx, review.BeginRequest{
		Claim: prepared.Claim, JobVersion: 1, Name: "collect_diagnostics", TargetID: targetID,
		ReviewID: prepared.Packet.ReviewID, Timeout: 30 * time.Second,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, action.GrantID)
	assert.False(t, action.GrantExpiresAt.IsZero())

	// The same action cannot be granted twice.
	again, err := f.remote.BeginAction(ctx, review.BeginRequest{
		Claim: prepared.Claim, JobVersion: 1, Name: "collect_diagnostics", TargetID: targetID,
		ReviewID: prepared.Packet.ReviewID, Timeout: 30 * time.Second,
	})
	require.ErrorIs(t, err, review.ErrActionExists)
	assert.Equal(t, action.ID, again.ID)

	// An undeclared action is refused by the registry's own guard.
	_, err = f.remote.BeginAction(ctx, review.BeginRequest{
		Claim: prepared.Claim, JobVersion: 1, Name: "delete_volume", TargetID: targetID, ReviewID: prepared.Packet.ReviewID,
	})
	var denied *review.GuardDeniedError
	require.ErrorAs(t, err, &denied)
	assert.Equal(t, review.DenyNotPermitted, denied.Reason)

	// A write under a claim that is not the job's current one is stale.
	stale := prepared.Claim
	stale.Fence++
	err = f.remote.FinishAction(ctx, review.FinishRequest{
		Claim: stale, JobID: f.jobID, ActionID: action.ID, GrantID: action.GrantID, State: review.ActionSucceeded,
	})
	require.ErrorIs(t, err, review.ErrStaleFence)

	actions, err := f.remote.Actions(ctx, f.jobID)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, review.ActionExecuting, actions[0].State)
}

// stubTransport answers GET requests from canned JSON by path prefix.
type stubTransport struct {
	t       *testing.T
	replies map[string]string
	// seq holds replies that are given once each, in order, before the
	// path falls back to replies.
	seq   map[string][]string
	calls []string
	fail  map[string]*review.TransportError
}

func (s *stubTransport) Do(_ context.Context, method, path string, _, out any) error {
	s.calls = append(s.calls, method+" "+path)
	if e, ok := s.fail[path]; ok {
		return e
	}
	raw, ok := s.replies[path]
	if queued := s.seq[path]; len(queued) > 0 {
		raw, ok, s.seq[path] = queued[0], true, queued[1:]
	}
	if !ok {
		return &review.TransportError{Status: http.StatusNotFound, Message: "no stub for " + path}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal([]byte(raw), out)
}

// Run evidence comes from the service's run history: only finished runs
// count, oldest finish first, across pages, starting after the cursor, with
// outputs attached and a run without outputs kept on its status alone.
func TestRemoteRunsAfterReadsFinishedRunsInOrder(t *testing.T) {
	job := "job_01HZX0000000000000000000AA"
	run := func(id, status, finished string) string {
		return fmt.Sprintf(`{"dagRunId":%q,"attemptId":%q,"name":%q,"statusLabel":%q,"status":0,"startedAt":"2026-10-09T10:00:00Z","finishedAt":%q,"artifactsAvailable":false,"autoRetryCount":0}`, id, "a-"+id, job, status, finished)
	}
	stub := &stubTransport{t: t, replies: map[string]string{
		"/dag-runs/" + job + "?limit=100": `{"dagRuns":[` +
			run("r3", "failed", "2026-10-09T10:03:00Z") + "," +
			run("r-running", "running", "") + "," +
			run("r1", "succeeded", "2026-10-09T10:01:00Z") + `],"nextCursor":"p2"}`,
		"/dag-runs/" + job + "?cursor=p2&limit=100": `{"dagRuns":[` +
			run("r2", "succeeded", "2026-10-09T10:02:00Z") + "," +
			run("r-queued", "queued", "") + `]}`,
		"/dag-runs/" + job + "/r2/outputs":                                 `{"metadata":{},"outputs":{"free_pct":"31"}}`,
		"/dag-runs/" + job + "/r2/spec":                                    `{"spec":"steps:\n  - name: measure\n"}`,
		"/dag-runs/" + job + "/r1":                                         `{"dagRunDetails":{"attemptId":"a-r1","statusLabel":"succeeded","finishedAt":"2026-10-09T10:01:00Z","nodes":[]}}`,
		"/dag-runs/" + job + "/r2":                                         `{"dagRunDetails":{"attemptId":"a-r2","statusLabel":"succeeded","nodes":[{"step":{"name":"measure"},"statusLabel":"succeeded"}]}}`,
		"/dag-runs/" + job + "/r3":                                         `{"dagRunDetails":{"attemptId":"a-r3","statusLabel":"failed","nodes":[{"step":{"name":"measure"},"statusLabel":"failed"}]}}`,
		"/dag-runs/" + job + "/r2/steps/measure/log?stream=stdout&tail=40": `{"content":"31"}`,
		"/dag-runs/" + job + "/r3/steps/measure/log?stream=stderr&tail=40": `{"content":"df: permission denied"}`,
	}}
	remote := &review.Remote{Transport: stub}

	// No review recorded yet: every finished run is returned, oldest first.
	stub.replies["/txe/jobs/"+job+"/reviews"] = `{"reviews":[]}`
	all, err := remote.RunsAfter(context.Background(), job, "")
	require.NoError(t, err)
	require.Len(t, all, 3)
	assert.Equal(t, "r1", all[0].RunID)

	// A recorded review covered r1's execution. An older review that
	// names runs but no executions covers nothing: r2 and r3 are still new.
	stub.replies["/txe/jobs/"+job+"/reviews"] = `{"reviews":[` +
		`{"review_id":"rev_2","detail":{"covered_executions":["r1@` + review.ExecutionRef("a-r1", "") + `"]}},` +
		`{"review_id":"rev_1","detail":{"covered_run_ids":["r2","r3"]}}]}`
	runs, err := remote.RunsAfter(context.Background(), job, "")
	require.NoError(t, err)
	require.Len(t, runs, 2)
	assert.Equal(t, "r2", runs[0].RunID)
	assert.Equal(t, map[string]string{"free_pct": "31"}, runs[0].Outputs)
	assert.Equal(t, "r3", runs[1].RunID)
	assert.Equal(t, "failed", runs[1].Status)
	assert.Empty(t, runs[1].Outputs, "a run with no outputs is still evidence")
	// Each step's own output is part of the evidence.
	assert.Equal(t, []review.StepEvidence{{Name: "measure", Status: "succeeded", Stdout: "31"}}, runs[0].Steps)
	assert.Equal(t, []review.StepEvidence{{Name: "measure", Status: "failed", Stderr: "df: permission denied"}}, runs[1].Steps)
	assert.False(t, runs[0].FinishedAt.IsZero())
	// A run carries the digest of the snapshot it ran, as the registry
	// computes a job's; a run whose snapshot is gone carries none.
	assert.Equal(t, fmt.Sprintf("sha256:%x", sha256.Sum256([]byte("steps:\n  - name: measure\n"))), runs[0].SpecSHA256)
	assert.Empty(t, runs[1].SpecSHA256)

	// A failure to read outputs that is not "none exist" fails the read:
	// evidence is not silently dropped.
	stub.fail = map[string]*review.TransportError{
		"/dag-runs/" + job + "/r2/outputs": {Status: http.StatusBadGateway, Message: "hub unreachable"},
	}
	_, err = remote.RunsAfter(context.Background(), job, "")
	require.ErrorContains(t, err, "outputs of run r2")

	// So does a failure to read what earlier reviews covered: without it
	// nothing can be said to be new, and nothing is returned.
	stub.fail = map[string]*review.TransportError{
		"/txe/jobs/" + job + "/reviews": {Status: http.StatusBadGateway, Message: "hub unreachable"},
	}
	got, err := remote.RunsAfter(context.Background(), job, "")
	require.ErrorContains(t, err, "earlier reviews covered")
	assert.Empty(t, got)
}

// runList is a stub of the service for one job: its run list, and the
// reviews recorded for it, which are the record of what has been covered.
type runList struct {
	job  string
	stub *stubTransport
	// reviews are the covered_executions of each recorded review.
	reviews [][]string
}

func newRunList(t *testing.T) *runList {
	l := &runList{job: "job_01HZX0000000000000000000AA", stub: &stubTransport{t: t, replies: map[string]string{}}}
	l.set()
	l.record()
	return l
}

// set replaces the listed runs; each is "id attempt status finishedAt",
// optionally followed by the time the attempt was queued.
func (l *runList) set(runs ...string) {
	l.stub.replies["/dag-runs/"+l.job+"?limit=100"] = l.page("", runs...)
}

// page is one page of the run list as the service returns it.
func (l *runList) page(next string, runs ...string) string {
	items := make([]string, 0, len(runs))
	for _, run := range runs {
		f := strings.Fields(run)
		finished := ""
		if len(f) > 3 && f[3] != "-" {
			finished = f[3]
		}
		queued := "2026-10-09T09:59:00Z"
		if len(f) > 4 {
			queued = f[4]
		}
		items = append(items, fmt.Sprintf(`{"dagRunId":%q,"attemptId":%q,"statusLabel":%q,"queuedAt":%q,"finishedAt":%q}`, f[0], f[1], f[2], queued, finished))
		l.stub.replies["/dag-runs/"+l.job+"/"+f[0]] = fmt.Sprintf(`{"dagRunDetails":{"attemptId":%q,"queuedAt":%q,"statusLabel":%q,"nodes":[]}}`, f[1], queued, f[2])
	}
	cursor := ""
	if next != "" {
		cursor = fmt.Sprintf(`,"nextCursor":%q`, next)
	}
	return `{"dagRuns":[` + strings.Join(items, ",") + `]` + cursor + `}`
}

// record adds one recorded review that covered the given results, as the
// reviewer records them, and republishes the job's reviews.
func (l *runList) record(covered ...review.RunEvidence) {
	if len(covered) > 0 {
		names := make([]string, 0, len(covered))
		for _, run := range covered {
			names = append(names, run.RunID+"@"+run.Execution().Ref())
		}
		l.reviews = append(l.reviews, names)
	}
	items := make([]string, 0, len(l.reviews))
	for i, names := range l.reviews {
		raw, err := json.Marshal(names)
		require.NoError(l.stub.t, err)
		items = append(items, fmt.Sprintf(`{"review_id":"rev_%d","detail":{"covered_executions":%s}}`, i, raw))
	}
	l.stub.replies["/txe/jobs/"+l.job+"/reviews"] = `{"reviews":[` + strings.Join(items, ",") + `]}`
}

// uncovered returns the results no recorded review covers.
func (l *runList) uncovered() []review.RunEvidence {
	l.stub.t.Helper()
	runs, err := (&review.Remote{Transport: l.stub}).RunsAfter(context.Background(), l.job, "")
	require.NoError(l.stub.t, err)
	return runs
}

// names is the results as "run@attempt", for reading in assertions.
func names(runs []review.RunEvidence) []string {
	out := make([]string, 0, len(runs))
	for _, run := range runs {
		out = append(out, run.RunID+"@"+run.AttemptID)
	}
	return out
}

// review lists the uncovered results and records a review that covered all
// of them, as one review episode does.
func (l *runList) review() []string {
	l.stub.t.Helper()
	runs := l.uncovered()
	l.record(runs...)
	return names(runs)
}

// A result is covered exactly when a recorded review names it. Listing it
// covers nothing, and neither does a review that was shown it but was not
// recorded: it is returned again until one is.
func TestRemoteRunsAfterCoversOnlyWhatARecordedReviewNames(t *testing.T) {
	l := newRunList(t)
	l.set("r1 a1 failed 2026-10-09T10:01:00Z", "r2 b1 succeeded 2026-10-09T10:02:00Z")
	assert.Equal(t, []string{"r1@a1", "r2@b1"}, names(l.uncovered()))
	assert.Equal(t, []string{"r1@a1", "r2@b1"}, names(l.uncovered()), "shown but not recorded: shown again")

	// A review that covered only the first is recorded.
	l.record(l.uncovered()[0])
	assert.Equal(t, []string{"r2@b1"}, names(l.uncovered()))
	assert.Equal(t, []string{"r2@b1"}, l.review())
	assert.Empty(t, l.uncovered())
}

// A native retry keeps the run id. On the direct path it starts a new
// attempt, on the queued path it runs the latest attempt again under a
// later queue marker. Either way the run's new execution is in no review
// and is returned again, and a run that finished between two executions is
// not passed over.
func TestRemoteRunsAfterShowsARetriedRunAgain(t *testing.T) {
	l := newRunList(t)
	l.set("r1 a1 failed 2026-10-09T10:01:00Z 2026-10-09T10:00:00Z")
	assert.Equal(t, []string{"r1@a1"}, l.review())
	assert.Empty(t, l.uncovered())

	// Direct path: a new attempt, which fails after r2 finished.
	l.set("r1 a2 failed 2026-10-09T10:05:00Z 2026-10-09T10:00:00Z", "r2 b1 succeeded 2026-10-09T10:02:00Z")
	assert.Equal(t, []string{"r2@b1", "r1@a2"}, l.review())
	assert.Empty(t, l.uncovered())

	// Queued path: the same attempt id queued again. Unfinished: nothing.
	l.set("r1 a2 queued - 2026-10-09T10:06:00Z", "r2 b1 succeeded 2026-10-09T10:02:00Z")
	assert.Empty(t, l.uncovered())
	// It ends, reporting the very end time of its earlier execution.
	l.set("r1 a2 failed 2026-10-09T10:05:00Z 2026-10-09T10:06:00Z", "r2 b1 succeeded 2026-10-09T10:02:00Z")
	again := l.uncovered()
	require.Equal(t, []string{"r1@a2"}, names(again), "the same attempt, queued again, is a new result")
	assert.Equal(t, "2026-10-09T10:06:00Z", again[0].QueuedAt)
	assert.Equal(t, review.ExecutionRef("a2", "2026-10-09T10:06:00Z"), again[0].Execution().Ref())
	l.record(again...)
	assert.Empty(t, l.uncovered(), "and it is shown once")
}

// Whether a result is covered never depends on when it ended. A result that
// is reported late, with an end time before results already covered, a
// result sharing its end time with covered ones and sorting before them,
// and a run created while the history was being listed are all in no
// review, so each is returned.
func TestRemoteRunsAfterDoesNotDependOnEndTimesOrListingOrder(t *testing.T) {
	l := newRunList(t)
	// r1 is still running when r2, which ended later, is covered.
	l.set("r1 a1 running", "r2 b1 succeeded 2026-10-09T10:05:00Z")
	assert.Equal(t, []string{"r2@b1"}, l.review())
	assert.Empty(t, l.uncovered(), "an unfinished run is not a result yet")

	// r1's result arrives with an end time before what is covered.
	l.set("r1 a1 failed 2026-10-09T10:03:00Z", "r2 b1 succeeded 2026-10-09T10:05:00Z")
	assert.Equal(t, []string{"r1@a1"}, l.review())

	// A run created later ends in the same second as a covered result and
	// sorts before it.
	l.set("a0 x1 failed 2026-10-09T10:05:00Z", "r1 a1 failed 2026-10-09T10:03:00Z", "r2 b1 succeeded 2026-10-09T10:05:00Z")
	assert.Equal(t, []string{"a0@x1"}, l.review())

	// A run that was queued when the others were covered ends with a time
	// before all of them.
	l.set("a0 x1 failed 2026-10-09T10:05:00Z", "q9 z1 queued", "r1 a1 failed 2026-10-09T10:03:00Z", "r2 b1 succeeded 2026-10-09T10:05:00Z")
	assert.Empty(t, l.uncovered())
	l.set("a0 x1 failed 2026-10-09T10:05:00Z", "q9 z1 failed 2026-10-09T10:00:00Z", "r1 a1 failed 2026-10-09T10:03:00Z", "r2 b1 succeeded 2026-10-09T10:05:00Z")
	assert.Equal(t, []string{"q9@z1"}, l.review())
	assert.Empty(t, l.uncovered())
}

// A listing of several pages is not one moment: a run can be created after
// the first page was read and end before an older run seen finished on a
// later page. The run that was never listed is in no review, so the next
// listing returns it. The clocks here are normal.
func TestRemoteRunsAfterDoesNotLoseARunCreatedBetweenPages(t *testing.T) {
	l := newRunList(t)
	first, p2 := "/dag-runs/"+l.job+"?limit=100", "/dag-runs/"+l.job+"?cursor=p2&limit=100"
	y := "y y1 succeeded 2026-10-09T10:20:00Z"
	// Page one is read before x exists; by page two, y has ended.
	l.stub.seq = map[string][]string{first: {l.page("p2", "old o1 failed 2026-10-09T10:00:00Z")}}
	l.stub.replies[p2] = l.page("", y)
	assert.Equal(t, []string{"old@o1", "y@y1"}, l.review())

	// x was created and ended in between, before y did.
	l.stub.replies[first] = l.page("p2", "x x1 failed 2026-10-09T10:15:00Z", "old o1 failed 2026-10-09T10:00:00Z")
	assert.Equal(t, []string{"x@x1"}, l.review())
	assert.Empty(t, l.uncovered())
}

// Evidence is read by run id. When the run is retried while its evidence is
// being read, the status of one execution is never paired with the output
// of another: the result is not returned, and since no review names it, the
// run's execution is met again by the next listing.
func TestRemoteRunsAfterNeverMixesTheEvidenceOfTwoExecutions(t *testing.T) {
	for name, after := range map[string]string{
		"a new attempt started":         `{"dagRunDetails":{"attemptId":"a2","queuedAt":"2026-10-09T09:59:00Z","statusLabel":"running","nodes":[]}}`,
		"the same attempt queued again": `{"dagRunDetails":{"attemptId":"a1","queuedAt":"2026-10-09T10:01:30Z","statusLabel":"queued","nodes":[]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			l := newRunList(t)
			l.set("r1 a1 failed 2026-10-09T10:01:00Z", "r2 b1 succeeded 2026-10-09T10:02:00Z")
			// r1 is retried between the first and the last read of its evidence.
			detail := "/dag-runs/" + l.job + "/r1"
			l.stub.seq = map[string][]string{detail: {
				`{"dagRunDetails":{"attemptId":"a1","queuedAt":"2026-10-09T09:59:00Z","statusLabel":"failed","nodes":[]}}`,
				after,
			}}
			assert.Equal(t, []string{"r2@b1"}, l.review())

			l.set("r1 a1 failed 2026-10-09T10:01:00Z", "r2 b1 succeeded 2026-10-09T10:02:00Z")
			assert.Equal(t, []string{"r1@a1"}, l.review(), "it is returned once its evidence can be read whole")
		})
	}
}

// Nothing in a job's history can stop its reviews. Hundreds of results in
// one instant, as when a whole queue is aborted at once, and a queue of any
// length are both read like any other history: every result is returned
// across reviews, each once, a bounded number at a time.
func TestRemoteRunsAfterIsNeverBlockedByTheShapeOfTheHistory(t *testing.T) {
	l := newRunList(t)
	runs := []string{"busy b1 running"}
	for i := range 700 {
		runs = append(runs, fmt.Sprintf("m%04d a1 aborted 2026-10-09T11:00:00Z", i))
	}
	for i := range 800 {
		runs = append(runs, fmt.Sprintf("q%04d a1 queued", i))
	}
	l.set(runs...)
	seen := map[string]bool{}
	for range 20 {
		page := l.review()
		require.LessOrEqual(t, len(page), 51, "one review is shown a bounded number of runs")
		for _, key := range page {
			require.False(t, seen[key], "%s shown twice", key)
			seen[key] = true
		}
	}
	assert.Len(t, seen, 700, "every result is returned, none twice, none refused")
	assert.Empty(t, l.uncovered())

	// A queued run that ends later is returned like any other.
	runs[701] = "q0000 a1 failed 2026-10-09T10:00:00Z"
	l.set(runs...)
	assert.Equal(t, []string{"q0000@a1"}, l.review())
}

// Coverage is by execution, so a service that reports a finished run with
// no attempt id is one this reviewer cannot run on. That is an explicit
// failure naming the run. The run is never recorded under its id alone,
// which would pass off every later retry of it as already reviewed.
func TestRemoteRunsAfterFailsOnARunTheServiceDoesNotIdentify(t *testing.T) {
	l := newRunList(t)
	l.stub.replies["/dag-runs/"+l.job+"?limit=100"] = `{"dagRuns":[` +
		`{"dagRunId":"r1","statusLabel":"failed","finishedAt":"2026-10-09T10:01:00Z"},` +
		`{"dagRunId":"r2","attemptId":"b1","statusLabel":"succeeded","finishedAt":"2026-10-09T10:02:00Z"}]}`
	runs, err := (&review.Remote{Transport: l.stub}).RunsAfter(context.Background(), l.job, "")
	require.ErrorIs(t, err, review.ErrUnidentifiedExecution)
	require.ErrorContains(t, err, "r1")
	assert.Empty(t, runs, "nothing is returned, so nothing can be covered")

	// An unfinished run without one is not a result yet and is no failure.
	l.stub.replies["/dag-runs/"+l.job+"?limit=100"] = `{"dagRuns":[{"dagRunId":"r1","statusLabel":"queued"}]}`
	runs, err = (&review.Remote{Transport: l.stub}).RunsAfter(context.Background(), l.job, "")
	require.NoError(t, err)
	assert.Empty(t, runs)
}

// The service's record of an abandoned preparation settles a question only
// for exactly the execution it names, and only when the run's records can
// be relied on. Another execution's record, such as someone else's retry of
// the same predecessor, says nothing about this one. A record the service
// does not vouch for, a service without such records, or one that cannot be
// asked, leave it unknown.
func TestRemoteAbandonedNeedsATrustedRecordOfExactlyThisExecution(t *testing.T) {
	path := "/txe/jobs/job_1/runs/run-1/abandonments"
	stub := &stubTransport{t: t, replies: map[string]string{}}
	runs := review.RemoteRuns(stub)
	mine := review.ExecutionRef("a2", "2026-10-09T12:00:00Z")
	record := func(attempt, queuedAt, outcome string) string {
		return fmt.Sprintf(`{"attempt_id":%q,"attributable":false,"outcome":%q,"abandoned_execution":{"attempt_id":%q,"queued_at":%q},"expected_execution":{"attempt_id":"a1","queued_at":""}}`, attempt, outcome, attempt, queuedAt)
	}
	list := func(entries ...string) string { return `{"abandonments":[` + strings.Join(entries, ",") + `]}` }
	for name, tc := range map[string]struct {
		reply            string
		fail             *review.TransportError
		abandoned, known bool
	}{
		"this execution, hidden":                         {reply: list(record("a2", "2026-10-09T12:00:00Z", "hidden")), abandoned: true, known: true},
		"this execution among others":                    {reply: list(record("a9", "", "hidden"), record("a2", "2026-10-09T12:00:00Z", "marked_failed")), abandoned: true, known: true},
		"no records":                                     {reply: list(), known: true},
		"another caller's retry of the same predecessor": {reply: list(record("a3", "2026-10-09T12:00:00Z", "hidden")), known: true},
		"the same attempt under another queued time":     {reply: list(record("a2", "2026-10-09T13:00:00Z", "hidden")), known: true},
		"a record the service does not vouch for":        {reply: list(`{"attempt_id":"a2","attributable":false,"error":"record unreadable"}`)},
		"an outcome this client does not know":           {reply: list(record("a2", "2026-10-09T12:00:00Z", "resurrected"))},
		"the service keeps no such records":              {fail: &review.TransportError{Status: http.StatusNotImplemented, Code: "abandonment_history_unsupported"}},
		"the service fails":                              {fail: &review.TransportError{Status: http.StatusBadGateway}},
		"not visible to this caller":                     {fail: &review.TransportError{Status: http.StatusNotFound, Code: "not_found"}},
	} {
		t.Run(name, func(t *testing.T) {
			stub.replies, stub.fail = map[string]string{path: tc.reply}, nil
			if tc.fail != nil {
				stub.replies, stub.fail = map[string]string{}, map[string]*review.TransportError{path: tc.fail}
			}
			abandoned, known := runs.Abandoned(context.Background(), "job_1", "run-1", mine)
			assert.Equal(t, tc.abandoned, abandoned)
			assert.Equal(t, tc.known, known)
		})
	}
}

// A failed run is shown to the review with what the service recorded about
// its preparation: a run the service created and never dispatched is
// labelled as such, so its failure is not read as a result of the job; when
// the service cannot say, that is stated; and a failed run with no such
// record carries no label.
func TestRemoteFailedRunEvidenceSaysWhetherItWasEverDispatched(t *testing.T) {
	path := func(l *runList, run string) string { return "/txe/jobs/" + l.job + "/runs/" + run + "/abandonments" }
	for name, tc := range map[string]struct {
		reply string
		want  string
	}{
		"abandoned before dispatch": {`{"abandonments":[{"attempt_id":"a1","attributable":false,"outcome":"marked_failed","predecessor_absent":true,"abandoned_execution":{"attempt_id":"a1","queued_at":"2026-10-09T09:59:00Z"}}]}`, review.PreparationAbandoned},
		"dispatched and failed":     {`{"abandonments":[]}`, ""},
		"the service cannot say":    {"", review.PreparationUnknown},
	} {
		t.Run(name, func(t *testing.T) {
			l := newRunList(t)
			l.set("r1 a1 failed 2026-10-09T10:01:00Z", "r2 b1 succeeded 2026-10-09T10:02:00Z")
			if tc.reply != "" {
				l.stub.replies[path(l, "r1")] = tc.reply
			}
			runs := l.uncovered()
			require.Len(t, runs, 2)
			assert.Equal(t, "r1", runs[0].RunID)
			assert.Equal(t, tc.want, runs[0].Preparation)
			assert.Empty(t, runs[1].Preparation, "only a failed run is asked about")
			assert.NotContains(t, l.stub.calls, "GET "+path(l, "r2"))
		})
	}
}

// A run that ended in the queue has no finish time and is still a result,
// ordered by the latest time the service has for it.
func TestRemoteRunsAfterKeepsRunsWithoutAFinishTime(t *testing.T) {
	l := newRunList(t)
	l.set("r2 b1 succeeded 2026-10-09T10:02:00Z", "r1 a1 rejected - 2026-10-09T10:01:00Z")
	assert.Equal(t, []string{"r1@a1", "r2@b1"}, l.review())
	assert.Empty(t, l.uncovered())
}

// runsTransport serves the part of the service's run API the adapter reads
// a run's state from, out of the fake run history.
type runsTransport struct {
	runs *runs
}

func (t runsTransport) Do(ctx context.Context, method, path string, _, out any) error {
	parts := strings.Split(strings.TrimPrefix(path, "/dag-runs/"), "/")
	if method != http.MethodGet || len(parts) != 2 {
		return &review.TransportError{Status: http.StatusNotFound, Message: "no fake for " + method + " " + path}
	}
	state, err := t.runs.RunState(ctx, parts[0], parts[1])
	if errors.Is(err, review.ErrNotFound) {
		return &review.TransportError{Status: http.StatusNotFound, Code: "not_found", Message: "run " + parts[1] + " not found"}
	}
	if err != nil {
		return &review.TransportError{Status: http.StatusBadGateway, Message: err.Error()}
	}
	raw, err := json.Marshal(map[string]any{"dagRunDetails": map[string]any{
		"attemptId": state.AttemptID, "queuedAt": state.QueuedAt, "statusLabel": state.Status,
	}})
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// splitTransport sends the service's own run API to a stub and everything
// else, the registry among it, to the real handlers.
type splitTransport struct {
	runs review.Transport
	rest review.Transport
}

func (s splitTransport) Do(ctx context.Context, method, path string, in, out any) error {
	if strings.HasPrefix(path, "/dag-runs/") {
		return s.runs.Do(ctx, method, path, in, out)
	}
	return s.rest.Do(ctx, method, path, in, out)
}

// Against the real registry: what a review covered is what its record says,
// and the next listing reads that record back. A result is returned again
// until a review that was shown it has been recorded, and a retried run's
// new execution is returned although its run id is in an earlier review.
func TestRemoteCoverageIsReadBackFromTheRegistrysReviewRecords(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	l := newRunList(t)
	l.job = f.jobID
	l.set("run-1 a1 failed 2026-10-09T10:01:00Z")
	remote := &review.Remote{
		Transport: splitTransport{runs: l.stub, rest: f.remote.Transport.(splitTransport).rest},
		MachineID: f.remote.MachineID, RunID: "tick-1", AgentClient: "fixture-agent 1.0",
	}
	reviewer := func(holder string) *review.Reviewer {
		r := f.reviewer(holder)
		r.Registry = remote
		return r
	}
	first := review.ExecutionRef("a1", "2026-10-09T09:59:00Z")

	// A reviewer is shown the result and dies before recording a review.
	// Nothing is covered: the next reviewer is shown it again.
	lost, err := reviewer("reviewer-a").Prepare(ctx, f.jobID)
	require.NoError(t, err)
	require.Equal(t, []string{"run-1"}, lost.Packet.RunIDs())
	require.NoError(t, remote.ReleaseClaim(ctx, lost.Claim))

	prepared, err := reviewer("reviewer-b").Prepare(ctx, f.jobID)
	require.NoError(t, err)
	require.Equal(t, []string{"run-1"}, prepared.Packet.RunIDs(), "shown, not recorded: shown again")
	_, err = reviewer("reviewer-b").Apply(ctx, prepared, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "it failed", EvidenceRunIDs: []string{"run-1"}})
	require.NoError(t, err)

	// The registry's own record of that review names the execution.
	stored, err := f.store.GetReview(ctx, f.jobID, prepared.Packet.ReviewID)
	require.NoError(t, err)
	assert.Contains(t, string(stored.Detail), `"covered_executions":["run-1@`+first+`"]`)
	back, err := remote.Review(ctx, f.jobID, prepared.Packet.ReviewID)
	require.NoError(t, err)
	assert.Equal(t, []string{"run-1@" + first}, back.CoveredExecutions)

	// Read back from the registry, the result is covered.
	runs, err := remote.RunsAfter(ctx, f.jobID, "")
	require.NoError(t, err)
	assert.Empty(t, runs)

	// The run is retried on the queued path: same attempt id, later queue
	// marker. It is another execution, in no review, and is shown again.
	l.set("run-1 a1 failed 2026-10-09T10:01:00Z 2026-10-09T10:00:30Z")
	again, err := reviewer("reviewer-c").Prepare(ctx, f.jobID)
	require.NoError(t, err)
	require.Equal(t, []string{"run-1"}, again.Packet.RunIDs())
	assert.Equal(t, "2026-10-09T10:00:30Z", again.Packet.NewRuns[0].QueuedAt)
	_, err = reviewer("reviewer-c").Apply(ctx, again, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "again", EvidenceRunIDs: []string{"run-1"}})
	require.NoError(t, err)
	runs, err = remote.RunsAfter(ctx, f.jobID, "")
	require.NoError(t, err)
	assert.Empty(t, runs)
}

// Opening a decision enqueues one run with the derived run id, and a
// conflict on that id means it was already opened.
func TestRemoteEnqueueTreatsConflictAsOpened(t *testing.T) {
	stub := &stubTransport{t: t, replies: map[string]string{"/dags/txe-decide-X/enqueue": `{}`}}
	enqueue := review.RemoteEnqueue(stub)
	require.NoError(t, enqueue(context.Background(), "txe-decide-X", "txe-abc", map[string]string{"PROPOSAL_ID": "prp_1", "JOB_ID": "job_A"}))
	assert.Equal(t, []string{"POST /dags/txe-decide-X/enqueue"}, stub.calls)

	stub.fail = map[string]*review.TransportError{"/dags/txe-decide-X/enqueue": {Status: http.StatusConflict}}
	require.ErrorIs(t, enqueue(context.Background(), "txe-decide-X", "txe-abc", nil), review.ErrRunExists)

	stub.fail = map[string]*review.TransportError{"/dags/txe-decide-X/enqueue": {Status: http.StatusInternalServerError, Message: `DAG "txe-decide-X" with ID "txe-abc" already exists`}}
	require.ErrorIs(t, enqueue(context.Background(), "txe-decide-X", "txe-abc", nil), review.ErrRunExists)

	stub.fail = map[string]*review.TransportError{"/dags/txe-decide-X/enqueue": {Status: http.StatusBadGateway}}
	require.Error(t, enqueue(context.Background(), "txe-decide-X", "txe-abc", nil))
}

// The native retry is sent with the execution it is for, and each of the
// service's refusals is "nothing started", never "unknown".
func TestRemoteRetryNamesTheExpectedExecution(t *testing.T) {
	path := "/dag-runs/job_1/run-1/retry"
	stub := &stubTransport{t: t, replies: map[string]string{path: `{}`}}
	var sent map[string]string
	runs := review.RemoteRuns(captureTransport{Transport: stub, path: path, into: &sent})
	queued := review.Execution{AttemptID: "a1", QueuedAt: "2026-10-09T16:36:43.039647Z"}
	admitted, err := runs.RetryRun(context.Background(), "job_1", "run-1", queued)
	require.NoError(t, err)
	assert.Equal(t, review.Execution{}, admitted, "the service's answer names no execution")

	// The execution the service names is returned only when its parts hold
	// together; anything else names none.
	next := review.Execution{AttemptID: "a2", QueuedAt: "2026-10-09T16:40:00Z"}
	for answer, want := range map[string]review.Execution{
		`{"attemptId":"a2","queuedAt":"2026-10-09T16:40:00Z","executionRef":"` + next.Ref() + `"}`:  next,
		`{"attemptId":"a3","executionRef":"` + review.ExecutionRef("a3", "") + `"}`:                 {AttemptID: "a3"},
		`{"attemptId":"a2","queuedAt":"2026-10-09T16:40:00Z","executionRef":"a2-0000000000000000"}`: {},
		`{"attemptId":"a2","queuedAt":"2026-10-09T16:40:00Z"}`:                                      {},
		`{"executionRef":"` + next.Ref() + `"}`:                                                     {},
		`[]`:                                                                                        {},
	} {
		stub.replies[path] = answer
		admitted, err := runs.RetryRun(context.Background(), "job_1", "run-1", queued)
		require.NoError(t, err, answer)
		assert.Equal(t, want, admitted, answer)
	}
	stub.replies[path] = `{}`
	assert.Equal(t, map[string]string{"dagRunId": "run-1", "expectedAttemptId": "a1", "expectedQueuedAt": "2026-10-09T16:36:43.039647Z"}, sent)

	// An execution that was never queued is named with an empty marker,
	// which is a value the service compares, not an omitted field.
	sent = nil
	_, err = runs.RetryRun(context.Background(), "job_1", "run-1", review.Execution{AttemptID: "a1"})
	require.NoError(t, err)
	marker, named := sent["expectedQueuedAt"]
	assert.True(t, named)
	assert.Empty(t, marker)

	// Only the refusals the service documents as made before anything is
	// queued or created mean "nothing started".
	for name, refusal := range map[string]*review.TransportError{
		"the run moved on, or the expected execution has not finished": {Status: http.StatusConflict, Code: "execution_changed", Message: "run is at another execution"},
		"it would run in a local process":                              {Status: http.StatusConflict, Code: "conditional_retry_unsupported", Message: "local process"},
	} {
		t.Run(name, func(t *testing.T) {
			stub.fail = map[string]*review.TransportError{path: refusal}
			_, err := runs.RetryRun(context.Background(), "job_1", "run-1", queued)
			require.ErrorIs(t, err, review.ErrRunNotRetryable)
		})
	}
	// Everything else leaves the outcome unknown: the service saying so
	// itself, a refusal this client does not recognise, and any failure of
	// the request. None of them is read as "nothing started".
	for name, failure := range map[string]*review.TransportError{
		"the service says the dispatch is uncertain":       {Status: http.StatusServiceUnavailable, Code: "dispatch_uncertain", Message: "the retry may or may not have been dispatched"},
		"a conflict with no code":                          {Status: http.StatusConflict, Message: "conflict"},
		"a conflict with a code this client does not know": {Status: http.StatusConflict, Code: "something_new", Message: "conflict"},
		"not found":      {Status: http.StatusNotFound, Message: "not found"},
		"bad request":    {Status: http.StatusBadRequest, Message: "expectedAttemptId and expectedQueuedAt go together"},
		"a server error": {Status: http.StatusBadGateway, Message: "upstream"},
	} {
		t.Run(name, func(t *testing.T) {
			stub.fail = map[string]*review.TransportError{path: failure}
			_, err := runs.RetryRun(context.Background(), "job_1", "run-1", queued)
			require.Error(t, err)
			require.NotErrorIs(t, err, review.ErrRunNotRetryable, "whether a retry started is unknown")
		})
	}
}

// Completing a human task: success, a run the service does not know, and a
// conflict. The service answers 409 both when the task was already answered
// and when it simply cannot be answered yet, so a conflict is "answered"
// only when the run shows the task's step, or the whole run, to be over.
// A run still on its way to the task is an error to try again, never a
// final outcome.
func TestRemoteCompleteReportsWhatTheServiceSaid(t *testing.T) {
	run := "/dag-runs/txe-decide-X/txe-abc"
	path := run + "/human-tasks/decide/complete"
	stub := &stubTransport{t: t, replies: map[string]string{path: `{"alreadyCompleted":false}`}}
	complete := review.RemoteComplete(stub)
	task := review.TaskLocator{DAG: "txe-decide-X", RunID: "txe-abc", StepID: "decide"}
	require.NoError(t, complete(context.Background(), task, map[string]string{"decision_id": review.NoDecisionID, "verdict": review.VerdictSuperseded}))
	assert.Equal(t, []string{"POST " + path}, stub.calls)

	stub.fail = map[string]*review.TransportError{path: {Status: http.StatusNotFound}}
	require.ErrorIs(t, complete(context.Background(), task, nil), review.ErrRunMissing)
	stub.fail = map[string]*review.TransportError{path: {Status: http.StatusBadGateway}}
	err := complete(context.Background(), task, nil)
	require.Error(t, err)
	require.NotErrorIs(t, err, review.ErrTaskAnswered)
	require.NotErrorIs(t, err, review.ErrRunMissing)

	stub.fail = map[string]*review.TransportError{path: {Status: http.StatusConflict, Message: "conflict"}}
	for name, tc := range map[string]struct {
		detail string
		want   error
		closed review.ClosureOutcome
	}{
		"completed by someone with another input": {
			detail: `{"dagRunDetails":{"statusLabel":"running","nodes":[{"step":{"name":"decide"},"statusLabel":"succeeded","humanTaskCompletedBy":"connor","humanTaskCompletedById":"u-1"}]}}`,
			want:   review.ErrTaskAnswered, closed: review.ClosureAnswered,
		},
		"completed by someone, run already over": {
			detail: `{"dagRunDetails":{"statusLabel":"succeeded","nodes":[{"step":{"name":"decide"},"statusLabel":"succeeded","humanTaskCompletedById":"os:501"}]}}`,
			want:   review.ErrTaskAnswered, closed: review.ClosureAnswered,
		},
		"run aborted before anyone answered": {
			detail: `{"dagRunDetails":{"statusLabel":"aborted","nodes":[{"step":{"name":"decide"},"statusLabel":"aborted"}]}}`,
			want:   review.ErrTaskEnded, closed: review.ClosureEnded,
		},
		"run failed before reaching the task": {
			detail: `{"dagRunDetails":{"statusLabel":"failed","nodes":[{"step":{"name":"decide"},"statusLabel":"not_started"}]}}`,
			want:   review.ErrTaskEnded, closed: review.ClosureEnded,
		},
		"step skipped: the service carries a completed task's answer into a step it skips": {
			detail: `{"dagRunDetails":{"statusLabel":"running","nodes":[{"step":{"name":"decide"},"statusLabel":"skipped"}]}}`,
			want:   review.ErrTaskOver, closed: review.ClosureOver,
		},
		"step failed with nobody on record": {
			detail: `{"dagRunDetails":{"statusLabel":"failed","nodes":[{"step":{"name":"decide"},"statusLabel":"failed"}]}}`,
			want:   review.ErrTaskOver, closed: review.ClosureOver,
		},
		"run aborted while the task was still waiting": {
			detail: `{"dagRunDetails":{"statusLabel":"aborted","nodes":[{"step":{"name":"decide"},"statusLabel":"waiting"}]}}`,
			want:   review.ErrTaskEnded, closed: review.ClosureEnded,
		},
		"step completed with nobody on record: answered or not is unknown": {
			detail: `{"dagRunDetails":{"statusLabel":"succeeded","nodes":[{"step":{"name":"decide"},"statusLabel":"succeeded"}]}}`,
			want:   review.ErrTaskOver, closed: review.ClosureOver,
		},
		"step rejected with nobody on record": {
			detail: `{"dagRunDetails":{"statusLabel":"rejected","nodes":[{"step":{"name":"decide"},"statusLabel":"rejected"}]}}`,
			want:   review.ErrTaskOver, closed: review.ClosureOver,
		},
		"the run has not reached the task yet": {
			detail: `{"dagRunDetails":{"statusLabel":"queued","nodes":[{"step":{"name":"decide"},"statusLabel":"not_started"}]}}`,
		},
		"the run is waiting but changed under the request": {
			detail: `{"dagRunDetails":{"statusLabel":"waiting","nodes":[{"step":{"name":"decide"},"statusLabel":"waiting"}]}}`,
		},
		"another step finished, not the task": {
			detail: `{"dagRunDetails":{"statusLabel":"running","nodes":[{"step":{"name":"other"},"statusLabel":"succeeded","humanTaskCompletedBy":"connor"},{"step":{"name":"decide"},"statusLabel":"running"}]}}`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			stub.replies[run] = tc.detail
			err := complete(context.Background(), task, nil)
			opener := &review.RunOpener{Complete: complete}
			outcome, closeErr := opener.CloseDecision(context.Background(), review.Proposal{NativeTask: task})
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
				require.NoError(t, closeErr)
				assert.Equal(t, tc.closed, outcome)
				return
			}
			require.Error(t, err)
			require.NotErrorIs(t, err, review.ErrTaskAnswered, "a task that cannot be answered yet was not answered")
			require.NotErrorIs(t, err, review.ErrTaskEnded, "and it has not ended")
			require.NotErrorIs(t, err, review.ErrTaskOver)
			// Closing the decision run on it is a failure to retry, not a
			// final closure.
			require.Error(t, closeErr)
			assert.Equal(t, review.ClosureFailed, outcome)
		})
	}
	t.Run("the run cannot be read", func(t *testing.T) {
		delete(stub.replies, run)
		err := complete(context.Background(), task, nil)
		require.Error(t, err)
		require.NotErrorIs(t, err, review.ErrTaskAnswered)
	})
}

// taskRecorder stands in for the service's human-task backend and records
// which native task the decision service completes, and with what.
type taskRecorder struct {
	completed []humantask.CompleteRequest
}

func (r *taskRecorder) Complete(_ context.Context, req humantask.CompleteRequest) (humantask.Result, error) {
	r.completed = append(r.completed, req)
	return humantask.Result{}, nil
}

// decide records the owner's verdict with the real decision service against
// the real registry, the way the dashboard endpoint does. Only the native
// human-task backend is replaced, because no decide run exists in this test.
func (f *remoteFixture) decide(p review.Proposal, revision int, verdict string) (*decision.Result, error) {
	svc := &decision.Service{
		Registry:          f.store,
		Tasks:             f.tasks,
		AuthorizeDecision: func(context.Context, *registry.JobTx, decision.Verdict) error { return nil },
		AuthorizeTask:     func(context.Context, string, string) error { return nil },
	}
	return svc.Decide(context.Background(), f.jobID, p.ID, decision.Request{
		BindingDigest: p.BindingDigest, ExpectedProposalRevision: revision,
		IdempotencyKey: "test-" + p.ID + "-" + verdict, Verdict: decision.Verdict(verdict),
	}, registry.Actor{Kind: registry.ActorHuman, ID: "connor"})
}

// The approve path over HTTP against the real registry and the real decision
// handler: an approved proposal is executed once under a fresh execution
// claim, a repeat does nothing, and the reviewer's next packet carries the
// owner's decisions.
func TestRemoteApprovedProposalExecutesOnce(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	targetID := f.targetID()
	prepared, err := f.reviewer("reviewer-a").Prepare(ctx, f.jobID)
	require.NoError(t, err)
	_, err = f.reviewer("reviewer-a").Apply(ctx, prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "grow", EvidenceRunIDs: []string{"run-1"},
		Actions: []review.AgentAction{
			{Name: "expand_volume", TargetID: targetID, Params: map[string]string{"size_gb": "200"}, Reason: "grow"},
			{Name: "expand_volume", TargetID: targetID, Params: map[string]string{"size_gb": "400"}, Reason: "grow more"},
		},
	})
	require.NoError(t, err)
	open, err := f.remote.OpenProposals(ctx, f.jobID)
	require.NoError(t, err)
	require.Len(t, open, 2)

	approved, err := f.decide(open[0], 1, "approve")
	require.NoError(t, err)
	rejected, err := f.decide(open[1], 1, "reject")
	require.NoError(t, err)

	// The decision service completed exactly the native task the reviewer
	// filed for each proposal.
	require.Len(t, f.tasks.completed, 2)
	for i, done := range f.tasks.completed {
		assert.Equal(t, open[i].NativeTask.RunID, done.DAGRunID)
		assert.Equal(t, review.DecideDAGName(f.remote.MachineID), done.DAGName)
	}

	exec := f.reviewer("executor")
	out, err := exec.Execute(ctx, f.jobID, open[0].ID, approved.Decision.DecisionID)
	require.NoError(t, err)
	require.Empty(t, out.Skipped)
	assert.Equal(t, review.ActionSucceeded, out.Action.State)
	assert.Equal(t, 1, f.fx.count("expand_volume"))

	// A repeat is refused by the registry: the proposal is already executed.
	out, err = exec.Execute(ctx, f.jobID, open[0].ID, approved.Decision.DecisionID)
	require.NoError(t, err)
	assert.NotEmpty(t, out.Skipped)

	out, err = exec.Execute(ctx, f.jobID, open[1].ID, rejected.Decision.DecisionID)
	require.NoError(t, err)
	assert.Equal(t, "verdict is reject", out.Skipped)

	out, err = exec.Execute(ctx, f.jobID, open[1].ID, review.NoDecisionID)
	require.NoError(t, err)
	assert.Contains(t, out.Skipped, "no recorded decision")
	assert.Equal(t, 1, f.fx.count("expand_volume"))

	actions, err := f.remote.Actions(ctx, f.jobID)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, approved.Decision.DecisionID, actions[0].DecisionID)
	assert.Equal(t, review.ActionSucceeded, actions[0].State)

	// The next review is told what the owner decided.
	decisions, err := f.remote.DecisionsAfter(ctx, f.jobID, "")
	require.NoError(t, err)
	require.Len(t, decisions, 2)
	assert.Equal(t, review.VerdictApprove, decisions[0].Verdict)
	assert.Equal(t, review.VerdictReject, decisions[1].Verdict)
	after, err := f.remote.DecisionsAfter(ctx, f.jobID, decisions[0].ID)
	require.NoError(t, err)
	require.Len(t, after, 1)
	assert.Equal(t, decisions[1].ID, after[0].ID)
}

// human is the person who decides in these tests.
var human = registry.Actor{Kind: registry.ActorHuman, ID: "connor"}

// retrying returns a reviewer that reads and retries runs through the given
// fake of the service's run API.
func (f *remoteFixture) retrying(holder string, service *runs) *review.Reviewer {
	r := f.reviewer(holder)
	r.Runs, r.RetryObserve = service, 20*time.Millisecond
	return r
}

// A retry the reviewer proposes is the registry's typed dagu.retry_run,
// bound to the snapshot the run ran and the package the reviewer saw. The
// registry accepts it only for a run of the current version, a person's
// retry verdict makes it executable, and it runs once.
func TestRemoteRetryRunIsBoundAndRunsOnce(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	job := f.job()
	f.remote.runs = []review.RunEvidence{
		{RunID: "run-1", Status: "failed", SpecSHA256: job.DAGSpecSHA256, AttemptID: "att-1"},
		{RunID: "run-old", Status: "failed", SpecSHA256: "sha256:older", AttemptID: "att-1"},
	}
	service := f.service
	service.fail("run-1", "att-1")
	prepared, err := f.retrying("reviewer-a", service).Prepare(ctx, f.jobID)
	require.NoError(t, err)
	assert.Equal(t, job.DAGSpecSHA256, prepared.Packet.Job.DAGSpecSHA256)
	_, err = f.retrying("reviewer-a", service).Apply(ctx, prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "both failed", EvidenceRunIDs: []string{"run-1", "run-old"},
		Actions: []review.AgentAction{
			{Name: review.RetryRunAction, Params: map[string]string{"run_id": "run-1"}, Reason: "transient"},
			{Name: review.RetryRunAction, Params: map[string]string{"run_id": "run-old"}, Reason: "older"},
		},
	})
	require.NoError(t, err)
	assert.Empty(t, service.retried)

	open, err := f.remote.OpenProposals(ctx, f.jobID)
	require.NoError(t, err)
	require.Len(t, open, 2)
	var retry review.Proposal
	for _, p := range open {
		if p.Kind == review.ProposalAction {
			retry = p
		} else {
			assert.Contains(t, p.Question, "run-old", "a run of an older version becomes a question, not a retry")
		}
	}
	require.NotEmpty(t, retry.ID)
	assert.Equal(t, map[string]string{
		"run_id": "run-1", "attempt_id": "att-1", "queued_at": "", "run_spec_sha256": job.DAGSpecSHA256, "package_digest": job.PackageDigest,
	}, retry.Params)
	stored := f.job().Proposals[retry.ID]
	require.NotNil(t, stored)
	assert.Equal(t, registry.ActionRetryRun, stored.Action.Name)
	assert.Nil(t, stored.Action.Target)

	// The decision service does not record a retry of a run yet, so the
	// person's verdict is written through the registry itself.
	decisionID, err := registry.NewID(registry.PrefixDecision, time.Now())
	require.NoError(t, err)
	_, err = f.store.WithJobTx(ctx, f.jobID, human, func(tx *registry.JobTx) error {
		_, err := tx.AppendDecision(registry.Decision{
			DecisionID: decisionID, ProposalID: retry.ID, ProposalRevision: 1, Verdict: registry.VerdictRetry,
			BindingDigest: retry.BindingDigest, IdempotencyKey: "retry-run-1",
		}, registry.ProposalDecided)
		return err
	})
	require.NoError(t, err)

	// The reviewer filed this proposal with a decision run, which executes
	// it; the per-tick sweep leaves it alone.
	swept, err := f.retrying("tick", service).RunRequestedRetries(ctx, f.remote.MachineID)
	require.NoError(t, err)
	assert.Empty(t, swept)

	exec := f.retrying("executor", service)
	out, err := exec.Execute(ctx, f.jobID, retry.ID, decisionID)
	require.NoError(t, err)
	require.Empty(t, out.Skipped)
	assert.Equal(t, review.ActionSucceeded, out.Action.State)
	assert.Equal(t, review.ExecutionRef("att-2", ""), out.Action.Receipt, "the receipt is the observed new execution")
	assert.Equal(t, []string{"run-1"}, service.retried)

	out, err = exec.Execute(ctx, f.jobID, retry.ID, decisionID)
	require.NoError(t, err)
	assert.NotEmpty(t, out.Skipped)
	assert.Len(t, service.retried, 1, "one retry verdict retries the run once")
	after, err := f.remote.Proposal(ctx, f.jobID, retry.ID)
	require.NoError(t, err)
	assert.Equal(t, review.ProposalState(registry.ProposalExecuted), after.State)
}

// A retry a person requests directly is already decided and has no decision
// run. The reviewer's tick executes it once, and never lists it again. The
// decision is about one failed attempt: when the retried attempt fails too,
// a fresh decision about that attempt allows one more retry, while the old
// decision, a second request for the same attempt and a request naming an
// attempt that is no longer the latest all run nothing.
func TestRemoteRequestedRetryIsExecutedByTheTick(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	job := f.job()
	service := f.service
	service.fail("run-7", "att-1")
	request := func(attempt, key string) (*registry.Proposal, *registry.Decision, error) {
		var proposal *registry.Proposal
		var decided *registry.Decision
		_, err := f.store.WithJobTx(ctx, f.jobID, human, func(tx *registry.JobTx) (err error) {
			proposal, decided, err = tx.ProposeRetry(registry.RetryRunParams{
				RunID: "run-7", AttemptID: attempt, RunSpecSHA256: job.DAGSpecSHA256, PackageDigest: job.PackageDigest,
			}, key)
			return err
		})
		return proposal, decided, err
	}
	proposal, decided, err := request("att-1", "retry-run-7")
	require.NoError(t, err)

	// A reviewer that cannot retry runs leaves the request where it is.
	none, err := f.reviewer("tick-0").RunRequestedRetries(ctx, f.remote.MachineID)
	require.NoError(t, err)
	assert.Empty(t, none)

	pending, err := f.remote.RequestedRetries(ctx, f.remote.MachineID, 10)
	require.NoError(t, err)
	assert.Equal(t, []review.RequestedRetry{{JobID: f.jobID, ProposalID: proposal.ProposalID, DecisionID: decided.DecisionID}}, pending)

	done, err := f.retrying("tick-1", service).RunRequestedRetries(ctx, f.remote.MachineID)
	require.NoError(t, err)
	require.Len(t, done, 1)
	assert.Empty(t, done[0].Error)
	assert.Empty(t, done[0].Executed.Skipped)
	assert.Equal(t, review.ActionSucceeded, done[0].Executed.Action.State)
	assert.Equal(t, review.ExecutionRef("att-2", ""), done[0].Executed.Action.Receipt, "the receipt is the new execution observed on the run")
	assert.Equal(t, []string{"run-7"}, service.retried)

	again, err := f.retrying("tick-2", service).RunRequestedRetries(ctx, f.remote.MachineID)
	require.NoError(t, err)
	assert.Empty(t, again)
	assert.Len(t, service.retried, 1)

	// While the new attempt runs, the run cannot be asked for again.
	_, _, err = request("att-2", "retry-run-7-early")
	assert.Equal(t, registry.CodeStaleBinding, registry.ErrorCode(err))

	// The retried attempt fails too. A fresh decision about that attempt
	// is a new proposal and allows exactly one more retry.
	service.fail("run-7", "att-2")
	later, laterDecision, err := request("att-2", "retry-run-7-again")
	require.NoError(t, err)
	assert.NotEqual(t, proposal.ProposalID, later.ProposalID, "each failed attempt is decided separately")
	// Replaying the first request returns nothing new and authorizes nothing.
	_, _, err = request("att-1", "retry-run-7")
	assert.Equal(t, registry.CodeDuplicate, registry.ErrorCode(err))
	// A second request for the attempt just decided is refused.
	_, _, err = request("att-2", "retry-run-7-twice")
	assert.Equal(t, registry.CodeProposalState, registry.ErrorCode(err))
	// So is one naming an attempt that is no longer the run's latest.
	_, _, err = request("att-1", "retry-run-7-stale")
	assert.Equal(t, registry.CodeStaleBinding, registry.ErrorCode(err))

	done, err = f.retrying("tick-3", service).RunRequestedRetries(ctx, f.remote.MachineID)
	require.NoError(t, err)
	require.Len(t, done, 1)
	assert.Equal(t, laterDecision.DecisionID, done[0].DecisionID)
	assert.Equal(t, review.ActionSucceeded, done[0].Executed.Action.State)
	assert.Equal(t, review.ExecutionRef("att-3", ""), done[0].Executed.Action.Receipt)
	assert.Len(t, service.retried, 2, "one retry per decided attempt")

	// The old decision, replayed against the executor, does nothing.
	out, err := f.retrying("old", service).Execute(ctx, f.jobID, proposal.ProposalID, decided.DecisionID)
	require.NoError(t, err)
	assert.NotEmpty(t, out.Skipped)
	// Nor does the later one, replayed after it ran.
	out, err = f.retrying("old", service).Execute(ctx, f.jobID, later.ProposalID, laterDecision.DecisionID)
	require.NoError(t, err)
	assert.NotEmpty(t, out.Skipped)
	assert.Len(t, service.retried, 2)

	// A request for a run of another version is refused outright.
	service.fail("run-8", "att-1")
	_, err = f.store.WithJobTx(ctx, f.jobID, human, func(tx *registry.JobTx) error {
		_, _, err := tx.ProposeRetry(registry.RetryRunParams{RunID: "run-8", AttemptID: "att-1", RunSpecSHA256: "sha256:older", PackageDigest: job.PackageDigest}, "retry-run-8")
		return err
	})
	assert.Equal(t, registry.CodeStaleBinding, registry.ErrorCode(err))
}

// On Dagu's queued path a retry runs the latest attempt again under the same
// attempt id with a later queue marker. Against the real registry: the
// decision is bound to (attempt, queued marker); the retry is recorded with
// the reference of the execution observed afterwards, which has the same
// attempt id; and when that execution fails too, a fresh decision about it
// is a different proposal and runs once, while one that still names the
// first execution of the attempt is refused.
func TestRemoteQueuedPathRetryIsBoundByTheQueueMarker(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	job := f.job()
	service := f.service
	service.fail("run-7", "att-1")
	// Every retry in this test takes the queued path.
	service.retry = func(runID string) error {
		service.requeue(runID)
		return nil
	}
	request := func(e review.Execution, key string) (*registry.Proposal, *registry.Decision, error) {
		var proposal *registry.Proposal
		var decided *registry.Decision
		_, err := f.store.WithJobTx(ctx, f.jobID, human, func(tx *registry.JobTx) (err error) {
			proposal, decided, err = tx.ProposeRetry(registry.RetryRunParams{
				RunID: "run-7", AttemptID: e.AttemptID, QueuedAt: e.QueuedAt, RunSpecSHA256: job.DAGSpecSHA256, PackageDigest: job.PackageDigest,
			}, key)
			return err
		})
		return proposal, decided, err
	}
	first := service.state["run-7"].Execution()
	require.Equal(t, review.Execution{AttemptID: "att-1"}, first, "never queued: the marker is empty, and that is a value")
	proposal, _, err := request(first, "retry-run-7-queued-1")
	require.NoError(t, err)

	done, err := f.retrying("tick-1", service).RunRequestedRetries(ctx, f.remote.MachineID)
	require.NoError(t, err)
	require.Len(t, done, 1)
	require.Empty(t, done[0].Executed.Skipped)
	assert.Equal(t, review.ActionSucceeded, done[0].Executed.Action.State)
	second := service.state["run-7"].Execution()
	assert.Equal(t, "att-1", second.AttemptID, "the queued path keeps the attempt id")
	assert.NotEmpty(t, second.QueuedAt)
	assert.Equal(t, second.Ref(), done[0].Executed.Action.Receipt, "the registry accepted the observed execution's reference as the receipt")
	assert.NotEqual(t, first.Ref(), second.Ref())
	assert.Contains(t, done[0].Executed.Action.Detail, "queued", "the record says the execution was queued, not that anything succeeded")

	// That execution fails as well.
	state := service.state["run-7"]
	state.Status, state.Active = "failed", false
	service.state["run-7"] = state

	// A decision that still names the first execution of att-1 is stale,
	// although the attempt id is the run's current one.
	_, _, err = request(first, "retry-run-7-queued-stale")
	assert.Equal(t, registry.CodeStaleBinding, registry.ErrorCode(err))
	// A fresh decision about the execution that just failed is another
	// proposal and runs exactly once.
	later, laterDecision, err := request(second, "retry-run-7-queued-2")
	require.NoError(t, err)
	assert.NotEqual(t, proposal.ProposalID, later.ProposalID)
	done, err = f.retrying("tick-2", service).RunRequestedRetries(ctx, f.remote.MachineID)
	require.NoError(t, err)
	require.Len(t, done, 1)
	assert.Equal(t, laterDecision.DecisionID, done[0].DecisionID)
	assert.Equal(t, review.ActionSucceeded, done[0].Executed.Action.State)
	third := service.state["run-7"].Execution()
	assert.Equal(t, third.Ref(), done[0].Executed.Action.Receipt)
	assert.Len(t, service.retried, 2)

	again, err := f.retrying("tick-3", service).RunRequestedRetries(ctx, f.remote.MachineID)
	require.NoError(t, err)
	assert.Empty(t, again)
	assert.Len(t, service.retried, 2)
}

// Requests that can no longer be carried out must not keep the ones that
// can from being reached. Several requests whose runs have moved on, one
// whose run is gone, and one that is still valid: the valid one is returned,
// and it is the only one.
func TestRemoteStaleRetryRequestsDoNotStarveAValidOne(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	job := f.job()
	service := f.service
	request := func(runID string) {
		t.Helper()
		service.fail(runID, "att-1")
		_, err := f.store.WithJobTx(ctx, f.jobID, human, func(tx *registry.JobTx) error {
			_, _, err := tx.ProposeRetry(registry.RetryRunParams{
				RunID: runID, AttemptID: "att-1", RunSpecSHA256: job.DAGSpecSHA256, PackageDigest: job.PackageDigest,
			}, "retry-"+runID)
			return err
		})
		require.NoError(t, err)
	}
	for i := range 8 {
		runID := fmt.Sprintf("stale-%02d", i)
		request(runID)
		// Someone else retried the run after the person decided.
		service.start(runID)
	}
	request("gone")
	delete(service.state, "gone")
	request("valid")

	pending, err := f.remote.RequestedRetries(ctx, f.remote.MachineID, 20)
	require.NoError(t, err)
	require.Len(t, pending, 1, "only a request that can still be carried out takes a place")

	// A run that cannot be read does not stop the others either: its
	// request is reported and left, and the valid one is still executed.
	request("unreadable")
	service.unreadable = map[string]error{"unreadable": errors.New("hub timeout")}
	done, err := f.retrying("tick-1", service).RunRequestedRetries(ctx, f.remote.MachineID)
	require.ErrorContains(t, err, "unreadable")
	require.ErrorContains(t, err, "left for the next tick")
	require.Len(t, done, 1)
	assert.Equal(t, review.ActionSucceeded, done[0].Executed.Action.State)
	assert.Equal(t, []string{"valid"}, service.retried)

	// Once it can be read again it is carried out, whatever the time of
	// day or the number of requests before it.
	service.unreadable = nil
	done, err = f.retrying("tick-2", service).RunRequestedRetries(ctx, f.remote.MachineID)
	require.NoError(t, err)
	require.Len(t, done, 1)
	assert.Equal(t, []string{"valid", "unreadable"}, service.retried)
}

// However many requests can never be carried out, a valid one behind all of
// them is reached in the same listing: nothing is scanned in part, and
// nothing depends on the clock. (Against a stub of the registry: the real
// one takes too long to be given hundreds of requests in a unit test.)
func TestRemoteAValidRetryBehindHundredsOfDeadOnesIsReached(t *testing.T) {
	job, machine := "job_01HZX0000000000000000000AA", "mch_1"
	stub := &stubTransport{t: t, replies: map[string]string{
		"/txe/jobs?machine=" + machine:  `{"jobs":[{"job_id":"` + job + `","lifecycle":"active","machine_id":"` + machine + `","availability":{"state":"ready"},"checkpoint":{"version":0}}]}`,
		"/txe/jobs/" + job + "/actions": `{"archived":[],"in_flight":[]}`,
	}}
	var proposals, decisions []string
	request := func(i int, runID, latestAttempt string) {
		proposals = append(proposals, fmt.Sprintf(`{"proposal_id":"prp_%04d","state":"decided","action":{"name":"dagu.retry_run","params":{"run_id":%q,"attempt_id":"a1","queued_at":""}}}`, i, runID))
		decisions = append(decisions, fmt.Sprintf(`{"decision_id":"dec_%04d","proposal_id":"prp_%04d","verdict":"retry"}`, i, i))
		stub.replies["/dag-runs/"+job+"/"+runID] = fmt.Sprintf(`{"dagRunDetails":{"attemptId":%q,"statusLabel":"failed"}}`, latestAttempt)
	}
	for i := range 450 {
		// Each of these runs was retried by someone else since.
		request(i, fmt.Sprintf("dead-%04d", i), "a2")
	}
	request(450, "valid", "a1")
	stub.replies["/txe/jobs/"+job+"/proposals"] = `{"open":[` + strings.Join(proposals, ",") + `],"finished":[]}`
	stub.replies["/txe/jobs/"+job+"/decisions?order=asc"] = `{"decisions":[` + strings.Join(decisions, ",") + `]}`

	pending, err := (&review.Remote{Transport: stub, MachineID: machine, RunID: "tick-1"}).RequestedRetries(context.Background(), machine, 20)
	require.NoError(t, err)
	assert.Equal(t, []review.RequestedRetry{{JobID: job, ProposalID: "prp_0450", DecisionID: "dec_0450"}}, pending)
}

// A registered target is named by its kind and its whole stable id. Two
// kinds with the same id, and two ids that read alike once their fields are
// joined, are different targets with different names, and an action on one
// is filed against that one.
func TestRemoteTargetsAreNeverConfusedWithEachOther(t *testing.T) {
	job := "job_01HZX0000000000000000000AA"
	targets := []apigen.TxeTarget{
		{Kind: "fixture.volume", StableId: map[string]string{"uid": "123"}},
		{Kind: "fixture.bucket", StableId: map[string]string{"uid": "123"}},
		{Kind: "fixture.volume", StableId: map[string]string{"a": "x,b=y"}},
		{Kind: "fixture.volume", StableId: map[string]string{"a": "x", "b": "y"}},
	}
	version, err := json.Marshal(map[string]any{"version": 1, "title": "t", "purpose": "p", "targets": targets,
		"package": map[string]any{"digest": "sha256:aa", "path": "/pkg", "entrypoint": "run.sh"}, "dag": map[string]any{"spec": "steps: []"}})
	require.NoError(t, err)
	stub := &stubTransport{t: t, replies: map[string]string{
		"/txe/jobs/" + job:                 `{"job_id":"` + job + `","version":1,"machine_id":"mch_1","lifecycle":"active","availability":{"state":"ready"},"checkpoint":{"version":0}}`,
		"/txe/jobs/" + job + "/versions/1": string(version),
	}}
	remote := &review.Remote{Transport: stub, MachineID: "mch_1", RunID: "tick-1"}
	got, err := remote.Job(context.Background(), job)
	require.NoError(t, err)
	require.Len(t, got.Targets, 4)
	ids := map[string]bool{}
	for i, target := range got.Targets {
		assert.False(t, ids[target.StableID], "target %d shares its id with another", i)
		ids[target.StableID] = true
		assert.Equal(t, targets[i].StableId, target.Identity, "the registered identity is kept for reading")
		assert.Equal(t, registry.TargetKey(registry.Target{Kind: targets[i].Kind, StableID: targets[i].StableId}), target.StableID)
	}

	// An action on the bucket is filed against the bucket, not the volume
	// with the same uid.
	var sent apigen.TxeProposalRequest
	capture := captureTransport{Transport: stub, path: "/txe/jobs/" + job + "/proposals", into: &sent}
	remote.Transport = capture
	stub.replies["/txe/jobs/"+job+"/proposals"] = `{"proposal_id":"prp_1","state":"open","action":{"name":"expand"}}`
	_, err = remote.CreateProposal(context.Background(), review.Claim{ID: "clm_1", JobID: job}, review.Proposal{
		ID: "prp_1", JobID: job, Kind: review.ProposalAction, ActionName: "expand", TargetID: got.Targets[1].StableID,
	})
	require.NoError(t, err)
	require.NotNil(t, sent.Proposal.Action.Target)
	assert.Equal(t, "fixture.bucket", sent.Proposal.Action.Target.Kind)
}

// captureTransport records the body of one request path.
type captureTransport struct {
	review.Transport
	path string
	into any
}

func (c captureTransport) Do(ctx context.Context, method, path string, in, out any) error {
	if path == c.path && in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(raw, c.into); err != nil {
			return err
		}
	}
	return c.Transport.Do(ctx, method, path, in, out)
}

// A retry whose dispatch was accepted but whose new attempt was not seen is
// uncertain in the real registry too, and the registry itself refuses to
// record it as succeeded on anything but the run's observed new attempt.
func TestRemoteRetryIsRecordedSucceededOnlyWithTheObservedAttempt(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	job := f.job()
	service := f.service
	service.fail("run-7", "att-1")
	var proposal *registry.Proposal
	var decided *registry.Decision
	_, err := f.store.WithJobTx(ctx, f.jobID, human, func(tx *registry.JobTx) (err error) {
		proposal, decided, err = tx.ProposeRetry(registry.RetryRunParams{
			RunID: "run-7", AttemptID: "att-1", RunSpecSHA256: job.DAGSpecSHA256, PackageDigest: job.PackageDigest,
		}, "retry-run-7")
		return err
	})
	require.NoError(t, err)

	// The service admits the request as a new attempt, which no worker
	// has taken yet.
	service.retry = func(runID string) error {
		service.state[runID] = review.RunState{AttemptID: "att-2", Status: "not_started", Active: true}
		return nil
	}
	out, err := f.retrying("tick-1", service).Execute(ctx, f.jobID, proposal.ProposalID, decided.DecisionID)
	require.NoError(t, err)
	assert.Equal(t, review.ActionUncertain, out.Action.State)
	assert.Empty(t, out.Action.Receipt)
	stored := f.job().Actions[out.Action.ID]
	require.NotNil(t, stored)
	assert.Equal(t, registry.ActionUncertain, stored.State)

	// The tick does not dispatch it again.
	again, err := f.retrying("tick-2", service).RunRequestedRetries(ctx, f.remote.MachineID)
	require.NoError(t, err)
	assert.Empty(t, again)
	assert.Len(t, service.retried, 1)

	require.Equal(t, review.ExecutionRef("att-2", ""), out.Action.AdmittedRef)
	stalled := func() (open, resolved []*registry.Exception) {
		for _, e := range f.job().Exceptions {
			if e.Kind != string(review.ExceptionRetryStalled) {
				continue
			}
			if e.ResolvedAt == nil {
				open = append(open, e)
			} else {
				resolved = append(resolved, e)
			}
		}
		return open, resolved
	}
	reviewAt := func(holder string, after time.Duration) {
		t.Helper()
		// The registry's clock moves; the half hour is measured on it. The
		// reviewer's own clock is three hours fast throughout, and that
		// changes nothing about when the exception is raised.
		*f.ahead = after
		r := f.retrying(holder, service)
		r.Now = func() time.Time { return time.Now().Add(after + 3*time.Hour) }
		prepared, err := r.Prepare(ctx, f.jobID)
		require.NoError(t, err)
		require.Empty(t, prepared.Skipped)
		_, err = r.Apply(ctx, prepared, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "waiting", EvidenceRunIDs: prepared.Packet.RunIDs()})
		require.NoError(t, err)
	}
	availability := f.job().Availability.State

	// Ten minutes on the attempt is still only reserved: a busy worker.
	// Nothing is raised, and the action stays open.
	reviewAt("reviewer-early", 10*time.Minute)
	open, _ := stalled()
	assert.Empty(t, open)

	// Past half an hour the owner is told by an exception about this
	// attempt of this action. Each review is a new process reading the
	// registry: it raises the same exception again and the registry keeps
	// one. The action stays uncertain and no question is asked.
	for i, after := range []time.Duration{2 * time.Hour, 4 * time.Hour} {
		reviewAt(fmt.Sprintf("reviewer-late-%d", i), after)
		open, _ = stalled()
		require.Len(t, open, 1)
		assert.Equal(t, registry.ScopeAction, open[0].Scope)
		assert.Equal(t, out.Action.ID, open[0].ActionID)
		assert.Contains(t, open[0].Detail, review.ExecutionRef("att-2", ""))
		job := f.job()
		assert.Equal(t, job.Actions[out.Action.ID].Attempt, open[0].Attempt)
		assert.Equal(t, registry.ActionUncertain, job.Actions[out.Action.ID].State)
		assert.Equal(t, availability, job.Availability.State, "the job's availability is untouched")
		assert.Nil(t, job.ReviewerAvailability, "and so is the reviewer's")
		for _, p := range job.Proposals {
			assert.NotEqual(t, review.UncertainEffectAction, p.Action.Name, "no question is put to the owner")
		}
	}
	assert.Len(t, service.retried, 1)

	// A worker takes it: the next review of the job sees the admitted
	// attempt running and settles the action with it. The admission the
	// reviewer journaled is what lets it recognise the attempt.
	service.state["run-7"] = review.RunState{AttemptID: "att-2", Status: "running", Active: true}
	r := f.retrying("reviewer-b", service)
	prepared, err := r.Prepare(ctx, f.jobID)
	require.NoError(t, err)
	_, err = r.Apply(ctx, prepared, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "waiting", EvidenceRunIDs: prepared.Packet.RunIDs()})
	require.NoError(t, err)
	actions, err := f.remote.Actions(ctx, f.jobID)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, review.ActionSucceeded, actions[0].State)
	assert.Equal(t, review.ExecutionRef("att-2", ""), actions[0].Receipt)
	assert.Len(t, service.retried, 1, "settled from the run, never by dispatching again")
	open, resolved := stalled()
	assert.Empty(t, open, "the registry resolves the exception when the attempt settles")
	assert.Len(t, resolved, 1)
}

// Against the real registry: a retry of a run whose outcome is unknown gets
// exactly one further attempt, and only on the owner's "retry" to the
// question about that attempt. The second attempt is the original decision
// executed again: it names the execution the owner decided about, never the
// run's latest. Its reservation is timed from its own grant, not from the
// action's creation. The question about the second attempt offers no
// "retry", because the registry allows no third.
func TestRemoteAnOwnersRetryAllowsOneMoreAttemptOfARunRetry(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	job := f.job()
	service := f.service
	service.fail("run-7", "att-1")
	decidedOn := review.Execution{AttemptID: "att-1"}
	var proposal *registry.Proposal
	var decided *registry.Decision
	_, err := f.store.WithJobTx(ctx, f.jobID, human, func(tx *registry.JobTx) (err error) {
		proposal, decided, err = tx.ProposeRetry(registry.RetryRunParams{
			RunID: "run-7", AttemptID: "att-1", RunSpecSHA256: job.DAGSpecSHA256, PackageDigest: job.PackageDigest,
		}, "retry-run-7")
		return err
	})
	require.NoError(t, err)
	reviewAt := func(holder string, after time.Duration) {
		t.Helper()
		*f.ahead = after
		r := f.retrying(holder, service)
		r.Now = func() time.Time { return time.Now().Add(after) }
		prepared, err := r.Prepare(ctx, f.jobID)
		require.NoError(t, err)
		require.Empty(t, prepared.Skipped)
		_, err = r.Apply(ctx, prepared, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "waiting", EvidenceRunIDs: prepared.Packet.RunIDs()})
		require.NoError(t, err)
	}
	question := func() review.Proposal {
		t.Helper()
		open, err := f.remote.OpenProposals(ctx, f.jobID)
		require.NoError(t, err)
		require.Len(t, open, 1)
		require.Equal(t, review.ProposalUncertain, open[0].Kind)
		return open[0]
	}
	stalled := func() (out []*registry.Exception) {
		for _, e := range f.job().Exceptions {
			if e.Kind == string(review.ExceptionRetryStalled) && e.ResolvedAt == nil {
				out = append(out, e)
			}
		}
		return out
	}

	// First attempt: the service admits the retry without naming an
	// execution, so its outcome is unknown and the owner is asked.
	service.unnamed = true
	service.retry = func(string) error { return nil }
	first, err := f.retrying("tick-1", service).Execute(ctx, f.jobID, proposal.ProposalID, decided.DecisionID)
	require.NoError(t, err)
	require.Equal(t, review.ActionUncertain, first.Action.State)
	actionID := first.Action.ID
	reviewAt("reviewer-a", time.Hour)
	require.Equal(t, registry.ActionEscalated, f.job().Actions[actionID].State)
	about1 := question()
	assert.Contains(t, about1.AllowedVerdicts, review.VerdictRetry, "one further attempt can be allowed")

	// Nothing runs again until the owner says so.
	again, err := f.retrying("tick-1b", service).Execute(ctx, f.jobID, proposal.ProposalID, decided.DecisionID)
	require.NoError(t, err)
	assert.NotEmpty(t, again.Skipped)
	require.Len(t, service.retried, 1)

	// The owner answers "retry". The question's decision run executes the
	// answer, and that performs the second attempt of the same action.
	answer, err := f.decide(about1, 1, "retry")
	require.NoError(t, err)
	*f.ahead = 5 * time.Hour
	service.unnamed = false
	service.retry = func(runID string) error {
		service.state[runID] = review.RunState{AttemptID: "att-2", Status: "not_started", Active: true}
		return nil
	}
	late := f.retrying("tick-2", service)
	late.Now = func() time.Time { return time.Now().Add(5 * time.Hour) }
	second, err := late.Execute(ctx, f.jobID, about1.ID, answer.Decision.DecisionID)
	require.NoError(t, err)
	require.Empty(t, second.Skipped)
	require.Equal(t, review.ActionUncertain, second.Action.State)
	require.Equal(t, review.ExecutionRef("att-2", ""), second.Action.AdmittedRef)
	stored := f.job().Actions[actionID]
	assert.Equal(t, 2, stored.Attempt, "the same action, attempted a second time")
	require.Len(t, service.requested, 2)
	assert.Equal(t, decidedOn, service.requested[1], "the second request names the execution the owner decided about")

	// Executing the same answer again does nothing: it was about attempt 1.
	replay, err := late.Execute(ctx, f.jobID, about1.ID, answer.Decision.DecisionID)
	require.NoError(t, err)
	assert.NotEmpty(t, replay.Skipped)
	require.Len(t, service.retried, 2)

	// The action is five hours old; its second attempt is ten minutes old.
	reviewAt("reviewer-b", 5*time.Hour+10*time.Minute)
	assert.Empty(t, stalled(), "the reservation is timed from the grant of its own attempt")
	reviewAt("reviewer-c", 7*time.Hour)
	raised := stalled()
	require.Len(t, raised, 1)
	assert.Equal(t, 2, raised[0].Attempt)

	// The second attempt also ends unknown: the run shows someone else's
	// execution. The owner is asked, and is not offered another retry.
	service.state["run-7"] = review.RunState{AttemptID: "att-other", Status: "running", Active: true}
	reviewAt("reviewer-d", 9*time.Hour)
	require.Equal(t, registry.ActionEscalated, f.job().Actions[actionID].State)
	about2 := question()
	assert.NotEqual(t, about1.ID, about2.ID)
	assert.NotContains(t, about2.AllowedVerdicts, review.VerdictRetry, "the registry allows no third attempt, so none is offered")
	assert.Empty(t, stalled(), "the exception about the attempt ended with it")
	assert.Len(t, service.retried, 2)
}

// Against the real registry: the values the agent chose for a routine
// action are validated by the registry against the schema the job declares,
// before anything is granted. The reviewer carries values as text and sends
// each as the JSON type its property declares, so a number is validated as a
// number, bounds included. A refused value runs nothing, is recorded on the
// review with the registry's reason, and does not fail the review.
func TestRemoteRoutineActionParameterValuesAreValidatedByTheRegistry(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	targetID := f.targetID()
	var ran []map[string]string
	f.fx.run = func(action review.Action) (review.EffectResult, bool) {
		ran = append(ran, action.Params)
		return review.EffectResult{Status: review.EffectApplied, Receipt: "ok"}, true
	}
	round := func(holder string, params map[string]string) review.Applied {
		t.Helper()
		*f.ahead += 2 * time.Hour
		r := f.reviewer(holder)
		r.Now = func() time.Time { return time.Now().Add(*f.ahead) }
		prepared, err := r.Prepare(ctx, f.jobID)
		require.NoError(t, err)
		require.Empty(t, prepared.Skipped)
		applied, err := r.Apply(ctx, prepared, review.AgentDecision{
			Outcome: review.OutcomeAct, Reasoning: "look", EvidenceRunIDs: prepared.Packet.RunIDs(),
			Actions: []review.AgentAction{{Name: "collect_diagnostics", TargetID: targetID, Params: params, Reason: "look"}},
		})
		require.NoError(t, err, "a refused value is not a failure of the review")
		return applied
	}

	// Values within the schema run, and reach the command as the text the
	// agent gave. The registry stores them as the types the schema declares.
	good := map[string]string{"depth": "3", "ratio": "0.25", "verbose": "true", "label": "007"}
	applied := round("reviewer-a", good)
	require.Len(t, applied.Executed, 1)
	assert.Equal(t, review.ActionSucceeded, applied.Executed[0].State)
	require.Len(t, ran, 1)
	assert.Equal(t, good, ran[0])
	// That the registry granted it shows the values were sent typed: it
	// does not coerce, and the string "3" is not an integer to it.
	journaled := func() []review.Action {
		t.Helper()
		actions, err := f.remote.Actions(ctx, f.jobID)
		require.NoError(t, err)
		return actions
	}
	require.Len(t, journaled(), 1)
	assert.Equal(t, good, journaled()[0].Params, "read back as the same text")

	// Values the schema does not allow: out of bounds, not a number at all,
	// a string too long, and a parameter that is declared but mistyped.
	for name, params := range map[string]map[string]string{
		"above the maximum":  {"depth": "9"},
		"not an integer":     {"depth": "3; rm -rf /"},
		"a fraction":         {"depth": "2.5"},
		"ratio out of range": {"ratio": "7"},
		"not a boolean":      {"verbose": "yes"},
		"label too long":     {"label": "far-too-long-a-label"},
	} {
		t.Run(name, func(t *testing.T) {
			applied := round("reviewer-"+name, params)
			assert.Empty(t, applied.Executed)
			assert.Len(t, ran, 1, "nothing ran")
			assert.Len(t, journaled(), 1, "nothing was journaled")
			require.NotEmpty(t, applied.Review.Notes)
			note := applied.Review.Notes[len(applied.Review.Notes)-1]
			assert.Contains(t, note, `action "collect_diagnostics" denied by the guard: invalid_params: the registry said "`)
		})
	}
}

// An effect whose outcome is unknown is escalated as the registry's typed
// txe.uncertain_effect. A person's retry verdict allows exactly one more
// attempt of that intent: the registry consumes it with the grant, and
// refuses the attempt after that until a person decides again.
func TestRemoteUncertainRetryAllowsOneMoreAttempt(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	targetID := f.targetID()
	f.fx.run = func(review.Action) (review.EffectResult, bool) {
		return review.EffectResult{Status: review.EffectUnknown, Detail: "timed out"}, true
	}
	notify := review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Tell the owner.",
		Actions: []review.AgentAction{{Name: "notify", TargetID: targetID, Reason: "low space"}},
	}
	round := func(holder string, d review.AgentDecision) review.Applied {
		t.Helper()
		prepared, err := f.reviewer(holder).Prepare(ctx, f.jobID)
		require.NoError(t, err)
		require.Empty(t, prepared.Skipped)
		applied, err := f.reviewer(holder).Apply(ctx, prepared, d)
		require.NoError(t, err)
		return applied
	}
	waiting := review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "waiting"}

	first := round("reviewer-a", notify)
	require.Len(t, first.Executed, 1)
	assert.Equal(t, review.ActionUncertain, first.Executed[0].State)
	actionID := first.Executed[0].ID

	// The next review cannot settle it and asks the owner, once.
	round("reviewer-b", waiting)
	want, err := registry.EscalationProposalID(actionID, 1, 1)
	require.NoError(t, err)
	open, err := f.remote.OpenProposals(ctx, f.jobID)
	require.NoError(t, err)
	require.Len(t, open, 1)
	escalation := open[0]
	assert.Equal(t, want, escalation.ID)
	assert.Equal(t, review.ProposalUncertain, escalation.Kind)
	assert.Equal(t, map[string]string{"action_id": actionID, "attempt": "1"}, escalation.Params, "the escalation is about that attempt of the action")
	assert.NotContains(t, escalation.AllowedVerdicts, review.VerdictApprove)
	assert.NotContains(t, escalation.AllowedVerdicts, review.VerdictRedirect)
	assert.Equal(t, registry.ActionEscalated, f.job().Actions[actionID].State)

	// Until the owner answers, the same intent is not attempted again.
	blocked := round("reviewer-c", notify)
	assert.Empty(t, blocked.Executed)
	assert.Equal(t, 1, f.fx.count("notify"))

	// An escalation is never executed, so it cannot be approved.
	_, err = f.decide(escalation, 1, "approve")
	require.Error(t, err)
	_, err = f.decide(escalation, 1, "retry")
	require.NoError(t, err)
	require.Contains(t, f.job().UncertainResolutions, actionID)

	// The one attempt the owner allowed runs, and uses the answer up.
	second := round("reviewer-d", notify)
	require.Len(t, second.Executed, 1)
	assert.Equal(t, 2, f.fx.count("notify"))
	assert.Empty(t, f.job().UncertainResolutions, "the grant consumed the owner's answer")

	// That attempt ended unknown too. Nothing runs a third time.
	third := round("reviewer-e", notify)
	assert.Empty(t, third.Executed)
	assert.Equal(t, 2, f.fx.count("notify"))
}

// A reviewer that cannot run is the reviewer's problem. The registry keeps
// it apart from the job's availability, and a recorded review clears it.
func TestRemoteReviewerExceptionLeavesTheJobAvailable(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	before := f.job().Availability.State

	require.NoError(t, f.remote.RaiseException(ctx, review.Exception{
		JobID: f.jobID, Kind: review.ExceptionReviewerAuth, MachineID: f.remote.MachineID, Message: "the agent is not logged in",
	}))
	// The same failure on the next tick is not filed again.
	require.NoError(t, f.remote.RaiseException(ctx, review.Exception{
		JobID: f.jobID, Kind: review.ExceptionReviewerAuth, MachineID: f.remote.MachineID, Message: "the agent is not logged in",
	}))
	job := f.job()
	assert.Equal(t, before, job.Availability.State, "the job's availability is untouched")
	require.NotNil(t, job.ReviewerAvailability)
	assert.Equal(t, registry.AvailabilityState("auth_required"), job.ReviewerAvailability.State)
	open := 0
	for _, e := range job.Exceptions {
		if e.ResolvedAt == nil {
			open++
			assert.Equal(t, registry.ScopeReviewer, e.Scope)
			assert.Equal(t, string(review.ExceptionReviewerAuth), e.Kind)
		}
	}
	assert.Equal(t, 1, open)

	// A problem with the job's target is the job's.
	require.NoError(t, f.remote.RaiseException(ctx, review.Exception{
		JobID: f.jobID, Kind: review.ExceptionUnavailable, MachineID: f.remote.MachineID, Message: "the volume is gone",
	}))
	assert.Equal(t, registry.AvailabilityState("target_unreachable"), f.job().Availability.State)

	prepared, err := f.reviewer("reviewer-a").Prepare(ctx, f.jobID)
	require.NoError(t, err)
	_, err = f.reviewer("reviewer-a").Apply(ctx, prepared, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "fine", EvidenceRunIDs: []string{"run-1"}})
	require.NoError(t, err)
	job = f.job()
	assert.Equal(t, registry.AvailabilityReady, job.ReviewerAvailability.State)
	for _, e := range job.Exceptions {
		if e.Scope == registry.ScopeReviewer {
			assert.NotNil(t, e.ResolvedAt, "a recorded review resolves the reviewer's exceptions")
		}
	}
	assert.Equal(t, registry.AvailabilityState("target_unreachable"), job.Availability.State, "and leaves the job's own state alone")

	// The review's cost is kept in the registry's typed fields.
	stored, err := f.store.GetReview(ctx, f.jobID, prepared.Packet.ReviewID)
	require.NoError(t, err)
	assert.Positive(t, stored.PacketBytes)
}

// A decision run that was already over is recorded as what the run showed.
// One whose task never completed ended before anyone answered: the
// registry's run_ended. One whose task completed with nobody on record is
// recorded as closed with a detail that neither claims an answer nor denies
// one. Neither is recorded as answered, and both leave the pending list.
func TestRemoteAnEndedDecisionRunIsNotRecordedAsAnswered(t *testing.T) {
	for name, tc := range map[string]struct {
		closed  review.ClosureOutcome
		stored  registry.ClosureOutcome
		says    string
		saysNot string
	}{
		"the task never completed":                 {review.ClosureEnded, registry.ClosureRunEnded, "ended before its task was answered", "is not known"},
		"the task completed with nobody on record": {review.ClosureOver, registry.ClosureClosed, "is not known from the run", "before its task was answered"},
	} {
		t.Run(name, func(t *testing.T) { endedDecisionRun(t, tc.closed, tc.stored, tc.says, tc.saysNot) })
	}
}

func endedDecisionRun(t *testing.T, closed review.ClosureOutcome, stored registry.ClosureOutcome, says, saysNot string) {
	t.Helper()
	f := newRemoteFixture(t)
	ctx := context.Background()
	prepared, err := f.reviewer("reviewer-a").Prepare(ctx, f.jobID)
	require.NoError(t, err)
	_, err = f.reviewer("reviewer-a").Apply(ctx, prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "grow", EvidenceRunIDs: []string{"run-1"},
		Actions: []review.AgentAction{{Name: "expand_volume", TargetID: f.targetID(), Params: map[string]string{"size_gb": "200"}, Reason: "grow"}},
	})
	require.NoError(t, err)
	_, err = f.store.WithJobTx(ctx, f.jobID, human, func(tx *registry.JobTx) error {
		return tx.Transition(registry.Transition{Op: registry.OpRetire, Reason: registry.RetireManual})
	})
	require.NoError(t, err)
	pending, err := f.remote.PendingClosures(ctx, f.remote.MachineID, 10)
	require.NoError(t, err)
	require.Len(t, pending, 1)

	f.opener.close = func(review.Proposal) (review.ClosureOutcome, error) { return closed, nil }
	done, err := f.reviewer("tick-1").CloseSuperseded(ctx, f.remote.MachineID)
	require.NoError(t, err)
	require.Len(t, done, 1)
	assert.Equal(t, closed, done[0].Outcome)

	pending, err = f.remote.PendingClosures(ctx, f.remote.MachineID, 10)
	require.NoError(t, err)
	assert.Empty(t, pending, "nothing is waiting, so nothing is pending")
	raw, err := json.Marshal(f.job())
	require.NoError(t, err)
	assert.NotContains(t, string(raw), `"outcome":"already_answered"`)
	closures, err := f.store.ListClosures(ctx, f.jobID, 0)
	require.NoError(t, err)
	require.Len(t, closures, 1)
	assert.Equal(t, stored, closures[0].Outcome)
	assert.Contains(t, closures[0].Detail, says)
	assert.NotContains(t, closures[0].Detail, saysNot, "the record claims only what the run showed")
	assert.Contains(t, closures[0].Detail, "The reviewer completed nothing")
}

// Superseded proposals leave their decision runs waiting. The registry
// lists them as pending closures; the reviewer closes each, the registry
// records the outcome, and one that keeps failing stays pending, is counted
// and becomes an exception without holding up the rest.
func TestRemoteSupersededDecisionRunsAreClosedAndRecorded(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	targetID := f.targetID()
	prepared, err := f.reviewer("reviewer-a").Prepare(ctx, f.jobID)
	require.NoError(t, err)
	_, err = f.reviewer("reviewer-a").Apply(ctx, prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "grow", EvidenceRunIDs: []string{"run-1"},
		Actions: []review.AgentAction{
			{Name: "expand_volume", TargetID: targetID, Params: map[string]string{"size_gb": "200"}, Reason: "grow"},
			{Name: "expand_volume", TargetID: targetID, Params: map[string]string{"size_gb": "400"}, Reason: "grow more"},
		},
	})
	require.NoError(t, err)
	open, err := f.remote.OpenProposals(ctx, f.jobID)
	require.NoError(t, err)
	require.Len(t, open, 2)

	none, err := f.reviewer("tick-0").CloseSuperseded(ctx, f.remote.MachineID)
	require.NoError(t, err)
	assert.Empty(t, none, "an open proposal's run is left waiting for its answer")

	// Retiring the job supersedes both proposals.
	_, err = f.store.WithJobTx(ctx, f.jobID, human, func(tx *registry.JobTx) error {
		return tx.Transition(registry.Transition{Op: registry.OpRetire, Reason: registry.RetireManual})
	})
	require.NoError(t, err)
	pending, err := f.remote.PendingClosures(ctx, f.remote.MachineID, 10)
	require.NoError(t, err)
	require.Len(t, pending, 2)
	stuck := pending[1]
	assert.Equal(t, review.DecisionRunID(stuck.ID), stuck.NativeTask.RunID)

	f.opener.close = func(p review.Proposal) (review.ClosureOutcome, error) {
		if p.ID == stuck.ID {
			return "", errors.New("hub unreachable")
		}
		return review.ClosureClosed, nil
	}
	first, err := f.reviewer("tick-1").CloseSuperseded(ctx, f.remote.MachineID)
	require.NoError(t, err)
	require.Len(t, first, 2)
	pending, err = f.remote.PendingClosures(ctx, f.remote.MachineID, 10)
	require.NoError(t, err)
	require.Len(t, pending, 1, "a closed run leaves the list; a failed one stays")
	assert.Equal(t, stuck.ID, pending[0].ID)

	for _, tick := range []string{"tick-2", "tick-3"} {
		_, err = f.reviewer(tick).CloseSuperseded(ctx, f.remote.MachineID)
		require.NoError(t, err)
	}
	job := f.job()
	require.Contains(t, job.PendingClosures, stuck.ID)
	assert.Equal(t, 3, job.PendingClosures[stuck.ID].Failures)
	raised := false
	for _, e := range job.Exceptions {
		raised = raised || e.Kind == string(review.ExceptionCleanupFailed)
	}
	assert.True(t, raised, "three failed attempts surface as an exception")
	assert.Equal(t, registry.LifecycleRetired, job.Lifecycle, "closing a run never changes the job")

	// Once the run can be closed, it is, and nothing is pending.
	f.opener.close = nil
	_, err = f.reviewer("tick-4").CloseSuperseded(ctx, f.remote.MachineID)
	require.NoError(t, err)
	pending, err = f.remote.PendingClosures(ctx, f.remote.MachineID, 10)
	require.NoError(t, err)
	assert.Empty(t, pending)
}
