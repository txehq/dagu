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
	store, err := registry.NewFileStore(filepath.Join(dir, "data"), registry.WithDAGStore(registry.NewDAGStore(repo)))
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
	sizeSchema := map[string]any{"type": "object", "properties": map[string]any{"size_gb": map[string]any{"type": "string"}}}
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
					{Name: "collect_diagnostics", Routine: true, Command: new("true"), Idempotency: &readOnly, TimeoutSec: 30},
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
		Remote: &review.Remote{Transport: transport, MachineID: machine, RunID: "tick-1", AgentClient: "fixture-agent 1.0"},
		runs:   []review.RunEvidence{{RunID: "run-1", Status: "failed", Outputs: map[string]string{"free_pct": "12"}}},
	}
	return &remoteFixture{t: t, store: store, remote: remote, jobID: jobID, target: target, fx: newEffects(), opener: &opener{}, tasks: &taskRecorder{}}
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
	targetID := "cluster_uid=c-1,uid=vol-1"

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
	targetID := "cluster_uid=c-1,uid=vol-1"
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
		return fmt.Sprintf(`{"dagRunId":%q,"name":%q,"statusLabel":%q,"status":0,"startedAt":"2026-10-09T10:00:00Z","finishedAt":%q,"artifactsAvailable":false,"autoRetryCount":0}`, id, job, status, finished)
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
		"/dag-runs/" + job + "/r1":                                         `{"dagRunDetails":{"statusLabel":"succeeded","finishedAt":"2026-10-09T10:01:00Z","nodes":[]}}`,
		"/dag-runs/" + job + "/r2":                                         `{"dagRunDetails":{"statusLabel":"succeeded","nodes":[{"step":{"name":"measure"},"statusLabel":"succeeded"}]}}`,
		"/dag-runs/" + job + "/r3":                                         `{"dagRunDetails":{"statusLabel":"failed","nodes":[{"step":{"name":"measure"},"statusLabel":"failed"}]}}`,
		"/dag-runs/" + job + "/r2/steps/measure/log?stream=stdout&tail=40": `{"content":"31"}`,
		"/dag-runs/" + job + "/r3/steps/measure/log?stream=stderr&tail=40": `{"content":"df: permission denied"}`,
	}}
	remote := &review.Remote{Transport: stub}

	runs, err := remote.RunsAfter(context.Background(), job, "r1")
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

	all, err := remote.RunsAfter(context.Background(), job, "")
	require.NoError(t, err)
	require.Len(t, all, 3)
	assert.Equal(t, "r1", all[0].RunID)

	// A failure to read outputs that is not "none exist" fails the read:
	// evidence is not silently dropped.
	stub.fail = map[string]*review.TransportError{
		"/dag-runs/" + job + "/r2/outputs": {Status: http.StatusBadGateway, Message: "hub unreachable"},
	}
	_, err = remote.RunsAfter(context.Background(), job, "r1")
	require.ErrorContains(t, err, "outputs of run r2")
}

// runList is a stub of the service's run list for one job.
type runList struct {
	job  string
	stub *stubTransport
}

func newRunList(t *testing.T) *runList {
	l := &runList{job: "job_01HZX0000000000000000000AA", stub: &stubTransport{t: t, replies: map[string]string{}}}
	l.set()
	return l
}

// set replaces the listed runs; each is "id attempt status finishedAt".
func (l *runList) set(runs ...string) {
	items := make([]string, 0, len(runs))
	for _, run := range runs {
		f := strings.Fields(run)
		finished := ""
		if len(f) > 3 {
			finished = f[3]
		}
		items = append(items, fmt.Sprintf(`{"dagRunId":%q,"attemptId":%q,"statusLabel":%q,"queuedAt":"2026-10-09T09:59:00Z","finishedAt":%q}`, f[0], f[1], f[2], finished))
		l.stub.replies["/dag-runs/"+l.job+"/"+f[0]] = fmt.Sprintf(`{"dagRunDetails":{"attemptId":%q,"statusLabel":%q,"nodes":[]}}`, f[1], f[2])
	}
	l.stub.replies["/dag-runs/"+l.job+"?limit=100"] = `{"dagRuns":[` + strings.Join(items, ",") + `]}`
}

// page is one page of the run list as the service returns it.
func (l *runList) page(next string, runs ...string) string {
	items := make([]string, 0, len(runs))
	for _, run := range runs {
		f := strings.Fields(run)
		finished := ""
		if len(f) > 3 {
			finished = f[3]
		}
		items = append(items, fmt.Sprintf(`{"dagRunId":%q,"attemptId":%q,"statusLabel":%q,"queuedAt":"2026-10-09T09:59:00Z","finishedAt":%q}`, f[0], f[1], f[2], finished))
		l.stub.replies["/dag-runs/"+l.job+"/"+f[0]] = fmt.Sprintf(`{"dagRunDetails":{"attemptId":%q,"statusLabel":%q,"nodes":[]}}`, f[1], f[2])
	}
	cursor := ""
	if next != "" {
		cursor = fmt.Sprintf(`,"nextCursor":%q`, next)
	}
	return `{"dagRuns":[` + strings.Join(items, ",") + `]` + cursor + `}`
}

// after returns the uncovered results as "run@attempt", and the cursor that
// covers all of them.
func (l *runList) after(cursor string) ([]string, string) {
	l.stub.t.Helper()
	runs, err := (&review.Remote{Transport: l.stub}).RunsAfter(context.Background(), l.job, cursor)
	require.NoError(l.stub.t, err)
	keys := make([]string, 0, len(runs))
	for _, run := range runs {
		keys = append(keys, run.RunID+"@"+run.AttemptID)
		cursor = run.Cursor
	}
	return keys, cursor
}

// Coverage is by run and attempt. A native retry keeps the run id, so the
// retried run's new result is shown again, and a run that finished between
// its two attempts is not passed over.
func TestRemoteRunsAfterShowsARetriedRunAgain(t *testing.T) {
	l := newRunList(t)
	l.set("r1 a1 failed 2026-10-09T10:01:00Z", "r2 b1 succeeded 2026-10-09T10:02:00Z")
	first, cursor := l.after("")
	assert.Equal(t, []string{"r1@a1", "r2@b1"}, first)
	none, _ := l.after(cursor)
	assert.Empty(t, none)

	// r1 is retried and fails again, after r2.
	l.set("r1 a2 failed 2026-10-09T10:05:00Z", "r2 b1 succeeded 2026-10-09T10:02:00Z")
	again, cursor := l.after(cursor)
	assert.Equal(t, []string{"r1@a2"}, again)
	none, _ = l.after(cursor)
	assert.Empty(t, none)

	// With only r1's first result covered, both later results are owed.
	l.set("r1 a1 failed 2026-10-09T10:01:00Z")
	_, onlyFirst := l.after("")
	l.set("r1 a2 failed 2026-10-09T10:05:00Z", "r2 b1 succeeded 2026-10-09T10:02:00Z")
	both, _ := l.after(onlyFirst)
	assert.Equal(t, []string{"r2@b1", "r1@a2"}, both)
}

// Two results with the same reported end time are told apart by run and
// attempt: covering one never covers the other, in either order, and a
// second attempt that ends in the same second as the first is still new.
func TestRemoteRunsAfterTellsApartResultsWithOneTimestamp(t *testing.T) {
	l := newRunList(t)
	l.set("r2 b1 failed 2026-10-09T10:01:00Z")
	first, cursor := l.after("")
	assert.Equal(t, []string{"r2@b1"}, first)

	// Another run, sorting before the covered one, reports the same time.
	l.set("r1 a1 failed 2026-10-09T10:01:00Z", "r2 b1 failed 2026-10-09T10:01:00Z")
	second, cursor := l.after(cursor)
	assert.Equal(t, []string{"r1@a1"}, second)

	// r2 is retried and its new attempt ends within the same second.
	l.set("r1 a1 failed 2026-10-09T10:01:00Z", "r2 b2 succeeded 2026-10-09T10:01:00Z")
	third, cursor := l.after(cursor)
	assert.Equal(t, []string{"r2@b2"}, third)
	none, _ := l.after(cursor)
	assert.Empty(t, none)
}

// A result can be reported late: the run was still unfinished when a later
// result was covered, and then turns out to have ended before it. It is
// owed from the moment it was seen unfinished and is shown once, whatever
// its time.
func TestRemoteRunsAfterShowsALateResultThatEndedBeforeTheCursor(t *testing.T) {
	l := newRunList(t)
	l.set("r1 a1 running", "r2 b1 succeeded 2026-10-09T10:05:00Z")
	first, cursor := l.after("")
	assert.Equal(t, []string{"r2@b1"}, first)
	still, _ := l.after(cursor)
	assert.Empty(t, still, "an unfinished run is not a result yet")

	// r1's result arrives with an end time before what is already covered.
	l.set("r1 a1 failed 2026-10-09T10:03:00Z", "r2 b1 succeeded 2026-10-09T10:05:00Z")
	late, next := l.after(cursor)
	assert.Equal(t, []string{"r1@a1"}, late)
	none, _ := l.after(next)
	assert.Empty(t, none, "and it is shown once")

	// Until a review has been shown it, it stays owed: a checkpoint that
	// did not cover it does not lose it.
	l.set("r1 a1 failed 2026-10-09T10:03:00Z", "r2 b1 succeeded 2026-10-09T10:05:00Z", "r3 c1 succeeded 2026-10-09T10:06:00Z")
	owed, _ := l.after(cursor)
	assert.Equal(t, []string{"r1@a1", "r3@c1"}, owed)
	runs, err := (&review.Remote{Transport: l.stub}).RunsAfter(context.Background(), l.job, cursor)
	require.NoError(t, err)
	onlyLate := runs[0].Cursor
	rest, _ := l.after(onlyLate)
	assert.Equal(t, []string{"r3@c1"}, rest, "covering the late result alone leaves the newer one owed")

	// The same holds for a retry: the run was queued again when the
	// cursor moved, and its new attempt reports an earlier end.
	l.set("r1 a2 queued", "r2 b1 succeeded 2026-10-09T10:05:00Z", "r3 c1 succeeded 2026-10-09T10:06:00Z")
	_, moved := l.after(next)
	l.set("r1 a2 failed 2026-10-09T10:04:00Z", "r2 b1 succeeded 2026-10-09T10:05:00Z", "r3 c1 succeeded 2026-10-09T10:06:00Z")
	retried, _ := l.after(moved)
	assert.Equal(t, []string{"r1@a2"}, retried)
}

// A listing of several pages is not one moment. A run created after the
// first page was read can end before an older run that is seen finished on
// a later page. Returning that older run alone would move the cursor past
// the new run's end without the new run ever having been listed. The
// second pass finds it, and it is owed. The clocks here are normal.
func TestRemoteRunsAfterDoesNotLoseARunCreatedBetweenPages(t *testing.T) {
	for name, tc := range map[string]struct {
		secondPass, later string
		want              []string
	}{
		"created and finished while the pages were read": {
			secondPass: "x x1 failed 2026-10-09T10:15:00Z", later: "x x1 failed 2026-10-09T10:15:00Z", want: []string{"x@x1"},
		},
		"created and still running at the second pass": {
			secondPass: "x x1 running", later: "x x1 failed 2026-10-09T10:15:00Z", want: []string{"x@x1"},
		},
		"an already covered run retried between pages": {
			secondPass: "old o2 failed 2026-10-09T10:15:00Z", later: "old o2 failed 2026-10-09T10:15:00Z", want: []string{"old@o2"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			l := newRunList(t)
			// "old" was covered earlier; y is still running then.
			l.set("old o1 failed 2026-10-09T10:00:00Z", "y y1 running")
			_, cursor := l.after("")
			first, p2 := "/dag-runs/"+l.job+"?limit=100", "/dag-runs/"+l.job+"?cursor=p2&limit=100"
			// First pass: page one before the new run exists; by the time
			// page two is read, y has ended at 10:20.
			y := "y y1 succeeded 2026-10-09T10:20:00Z"
			secondFirst := []string{tc.secondPass}
			if !strings.HasPrefix(tc.secondPass, "old ") {
				secondFirst = append(secondFirst, "old o1 failed 2026-10-09T10:00:00Z")
			}
			l.stub.seq = map[string][]string{
				first: {l.page("p2", "old o1 failed 2026-10-09T10:00:00Z"), l.page("p2", secondFirst...)},
				p2:    {l.page("", y), l.page("", y)},
			}
			shown, next := l.after(cursor)
			assert.Equal(t, []string{"y@y1"}, shown, "only what both passes saw finished is returned")
			assert.Empty(t, l.stub.seq[first], "the listing was read twice")

			// The run that appeared in between is owed, though it ended
			// before the cursor.
			rest := []string{tc.later, y}
			if !strings.HasPrefix(tc.later, "old ") {
				rest = append(rest, "old o1 failed 2026-10-09T10:00:00Z")
			}
			l.set(rest...)
			owed, done := l.after(next)
			assert.Equal(t, tc.want, owed)
			none, _ := l.after(done)
			assert.Empty(t, none)
		})
	}
}

// A result returned in the first pass that the second pass no longer finds
// as it was is not returned: its run is owed instead.
func TestRemoteRunsAfterHoldsBackAResultThatChangedBetweenPasses(t *testing.T) {
	l := newRunList(t)
	first, p2 := "/dag-runs/"+l.job+"?limit=100", "/dag-runs/"+l.job+"?cursor=p2&limit=100"
	l.stub.seq = map[string][]string{
		first: {l.page("p2", "a a1 failed 2026-10-09T10:01:00Z"), l.page("p2", "a a2 queued")},
		p2:    {l.page("", "b b1 succeeded 2026-10-09T10:02:00Z"), l.page("", "b b1 succeeded 2026-10-09T10:02:00Z")},
	}
	shown, cursor := l.after("")
	assert.Equal(t, []string{"b@b1"}, shown)
	l.set("a a2 failed 2026-10-09T10:01:30Z", "b b1 succeeded 2026-10-09T10:02:00Z")
	owed, _ := l.after(cursor)
	assert.Equal(t, []string{"a@a2"}, owed, "the retried run's result is shown although it ended before the cursor")
}

// Evidence is read by run id. When the run is retried while its evidence is
// being read, the status of one attempt is never paired with the output of
// another: the result is held back and owed.
func TestRemoteRunsAfterNeverMixesTheEvidenceOfTwoAttempts(t *testing.T) {
	l := newRunList(t)
	l.set("r1 a1 failed 2026-10-09T10:01:00Z", "r2 b1 succeeded 2026-10-09T10:02:00Z")
	// r1 is retried between the first and the last read of its evidence.
	detail := "/dag-runs/" + l.job + "/r1"
	l.stub.seq = map[string][]string{detail: {
		`{"dagRunDetails":{"attemptId":"a1","statusLabel":"failed","nodes":[]}}`,
		`{"dagRunDetails":{"attemptId":"a2","statusLabel":"running","nodes":[]}}`,
	}}
	shown, cursor := l.after("")
	assert.Equal(t, []string{"r2@b1"}, shown)

	l.set("r1 a2 failed 2026-10-09T10:01:30Z", "r2 b1 succeeded 2026-10-09T10:02:00Z")
	owed, _ := l.after(cursor)
	assert.Equal(t, []string{"r1@a2"}, owed)
}

// A run that ended in the queue has no finish time and is still a result.
// One page of results is bounded, and what it leaves is returned next.
func TestRemoteRunsAfterIsBoundedAndKeepsRunsWithoutAFinishTime(t *testing.T) {
	l := newRunList(t)
	l.set("r1 a1 rejected")
	first, cursor := l.after("")
	assert.Equal(t, []string{"r1@a1"}, first, "ordered by the latest time the service has for it")
	none, _ := l.after(cursor)
	assert.Empty(t, none)

	var many []string
	for i := range 120 {
		many = append(many, fmt.Sprintf("m%03d a1 succeeded 2026-10-09T11:%02d:%02dZ", i, i/60, i%60))
	}
	l.set(many...)
	seen := map[string]bool{}
	cursor = ""
	for range 4 {
		page, next := l.after(cursor)
		require.LessOrEqual(t, len(page), 51)
		for _, key := range page {
			require.False(t, seen[key], "%s shown twice", key)
			seen[key] = true
		}
		cursor = next
	}
	assert.Len(t, seen, 120, "every result is returned across pages")
	assert.Less(t, len(cursor), 200, "the cursor does not grow with the history")
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

// Completing a task through the service reports an answered task and an
// unknown run as distinct results.
func TestRemoteCompleteReportsWhatTheServiceSaid(t *testing.T) {
	path := "/dag-runs/txe-decide-X/txe-abc/human-tasks/decide/complete"
	stub := &stubTransport{t: t, replies: map[string]string{path: `{"alreadyCompleted":false}`}}
	complete := review.RemoteComplete(stub)
	task := review.TaskLocator{DAG: "txe-decide-X", RunID: "txe-abc", StepID: "decide"}
	require.NoError(t, complete(context.Background(), task, map[string]string{"decision_id": review.NoDecisionID, "verdict": review.VerdictSuperseded}))
	assert.Equal(t, []string{"POST " + path}, stub.calls)

	stub.fail = map[string]*review.TransportError{path: {Status: http.StatusConflict}}
	require.ErrorIs(t, complete(context.Background(), task, nil), review.ErrTaskAnswered)
	stub.fail = map[string]*review.TransportError{path: {Status: http.StatusNotFound}}
	require.ErrorIs(t, complete(context.Background(), task, nil), review.ErrRunMissing)
	stub.fail = map[string]*review.TransportError{path: {Status: http.StatusBadGateway}}
	err := complete(context.Background(), task, nil)
	require.Error(t, err)
	require.NotErrorIs(t, err, review.ErrTaskAnswered)
	require.NotErrorIs(t, err, review.ErrRunMissing)
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
	targetID := "cluster_uid=c-1,uid=vol-1"
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
	service := newRuns()
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
		"run_id": "run-1", "attempt_id": "att-1", "run_spec_sha256": job.DAGSpecSHA256, "package_digest": job.PackageDigest,
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
	assert.Equal(t, "att-2", out.Action.Receipt, "the receipt is the observed new attempt")
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
// run. The reviewer's tick executes it once, and never lists it again.
func TestRemoteRequestedRetryIsExecutedByTheTick(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	job := f.job()
	var proposal *registry.Proposal
	var decided *registry.Decision
	_, err := f.store.WithJobTx(ctx, f.jobID, human, func(tx *registry.JobTx) (err error) {
		proposal, decided, err = tx.ProposeRetry(registry.RetryRunParams{
			RunID: "run-7", RunSpecSHA256: job.DAGSpecSHA256, PackageDigest: job.PackageDigest,
		}, "retry-run-7")
		return err
	})
	require.NoError(t, err)

	service := newRuns()
	service.fail("run-7", "att-1")
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
	assert.Equal(t, []string{"run-7"}, service.retried)

	again, err := f.retrying("tick-2", service).RunRequestedRetries(ctx, f.remote.MachineID)
	require.NoError(t, err)
	assert.Empty(t, again)
	assert.Len(t, service.retried, 1)

	// The same request for a run of another version is refused outright.
	_, err = f.store.WithJobTx(ctx, f.jobID, human, func(tx *registry.JobTx) error {
		_, _, err := tx.ProposeRetry(registry.RetryRunParams{RunID: "run-8", RunSpecSHA256: "sha256:older", PackageDigest: job.PackageDigest}, "retry-run-8")
		return err
	})
	assert.Equal(t, registry.CodeStaleBinding, registry.ErrorCode(err))
}

// An effect whose outcome is unknown is escalated as the registry's typed
// txe.uncertain_effect. A person's retry verdict allows exactly one more
// attempt of that intent: the registry consumes it with the grant, and
// refuses the attempt after that until a person decides again.
func TestRemoteUncertainRetryAllowsOneMoreAttempt(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	targetID := "cluster_uid=c-1,uid=vol-1"
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
	want, err := registry.EscalationProposalID(actionID, 1)
	require.NoError(t, err)
	open, err := f.remote.OpenProposals(ctx, f.jobID)
	require.NoError(t, err)
	require.Len(t, open, 1)
	escalation := open[0]
	assert.Equal(t, want, escalation.ID)
	assert.Equal(t, review.ProposalUncertain, escalation.Kind)
	assert.Equal(t, map[string]string{"action_id": actionID}, escalation.Params)
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

// Superseded proposals leave their decision runs waiting. The registry
// lists them as pending closures; the reviewer closes each, the registry
// records the outcome, and one that keeps failing stays pending, is counted
// and becomes an exception without holding up the rest.
func TestRemoteSupersededDecisionRunsAreClosedAndRecorded(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	targetID := "cluster_uid=c-1,uid=vol-1"
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
