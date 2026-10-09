// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dag"
	"github.com/dagucloud/dagu/v2/internal/runtime"
	apiv1 "github.com/dagucloud/dagu/v2/internal/service/frontend/api/v1"
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
	cfg.Server.Permissions = map[config.Permission]bool{config.PermissionWriteDAGs: true}
	a := apiv1.New(repo, nil, nil, nil, runtime.Manager{}, cfg, nil, nil, prometheus.NewRegistry(), nil, apiv1.WithTxeRegistry(store))

	router := chi.NewRouter()
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
	return &remoteFixture{t: t, store: store, remote: remote, jobID: jobID, target: target, fx: newEffects(), opener: &opener{}}
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
	require.Len(t, packet.Job.Review.Actions, 2)
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
	calls   []string
	fail    map[string]*review.TransportError
}

func (s *stubTransport) Do(_ context.Context, method, path string, _, out any) error {
	s.calls = append(s.calls, method+" "+path)
	if e, ok := s.fail[path]; ok {
		return e
	}
	raw, ok := s.replies[path]
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
		"/dag-runs/" + job + "/r2/outputs": `{"metadata":{},"outputs":{"free_pct":"31"}}`,
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
	assert.False(t, runs[0].FinishedAt.IsZero())

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
