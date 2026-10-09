// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// Transport sends one JSON request to the service's API, with paths relative
// to its /api/v1 root, and decodes a successful response into out. A refusal
// by the service is returned as *TransportError.
type Transport interface {
	Do(ctx context.Context, method, path string, in, out any) error
}

// TransportError is a response the service refused. Code is the registry's
// own reason when the refusal came from the TXE registry.
type TransportError struct {
	Status  int
	Code    string
	Message string
}

func (e *TransportError) Error() string {
	return fmt.Sprintf("txe registry: %d %s: %s", e.Status, e.Code, e.Message)
}

// Registry refusal codes the reviewer acts on.
const (
	codeNotFound         = "not_found"
	codeVersionConflict  = "version_conflict"
	codeLifecycle        = "lifecycle"
	codeClaimHeld        = "claim_held"
	codeClaimStale       = "claim_stale"
	codeNotPermitted     = "not_permitted"
	codeStaleBinding     = "stale_binding"
	codeProposalState    = "proposal_state"
	codeActionExists     = "action_exists"
	codeIntentUnresolved = "intent_unresolved"
	codeReviewConflict   = "review_conflict"
)

// Remote implements Registry on the service's /api/v1/txe API, and reads a
// job's finished runs from the service's own run history.
type Remote struct {
	Transport Transport
	// MachineID, RunID and AgentClient identify this reviewer in claims.
	MachineID   string
	RunID       string
	AgentClient string
}

var _ Registry = (*Remote)(nil)

func (r *Remote) actor() *api.TxeActor {
	return &api.TxeActor{Kind: api.TxeActorKindReviewer, Id: r.MachineID + "/" + r.RunID, MachineId: &r.MachineID}
}

func jobPath(jobID string, rest ...string) string {
	var p strings.Builder
	p.WriteString("/txe/jobs/" + url.PathEscape(jobID))
	for _, part := range rest {
		p.WriteString("/" + url.PathEscape(part))
	}
	return p.String()
}

// refusal maps the registry's reason for a refusal onto the reviewer's
// errors. Anything it does not recognise is returned unchanged, so an
// unexpected refusal fails the step instead of being read as permission.
func refusal(err error) error {
	var te *TransportError
	if !errors.As(err, &te) {
		return err
	}
	switch te.Code {
	case codeNotFound:
		return fmt.Errorf("%w: %s", ErrNotFound, te.Message)
	case codeClaimHeld:
		return fmt.Errorf("%w: %s", ErrClaimHeld, te.Message)
	case codeClaimStale:
		return fmt.Errorf("%w: %s", ErrStaleFence, te.Message)
	case codeVersionConflict, codeReviewConflict:
		return fmt.Errorf("%w: %s", ErrConflict, te.Message)
	case codeActionExists:
		return fmt.Errorf("%w: %s", ErrActionExists, te.Message)
	case codeLifecycle:
		return &GuardDeniedError{Reason: DenyLifecycle, Detail: te.Message}
	case codeNotPermitted:
		return &GuardDeniedError{Reason: DenyNotPermitted, Detail: te.Message}
	case codeStaleBinding, codeProposalState:
		return &GuardDeniedError{Reason: DenyDecisionStale, Detail: te.Message}
	case codeIntentUnresolved:
		return &GuardDeniedError{Reason: DenyIntentUnresolved, Detail: te.Message}
	}
	if te.Status == http.StatusNotFound {
		return fmt.Errorf("%w: %s", ErrNotFound, te.Message)
	}
	return err
}

func (r *Remote) do(ctx context.Context, method, path string, in, out any) error {
	return refusal(r.Transport.Do(ctx, method, path, in, out))
}

// targetKey is the reviewer's single-string form of a target's stable
// identity: its fields in key order.
func targetKey(stable map[string]string) string {
	keys := make([]string, 0, len(stable))
	for k := range stable {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+stable[k])
	}
	return strings.Join(parts, ",")
}

// optional returns nil for an empty string, so an absent value is omitted.
func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

func paramsOf(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	var m map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil {
		return out
	}
	for k, val := range m {
		if s, ok := val.(string); ok {
			out[k] = s
		} else {
			out[k] = fmt.Sprint(val)
		}
	}
	return out
}

func paramsValue(params map[string]string) json.RawMessage {
	if len(params) == 0 {
		return nil
	}
	// A string map always marshals, with its keys in order.
	raw, _ := json.Marshal(params)
	return raw
}

// shellCommand runs a registered command line through the shell. Parameters
// never appear in it: they reach the process as environment variables.
func shellCommand(line *string) []string {
	if line == nil || strings.TrimSpace(*line) == "" {
		return nil
	}
	return []string{"/bin/sh", "-c", *line}
}

func paramNames(schema any) []string {
	m, _ := schema.(map[string]any)
	props, _ := m["properties"].(map[string]any)
	names := make([]string, 0, len(props))
	for name := range props {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func cadenceSeconds(cadence *string) int {
	if cadence == nil {
		return 0
	}
	d, err := time.ParseDuration(*cadence)
	if err != nil || d <= 0 {
		return 0
	}
	return int(d / time.Second)
}

func (r *Remote) jobDoc(ctx context.Context, jobID string) (api.TxeJob, error) {
	var doc api.TxeJob
	err := r.do(ctx, http.MethodGet, jobPath(jobID), nil, &doc)
	return doc, err
}

// DueJobs implements Registry.
func (r *Remote) DueJobs(ctx context.Context, machineID string, now time.Time) ([]string, error) {
	q := url.Values{"machine": {machineID}, "review_due_before": {now.UTC().Format(time.RFC3339)}}
	var list api.TxeJobList
	if err := r.do(ctx, http.MethodGet, "/txe/jobs?"+q.Encode(), nil, &list); err != nil {
		return nil, err
	}
	jobs := list.Jobs
	// Longest overdue first; a job never reviewed is the most overdue.
	sort.SliceStable(jobs, func(i, j int) bool {
		a, b := deref(jobs[i].Checkpoint.NextReviewAt), deref(jobs[j].Checkpoint.NextReviewAt)
		if !a.Equal(b) {
			return a.Before(b)
		}
		return jobs[i].JobId < jobs[j].JobId
	})
	ids := make([]string, 0, len(jobs))
	for _, job := range jobs {
		if Lifecycle(job.Lifecycle).Reviewable() {
			ids = append(ids, job.JobId)
		}
	}
	return ids, nil
}

// Job implements Registry. The job's context comes from its current version.
func (r *Remote) Job(ctx context.Context, jobID string) (Job, error) {
	doc, err := r.jobDoc(ctx, jobID)
	if err != nil {
		return Job{}, err
	}
	var v api.TxeJobVersion
	if err := r.do(ctx, http.MethodGet, jobPath(jobID, "versions", strconv.Itoa(doc.Version)), nil, &v); err != nil {
		return Job{}, err
	}
	job := Job{
		ID: doc.JobId, OwnerID: doc.OwnerId, ProjectID: doc.ProjectId, MachineID: doc.MachineId,
		Version: doc.Version, PackageDigest: doc.PackageDigest,
		WorkingDir: deref(v.Package.WorkingDir), Title: v.Title, Purpose: v.Purpose,
		Lifecycle: Lifecycle(doc.Lifecycle), Availability: Availability(doc.Availability.State),
	}
	if job.WorkingDir == "" {
		job.WorkingDir = v.Package.Path
	}
	// The DAG a version runs and the package it runs from are bound by the
	// version's immutable record. The job's digest is given only when that
	// record and the job agree on both, so a run whose snapshot matches it
	// is known to have run this package. Otherwise it is left unknown, and
	// nothing that depends on the binding is proposed.
	if spec := deref(v.Dag.SpecSha256); spec != "" && spec == doc.DagSpecSha256 && v.Package.Digest == doc.PackageDigest {
		job.DAGSpecSHA256 = spec
	}
	for _, t := range deref(v.Targets) {
		job.Targets = append(job.Targets, Target{Kind: t.Kind, StableID: targetKey(t.StableId), Environment: deref(t.Environment)})
	}
	if eo := v.ExpectedOutcome; eo != nil {
		job.ExpectedOutcomes = deref(eo.SuccessCriteria)
		for _, d := range deref(eo.Deliverables) {
			job.Deliverables = append(job.Deliverables, strings.TrimSpace(strings.Join([]string{deref(d.Type), deref(d.Path), deref(d.Description)}, " ")))
		}
	}
	if rr := v.RetirementRules; rr != nil {
		rules := map[string]string{
			"on_target_deleted": string(deref(rr.OnTargetDeleted)),
			"on_replacement":    string(deref(rr.OnReplacement)),
			"on_completion":     string(deref(rr.OnCompletion)),
			"active_run_policy": string(deref(rr.ActiveRunPolicy)),
		}
		for _, name := range []string{"on_target_deleted", "on_replacement", "on_completion", "active_run_policy"} {
			if rules[name] != "" {
				job.RetirementRules = append(job.RetirementRules, name+": "+rules[name])
			}
		}
	}
	if rp := v.ReviewPolicy; rp != nil {
		job.Review = ReviewPolicy{
			Brief: deref(rp.Brief), CadenceSec: cadenceSeconds(rp.Cadence), MaxAttempts: deref(rp.MaxAttempts),
			HumanDecisionConditions: deref(rp.HumanDecisionConditions),
		}
		for _, pa := range deref(rp.PermittedActions) {
			job.Review.Actions = append(job.Review.Actions, DeclaredAction{
				Name: pa.Name, Routine: pa.Routine, Command: shellCommand(pa.Command),
				Params: paramNames(pa.ParamSchema), Idempotency: Idempotency(deref(pa.Idempotency)),
				Reconcile: shellCommand(pa.Reconcile), TimeoutSec: pa.TimeoutSec,
			})
		}
	}
	return job, nil
}

// Checkpoint implements Registry.
func (r *Remote) Checkpoint(ctx context.Context, jobID string) (Checkpoint, error) {
	doc, err := r.jobDoc(ctx, jobID)
	if err != nil {
		return Checkpoint{}, err
	}
	cp := doc.Checkpoint
	return Checkpoint{
		JobID: jobID, Version: cp.Version, RunCursor: deref(cp.RunCursor), DecisionCursor: deref(cp.DecisionCursor),
		LastReviewID: deref(cp.LastReviewId), NextReviewAt: deref(cp.NextReviewAt),
	}, nil
}

// AcquireClaim implements Registry.
func (r *Remote) AcquireClaim(ctx context.Context, req ClaimRequest) (Claim, error) {
	body := api.TxeClaimRequest{
		Actor: r.actor(), Kind: api.TxeClaimKind(req.Kind), TtlSec: int(req.TTL / time.Second),
		Reviewer: api.TxeReviewer{MachineId: &r.MachineID, DagRunId: &r.RunID, AgentClientVersion: &r.AgentClient},
	}
	var out api.TxeClaim
	if err := r.do(ctx, http.MethodPost, jobPath(req.JobID, "claims"), body, &out); err != nil {
		return Claim{}, err
	}
	return Claim{
		ID: out.ClaimId, JobID: req.JobID, Kind: ClaimKind(out.Kind), Holder: req.Holder,
		Fence: int(out.Fence), ExpiresAt: out.ExpiresAt,
	}, nil
}

// ReleaseClaim implements Registry.
func (r *Remote) ReleaseClaim(ctx context.Context, claim Claim) error {
	body := api.TxeFencedRequest{Actor: r.actor(), Fence: int64(claim.Fence)}
	return r.do(ctx, http.MethodPost, jobPath(claim.JobID, "claims", claim.ID, "release"), body, nil)
}

// terminalRunStatuses are the run states that count as a finished result.
var terminalRunStatuses = map[api.StatusLabel]bool{
	api.StatusLabelSucceeded: true, api.StatusLabelFailed: true, api.StatusLabelAborted: true,
	api.StatusLabelPartiallySucceeded: true, api.StatusLabelRejected: true,
}

const runPageLimit = 100

// RunsAfter implements Registry from the service's run history: the job's
// DAG has the job's id as its name.
func (r *Remote) RunsAfter(ctx context.Context, jobID, cursor string) ([]RunEvidence, error) {
	var finished []api.DAGRunSummary
	page := ""
	for {
		q := url.Values{"limit": {strconv.Itoa(runPageLimit)}}
		if page != "" {
			q.Set("cursor", page)
		}
		var resp api.DAGRunsPageResponse
		if err := r.do(ctx, http.MethodGet, "/dag-runs/"+url.PathEscape(jobID)+"?"+q.Encode(), nil, &resp); err != nil {
			return nil, err
		}
		for _, run := range resp.DagRuns {
			if terminalRunStatuses[run.StatusLabel] {
				finished = append(finished, run)
			}
		}
		page = deref(resp.NextCursor)
		if page == "" {
			break
		}
	}
	sort.SliceStable(finished, func(i, j int) bool {
		if finished[i].FinishedAt != finished[j].FinishedAt {
			return finished[i].FinishedAt < finished[j].FinishedAt
		}
		return finished[i].DagRunId < finished[j].DagRunId
	})
	start := 0
	for i, run := range finished {
		if run.DagRunId == cursor {
			start = i + 1
		}
	}
	finished = finished[start:]
	// One packet holds a bounded number of runs; one more tells it that
	// others are waiting.
	if len(finished) > maxPacketRuns+1 {
		finished = finished[:maxPacketRuns+1]
	}
	out := make([]RunEvidence, 0, len(finished))
	for _, run := range finished {
		ev := RunEvidence{RunID: run.DagRunId, Status: string(run.StatusLabel)}
		ev.StartedAt, _ = time.Parse(time.RFC3339, run.StartedAt)
		ev.FinishedAt, _ = time.Parse(time.RFC3339, run.FinishedAt)
		var outputs api.DAGRunOutputs
		err := r.do(ctx, http.MethodGet, "/dag-runs/"+url.PathEscape(jobID)+"/"+url.PathEscape(run.DagRunId)+"/outputs", nil, &outputs)
		switch {
		case err == nil:
			ev.Outputs = outputs.Outputs
		case errors.Is(err, ErrNotFound):
			// A run that failed early has no outputs; its status is the evidence.
		default:
			return nil, fmt.Errorf("outputs of run %s: %w", run.DagRunId, err)
		}
		if ev.SpecSHA256, err = r.runSpecDigest(ctx, jobID, run.DagRunId); err != nil {
			return nil, fmt.Errorf("spec of run %s: %w", run.DagRunId, err)
		}
		if ev.Steps, err = r.stepEvidence(ctx, jobID, run.DagRunId); err != nil {
			return nil, fmt.Errorf("steps of run %s: %w", run.DagRunId, err)
		}
		out = append(out, ev)
	}
	return out, nil
}

// runSpecDigest is the digest of the DAG snapshot a run ran, computed the
// way the registry computes a job's: over the snapshot's YAML as stored. A
// run whose snapshot the service no longer has gets no digest, and nothing
// that needs one is proposed for it.
func (r *Remote) runSpecDigest(ctx context.Context, jobID, runID string) (string, error) {
	var out struct {
		Spec string `json:"spec"`
	}
	err := r.do(ctx, http.MethodGet, "/dag-runs/"+url.PathEscape(jobID)+"/"+url.PathEscape(runID)+"/spec", nil, &out)
	if errors.Is(err, ErrNotFound) || (err == nil && out.Spec == "") {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(out.Spec))), nil
}

const (
	stepLogTailLines = 40
	stepLogTailBytes = 2048
)

// stepEvidence reads the end of each step's output from the service. A
// script's result is in its output whichever way it also publishes values.
func (r *Remote) stepEvidence(ctx context.Context, jobID, runID string) ([]StepEvidence, error) {
	var detail struct {
		DagRunDetails struct {
			Nodes []struct {
				Step struct {
					Name string `json:"name"`
				} `json:"step"`
				StatusLabel string `json:"statusLabel"`
			} `json:"nodes"`
		} `json:"dagRunDetails"`
	}
	base := "/dag-runs/" + url.PathEscape(jobID) + "/" + url.PathEscape(runID)
	if err := r.do(ctx, http.MethodGet, base, nil, &detail); err != nil {
		return nil, err
	}
	steps := make([]StepEvidence, 0, len(detail.DagRunDetails.Nodes))
	for _, node := range detail.DagRunDetails.Nodes {
		step := StepEvidence{Name: node.Step.Name, Status: node.StatusLabel}
		for stream, into := range map[string]*string{"stdout": &step.Stdout, "stderr": &step.Stderr} {
			// The stream parameter is always sent: the service fails a
			// step-log request that omits it.
			q := url.Values{"stream": {stream}, "tail": {strconv.Itoa(stepLogTailLines)}}
			var log struct {
				Content string `json:"content"`
			}
			err := r.do(ctx, http.MethodGet, base+"/steps/"+url.PathEscape(step.Name)+"/log?"+q.Encode(), nil, &log)
			switch {
			case err == nil:
				*into = tailBytes(log.Content, stepLogTailBytes)
			case errors.Is(err, ErrNotFound):
				// The step wrote nothing to this stream.
			default:
				return nil, fmt.Errorf("%s of step %s: %w", stream, step.Name, err)
			}
		}
		steps = append(steps, step)
	}
	return steps, nil
}

func tailBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

func decisionOf(jobID string, d api.TxeDecision) Decision {
	return Decision{
		ID: d.DecisionId, ProposalID: d.ProposalId, JobID: jobID, BindingDigest: d.BindingDigest,
		Verdict: Verdict(d.Verdict), Instructions: deref(d.Instructions), Actor: d.Actor.Id, CreatedAt: d.DecidedAt,
	}
}

// DecisionsAfter implements Registry.
func (r *Remote) DecisionsAfter(ctx context.Context, jobID, cursor string) ([]Decision, error) {
	// Oldest first: the last one is the reviewer's cursor, and the latest
	// answer to a proposal is the one that counts.
	q := url.Values{"order": {"asc"}}
	if cursor != "" {
		q.Set("since", cursor)
	}
	var list api.TxeDecisionList
	if err := r.do(ctx, http.MethodGet, jobPath(jobID, "decisions")+"?"+q.Encode(), nil, &list); err != nil {
		return nil, err
	}
	out := make([]Decision, 0, len(list.Decisions))
	for _, d := range list.Decisions {
		out = append(out, decisionOf(jobID, d))
	}
	return out, nil
}

// Decision implements Registry.
func (r *Remote) Decision(ctx context.Context, jobID, decisionID string) (Decision, error) {
	all, err := r.DecisionsAfter(ctx, jobID, "")
	if err != nil {
		return Decision{}, err
	}
	for _, d := range all {
		if d.ID == decisionID {
			return d, nil
		}
	}
	return Decision{}, ErrNotFound
}

func (r *Remote) proposalOf(jobID string, p api.TxeProposal) Proposal {
	out := Proposal{
		ID: p.ProposalId, JobID: jobID, JobVersion: p.JobVersion, PackageDigest: p.PackageDigest,
		Kind: ProposalQuestion, Question: deref(p.Question), Rationale: deref(p.Rationale),
		ReviewID: deref(p.ReviewId), BindingDigest: p.BindingDigest, State: ProposalState(p.State),
		WaitingOn: string(deref(p.WaitingOn)),
	}
	for _, v := range deref(p.AllowedVerdicts) {
		out.AllowedVerdicts = append(out.AllowedVerdicts, Verdict(v))
	}
	if ev := p.Evidence; ev != nil {
		out.EvidenceRuns = deref(ev.RunIds)
		out.ObservedAt = deref(ev.ObservedAt)
		for _, ref := range deref(ev.ArtifactRefs) {
			out.ArtifactRefs = append(out.ArtifactRefs, ref.Path)
		}
	}
	if nt := p.NativeTask; nt != nil {
		out.NativeTask = TaskLocator{DAG: nt.Dag, RunID: nt.RunId, StepID: nt.StepId}
	}
	switch {
	case p.Action.Name == UncertainEffectAction:
		out.Kind = ProposalUncertain
	case p.Action.Name != "":
		out.Kind = ProposalAction
	}
	if out.Kind != ProposalQuestion {
		out.ActionName = p.Action.Name
		out.Params = paramsOf(p.Action.Params)
	}
	if out.Kind == ProposalUncertain {
		out.RelatedAction = out.Params[UncertainEffectParam]
	}
	if t := p.Action.Target; t != nil {
		out.TargetID = targetKey(t.StableId)
	}
	return out
}

func (r *Remote) proposals(ctx context.Context, jobID string) (api.TxeProposalList, error) {
	var list api.TxeProposalList
	err := r.do(ctx, http.MethodGet, jobPath(jobID, "proposals"), nil, &list)
	return list, err
}

// Proposal implements Registry.
func (r *Remote) Proposal(ctx context.Context, jobID, proposalID string) (Proposal, error) {
	list, err := r.proposals(ctx, jobID)
	if err != nil {
		return Proposal{}, err
	}
	for _, p := range append(list.Open, list.Finished...) {
		if p.ProposalId == proposalID {
			return r.proposalOf(jobID, p), nil
		}
	}
	return Proposal{}, ErrNotFound
}

// OpenProposals implements Registry.
func (r *Remote) OpenProposals(ctx context.Context, jobID string) ([]Proposal, error) {
	list, err := r.proposals(ctx, jobID)
	if err != nil {
		return nil, err
	}
	var out []Proposal
	for _, p := range list.Open {
		if p.State == api.TxeProposalState(ProposalOpen) || p.State == api.TxeProposalState(ProposalSnoozed) {
			out = append(out, r.proposalOf(jobID, p))
		}
	}
	return out, nil
}

// PendingClosures implements Registry from the registry's own list of
// superseded proposals whose decision run is still to be closed: never
// attempted first, then least recently attempted.
func (r *Remote) PendingClosures(ctx context.Context, machineID string, limit int) ([]Proposal, error) {
	q := url.Values{"machine": {machineID}}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var list api.TxePendingClosureList
	if err := r.do(ctx, http.MethodGet, "/txe/proposal-closures/pending?"+q.Encode(), nil, &list); err != nil {
		return nil, err
	}
	out := make([]Proposal, 0, len(list.Closures))
	for _, c := range list.Closures {
		out = append(out, Proposal{
			ID: c.ProposalId, JobID: c.JobId, State: ProposalSuperseded,
			NativeTask: TaskLocator{DAG: c.NativeTask.Dag, RunID: c.NativeTask.RunId, StepID: c.NativeTask.StepId},
		})
	}
	return out, nil
}

// RequestedRetries implements Registry. A retry a person requested is a
// decided retry proposal without a native task; one that already has a
// journaled action was attempted and is the journal's business from then on.
func (r *Remote) RequestedRetries(ctx context.Context, machineID string, limit int) ([]RequestedRetry, error) {
	var list api.TxeJobList
	if err := r.do(ctx, http.MethodGet, "/txe/jobs?"+url.Values{"machine": {machineID}}.Encode(), nil, &list); err != nil {
		return nil, err
	}
	var out []RequestedRetry
	for _, job := range list.Jobs {
		if !Lifecycle(job.Lifecycle).Reviewable() {
			continue
		}
		proposals, err := r.proposals(ctx, job.JobId)
		if err != nil {
			return nil, err
		}
		var decided []string
		for _, p := range append(proposals.Open, proposals.Finished...) {
			if p.State == api.TxeProposalState(ProposalDecided) && p.Action.Name == RetryRunAction && p.NativeTask == nil {
				decided = append(decided, p.ProposalId)
			}
		}
		if len(decided) == 0 {
			continue
		}
		actions, err := r.Actions(ctx, job.JobId)
		if err != nil {
			return nil, err
		}
		attempted := map[string]bool{}
		for _, a := range actions {
			attempted[a.ProposalID] = true
		}
		decisions, err := r.DecisionsAfter(ctx, job.JobId, "")
		if err != nil {
			return nil, err
		}
		sort.Strings(decided)
		for _, id := range decided {
			if attempted[id] {
				continue
			}
			// The latest answer to a proposal is the one that counts.
			for _, d := range slices.Backward(decisions) {
				if d.ProposalID != id {
					continue
				}
				if d.Verdict == VerdictRetry {
					out = append(out, RequestedRetry{JobID: job.JobId, ProposalID: id, DecisionID: d.ID})
				}
				break
			}
			if limit > 0 && len(out) >= limit {
				return out, nil
			}
		}
	}
	return out, nil
}

// RecordClosure implements Registry. The registry keeps every attempt and
// counts the failed ones; any other outcome is final and takes the proposal
// off its pending list.
func (r *Remote) RecordClosure(ctx context.Context, closure Closure) (int, error) {
	body := api.TxeClosureRequest{Actor: r.actor(), Outcome: api.TxeClosureOutcome(closure.Outcome), Detail: optional(closure.Detail)}
	var out api.TxeClosure
	err := r.do(ctx, http.MethodPost, jobPath(closure.JobID, "proposals", closure.ProposalID, "closures"), body, &out)
	if denied, ok := errors.AsType[*GuardDeniedError](err); ok && denied.Reason == DenyDecisionStale {
		// Another final outcome is already recorded for this proposal. The
		// record stands and there is nothing left to close.
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if closure.Outcome != ClosureFailed {
		return 0, nil
	}
	return out.Attempt, nil
}

// reviewDetail is what the reviewer keeps in a review record's free-form
// detail: the parts of a review the registry has no typed field for.
type reviewDetail struct {
	Episode          int       `json:"episode"`
	CoveredRuns      []string  `json:"covered_run_ids"`
	CoveredDecisions []string  `json:"covered_decision_ids"`
	ActionIDs        []string  `json:"action_ids,omitempty"`
	ProposalIDs      []string  `json:"proposal_ids,omitempty"`
	Notes            []string  `json:"notes,omitempty"`
	Reviewer         string    `json:"reviewer"`
	Handoff          LocalFile `json:"handoff,omitzero"`
}

// Review implements Registry.
func (r *Remote) Review(ctx context.Context, jobID, reviewID string) (Review, error) {
	var rev api.TxeReview
	if err := r.do(ctx, http.MethodGet, jobPath(jobID, "reviews", reviewID), nil, &rev); err != nil {
		return Review{}, err
	}
	var detail reviewDetail
	if raw, err := json.Marshal(rev.Detail); err == nil {
		_ = json.Unmarshal(raw, &detail)
	}
	return Review{
		ID: rev.ReviewId, JobID: jobID, JobVersion: deref(rev.JobVersion), Episode: detail.Episode,
		Outcome: Outcome(rev.Outcome), Reasoning: deref(rev.Reasoning), EvidenceRuns: deref(rev.EvidenceRunIds),
		CoveredRuns: detail.CoveredRuns, CoveredDecisions: detail.CoveredDecisions,
		ActionIDs: detail.ActionIDs, ProposalIDs: detail.ProposalIDs, Notes: detail.Notes,
		Reviewer: detail.Reviewer, AgentClient: deref(rev.AgentClientVersion), PacketBytes: int(deref(rev.PacketBytes)),
		AgentInputTokens: int(deref(rev.AgentInputTokens)), AgentOutputTokens: int(deref(rev.AgentOutputTokens)),
		PacketArtifact: deref(rev.PacketArtifact), DecisionArtifact: deref(rev.DecisionArtifact),
		Handoff: detail.Handoff,
	}, nil
}

func (r *Remote) actionOf(jobID string, a api.TxeAction) Action {
	out := Action{
		ID: a.ActionId, JobID: jobID, JobVersion: a.JobVersion, Name: a.Spec.Name, Params: paramsOf(a.Spec.Params),
		ReviewID: deref(a.ReviewId), ProposalID: deref(a.ProposalId), DecisionID: deref(a.DecisionId),
		State: ActionState(a.State), Receipt: deref(a.Receipt), ClaimID: deref(a.ClaimId),
		StartedAt: a.Created.At, FinishedAt: a.Updated.At,
	}
	if t := a.Spec.Target; t != nil {
		out.TargetID = targetKey(t.StableId)
	}
	out.IntentKey = IntentKey(out.Name, out.TargetID, out.Params)
	if g := a.Grant; g != nil {
		out.GrantID, out.GrantExpiresAt = g.GrantId, g.ExpiresAt
	}
	var outcome struct {
		Detail string `json:"detail"`
	}
	if len(a.Outcome) > 0 && json.Unmarshal(a.Outcome, &outcome) == nil {
		out.Detail = outcome.Detail
	}
	// The registry's first state for an authorized attempt is one the
	// reviewer treats the same as executing: the effect may have begun.
	if out.State == "intended" {
		out.State = ActionExecuting
	}
	return out
}

// Actions implements Registry.
func (r *Remote) Actions(ctx context.Context, jobID string) ([]Action, error) {
	var list api.TxeActionList
	if err := r.do(ctx, http.MethodGet, jobPath(jobID, "actions"), nil, &list); err != nil {
		return nil, err
	}
	all := append(list.Archived, list.InFlight...)
	sort.SliceStable(all, func(i, j int) bool { return all[i].Created.At.Before(all[j].Created.At) })
	out := make([]Action, 0, len(all))
	for _, a := range all {
		out = append(out, r.actionOf(jobID, a))
	}
	return out, nil
}

func (r *Remote) specOf(ctx context.Context, jobID, name, targetID string, params map[string]string) (api.TxeActionSpec, error) {
	spec := api.TxeActionSpec{Name: name, Params: paramsValue(params)}
	if targetID == "" {
		return spec, nil
	}
	doc, err := r.jobDoc(ctx, jobID)
	if err != nil {
		return spec, err
	}
	var v api.TxeJobVersion
	if err := r.do(ctx, http.MethodGet, jobPath(jobID, "versions", strconv.Itoa(doc.Version)), nil, &v); err != nil {
		return spec, err
	}
	for _, t := range deref(v.Targets) {
		if targetKey(t.StableId) == targetID {
			target := t
			spec.Target = &target
			return spec, nil
		}
	}
	return spec, &GuardDeniedError{Reason: DenyNotPermitted, Detail: "target " + targetID + " is not a target of the job's current version"}
}

func routineActionID(reviewID string, spec api.TxeActionSpec) (string, error) {
	raw, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	var stored registry.ActionSpec
	if err := json.Unmarshal(raw, &stored); err != nil {
		return "", err
	}
	return registry.RoutineActionID(reviewID, stored)
}

// BeginAction implements Registry through the registry's effect grant, which
// is its pre-effect guard and its journal entry in one transaction.
func (r *Remote) BeginAction(ctx context.Context, req BeginRequest) (Action, error) {
	jobID := req.Claim.JobID
	doc, err := r.jobDoc(ctx, jobID)
	if err != nil {
		return Action{}, err
	}
	body := api.TxeEffectGrantRequest{
		ActionId: req.ActionID, Actor: r.actor(), JobVersion: req.JobVersion, PackageDigest: doc.PackageDigest,
	}
	if req.DecisionID != "" {
		body.Approved = &struct {
			ClaimId    string `json:"claim_id"`
			DecisionId string `json:"decision_id"`
			Fence      int64  `json:"fence"`
			ProposalId string `json:"proposal_id"`
		}{ClaimId: req.Claim.ID, DecisionId: req.DecisionID, Fence: int64(req.Claim.Fence), ProposalId: req.ProposalID}
	} else {
		spec, err := r.specOf(ctx, jobID, req.Name, req.TargetID, req.Params)
		if err != nil {
			return Action{}, err
		}
		// The registry derives a routine action's id from the review and
		// the spec as it stores them, and refuses any other id.
		if req.ActionID, err = routineActionID(req.ReviewID, spec); err != nil {
			return Action{}, err
		}
		body.ActionId = req.ActionID
		body.Routine = &struct {
			ClaimId  string            `json:"claim_id"`
			Fence    int64             `json:"fence"`
			ReviewId string            `json:"review_id"`
			Spec     api.TxeActionSpec `json:"spec"`
		}{ClaimId: req.Claim.ID, Fence: int64(req.Claim.Fence), ReviewId: req.ReviewID, Spec: spec}
	}
	var grant api.TxeGrant
	err = r.do(ctx, http.MethodPost, jobPath(jobID, "effect-grants"), body, &grant)
	if errors.Is(err, ErrActionExists) {
		// The stored record is authoritative; nothing may run on it.
		actions, listErr := r.Actions(ctx, jobID)
		if listErr != nil {
			return Action{}, listErr
		}
		for _, a := range actions {
			if a.ID == req.ActionID {
				return a, ErrActionExists
			}
		}
		return Action{ID: req.ActionID, JobID: jobID, State: ActionUncertain}, ErrActionExists
	}
	if err != nil {
		return Action{}, err
	}
	return Action{
		ID: req.ActionID, JobID: jobID, JobVersion: req.JobVersion, Name: req.Name, TargetID: req.TargetID,
		Params: req.Params, IntentKey: req.IntentKey, ReviewID: req.ReviewID, ProposalID: req.ProposalID,
		DecisionID: req.DecisionID, State: ActionExecuting, GrantID: grant.GrantId, GrantExpiresAt: grant.ExpiresAt,
		ClaimID: req.Claim.ID,
	}, nil
}

// FinishAction implements Registry.
func (r *Remote) FinishAction(ctx context.Context, req FinishRequest) error {
	body := api.TxeSettleRequest{
		Actor: r.actor(), ClaimId: req.Claim.ID, Fence: int64(req.Claim.Fence), GrantId: req.GrantID,
		State: api.TxeActionState(req.State),
	}
	if req.Receipt != "" {
		body.Receipt = &req.Receipt
	}
	if req.Detail != "" {
		body.Outcome, _ = json.Marshal(map[string]string{"detail": req.Detail})
	}
	return r.do(ctx, http.MethodPut, jobPath(req.JobID, "actions", req.ActionID), body, nil)
}

// CreateProposal implements Registry.
func (r *Remote) CreateProposal(ctx context.Context, claim Claim, draft Proposal) (Proposal, error) {
	in := api.TxeProposalInput{
		ProposalId: draft.ID, Question: &draft.Question,
		NativeTask: &api.TxeNativeTask{Dag: draft.NativeTask.DAG, RunId: draft.NativeTask.RunID, StepId: draft.NativeTask.StepID},
		Evidence:   &api.TxeProposalEvidence{RunIds: &draft.EvidenceRuns},
	}
	if draft.Rationale != "" {
		in.Rationale = &draft.Rationale
	}
	if draft.ReviewID != "" {
		in.ReviewId = &draft.ReviewID
	}
	if !draft.ObservedAt.IsZero() {
		in.Evidence.ObservedAt = &draft.ObservedAt
	}
	if draft.WaitingOn != "" {
		w := api.TxeProposalInputWaitingOn(draft.WaitingOn)
		in.WaitingOn = &w
	}
	verdicts := make([]api.TxeVerdict, 0, len(draft.AllowedVerdicts))
	for _, v := range draft.AllowedVerdicts {
		verdicts = append(verdicts, api.TxeVerdict(v))
	}
	in.AllowedVerdicts = &verdicts
	if draft.Kind == ProposalUncertain {
		// A reserved, non-executable action naming the journaled action.
		in.Action = api.TxeActionSpec{Name: UncertainEffectAction, Params: paramsValue(draft.Params)}
	}
	if draft.Kind == ProposalAction {
		spec, err := r.specOf(ctx, draft.JobID, draft.ActionName, draft.TargetID, draft.Params)
		if err != nil {
			return Proposal{}, err
		}
		in.Action = spec
	}
	var out api.TxeProposal
	body := api.TxeProposalRequest{Actor: r.actor(), ClaimId: claim.ID, Fence: int64(claim.Fence), Proposal: in}
	if err := r.do(ctx, http.MethodPost, jobPath(draft.JobID, "proposals"), body, &out); err != nil {
		return Proposal{}, err
	}
	return r.proposalOf(draft.JobID, out), nil
}

// RecordReview implements Registry.
func (r *Remote) RecordReview(ctx context.Context, claim Claim, rev Review) error {
	detail := reviewDetail{
		Episode: rev.Episode, CoveredRuns: rev.CoveredRuns, CoveredDecisions: rev.CoveredDecisions,
		ActionIDs: rev.ActionIDs, ProposalIDs: rev.ProposalIDs, Notes: rev.Notes, Reviewer: rev.Reviewer,
		Handoff: rev.Handoff,
	}
	body := api.TxeReviewRequest{
		Actor: r.actor(), ClaimId: claim.ID, Fence: int64(claim.Fence),
		Review: api.TxeReview{
			ReviewId: rev.ID, Outcome: api.TxeReviewOutcome(rev.Outcome), Reasoning: &rev.Reasoning,
			EvidenceRunIds: &rev.EvidenceRuns, EvidenceDecisionIds: &rev.CoveredDecisions,
			AgentClientVersion: &rev.AgentClient, Detail: detail,
			PacketArtifact: optional(rev.PacketArtifact), DecisionArtifact: optional(rev.DecisionArtifact),
			PacketBytes: count(rev.PacketBytes), AgentInputTokens: count(rev.AgentInputTokens), AgentOutputTokens: count(rev.AgentOutputTokens),
		},
	}
	if err := r.do(ctx, http.MethodPost, jobPath(rev.JobID, "reviews"), body, nil); err != nil {
		return err
	}
	return r.reviewerRecovered(ctx, rev.JobID)
}

// count returns nil for zero, so an unknown count is omitted.
func count(n int) *int64 {
	if n == 0 {
		return nil
	}
	v := int64(n)
	return &v
}

// reviewerRecovered tells the registry the reviewer works again, once a
// review was recorded for a job whose reviewer it had as unavailable. That
// resolves the reviewer's open exceptions; the job's own availability is
// not touched.
func (r *Remote) reviewerRecovered(ctx context.Context, jobID string) error {
	doc, err := r.jobDoc(ctx, jobID)
	if err != nil {
		return err
	}
	if av := doc.ReviewerAvailability; av == nil || av.State == api.TxeAvailabilityState(registry.AvailabilityReady) {
		return nil
	}
	scope := api.TxeObservationRequestScopeReviewer
	detail := "a review was recorded"
	body := api.TxeObservationRequest{Actor: r.actor(), State: api.TxeAvailabilityState(registry.AvailabilityReady), Scope: &scope, Detail: &detail}
	return r.do(ctx, http.MethodPost, jobPath(jobID, "observations"), body, nil)
}

// AdvanceCheckpoint implements Registry.
func (r *Remote) AdvanceCheckpoint(ctx context.Context, claim Claim, next Checkpoint, expectedVersion int) error {
	cp := api.TxeCheckpoint{Version: next.Version}
	if next.RunCursor != "" {
		cp.RunCursor = &next.RunCursor
	}
	if next.DecisionCursor != "" {
		cp.DecisionCursor = &next.DecisionCursor
	}
	if next.LastReviewID != "" {
		cp.LastReviewId = &next.LastReviewID
	}
	if !next.NextReviewAt.IsZero() {
		cp.NextReviewAt = &next.NextReviewAt
	}
	body := api.TxeCheckpointRequest{
		Actor: r.actor(), Checkpoint: cp, ClaimId: claim.ID, ExpectedVersion: expectedVersion, Fence: int64(claim.Fence),
	}
	return r.do(ctx, http.MethodPut, jobPath(next.JobID, "checkpoint"), body, nil)
}

// DeferReview implements Registry.
func (r *Remote) DeferReview(ctx context.Context, claim Claim, until time.Time) error {
	body := api.TxeDeferRequest{Actor: r.actor(), ClaimId: claim.ID, Fence: int64(claim.Fence), NextReviewAt: until}
	return r.do(ctx, http.MethodPost, jobPath(claim.JobID, "checkpoint", "defer"), body, nil)
}

// exceptionStates maps a reviewer exception onto the availability state the
// registry files it under. None of them is a lifecycle change.
var exceptionStates = map[ExceptionKind]api.TxeAvailabilityState{
	ExceptionReviewerAuth:   "auth_required",
	ExceptionReviewerFailed: "stale",
	ExceptionUnavailable:    "target_unreachable",
}

// jobExceptions are the exceptions about the job itself. Every other one is
// a problem of the reviewer, which the registry keeps apart: a reviewer
// that cannot run does not make the job unavailable.
var jobExceptions = map[ExceptionKind]bool{ExceptionUnavailable: true}

// RaiseException implements Registry.
func (r *Remote) RaiseException(ctx context.Context, exc Exception) error {
	kind := string(exc.Kind)
	body := api.TxeObservationRequest{Actor: r.actor(), State: exceptionStates[exc.Kind], Kind: &kind, Detail: &exc.Message}
	if body.State == "" {
		body.State = "stale"
	}
	if !jobExceptions[exc.Kind] {
		scope := api.TxeObservationRequestScopeReviewer
		body.Scope = &scope
		// The registry files one exception per observation. A reviewer that
		// fails the same way on every tick reports it once, not once a tick.
		doc, err := r.jobDoc(ctx, exc.JobID)
		if err != nil {
			return err
		}
		if av := doc.ReviewerAvailability; av != nil && av.State == body.State && deref(av.Detail) == exc.Message {
			return nil
		}
	}
	return r.do(ctx, http.MethodPost, jobPath(exc.JobID, "observations"), body, nil)
}

// RemoteEnqueue returns an EnqueueFunc that opens a decision run through the
// service, with the run id the reviewer derived for the proposal.
func RemoteEnqueue(t Transport) EnqueueFunc {
	return func(ctx context.Context, dag, runID string, params map[string]string) error {
		names := make([]string, 0, len(params))
		for name := range params {
			names = append(names, name)
		}
		sort.Strings(names)
		pairs := make([]string, 0, len(names))
		for _, name := range names {
			pairs = append(pairs, name+"="+strconv.Quote(params[name]))
		}
		joined := strings.Join(pairs, " ")
		body := map[string]any{"dagRunId": runID, "params": joined}
		err := t.Do(ctx, http.MethodPost, "/dags/"+url.PathEscape(dag)+"/enqueue", body, nil)
		var te *TransportError
		// The service reports a taken run id as a conflict or, on some
		// paths, as a plain error whose message says so.
		if errors.As(err, &te) && (te.Status == http.StatusConflict || strings.Contains(te.Message, "already exists")) {
			return ErrRunExists
		}
		return err
	}
}

// RemoteComplete returns a CompleteFunc that completes a human task through
// the service.
func RemoteComplete(t Transport) CompleteFunc {
	return func(ctx context.Context, task TaskLocator, input map[string]string) error {
		path := "/dag-runs/" + url.PathEscape(task.DAG) + "/" + url.PathEscape(task.RunID) +
			"/human-tasks/" + url.PathEscape(task.StepID) + "/complete"
		err := t.Do(ctx, http.MethodPost, path, input, nil)
		// 409: the task was already completed with another input. 404: the
		// service knows no such run. An identical earlier completion is a
		// plain success.
		if te, ok := errors.AsType[*TransportError](err); ok {
			switch te.Status {
			case http.StatusConflict:
				return ErrTaskAnswered
			case http.StatusNotFound:
				return ErrRunMissing
			}
		}
		return err
	}
}

// RemoteRetry returns a RetryFunc that retries one run through the service
// and reports the service's answer as the receipt.
func RemoteRetry(t Transport) RetryFunc {
	return func(ctx context.Context, jobID, runID string) (string, error) {
		var out json.RawMessage
		path := "/dag-runs/" + url.PathEscape(jobID) + "/" + url.PathEscape(runID) + "/retry"
		if err := t.Do(ctx, http.MethodPost, path, map[string]string{"dagRunId": runID}, &out); err != nil {
			return "", err
		}
		receipt := "retry of " + runID + " accepted"
		if len(out) > 0 && len(out) < maxReceiptLen {
			receipt += ": " + string(out)
		}
		return receipt, nil
	}
}
