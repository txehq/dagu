// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
	p := "/txe/jobs/" + url.PathEscape(jobID)
	for _, part := range rest {
		p += "/" + url.PathEscape(part)
	}
	return p
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

func deref[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}

func paramsOf(v any) map[string]string {
	out := map[string]string{}
	m, ok := v.(map[string]any)
	if !ok {
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

func paramsValue(params map[string]string) any {
	if len(params) == 0 {
		return nil
	}
	out := make(map[string]any, len(params))
	for k, v := range params {
		out[k] = v
	}
	return out
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
		out = append(out, ev)
	}
	return out, nil
}

func decisionOf(jobID string, d api.TxeDecision) Decision {
	return Decision{
		ID: d.DecisionId, ProposalID: d.ProposalId, JobID: jobID, BindingDigest: d.BindingDigest,
		Verdict: Verdict(d.Verdict), Instructions: deref(d.Instructions), Actor: d.Actor.Id, CreatedAt: d.DecidedAt,
	}
}

// DecisionsAfter implements Registry.
func (r *Remote) DecisionsAfter(ctx context.Context, jobID, cursor string) ([]Decision, error) {
	path := jobPath(jobID, "decisions")
	if cursor != "" {
		path += "?" + url.Values{"since": {cursor}}.Encode()
	}
	var list api.TxeDecisionList
	if err := r.do(ctx, http.MethodGet, path, nil, &list); err != nil {
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
		WaitingOn: string(deref(p.WaitingOn)), RelatedAction: deref(p.Reasoning),
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
	case out.RelatedAction != "":
		out.Kind = ProposalUncertain
	case p.Action.Name != "":
		out.Kind = ProposalAction
	}
	if out.Kind != ProposalQuestion {
		out.ActionName = p.Action.Name
		out.Params = paramsOf(p.Action.Params)
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

// reviewDetail is what the reviewer keeps in a review record's free-form
// detail until the registry has typed fields for it.
type reviewDetail struct {
	Episode           int      `json:"episode"`
	CoveredRuns       []string `json:"covered_run_ids"`
	CoveredDecisions  []string `json:"covered_decision_ids"`
	ActionIDs         []string `json:"action_ids,omitempty"`
	ProposalIDs       []string `json:"proposal_ids,omitempty"`
	Notes             []string `json:"notes,omitempty"`
	Reviewer          string   `json:"reviewer"`
	PacketBytes       int      `json:"packet_bytes"`
	AgentInputTokens  int      `json:"agent_input_tokens,omitempty"`
	AgentOutputTokens int      `json:"agent_output_tokens,omitempty"`
}

// Review implements Registry.
func (r *Remote) Review(ctx context.Context, jobID, reviewID string) (Review, error) {
	var list api.TxeReviewList
	if err := r.do(ctx, http.MethodGet, jobPath(jobID, "reviews"), nil, &list); err != nil {
		return Review{}, err
	}
	for _, rev := range list.Reviews {
		if rev.ReviewId != reviewID {
			continue
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
			Reviewer: detail.Reviewer, AgentClient: deref(rev.AgentClientVersion), PacketBytes: detail.PacketBytes,
		}, nil
	}
	return Review{}, ErrNotFound
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
	if m, ok := a.Outcome.(map[string]any); ok {
		out.Detail, _ = m["detail"].(string)
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
		body.Outcome = map[string]any{"detail": req.Detail}
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
	if draft.RelatedAction != "" {
		// The escalated action's id; the registry has no typed field for it.
		in.Reasoning = &draft.RelatedAction
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
		PacketBytes: rev.PacketBytes, AgentInputTokens: rev.AgentInputTokens, AgentOutputTokens: rev.AgentOutputTokens,
	}
	body := api.TxeReviewRequest{
		Actor: r.actor(), ClaimId: claim.ID, Fence: int64(claim.Fence),
		Review: api.TxeReview{
			ReviewId: rev.ID, Outcome: api.TxeReviewOutcome(rev.Outcome), Reasoning: &rev.Reasoning,
			EvidenceRunIds: &rev.EvidenceRuns, EvidenceDecisionIds: &rev.CoveredDecisions,
			AgentClientVersion: &rev.AgentClient, Detail: detail,
		},
	}
	return r.do(ctx, http.MethodPost, jobPath(rev.JobID, "reviews"), body, nil)
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

// RaiseException implements Registry.
func (r *Remote) RaiseException(ctx context.Context, exc Exception) error {
	kind := string(exc.Kind)
	body := api.TxeObservationRequest{Actor: r.actor(), State: exceptionStates[exc.Kind], Kind: &kind, Detail: &exc.Message}
	if body.State == "" {
		body.State = "stale"
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
		if errors.As(err, &te) && te.Status == http.StatusConflict {
			return ErrRunExists
		}
		return err
	}
}
