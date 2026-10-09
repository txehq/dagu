// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	codeInvalid          = "invalid"
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

// targetKey is the reviewer's single-string form of a registered target. It
// is the registry's own canonical identity, over the target's kind and its
// whole stable id, so two targets never share one: not two kinds with the
// same id, and not two ids that only read alike once their fields are
// joined.
func targetKey(t api.TxeTarget) string {
	return registry.TargetKey(registry.Target{Kind: t.Kind, StableID: t.StableId})
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
	// Numbers are kept as they are written, not as floating point: a value
	// stored as 1000000 reaches the command as 1000000, and its intent key
	// is the one the reviewer computed from that text.
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var m map[string]any
	if len(raw) == 0 || dec.Decode(&m) != nil {
		return out
	}
	for k, val := range m {
		switch v := val.(type) {
		case string:
			out[k] = v
		case json.Number:
			out[k] = v.String()
		default:
			out[k] = fmt.Sprint(val)
		}
	}
	return out
}

// paramsValue encodes an action's parameters for the registry. The reviewer
// carries every value as text: that is what the agent returns and what the
// command receives in its environment. The registry validates the values
// against the schema the job declares, as JSON and without coercion, so a
// value whose property the schema types as integer, number or boolean is
// sent as that JSON type when its text is exactly one. Any other value is
// sent as the string it is, and the registry decides: nothing is guessed or
// repaired here. schema is the action's declared param_schema, or nil.
func paramsValue(params map[string]string, schema any) json.RawMessage {
	if len(params) == 0 {
		return nil
	}
	m, _ := schema.(map[string]any)
	props, _ := m["properties"].(map[string]any)
	typed := make(map[string]json.RawMessage, len(params))
	for name, text := range params {
		prop, _ := props[name].(map[string]any)
		declared, _ := prop["type"].(string)
		typed[name] = paramValue(text, declared)
	}
	// A map always marshals, with its keys in order.
	raw, _ := json.Marshal(typed)
	return raw
}

// paramValue is one parameter's JSON value: text as the declared type when
// it is exactly a value of that type, and as a string otherwise.
func paramValue(text, declared string) json.RawMessage {
	switch declared {
	case "integer":
		// Only the canonical text of an integer: "007" and "+7" stay text.
		if n, err := strconv.ParseInt(text, 10, 64); err == nil && strconv.FormatInt(n, 10) == text {
			return json.RawMessage(text)
		}
	case "number":
		var n json.Number
		if json.Unmarshal([]byte(text), &n) == nil && n.String() == text {
			return json.RawMessage(text)
		}
	case "boolean":
		if text == "true" || text == "false" {
			return json.RawMessage(text)
		}
	}
	raw, _ := json.Marshal(text)
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
		job.Targets = append(job.Targets, Target{Kind: t.Kind, StableID: targetKey(t), Identity: t.StableId, Environment: deref(t.Environment)})
	}
	if eo := v.ExpectedOutcome; eo != nil {
		job.ExpectedOutcomes = deref(eo.SuccessCriteria)
		for _, d := range deref(eo.Deliverables) {
			job.Deliverables = append(job.Deliverables, strings.TrimSpace(strings.Join(strings.Fields(strings.Join([]string{d.Name, deref(d.Type), d.Path, deref(d.Description)}, " ")), " ")))
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
		Fence: int(out.Fence), ExpiresAt: out.ExpiresAt, AcquiredAt: out.AcquiredAt,
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

// walkRuns visits every run the service lists for the job, newest created
// first.
func (r *Remote) walkRuns(ctx context.Context, jobID string, visit func(runSummary) error) error {
	page := ""
	for {
		q := url.Values{"limit": {strconv.Itoa(runPageLimit)}}
		if page != "" {
			q.Set("cursor", page)
		}
		var resp struct {
			DagRuns    []runSummary `json:"dagRuns"`
			NextCursor *string      `json:"nextCursor"`
		}
		if err := r.do(ctx, http.MethodGet, "/dag-runs/"+url.PathEscape(jobID)+"?"+q.Encode(), nil, &resp); err != nil {
			return err
		}
		for _, run := range resp.DagRuns {
			if err := visit(run); err != nil {
				return err
			}
		}
		if page = deref(resp.NextCursor); page == "" {
			return nil
		}
	}
}

// RunsAfter implements Registry from the service's run history: the job's
// DAG has the job's id as its name. It returns the results no recorded
// review covers yet, oldest first.
//
// What is covered is not kept in a cursor. It is what the job's recorded
// reviews say they covered, each result named by run and execution
// (covered_executions). A result is covered exactly when a recorded review
// names it, so nothing is covered before the review that was shown it is
// persisted, a crash or a failed read covers nothing, and no ordering of
// end times, late report or number of unfinished runs can make a result
// pass for covered. The cursor argument is not used.
//
// The service shows one result per run: its latest execution. An execution
// that was replaced by a retry between two reviews was never listed and is
// not reviewed.
//
// A review that names no executions, as one recorded before coverage was
// by execution, covers nothing here: its runs are shown again rather than
// taken for covered. A finished run the service gives no attempt id for
// fails the listing with ErrUnidentifiedExecution.
//
// The cost is a read of the job's whole review and run history on every
// review. That is the price of exactness without an index; making it
// cheaper is capacity work and must not change what counts as covered.
func (r *Remote) RunsAfter(ctx context.Context, jobID, _ string) ([]RunEvidence, error) {
	covered, err := r.coveredExecutions(ctx, jobID)
	if err != nil {
		return nil, fmt.Errorf("read what earlier reviews covered: %w", err)
	}
	// One packet holds a bounded number of runs; one more tells it that
	// others are waiting. Only that many are kept while the history is read.
	todo := uncovered{limit: maxPacketRuns + 1}
	byKey := map[string]runSummary{}
	err = r.walkRuns(ctx, jobID, func(run runSummary) error {
		if !terminalRunStatuses[run.StatusLabel] {
			// Not a result yet. Nothing has to be remembered about it:
			// when it ends, its execution is in no review and is returned.
			return nil
		}
		if run.AttemptID == "" {
			// Never recorded under the run id alone: that would cover every
			// later execution of the run without anyone having seen it.
			return fmt.Errorf("%w: run %s of job %s is %s and has no attempt id", ErrUnidentifiedExecution, run.DagRunID, jobID, run.StatusLabel)
		}
		point := run.point()
		if covered[point.key()] {
			return nil
		}
		todo.add(point)
		byKey[point.key()] = run
		if len(byKey) > 8*todo.limit {
			keep := map[string]runSummary{}
			for _, p := range todo.settle() {
				keep[p.key()] = byKey[p.key()]
			}
			byKey = keep
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Evidence is read by run id, so a retry while it is being read would
	// pair one execution's status with another's output. A result whose run
	// moved on meanwhile is not returned. It is in no review, so the next
	// listing meets whatever the run's latest execution is by then.
	points := todo.settle()
	out := make([]RunEvidence, 0, len(points))
	for _, p := range points {
		ev, same, err := r.runEvidence(ctx, jobID, byKey[p.key()])
		if err != nil {
			return nil, err
		}
		if same {
			out = append(out, ev)
		}
	}
	return out, nil
}

// coveredExecutions is the set of results the job's recorded reviews say
// they covered, as "run@execution".
func (r *Remote) coveredExecutions(ctx context.Context, jobID string) (map[string]bool, error) {
	// Only the names are decoded: the history can be long.
	var list struct {
		Reviews []struct {
			Detail struct {
				CoveredExecutions []string `json:"covered_executions"`
			} `json:"detail"`
		} `json:"reviews"`
	}
	if err := r.do(ctx, http.MethodGet, jobPath(jobID, "reviews"), nil, &list); err != nil {
		return nil, err
	}
	covered := map[string]bool{}
	for _, rev := range list.Reviews {
		for _, key := range rev.Detail.CoveredExecutions {
			covered[key] = true
		}
	}
	return covered, nil
}

// runEvidence reads one result's evidence. same is false when the run's
// latest attempt is no longer the listed one once everything was read.
func (r *Remote) runEvidence(ctx context.Context, jobID string, run runSummary) (ev RunEvidence, same bool, err error) {
	ev = RunEvidence{RunID: run.DagRunID, Status: string(run.StatusLabel), AttemptID: run.AttemptID, QueuedAt: run.QueuedAt}
	ev.StartedAt, _ = time.Parse(time.RFC3339, run.StartedAt)
	ev.FinishedAt, _ = time.Parse(time.RFC3339, run.FinishedAt)
	base := "/dag-runs/" + url.PathEscape(jobID) + "/" + url.PathEscape(run.DagRunID)
	var outputs api.DAGRunOutputs
	err = r.do(ctx, http.MethodGet, base+"/outputs", nil, &outputs)
	switch {
	case err == nil:
		ev.Outputs = outputs.Outputs
	case errors.Is(err, ErrNotFound):
		// A run that failed early has no outputs; its status is the evidence.
	default:
		return ev, false, fmt.Errorf("outputs of run %s: %w", run.DagRunID, err)
	}
	if ev.SpecSHA256, err = r.runSpecDigest(ctx, jobID, run.DagRunID); err != nil {
		return ev, false, fmt.Errorf("spec of run %s: %w", run.DagRunID, err)
	}
	if ev.Steps, err = r.stepEvidence(ctx, jobID, run.DagRunID); err != nil {
		return ev, false, fmt.Errorf("steps of run %s: %w", run.DagRunID, err)
	}
	var after struct {
		DagRunDetails runSummary `json:"dagRunDetails"`
	}
	if err := r.do(ctx, http.MethodGet, base, nil, &after); err != nil {
		return ev, false, fmt.Errorf("run %s after reading its evidence: %w", run.DagRunID, err)
	}
	now := after.DagRunDetails
	return ev, now.AttemptID == run.AttemptID && now.QueuedAt == run.QueuedAt && now.StatusLabel == run.StatusLabel, nil
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
				Content    string `json:"content"`
				HasMore    bool   `json:"hasMore"`
				LineCount  int    `json:"lineCount"`
				TotalLines int    `json:"totalLines"`
			}
			err := r.do(ctx, http.MethodGet, base+"/steps/"+url.PathEscape(step.Name)+"/log?"+q.Encode(), nil, &log)
			switch {
			case err == nil:
				*into = tailBytes(log.Content, stepLogTailBytes)
				// The evidence says when it is only the end of what the
				// step printed.
				if log.HasMore || log.TotalLines > log.LineCount || len(*into) != len(log.Content) {
					step.Truncated = true
				}
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
		out.TargetID = targetKey(*t)
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
// decided retry proposal without a native task. Its latest retry decision
// is the request; once that decision has a journaled action it was
// attempted and is the journal's business. The key is the decision, not the
// proposal: a later decision about the same run is a new request.
//
// A request whose run has moved on from the execution it names can never be
// carried out, and nothing in the registry ends it. Such a request must not
// take a place in the batch, or enough of them would keep every valid one
// waiting for good. So every request is checked against its run, in a fixed
// order, and the first limit that can still be carried out are returned.
// Those are executed and leave the list, so the ones behind them are next;
// no request depends on the clock or on where a scan happened to start.
//
// A run that cannot be read does not stop the others: its request is left
// for the next listing, and the failures are returned as an error alongside
// the requests that were found.
//
// The cost is one read of a run for each request that was never attempted,
// on every listing. Requests that can never run stay in that number until
// the job's version changes; ending them is the registry's to do.
func (r *Remote) RequestedRetries(ctx context.Context, machineID string, limit int) ([]RequestedRetry, error) {
	var list api.TxeJobList
	if err := r.do(ctx, http.MethodGet, "/txe/jobs?"+url.Values{"machine": {machineID}}.Encode(), nil, &list); err != nil {
		return nil, err
	}
	type request struct {
		RequestedRetry
		runID string
		bound Execution
	}
	var all []request
	for _, job := range list.Jobs {
		if !Lifecycle(job.Lifecycle).Reviewable() {
			continue
		}
		proposals, err := r.proposals(ctx, job.JobId)
		if err != nil {
			return nil, err
		}
		decided := map[string]api.TxeProposal{}
		for _, p := range append(proposals.Open, proposals.Finished...) {
			if p.State == api.TxeProposalState(ProposalDecided) && p.Action.Name == RetryRunAction && p.NativeTask == nil {
				decided[p.ProposalId] = p
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
			attempted[a.DecisionID] = true
		}
		decisions, err := r.DecisionsAfter(ctx, job.JobId, "")
		if err != nil {
			return nil, err
		}
		latest := map[string]Decision{}
		for _, d := range decisions {
			// The latest answer to a proposal is the one that counts.
			latest[d.ProposalID] = d
		}
		for id, p := range decided {
			d, ok := latest[id]
			if !ok || d.Verdict != VerdictRetry || attempted[d.ID] {
				continue
			}
			params := paramsOf(p.Action.Params)
			bound, complete := retriedExecution(params)
			if !complete {
				continue
			}
			all = append(all, request{
				RequestedRetry: RequestedRetry{JobID: job.JobId, ProposalID: id, DecisionID: d.ID},
				runID:          params[RetryRunParam], bound: bound,
			})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].DecisionID < all[j].DecisionID })
	runs := remoteRuns{t: r.Transport}
	var out []RequestedRetry
	var unread []error
	for _, req := range all {
		if limit > 0 && len(out) >= limit {
			break
		}
		state, err := runs.RunState(ctx, req.JobID, req.runID)
		switch {
		case errors.Is(err, ErrNotFound):
			// The service no longer has the run: nothing can be retried.
		case err != nil:
			if len(unread) < maxUnreadReported {
				unread = append(unread, fmt.Errorf("run %s of job %s: %w", req.runID, req.JobID, err))
			}
		case state.retryable(req.bound):
			out = append(out, req.RequestedRetry)
		}
	}
	if len(unread) > 0 {
		return out, fmt.Errorf("some requested retries could not be checked and are left for the next tick: %w", errors.Join(unread...))
	}
	return out, nil
}

// endedDetail and overDetail are what the registry is told about a decision
// run that was already over when the reviewer came to close it.
const (
	endedDetail = "the decision run ended before its task was answered: the task's step was aborted or never finished. The reviewer completed nothing."
	overDetail  = "the decision run's task was already over and the service records no completion for it; whether it had been answered is not known from the run. The reviewer completed nothing."
)

// maxUnreadReported bounds how many unreadable runs one listing names.
const maxUnreadReported = 10

// RecordClosure implements Registry. The registry keeps every attempt and
// counts the failed ones; any other outcome is final and takes the proposal
// off its pending list.
func (r *Remote) RecordClosure(ctx context.Context, closure Closure) (int, error) {
	outcome, detail := api.TxeClosureOutcome(closure.Outcome), closure.Detail
	switch closure.Outcome {
	case ClosureEnded:
		// The registry's outcome for a task whose run ended before anyone
		// answered, which is what the run showed: the step never completed.
		outcome = api.TxeClosureOutcomeRunEnded
		detail = strings.TrimSpace(endedDetail + " " + detail)
	case ClosureOver:
		// The registry has no outcome for a completed task with nobody on
		// record. It is recorded as closed, with a detail that says exactly
		// what is known: the task was over, the service shows no
		// completion, the reviewer completed nothing. It neither claims an
		// answer nor denies one.
		outcome = api.TxeClosureOutcomeClosed
		detail = strings.TrimSpace(overDetail + " " + detail)
	case ClosureClosed, ClosureAnswered, ClosureMissing, ClosureRefused, ClosureFailed:
		// Recorded under the registry's outcome of the same name.
	}
	body := api.TxeClosureRequest{Actor: r.actor(), Outcome: outcome, Detail: optional(detail)}
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
	Episode           int       `json:"episode"`
	CoveredRuns       []string  `json:"covered_run_ids"`
	CoveredDecisions  []string  `json:"covered_decision_ids"`
	ActionIDs         []string  `json:"action_ids,omitempty"`
	ProposalIDs       []string  `json:"proposal_ids,omitempty"`
	Notes             []string  `json:"notes,omitempty"`
	Reviewer          string    `json:"reviewer"`
	Handoff           LocalFile `json:"handoff,omitzero"`
	RunCursor         string    `json:"run_cursor,omitempty"`
	CoveredExecutions []string  `json:"covered_executions,omitempty"`
	TrimmedExecutions []string  `json:"trimmed_executions,omitempty"`
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
		Handoff: detail.Handoff, RunCursor: detail.RunCursor, CoveredExecutions: detail.CoveredExecutions, TrimmedExecutions: detail.TrimmedExecutions,
	}, nil
}

func (r *Remote) actionOf(jobID string, a api.TxeAction) Action {
	out := Action{
		ID: a.ActionId, JobID: jobID, JobVersion: a.JobVersion, Name: a.Spec.Name, Params: paramsOf(a.Spec.Params),
		ReviewID: deref(a.ReviewId), ProposalID: deref(a.ProposalId), DecisionID: deref(a.DecisionId),
		State: ActionState(a.State), Receipt: deref(a.Receipt), ClaimID: deref(a.ClaimId),
		StartedAt: a.Created.At, FinishedAt: a.Updated.At, Attempt: a.Attempt, MaxAttempts: a.MaxAttempts,
	}
	// An action written before the registry recorded attempts' grants has
	// only its creation time.
	out.AttemptStartedAt = a.Created.At
	if a.AttemptStartedAt != nil {
		out.AttemptStartedAt = *a.AttemptStartedAt
	}
	if t := a.Spec.Target; t != nil {
		out.TargetID = targetKey(*t)
	}
	out.IntentKey = IntentKey(out.Name, out.TargetID, out.Params)
	if g := a.Grant; g != nil {
		out.GrantID, out.GrantExpiresAt = g.GrantId, g.ExpiresAt
	}
	var outcome actionOutcome
	if len(a.Outcome) > 0 && json.Unmarshal(a.Outcome, &outcome) == nil {
		out.Detail, out.Admitted, out.AdmittedRef = outcome.Detail, outcome.Admitted, outcome.AdmittedRef
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
	spec := api.TxeActionSpec{Name: name}
	doc, err := r.jobDoc(ctx, jobID)
	if err != nil {
		return spec, err
	}
	var v api.TxeJobVersion
	if err := r.do(ctx, http.MethodGet, jobPath(jobID, "versions", strconv.Itoa(doc.Version)), nil, &v); err != nil {
		return spec, err
	}
	// The values are typed by the schema of the action as the job's current
	// version declares it, which is what the registry validates against.
	var schema any
	if rp := v.ReviewPolicy; rp != nil {
		for _, pa := range deref(rp.PermittedActions) {
			if pa.Name == name {
				schema = pa.ParamSchema
			}
		}
	}
	spec.Params = paramsValue(params, schema)
	if targetID == "" {
		return spec, nil
	}
	for _, t := range deref(v.Targets) {
		if targetKey(t) == targetID {
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
	if te, ok := errors.AsType[*TransportError](err); ok && te.Status == http.StatusBadRequest && te.Code == codeInvalid {
		// The registry validates an attempt's parameter values against the
		// action's declared schema before it grants anything. A refusal is
		// made before any effect: nothing runs, and it is reported as a
		// refused action, not as a failure of the review.
		return Action{}, &GuardDeniedError{Reason: DenyInvalidParams, Detail: te.Message}
	}
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

// actionOutcome is what the reviewer keeps in an action's free-form outcome.
type actionOutcome struct {
	Detail string `json:"detail,omitempty"`
	// Admitted: the destination accepted the request; only its result was
	// not seen.
	Admitted bool `json:"admitted,omitempty"`
	// AdmittedRef: the execution the destination named for the request.
	AdmittedRef string `json:"admitted_execution,omitempty"`
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
	if req.Detail != "" || req.Admitted {
		body.Outcome, _ = json.Marshal(actionOutcome{Detail: req.Detail, Admitted: req.Admitted, AdmittedRef: req.AdmittedRef})
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
		// A reserved, non-executable action naming the journaled action
		// and the attempt of it in question. The registry takes the
		// attempt as a number.
		attempt, err := strconv.Atoi(draft.Params[UncertainAttemptParam])
		if err != nil {
			return Proposal{}, fmt.Errorf("escalation of action %s names no attempt: %w", draft.Params[UncertainEffectParam], err)
		}
		params, err := json.Marshal(registry.UncertainEffectParams{ActionID: draft.Params[UncertainEffectParam], Attempt: attempt})
		if err != nil {
			return Proposal{}, err
		}
		in.Action = api.TxeActionSpec{Name: UncertainEffectAction, Params: params}
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
		Handoff: rev.Handoff, RunCursor: rev.RunCursor, CoveredExecutions: rev.CoveredExecutions, TrimmedExecutions: rev.TrimmedExecutions,
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
	if exc.ActionID != "" {
		// An exception about one attempt of an action is filed under the
		// claim that holds the job. It changes no availability. The
		// registry keeps one open per (action, attempt, kind), so raising
		// it again is harmless, and resolves it itself when that attempt
		// is settled or another is granted.
		kind, scope := string(exc.Kind), api.TxeObservationRequestScopeAction
		fence := int64(exc.Claim.Fence)
		body := api.TxeObservationRequest{
			Actor: r.actor(), Scope: &scope, Kind: &kind, Detail: &exc.Message,
			// The registry ignores the state of an action observation; the
			// field is required by the request's schema.
			State:    api.TxeAvailabilityState(registry.AvailabilityReady),
			ActionId: &exc.ActionID, Attempt: &exc.Attempt, ClaimId: &exc.Claim.ID, Fence: &fence,
		}
		return r.do(ctx, http.MethodPost, jobPath(exc.JobID, "observations"), body, nil)
	}
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
//
// The service answers 409 for three different things: the task was completed
// with another input; the task can no longer be completed because its step
// or run is over; and the task cannot be completed yet, because the run has
// not reached it, is being finalized, or changed underneath the request. So
// a conflict is checked against the run itself:
//
//   - answered, only when the task's step records who completed it;
//   - ended, when the step or the whole run is over and no completion is
//     recorded: nothing is waiting, and whether anyone answered is not
//     known;
//   - otherwise an error, which leaves the task to be tried again and is
//     never recorded as a final outcome.
//
// A service that does not record who completed a task, as one running
// without authentication, shows an answered task as ended. Both are final,
// and what is recorded for an ended task says that no completion is on
// record, not that nobody answered.
func RemoteComplete(t Transport) CompleteFunc {
	return func(ctx context.Context, task TaskLocator, input map[string]string) error {
		base := "/dag-runs/" + url.PathEscape(task.DAG) + "/" + url.PathEscape(task.RunID)
		err := t.Do(ctx, http.MethodPost, base+"/human-tasks/"+url.PathEscape(task.StepID)+"/complete", input, nil)
		te, refused := errors.AsType[*TransportError](err)
		if !refused {
			return err
		}
		switch te.Status {
		case http.StatusNotFound:
			return ErrRunMissing
		case http.StatusConflict:
			var detail struct {
				DagRunDetails struct {
					StatusLabel api.StatusLabel `json:"statusLabel"`
					Nodes       []struct {
						Step struct {
							Name string `json:"name"`
						} `json:"step"`
						StatusLabel   string `json:"statusLabel"`
						CompletedBy   string `json:"humanTaskCompletedBy"`
						CompletedByID string `json:"humanTaskCompletedById"`
					} `json:"nodes"`
				} `json:"dagRunDetails"`
			}
			if readErr := t.Do(ctx, http.MethodGet, base, nil, &detail); readErr != nil {
				return fmt.Errorf("the task could not be completed (%s) and its run could not be read: %w", te.Message, readErr)
			}
			run := detail.DagRunDetails
			stepOver, stepStatus := false, "not found"
			for _, node := range run.Nodes {
				if node.Step.Name != task.StepID {
					continue
				}
				if node.CompletedBy != "" || node.CompletedByID != "" {
					return ErrTaskAnswered
				}
				stepOver, stepStatus = finishedStepStatuses[node.StatusLabel], node.StatusLabel
			}
			switch {
			case answerableStepStatuses[stepStatus]:
				// The step is in a state it can hold an answer in, and
				// nobody is recorded for it.
				return fmt.Errorf("%w: its run is %s and its step is %s", ErrTaskOver, run.StatusLabel, stepStatus)
			case stepOver || terminalRunStatuses[run.StatusLabel]:
				// The step never completed and no longer can.
				return fmt.Errorf("%w: its run is %s and its step is %s", ErrTaskEnded, run.StatusLabel, stepStatus)
			}
			return fmt.Errorf("the task cannot be completed yet: %s (run is %s)", te.Message, run.StatusLabel)
		}
		return err
	}
}

// finishedStepStatuses are the step states after which a human task can no
// longer be answered.
// answerableStepStatuses are the finished states a human task's step can
// be in while holding an answer: completed or rejected by someone, and also
// skipped or failed, because the service carries a completed task's input
// over into a step it then skips (selected-step runs, edit and retry). Only
// a step that was aborted, or never finished in a run that is over, is
// taken to have ended unanswered.
var answerableStepStatuses = map[string]bool{
	"succeeded": true, "partially_succeeded": true, "rejected": true, "skipped": true, "failed": true,
}

var finishedStepStatuses = map[string]bool{
	"succeeded": true, "failed": true, "aborted": true, "skipped": true, "rejected": true, "partially_succeeded": true,
}

// remoteRuns reads and retries runs through the service's own run API.
type remoteRuns struct {
	t Transport
}

// RemoteRuns returns a RunRetrier on the service's run API.
func RemoteRuns(t Transport) RunRetrier {
	return remoteRuns{t: t}
}

// runSummary is the part of the service's run summary the reviewer reads.
type runSummary struct {
	DagRunID    string          `json:"dagRunId"`
	AttemptID   string          `json:"attemptId"`
	StatusLabel api.StatusLabel `json:"statusLabel"`
	QueuedAt    string          `json:"queuedAt"`
	StartedAt   string          `json:"startedAt"`
	FinishedAt  string          `json:"finishedAt"`
}

// execution is the reference of the run's latest execution.
func (s runSummary) execution() string {
	return ExecutionRef(s.AttemptID, s.QueuedAt)
}

// point is the run's latest execution as a result to cover, with the time
// it is ordered by. A run that ended before it started, such as one refused
// or aborted in the queue, has no finish time, so the latest time the
// service has for it stands in. The time only orders results; it never
// decides whether one is covered.
func (s runSummary) point() runPoint {
	p := runPoint{runID: s.DagRunID, execution: s.execution()}
	for _, raw := range []string{s.FinishedAt, s.StartedAt, s.QueuedAt} {
		if t, err := time.Parse(time.RFC3339, raw); err == nil && !t.IsZero() {
			p.at = t
			break
		}
	}
	return p
}

func (s runSummary) state() RunState {
	return RunState{
		AttemptID: s.AttemptID, QueuedAt: s.QueuedAt, Status: string(s.StatusLabel),
		Active:    !terminalRunStatuses[s.StatusLabel],
		Succeeded: s.StatusLabel == api.StatusLabelSucceeded,
	}
}

// RunState implements RunRetrier.
func (r remoteRuns) RunState(ctx context.Context, jobID, runID string) (RunState, error) {
	var out struct {
		DagRunDetails runSummary `json:"dagRunDetails"`
	}
	path := "/dag-runs/" + url.PathEscape(jobID) + "/" + url.PathEscape(runID)
	if err := refusal(r.t.Do(ctx, http.MethodGet, path, nil, &out)); err != nil {
		return RunState{}, err
	}
	return out.DagRunDetails.state(), nil
}

// RetryRun implements RunRetrier. The request names the execution the retry
// is for, and the service admits it only while that is the run's latest
// execution and has finished, checking it together with the admission.
//
// "Nothing was started" is claimed only for the refusals the service itself
// documents as made before anything is queued or created: 409 with
// details.code execution_changed (another execution is the latest, or the
// expected one has not finished) and 409 with conditional_retry_unsupported
// (the retry would run in a local process). Every other failure is returned
// as it is and leaves the outcome unknown: 503 dispatch_uncertain, where
// the service says itself that the retry may have been dispatched, any
// other status, and a failure of the transport. An unknown outcome is
// settled by looking at the run, never by assuming.
func (r remoteRuns) RetryRun(ctx context.Context, jobID, runID string, expected Execution) (Execution, error) {
	path := "/dag-runs/" + url.PathEscape(jobID) + "/" + url.PathEscape(runID) + "/retry"
	body := map[string]string{"dagRunId": runID, "expectedAttemptId": expected.AttemptID, "expectedQueuedAt": expected.QueuedAt}
	var answer json.RawMessage
	err := r.t.Do(ctx, http.MethodPost, path, body, &answer)
	if te, ok := errors.AsType[*TransportError](err); ok && te.Status == http.StatusConflict && retryRefusedBeforeEffect[te.Code] {
		return Execution{}, fmt.Errorf("%w: %d %s %s", ErrRunNotRetryable, te.Status, te.Code, te.Message)
	}
	if err != nil {
		return Execution{}, err
	}
	return admittedExecution(answer), nil
}

// admittedExecution reads the execution the service says it admitted a
// conditional retry as: {attemptId, queuedAt, executionRef} in the answer.
// A service that answers without it, or with something that does not hold
// together, has named no execution: the zero Execution is returned, and the
// caller records nothing from the run.
func admittedExecution(answer json.RawMessage) Execution {
	var named struct {
		AttemptID    string `json:"attemptId"`
		QueuedAt     string `json:"queuedAt"`
		ExecutionRef string `json:"executionRef"`
	}
	if len(answer) == 0 || json.Unmarshal(answer, &named) != nil || named.AttemptID == "" {
		return Execution{}
	}
	admitted := Execution{AttemptID: named.AttemptID, QueuedAt: named.QueuedAt}
	if named.ExecutionRef != admitted.Ref() {
		return Execution{}
	}
	return admitted
}

// retryRefusedBeforeEffect are the service's codes for a conditional retry
// it refused before queueing or creating anything.
var retryRefusedBeforeEffect = map[string]bool{
	"execution_changed":             true,
	"conditional_retry_unsupported": true,
}
