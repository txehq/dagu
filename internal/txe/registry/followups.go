// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"sort"
	"strings"
	"time"
)

// Reserved action names. The registry gives them their meaning; a job's
// policy can never permit them as its own actions.
const (
	// ActionRetryRun retries one Dagu run of the job. A retry verdict on it is
	// an executable decision, carried out under an execution claim.
	ActionRetryRun = "dagu.retry_run"
	// ActionUncertainEffect asks a person what to do about an action whose
	// outcome could not be reconciled. It is never executable; a retry verdict
	// closes it and allows one more attempt of that action.
	ActionUncertainEffect = "txe.uncertain_effect"
)

var reservedActionPrefixes = []string{"txe.", "dagu."}

// IsReservedAction reports whether name belongs to the registry.
func IsReservedAction(name string) bool {
	for _, p := range reservedActionPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// RetryRunParams are the parameters of dagu.retry_run. The run's DAG
// snapshot and package must be the job's current ones: a run of an older
// version is never retried silently on the new code, or the old.
//
// AttemptID is the attempt being retried, Dagu's own attempt identity: a
// native retry keeps the run ID and starts a new attempt, so the attempt is
// what a person decided on, and each failed attempt is decided separately.
type RetryRunParams struct {
	RunID     string `json:"run_id"`
	AttemptID string `json:"attempt_id"`
	// QueuedAt is the queue marker of the execution being retried, as Dagu
	// stored it; with AttemptID it names the execution.
	QueuedAt      string `json:"queued_at"`
	RunSpecSHA256 string `json:"run_spec_sha256"`
	PackageDigest string `json:"package_digest"`
}

// UncertainEffectParams are the parameters of txe.uncertain_effect.
type UncertainEffectParams struct {
	ActionID string `json:"action_id"`
}

// UncertainResolution is a person's retry verdict on an action whose outcome
// could not be reconciled. It allows at most one more attempt of exactly
// that action, under the same job version, package and binding, and is
// consumed by the grant of that attempt.
type UncertainResolution struct {
	ActionID      string    `json:"action_id"`
	Attempt       int       `json:"attempt"`
	JobVersion    int       `json:"job_version"`
	PackageDigest string    `json:"package_digest"`
	BindingDigest string    `json:"binding_digest"`
	DecisionID    string    `json:"decision_id"`
	At            time.Time `json:"at"`
}

// IntentRecord is the latest action for one intent (action name, target and
// parameters). It survives the archival of review episodes, so an intent
// whose effect is unresolved cannot be started again by a later episode.
type IntentRecord struct {
	ActionID string      `json:"action_id"`
	State    ActionState `json:"state"`
	Updated  time.Time   `json:"updated"`
}

// EscalationProposalID is the ID of the proposal that asks about the
// unresolved outcome of actionID at jobVersion.
func EscalationProposalID(actionID string, jobVersion int) (string, error) {
	return DerivedID(PrefixProposal, "uncertain", actionID, jobVersion)
}

// RetryProposalID is the ID of the proposal to retry the execution
// executionRef of runID at jobVersion.
func RetryProposalID(runID, executionRef string, jobVersion int) (string, error) {
	return DerivedID(PrefixProposal, "retry", runID, executionRef, jobVersion)
}

// ExecutionRef is the portable reference of one execution of a run: the
// attempt ID and the first 8 bytes of sha256(attemptID + "\n" + queuedAt) in
// hex. A queued retry runs an attempt again under a later queue marker, so
// the attempt ID alone does not name an execution. The reference is the only
// form used as a path segment, a proposal input and a receipt.
func ExecutionRef(attemptID, queuedAt string) string {
	sum := sha256.Sum256([]byte(attemptID + "\n" + queuedAt))
	return attemptID + "-" + hex.EncodeToString(sum[:8])
}

// Ref is the execution's portable reference.
func (a RunAttempt) Ref() string { return ExecutionRef(a.AttemptID, a.QueuedAt) }

// DecideTaskDAG is the name of the DAG that holds a machine's decision tasks.
func DecideTaskDAG(machineID string) string {
	return "txe-decide-" + strings.TrimPrefix(machineID, string(PrefixMachine)+"_")
}

// DecideTaskStep is the step of DecideTaskDAG that waits for a decision.
const DecideTaskStep = "decide"

// intentKey identifies an action's intent: its name, target and parameters.
func intentKey(spec ActionSpec) string {
	var target string
	if spec.Target != nil {
		target = TargetKey(*spec.Target)
	}
	params := spec.Params
	if len(params) == 0 {
		params = json.RawMessage("null")
	}
	b, _ := CanonicalJSON(map[string]any{"name": spec.Name, "target": target, "params": params})
	return sha256Hex(b)
}

// unresolved reports whether an action in state s has an effect whose
// outcome is not known.
func unresolved(s ActionState) bool {
	return s == ActionExecuting || s == ActionUncertain || s == ActionEscalated
}

// noteIntent records a's state as the latest of its intent.
func (tx *JobTx) noteIntent(a *Action) {
	j := tx.Job
	if j.Intents == nil {
		j.Intents = map[string]*IntentRecord{}
	}
	key := intentKey(a.Spec)
	if cur, ok := j.Intents[key]; ok && cur.ActionID != a.ActionID && !unresolved(a.State) && unresolved(cur.State) {
		// Settling an older attempt never clears a newer unresolved one.
		return
	}
	j.Intents[key] = &IntentRecord{ActionID: a.ActionID, State: a.State, Updated: tx.now}
	tx.touch()
}

// decodeParams decodes an action's parameters strictly.
func decodeParams(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return refuse(CodeInvalid, "action params: %v", err)
	}
	return nil
}

// checkReservedProposal validates a proposal for a reserved action against
// the current job.
func (tx *JobTx) checkReservedProposal(p *Proposal) error {
	j := tx.Job
	switch p.Action.Name {
	case ActionRetryRun:
		var rp RetryRunParams
		if err := decodeParams(p.Action.Params, &rp); err != nil {
			return err
		}
		if rp.RunID == "" {
			return refuse(CodeInvalid, "dagu.retry_run needs run_id")
		}
		if err := tx.checkRunBinding(rp, true); err != nil {
			return err
		}
		if p.Action.Target != nil {
			return refuse(CodeInvalid, "dagu.retry_run takes no target")
		}
	case ActionUncertainEffect:
		var up UncertainEffectParams
		if err := decodeParams(p.Action.Params, &up); err != nil {
			return err
		}
		want, err := EscalationProposalID(up.ActionID, j.Version)
		if err != nil {
			return err
		}
		if p.ProposalID != want {
			return refuse(CodeInvalid, "the escalation proposal for action %s at version %d is %s", up.ActionID, j.Version, want)
		}
		a, ok := j.Actions[up.ActionID]
		if !ok || (a.State != ActionUncertain && a.State != ActionEscalated) {
			return refuse(CodeActionState, "action %s has no unresolved outcome", up.ActionID)
		}
	default:
		if IsReservedAction(p.Action.Name) {
			return refuse(CodeInvalid, "%q is a reserved action name", p.Action.Name)
		}
	}
	return nil
}

// checkRunBinding resolves a run to the job's immutable versions through
// its saved DAG spec digest: every version whose spec has that digest must
// name the same package, the current version must be among them, and that
// package must be the one the request names and the job's current one. A
// spec that matches no version, or versions with different packages, is
// refused: the run's package is then unknown, and an unknown binding is
// never retried.
//
// retain keeps the verified terminal status as the retry's evidence; it is
// set where a retry is decided (proposal), not where it is executed.
func (tx *JobTx) checkRunBinding(rp RetryRunParams, retain bool) error {
	j := tx.Job
	stale := func(msg string) error {
		return &Error{Code: CodeStaleBinding, Message: "run " + rp.RunID + " " + msg + "; it is not retried", Current: j}
	}
	if rp.AttemptID == "" || rp.RunSpecSHA256 == "" || rp.PackageDigest == "" {
		return refuse(CodeInvalid, "dagu.retry_run needs attempt_id, run_spec_sha256 and package_digest")
	}
	// The attempt and its digest are the run's own, read from what Dagu
	// stored, never taken from the caller: a current digest cannot be paired
	// with an old run, and a run that moved on is not retried again.
	if tx.store.runs == nil {
		return refuse(CodeNotReady, "run history is not available to bind run %s", rp.RunID)
	}
	latest, err := tx.store.runs.LatestAttempt(tx.ctx, j.JobID, rp.RunID)
	switch {
	case errors.Is(err, ErrRunNotFound):
		return stale("is not a run of this job")
	case err != nil:
		return err
	case latest.AttemptID != rp.AttemptID || latest.QueuedAt != rp.QueuedAt:
		return stale("is now at execution " + latest.Ref() + ", not " + ExecutionRef(rp.AttemptID, rp.QueuedAt))
	case !latest.Finished || latest.Succeeded:
		return stale("attempt " + latest.AttemptID + " is " + latest.Status + ", not finished unsuccessfully")
	case latest.SpecSHA256 != rp.RunSpecSHA256:
		return stale("ran another DAG than the one named")
	}
	if retain {
		if err := tx.store.retainExecution(tx.ctx, j.JobID, rp.RunID, latest, EvidenceRetry); err != nil {
			return err
		}
	}
	packages := map[string]bool{}
	current := false
	for n := 1; n <= j.Version; n++ {
		v, err := tx.Version(n)
		if err != nil {
			return err
		}
		if v.DAG.SpecSHA256 != rp.RunSpecSHA256 {
			continue
		}
		packages[v.Package.Digest] = true
		current = current || n == j.Version
	}
	switch {
	case len(packages) == 0:
		return stale("ran a DAG that is no version of this job")
	case len(packages) > 1:
		return stale("ran a DAG that versions with different packages share, so its package is unknown")
	case !current:
		return stale(fmt.Sprintf("is of an older version, not the current version %d", j.Version))
	case !packages[j.PackageDigest] || rp.PackageDigest != j.PackageDigest:
		return stale("ran another package than the current one")
	}
	return nil
}

// checkRetryReceipt allows a retry to succeed only with the new attempt Dagu
// was observed to start: the run's latest attempt, and not the retried one.
// The receipt names that attempt; an accepted request alone is no receipt.
func (tx *JobTx) checkRetryReceipt(a *Action, receipt string) error {
	var rp RetryRunParams
	if err := decodeParams(a.Spec.Params, &rp); err != nil {
		return err
	}
	if tx.store.runs == nil {
		return refuse(CodeNotReady, "run history is not available to check the retry of run %s", rp.RunID)
	}
	latest, err := tx.store.runs.LatestAttempt(tx.ctx, tx.Job.JobID, rp.RunID)
	if err != nil {
		return err
	}
	retried := ExecutionRef(rp.AttemptID, rp.QueuedAt)
	if receipt == retried || receipt != latest.Ref() {
		return refuse(CodeInvalid, "a retry of run %s succeeds only with the new execution observed on it (latest is %s, retried %s)", rp.RunID, latest.Ref(), retried)
	}
	return nil
}

// executionsPrefix holds immutable copies of executions' stored status.
const executionsPrefix = "executions/"

// Evidence purposes: each is kept once per execution, separately, because
// they are taken at different stages of the execution.
const (
	// EvidenceRetry is the terminal status a retry was decided on.
	EvidenceRetry = "retry"
	// EvidencePublication is the status observed while the execution
	// published its deliverables; it is not the execution's final state.
	EvidencePublication = "publication"
)

func evidenceKey(jobID, runID, executionRef, purpose string) string {
	return executionsPrefix + jobID + "/" + runID + "/" + executionRef + "/" + purpose
}

// retainExecution keeps the stored status of an execution the registry
// acts on, once per purpose: a queued retry overwrites it in place, and the
// evidence of what was decided or published must survive that. The first
// copy for a purpose stands.
func (s *Store) retainExecution(ctx context.Context, jobID, runID string, e RunAttempt, purpose string) error {
	if len(e.Snapshot) == 0 {
		return nil
	}
	err := s.col.Create(ctx, &persis.Record{ID: evidenceKey(jobID, runID, e.Ref(), purpose), Data: e.Snapshot,
		CreatedAt: s.clock(), UpdatedAt: s.clock()})
	if errors.Is(err, persis.ErrConflict) {
		return nil
	}
	return err
}

// GetRetainedExecution returns the stored status the registry kept for an
// execution of a run, for one purpose.
func (s *Store) GetRetainedExecution(ctx context.Context, jobID, runID, executionRef, purpose string) (json.RawMessage, error) {
	rec, err := s.col.Get(ctx, evidenceKey(jobID, runID, executionRef, purpose))
	if err != nil {
		if errors.Is(err, persis.ErrNotFound) {
			return nil, refuse(CodeNotFound, "execution %s of run %s has no %s evidence", executionRef, runID, purpose)
		}
		return nil, err
	}
	return rec.Data, nil
}

// checkNativeTask validates a proposal's Dagu human task locator: decisions
// wait in the job's machine's decide DAG, at its decide step.
func (tx *JobTx) checkNativeTask(p *Proposal) error {
	t := p.NativeTask
	if t == nil {
		return nil
	}
	if want := DecideTaskDAG(tx.Job.MachineID); t.DAG != want || t.StepID != DecideTaskStep || t.RunID == "" {
		return refuse(CodeInvalid, "native_task must be a run of %s at step %s", want, DecideTaskStep)
	}
	return nil
}

// checkRetryVerdict refuses a retry verdict except where it has a meaning,
// and an approval of an escalation, which is never executable.
func checkRetryVerdict(p *Proposal, v Verdict) error {
	switch {
	case v == VerdictRetry && p.Action.Name != ActionRetryRun && p.Action.Name != ActionUncertainEffect:
		return &Error{Code: CodeNotPermitted, Message: "verdict retry applies only to dagu.retry_run and txe.uncertain_effect", Current: p}
	case p.Action.Name == ActionUncertainEffect && (v == VerdictApprove || v == VerdictRedirect):
		return &Error{Code: CodeNotPermitted, Message: "an escalation is answered with retry, reject, snooze or a lifecycle verdict; it is never executed", Current: p}
	}
	return nil
}

// resolveUncertain records a retry verdict on an escalation: one more
// attempt of the action, bound to its attempt, version, package and binding.
func (tx *JobTx) resolveUncertain(p *Proposal, d *Decision) error {
	j := tx.Job
	var up UncertainEffectParams
	if err := decodeParams(p.Action.Params, &up); err != nil {
		return err
	}
	a, ok := j.Actions[up.ActionID]
	if !ok || (a.State != ActionUncertain && a.State != ActionEscalated) {
		return refuse(CodeActionState, "action %s has no unresolved outcome", up.ActionID)
	}
	if a.Attempt >= a.MaxAttempts {
		return &Error{Code: CodeNotPermitted, Message: fmt.Sprintf("action %s used all %d attempts its policy allows", a.ActionID, a.MaxAttempts), Current: a}
	}
	if a.JobVersion != j.Version {
		return &Error{Code: CodeStaleBinding, Message: fmt.Sprintf("action %s was attempted under version %d", a.ActionID, a.JobVersion), Current: a}
	}
	if j.UncertainResolutions == nil {
		j.UncertainResolutions = map[string]*UncertainResolution{}
	}
	j.UncertainResolutions[a.ActionID] = &UncertainResolution{
		ActionID: a.ActionID, Attempt: a.Attempt, JobVersion: j.Version, PackageDigest: j.PackageDigest,
		BindingDigest: a.BindingDigest, DecisionID: d.DecisionID, At: tx.now,
	}
	return nil
}

// takeResolution consumes the resolution that allows one more attempt of
// the unresolved action prior, granted as a (prior itself, or the same
// intent in a later episode). It refuses when there is none, or when the
// version, package or binding changed since the person decided.
func (tx *JobTx) takeResolution(prior string, a *Action) error {
	j := tx.Job
	r, ok := j.UncertainResolutions[prior]
	if !ok {
		return &Error{Code: CodeIntentUnresolved, Message: "the outcome of action " + prior + " is not resolved; a person must decide on its escalation first", Current: prior}
	}
	if r.JobVersion != j.Version || r.PackageDigest != j.PackageDigest || r.BindingDigest != a.BindingDigest {
		return &Error{Code: CodeStaleBinding, Message: "the retry decided for action " + prior + " was for another version, package or binding", Current: r}
	}
	if p, ok := j.Actions[prior]; ok && p.Attempt != r.Attempt {
		return &Error{Code: CodeStaleBinding, Message: "action " + prior + " was attempted again after the retry was decided", Current: r}
	}
	delete(j.UncertainResolutions, prior)
	return nil
}

// ProposeRetry records a person's request to retry one run of the job as a
// dagu.retry_run proposal decided with a retry verdict, in one commit and
// without a review claim. The executor then authorizes it under an
// execution claim. A replayed idempotency key returns the stored decision.
// The caller has checked that runID is a run of the job's DAG.
func (tx *JobTx) ProposeRetry(params RetryRunParams, idempotencyKey string) (*Proposal, *Decision, error) {
	j := tx.Job
	if tx.actor.Kind != ActorHuman {
		return nil, nil, refuse(CodeNotPermitted, "a retry is requested by a person, not %s", tx.actor.Kind)
	}
	if idempotencyKey == "" {
		return nil, nil, refuse(CodeInvalid, "idempotency_key is required")
	}
	if id, ok := j.DecisionKeys[idempotencyKey]; ok {
		return nil, nil, &Error{Code: CodeDuplicate, Message: "idempotency key already decided", Current: id}
	}
	if !j.Lifecycle.AcceptsEffects() {
		return nil, nil, &Error{Code: CodeLifecycle, Message: "job is " + string(j.Lifecycle), Current: j}
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, nil, err
	}
	id, err := RetryProposalID(params.RunID, ExecutionRef(params.AttemptID, params.QueuedAt), j.Version)
	if err != nil {
		return nil, nil, err
	}
	p := Proposal{ProposalID: id, Action: ActionSpec{Name: ActionRetryRun, Params: raw},
		AllowedVerdicts: []Verdict{VerdictRetry, VerdictReject}, WaitingOn: "person", Question: "Retry run " + params.RunID + "?"}
	if err := tx.checkReservedProposal(&p); err != nil {
		return nil, nil, err
	}
	if cur, ok := j.Proposals[id]; ok && cur.State != ProposalOpen && cur.State != ProposalSnoozed {
		return nil, nil, &Error{Code: CodeProposalState, Message: "the retry of execution " + ExecutionRef(params.AttemptID, params.QueuedAt) + " of run " + params.RunID + " is already " + string(cur.State), Current: cur}
	}
	binding, err := BindingDigest(j, p.Action)
	if err != nil {
		return nil, nil, err
	}
	if _, ok := j.Proposals[id]; !ok {
		p.JobVersion, p.PackageDigest, p.BindingDigest = j.Version, j.PackageDigest, binding
		p.Revision, p.State = 1, ProposalOpen
		p.Created = Stamp{At: tx.now, By: tx.actor}
		p.Updated = p.Created
		if j.Proposals == nil {
			j.Proposals = map[string]*Proposal{}
		}
		j.Proposals[id] = &p
	}
	decisionID, err := NewID(PrefixDecision, tx.now)
	if err != nil {
		return nil, nil, err
	}
	cur := j.Proposals[id]
	d, err := tx.AppendDecision(Decision{DecisionID: decisionID, ProposalID: id, ProposalRevision: cur.Revision,
		Verdict: VerdictRetry, BindingDigest: binding, IdempotencyKey: idempotencyKey, Actor: tx.actor}, ProposalDecided)
	if err != nil {
		return nil, nil, err
	}
	out := *j.Proposals[id]
	return &out, d, nil
}

// ClosureOutcome is the result of closing a superseded proposal's Dagu
// human task.
type ClosureOutcome string

const (
	// ClosureClosed: the task was closed.
	ClosureClosed ClosureOutcome = "closed"
	// ClosureAlreadyAnswered: a person had answered the task first.
	ClosureAlreadyAnswered ClosureOutcome = "already_answered"
	// ClosureRunMissing: the task's run no longer exists.
	ClosureRunMissing ClosureOutcome = "run_missing"
	// ClosureLocatorRefused: the machine refused the task's locator.
	ClosureLocatorRefused ClosureOutcome = "locator_refused"
	// ClosureFailed: the attempt failed and will be retried.
	ClosureFailed ClosureOutcome = "failed"
)

// Final reports whether the outcome ends the closure obligation.
func (o ClosureOutcome) Final() bool { return o != ClosureFailed }

func knownClosureOutcome(o ClosureOutcome) bool {
	switch o {
	case ClosureClosed, ClosureAlreadyAnswered, ClosureRunMissing, ClosureLocatorRefused, ClosureFailed:
		return true
	}
	return false
}

// PendingClosure is a superseded proposal whose Dagu human task still waits.
type PendingClosure struct {
	JobID         string     `json:"job_id"`
	ProposalID    string     `json:"proposal_id"`
	MachineID     string     `json:"machine_id"`
	NativeTask    NativeTask `json:"native_task"`
	SupersededAt  time.Time  `json:"superseded_at"`
	Failures      int        `json:"failures"`
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
}

// Closure is an immutable record of one attempt to close a superseded
// proposal's Dagu human task.
type Closure struct {
	ClosureID  string         `json:"closure_id"`
	ProposalID string         `json:"proposal_id"`
	Outcome    ClosureOutcome `json:"outcome"`
	Detail     string         `json:"detail,omitempty"`
	Attempt    int            `json:"attempt"`
	Created    Stamp          `json:"created"`
	Prev       string         `json:"prev,omitempty"`
}

// closeLater records that p's Dagu human task must be closed: superseding
// the proposal does not end the task a person may still be looking at.
func (tx *JobTx) closeLater(p *Proposal) {
	if p.NativeTask == nil {
		return
	}
	j := tx.Job
	if j.PendingClosures == nil {
		j.PendingClosures = map[string]*PendingClosure{}
	}
	j.PendingClosures[p.ProposalID] = &PendingClosure{JobID: j.JobID, ProposalID: p.ProposalID, MachineID: j.MachineID,
		NativeTask: *p.NativeTask, SupersededAt: tx.now}
}

// RecordClosure appends the outcome of an attempt to close a superseded
// proposal's Dagu human task. A failure is counted and the closure stays
// pending; a final outcome ends it. Replaying a final outcome after it was
// recorded returns the stored closure; another final outcome is refused.
func (tx *JobTx) RecordClosure(ctx context.Context, s *Store, proposalID string, outcome ClosureOutcome, detail string) (*Closure, error) {
	j := tx.Job
	if !knownClosureOutcome(outcome) {
		return nil, refuse(CodeInvalid, "unknown closure outcome %q", outcome)
	}
	pc, ok := j.PendingClosures[proposalID]
	if !ok {
		final, err := s.finalClosure(ctx, j, proposalID)
		if err != nil {
			return nil, err
		}
		switch {
		case final == nil:
			return nil, refuse(CodeNotFound, "proposal %s has no task to close", proposalID)
		case final.Outcome == outcome:
			return final, nil
		}
		return nil, &Error{Code: CodeProposalState, Message: "the closure of proposal " + proposalID + " already ended as " + string(final.Outcome), Current: final}
	}
	id, err := NewID(PrefixClosure, tx.now)
	if err != nil {
		return nil, err
	}
	c := Closure{ClosureID: id, ProposalID: proposalID, Outcome: outcome, Detail: detail, Attempt: pc.Failures + 1, Created: Stamp{At: tx.now, By: tx.actor}}
	if _, err := tx.attach(kindClosures, &c, func(prev string) { c.Prev = prev }); err != nil {
		return nil, err
	}
	if outcome.Final() {
		delete(j.PendingClosures, proposalID)
	} else {
		now := tx.now
		pc.Failures++
		pc.LastAttemptAt = &now
		pc.LastError = detail
	}
	tx.touch()
	return &c, nil
}

// finalClosure returns the final closure recorded for proposalID, or nil.
func (s *Store) finalClosure(ctx context.Context, job *Job, proposalID string) (*Closure, error) {
	for id := job.Chains.Closures; id != ""; {
		var c Closure
		if err := s.getJSON(ctx, id, &c); err != nil {
			return nil, fmt.Errorf("registry: history %s: %w", id, err)
		}
		if c.ProposalID == proposalID && c.Outcome.Final() {
			return &c, nil
		}
		id = c.Prev
	}
	return nil, nil
}

// ListClosures returns a job's closure records, newest first.
func (s *Store) ListClosures(ctx context.Context, jobID string, limit int) ([]*Closure, error) {
	return walkChain[Closure](ctx, s, jobID, func(c Chains) string { return c.Closures }, func(c *Closure) string { return c.Prev }, limit)
}

// PendingClosures lists the closures still owed on a machine's jobs that
// filter keeps, least recently attempted first (never attempted first),
// then by proposal ID.
func (s *Store) PendingClosures(ctx context.Context, machineID string, limit int, keep func(*Job) bool) ([]PendingClosure, error) {
	jobs, err := s.ListJobs(ctx, JobFilter{MachineID: machineID})
	if err != nil {
		return nil, err
	}
	var out []PendingClosure
	for _, j := range jobs {
		if keep != nil && !keep(j) {
			continue
		}
		for _, pc := range j.PendingClosures {
			out = append(out, *pc)
		}
	}
	sort.Slice(out, func(i, k int) bool {
		a, b := out[i].LastAttemptAt, out[k].LastAttemptAt
		switch {
		case a == nil && b != nil:
			return true
		case a != nil && b == nil:
			return false
		case a != nil && b != nil && !a.Equal(*b):
			return a.Before(*b)
		}
		return out[i].ProposalID < out[k].ProposalID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
