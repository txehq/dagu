// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"encoding/json"
	"fmt"
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
type RetryRunParams struct {
	RunID         string `json:"run_id"`
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

// RetryProposalID is the ID of the proposal to retry runID at jobVersion.
func RetryProposalID(runID string, jobVersion int) (string, error) {
	return DerivedID(PrefixProposal, "retry", runID, jobVersion)
}

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
		if rp.RunSpecSHA256 != j.DAGSpecSHA256 || rp.PackageDigest != j.PackageDigest {
			return &Error{Code: CodeStaleBinding, Message: fmt.Sprintf("run %s is not of the current version %d; it is not retried", rp.RunID, j.Version), Current: j}
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
	id, err := RetryProposalID(params.RunID, j.Version)
	if err != nil {
		return nil, nil, err
	}
	p := Proposal{ProposalID: id, Action: ActionSpec{Name: ActionRetryRun, Params: raw},
		AllowedVerdicts: []Verdict{VerdictRetry, VerdictReject}, WaitingOn: "person", Question: "Retry run " + params.RunID + "?"}
	if err := tx.checkReservedProposal(&p); err != nil {
		return nil, nil, err
	}
	if cur, ok := j.Proposals[id]; ok && cur.State != ProposalOpen && cur.State != ProposalSnoozed {
		return nil, nil, &Error{Code: CodeProposalState, Message: "a retry of run " + params.RunID + " is already " + string(cur.State), Current: cur}
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
