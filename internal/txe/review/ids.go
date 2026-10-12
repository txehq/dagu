// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"strings"

	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// derivedID derives an id with the registry's own function, so the reviewer
// and the registry cannot disagree about an id either of them computes.
func derivedID(prefix string, parts ...any) string {
	id, err := registry.DerivedID(registry.Prefix(prefix), parts...)
	if err != nil {
		// Only strings, ints and string maps are hashed.
		panic(err)
	}
	return id
}

func normalizeParams(params map[string]string) map[string]string {
	if params == nil {
		return map[string]string{}
	}
	return params
}

// ReviewID identifies one review episode of a job. A reviewer that replaces
// a crashed one works the same episode and derives the same id; the id
// changes only after the checkpoint advances.
func ReviewID(jobID string, episode int) string {
	return derivedID("rev", jobID, episode)
}

// IntentKey identifies the same follow-up intent across episodes. It bounds
// repeated attempts; it never suppresses a later episode's action.
func IntentKey(name, targetID string, params map[string]string) string {
	return derivedID("int", name, targetID, normalizeParams(params))
}

// RoutineActionID identifies a routine action within one review episode. A
// replay of the same decision in the same episode maps to the same record.
func RoutineActionID(reviewID, name, targetID string, params map[string]string) string {
	return derivedID("act", reviewID, name, targetID, normalizeParams(params))
}

// ApprovedActionID identifies the single effect one approve decision allows.
func ApprovedActionID(proposalID, decisionID string) string {
	return derivedID("act", proposalID, decisionID)
}

// ProposalID identifies a proposal raised by a review episode. The reviewer
// derives it, so filing the same proposal again is a no-op in the registry.
func ProposalID(reviewID string, kind ProposalKind, name, targetID string, params map[string]string, question string) string {
	return derivedID("prp", reviewID, string(kind), name, targetID, normalizeParams(params), question)
}

// UncertainProposalID identifies the escalation of one attempt of an action
// as asked about one version of its job. An answer is tied to the attempt
// it was given about and to the job as it was then: after another attempt,
// or after the job changes, the question has a new id and the old answer no
// longer applies.
func UncertainProposalID(actionID string, attempt, jobVersion int) string {
	id, err := registry.EscalationProposalID(actionID, attempt, jobVersion)
	if err != nil {
		// Only a string and ints are hashed.
		panic(err)
	}
	return id
}

// DecisionRunID is the id of the native run that carries a proposal's human
// task. It is derived from the proposal id so enqueueing twice conflicts
// instead of opening a second task.
func DecisionRunID(proposalID string) string {
	return "txe-" + strings.ToLower(strings.TrimPrefix(proposalID, "prp_"))
}

// Execution identifies one execution of a run the way the service does: by
// the attempt and by when that attempt was last queued. A retry keeps the
// run id. Dagu either starts a new attempt for it, or queues the latest
// attempt again under the same attempt id with a later queued time, so
// neither part alone names an execution.
type Execution struct {
	AttemptID string `json:"attempt_id"`
	// QueuedAt is the service's stored value, byte for byte; empty for an
	// attempt that was never queued.
	QueuedAt string `json:"queued_at,omitempty"`
}

// known reports whether the service identified the execution at all.
func (e Execution) known() bool {
	return e.AttemptID != ""
}

// Ref is the portable reference to the execution: the one form used in
// records, receipts and cursors.
func (e Execution) Ref() string {
	return ExecutionRef(e.AttemptID, e.QueuedAt)
}

// ExecutionRef is the registry's reference of an execution. The reviewer
// never derives one itself: a receipt it records has to be the one the
// registry observes.
func ExecutionRef(attemptID, queuedAt string) string {
	return registry.ExecutionRef(attemptID, queuedAt)
}
