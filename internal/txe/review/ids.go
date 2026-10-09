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

// UncertainProposalID identifies the escalation of one action as asked
// about one version of its job. An answer is tied to the job as it was when
// the owner gave it: after the job changes, the question has a new id and
// the old answer no longer applies.
func UncertainProposalID(actionID string, jobVersion int) string {
	id, err := registry.EscalationProposalID(actionID, jobVersion)
	if err != nil {
		// Only a string and an int are hashed.
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
