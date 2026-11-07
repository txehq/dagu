// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package ir

// Status represents the canonical lifecycle phases for a DAG execution.
type Status int

const (
	NotStarted Status = iota
	Running
	Failed
	Aborted
	Succeeded
	Queued
	PartiallySucceeded
	Waiting
	Rejected
)

// String returns the canonical lowercase token used across APIs, logs, and
// environment variables.
func (s Status) String() string {
	switch s {
	case NotStarted:
		return "not_started"
	case Running:
		return "running"
	case Failed:
		return "failed"
	case Aborted:
		return "aborted"
	case Succeeded:
		return "succeeded"
	case Queued:
		return "queued"
	case PartiallySucceeded:
		return "partially_succeeded"
	case Waiting:
		return "waiting"
	case Rejected:
		return "rejected"
	default:
		return "unknown"
	}
}

// IsActive checks if the status is active (not yet completed).
// This includes running, queued, and waiting executions.
func (s Status) IsActive() bool {
	return s == Running || s == Queued || s == Waiting
}

// IsSuccess checks if the status indicates a successful execution.
func (s Status) IsSuccess() bool {
	return s == Succeeded || s == PartiallySucceeded
}

// IsWaiting checks if the status requires manual action before it can continue.
func (s Status) IsWaiting() bool {
	return s == Waiting
}

// NodeStatus represents the canonical lifecycle phases for an individual node.
type NodeStatus int

const (
	// Keep numeric values stable because NodeStatus is persisted in run status
	// snapshots and older files/tests depend on the historical encoding.
	NodeNotStarted         NodeStatus = 0
	NodeRunning            NodeStatus = 1
	NodeFailed             NodeStatus = 2
	NodeAborted            NodeStatus = 3
	NodeSucceeded          NodeStatus = 4
	NodeSkipped            NodeStatus = 5
	NodePartiallySucceeded NodeStatus = 6
	NodeWaiting            NodeStatus = 7
	NodeRejected           NodeStatus = 8
	NodeRetrying           NodeStatus = 9
)

// IsSuccess checks if the node status indicates a successful execution.
func (s NodeStatus) IsSuccess() bool {
	return s == NodeSucceeded || s == NodePartiallySucceeded
}

// IsWaiting checks if the node status requires manual action before it can continue.
func (s NodeStatus) IsWaiting() bool {
	return s == NodeWaiting
}

// IsDone checks if the node has completed (success, failure, skipped, aborted, rejected, or partially succeeded).
func (s NodeStatus) IsDone() bool {
	return s == NodeSucceeded ||
		s == NodeFailed ||
		s == NodeSkipped ||
		s == NodeAborted ||
		s == NodePartiallySucceeded ||
		s == NodeRejected
}

// String returns the canonical lowercase token for the node lifecycle phase.
func (s NodeStatus) String() string {
	switch s {
	case NodeNotStarted:
		return "not_started"
	case NodeRunning:
		return "running"
	case NodeRetrying:
		return "retrying"
	case NodeFailed:
		return "failed"
	case NodeAborted:
		return "aborted"
	case NodeSucceeded:
		return "succeeded"
	case NodeSkipped:
		return "skipped"
	case NodePartiallySucceeded:
		return "partially_succeeded"
	case NodeWaiting:
		return "waiting"
	case NodeRejected:
		return "rejected"
	default:
		return "unknown"
	}
}

// TriggerType represents how a DAG run was initiated.
type TriggerType int

const (
	TriggerTypeUnknown TriggerType = iota
	TriggerTypeScheduler
	TriggerTypeManual
	TriggerTypeWebhook
	TriggerTypeSubDAG
	TriggerTypeRetry
	TriggerTypeCatchUp
	// TriggerTypeFile is a run started by a file arriving in a watched folder.
	TriggerTypeFile
)

// Unbound reports whether a run of this trigger type is asked for by no hub
// principal: a webhook delivery, local or through Dagu Cloud, comes from an
// outside sender the hub's roles and owners know nothing of. Such a run is
// queued only with the owner rule's decision (intake.QueueRequest.Unbound,
// TXE-5923). Every other trigger is a principal's own act or one its DAG
// declares (a schedule, a catch-up, a file it watches), or follows one (a
// retry, a sub-DAG). The switch names every trigger type, so a new one is
// classified here before it builds (the exhaustive linter).
func (t TriggerType) Unbound() bool {
	switch t {
	case TriggerTypeWebhook:
		return true
	case TriggerTypeUnknown, TriggerTypeScheduler, TriggerTypeManual, TriggerTypeSubDAG,
		TriggerTypeRetry, TriggerTypeCatchUp, TriggerTypeFile:
		return false
	}
	// A value outside the declared ones is unbound: it fails closed.
	return true
}

// String returns the canonical lowercase token for the trigger type.
func (t TriggerType) String() string {
	switch t {
	case TriggerTypeUnknown:
		return "unknown"
	case TriggerTypeScheduler:
		return "scheduler"
	case TriggerTypeManual:
		return "manual"
	case TriggerTypeWebhook:
		return "webhook"
	case TriggerTypeSubDAG:
		return "subdag"
	case TriggerTypeRetry:
		return "retry"
	case TriggerTypeCatchUp:
		return "catchup"
	case TriggerTypeFile:
		return "file"
	default:
		return "unknown"
	}
}

// ParseTriggerType parses a string into a TriggerType.
func ParseTriggerType(s string) TriggerType {
	switch s {
	case "scheduler":
		return TriggerTypeScheduler
	case "manual":
		return TriggerTypeManual
	case "webhook":
		return TriggerTypeWebhook
	case "subdag":
		return TriggerTypeSubDAG
	case "retry":
		return TriggerTypeRetry
	case "catchup":
		return TriggerTypeCatchUp
	case "file":
		return TriggerTypeFile
	default:
		return TriggerTypeUnknown
	}
}
