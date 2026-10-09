// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package persis

import (
	"context"
	"errors"

	"github.com/dagucloud/dagu/v2/internal/ir"
)

// AttemptAbandonmentSchema is the version of AttemptAbandonment records this
// build writes and reads.
const AttemptAbandonmentSchema = 1

// AttemptAbandonmentReason values.
const (
	// AbandonedRetryPreparation is an attempt created for a retry or a new
	// execution that was never handed to a worker.
	AbandonedRetryPreparation = "retry_preparation_abandoned"
)

// Abandonment outcomes.
const (
	// AbandonmentHidden: the attempt was hidden and the execution before it
	// is the latest again.
	AbandonmentHidden = "hidden"
	// AbandonmentMarkedFailed: the run had no earlier execution, so the
	// attempt stays visible, marked Failed with a not-dispatched reason. The
	// record, not the status, says nothing ran.
	AbandonmentMarkedFailed = "marked_failed"
)

// Evidence values for each authoritative lookup an abandonment rests on.
const (
	EvidenceAbsent = "absent"
)

var (
	// ErrAttemptAbandonmentUnsupported is returned when the store cannot
	// record and hide an abandoned attempt.
	ErrAttemptAbandonmentUnsupported = errors.New("attempt abandonment is not supported by this store")
	// ErrAttemptNotAbandonable is returned when the attempt is settled as not
	// one to abandon: it is not the run's latest, it is gone, or its status
	// shows it started or was claimed. Nothing is recorded or hidden. A read
	// that failed is a different error, since the attempt may yet be one.
	ErrAttemptNotAbandonable = errors.New("attempt is not an abandonable never-dispatched attempt")
	// ErrAttemptAbandonmentConflict is returned when an existing record for
	// the attempt is unreadable or describes something else; it never
	// authorizes a hide.
	ErrAttemptAbandonmentConflict = errors.New("existing attempt abandonment record conflicts")
)

// ExecutionIdentity names one execution of an attempt.
type ExecutionIdentity struct {
	AttemptID string `json:"attemptId"`
	QueuedAt  string `json:"queuedAt,omitempty"`
}

// RequestCorrelation binds an execution to the request that asked for it
// (TXE-3827). An abandonment without one cannot be attributed to a caller.
type RequestCorrelation struct {
	ID            string `json:"id"`
	ActionID      string `json:"actionId"`
	ActionAttempt string `json:"actionAttempt"`
	BindingDigest string `json:"bindingDigest"`
}

// AbandonmentEvidence is what proved that nothing was ever dispatched for the
// attempt. Each field is EvidenceAbsent; a lookup that failed is unknown and
// never produces a record.
type AbandonmentEvidence struct {
	DispatchTask string `json:"dispatchTask"`
	Lease        string `json:"lease"`
	ActiveRun    string `json:"activeRun"`
	Worker       string `json:"worker"`
	ObservedAt   string `json:"observedAt"`
}

// AttemptAbandonment is the immutable record written into an attempt's own
// directory before the attempt is hidden. It keeps the abandoned preparation
// and its proof together, and is read back through the run's history.
type AttemptAbandonment struct {
	Schema             int          `json:"schema"`
	Run                ir.DAGRunRef `json:"run"`
	RootRun            ir.DAGRunRef `json:"rootRun"`
	AbandonedAttemptID string       `json:"abandonedAttemptId"`
	// AbandonedExecution is the execution that was abandoned: the attempt and
	// the queued-at marker its status carried, empty for a new attempt. The
	// store sets it. A later retry that re-queues the same attempt is a
	// different execution, which the record does not cover.
	AbandonedExecution ExecutionIdentity `json:"abandonedExecution"`
	// Outcome is AbandonmentHidden or AbandonmentMarkedFailed.
	Outcome string `json:"outcome"`
	// ExpectedExecution is the execution that is the latest again after a
	// hide. PredecessorAbsent is true, and ExpectedExecution nil, when the
	// run had none.
	ExpectedExecution  *ExecutionIdentity  `json:"expectedExecution,omitempty"`
	PredecessorAbsent  bool                `json:"predecessorAbsent"`
	RequestCorrelation *RequestCorrelation `json:"requestCorrelation,omitempty"`
	Reason             string              `json:"reason"`
	Detail             string              `json:"detail,omitempty"`
	DecidedAt          string              `json:"decidedAt"`
	CoordinatorID      string              `json:"coordinatorId,omitempty"`
	Evidence           AbandonmentEvidence `json:"evidence"`
}

// Attributable reports whether the record can be attributed to a caller's
// request. Without a correlation it cannot: another caller may have abandoned
// an attempt for the same predecessor.
func (a AttemptAbandonment) Attributable() bool {
	c := a.RequestCorrelation
	return c != nil && c.ID != "" && c.ActionID != "" && c.ActionAttempt != "" && c.BindingDigest != ""
}

// Covers reports whether the record abandons the execution of its attempt
// that carries executionMarker, the queued-at marker a dispatched task names.
func (a AttemptAbandonment) Covers(attemptID, executionMarker string) bool {
	return a.AbandonedAttemptID == attemptID && a.AbandonedExecution.QueuedAt == executionMarker
}

// AbandonAttemptRequest asks the store to record and hide the run's latest
// attempt, which must still be the named, never-dispatched attempt.
type AbandonAttemptRequest struct {
	DAGRun     ir.DAGRunRef
	RootDAGRun ir.DAGRunRef
	// Record is written as given, except Outcome, ExpectedExecution and
	// PredecessorAbsent, which the store sets from the run under its lock.
	Record AttemptAbandonment
}

// DAGRunAttemptAbandoner is implemented by stores that can record and hide an
// abandoned attempt, and list such records.
type DAGRunAttemptAbandoner interface {
	// AbandonAttempt, under the store's lock for the run, checks that the
	// latest attempt is req.Record.AbandonedAttemptID, not started and
	// without a worker, and writes the record into that attempt's directory,
	// or verifies the one already there. Then it applies the outcome: with an
	// earlier execution it hides the attempt; without one it marks the
	// attempt Failed with the record's detail, keeping the run visible. It
	// returns the record now on disk.
	AbandonAttempt(ctx context.Context, req AbandonAttemptRequest) (*AttemptAbandonment, error)
	// ListAttemptAbandonments returns the records of a run's abandoned
	// attempts, hidden or not, newest attempt first. It skips a record it
	// cannot read, so it serves history, never authorization.
	ListAttemptAbandonments(ctx context.Context, dagRun, rootDAGRun ir.DAGRunRef) ([]AttemptAbandonment, error)
	// ReadAttemptAbandonment returns the record of one attempt, or nil when the
	// attempt has none. A record that exists but cannot be read, or names
	// another attempt, is an error, so a caller deciding whether to authorize
	// an execution fails closed.
	ReadAttemptAbandonment(ctx context.Context, dagRun, rootDAGRun ir.DAGRunRef, attemptID string) (*AttemptAbandonment, error)
}

// AbandonAttempt records and hides a never-dispatched attempt.
func (r *DAGRunRepository) AbandonAttempt(ctx context.Context, req AbandonAttemptRequest) (*AttemptAbandonment, error) {
	abandoner, ok := r.store.(DAGRunAttemptAbandoner)
	if !ok {
		return nil, ErrAttemptAbandonmentUnsupported
	}
	if req.RootDAGRun.Zero() {
		req.RootDAGRun = req.DAGRun
	}
	return abandoner.AbandonAttempt(ctx, req)
}

// ReadAttemptAbandonment reads one attempt's abandonment record.
func (r *DAGRunRepository) ReadAttemptAbandonment(ctx context.Context, dagRun, rootDAGRun ir.DAGRunRef, attemptID string) (*AttemptAbandonment, error) {
	abandoner, ok := r.store.(DAGRunAttemptAbandoner)
	if !ok {
		return nil, ErrAttemptAbandonmentUnsupported
	}
	if rootDAGRun.Zero() {
		rootDAGRun = dagRun
	}
	return abandoner.ReadAttemptAbandonment(ctx, dagRun, rootDAGRun, attemptID)
}

// ListAttemptAbandonments lists a run's abandonment records.
func (r *DAGRunRepository) ListAttemptAbandonments(ctx context.Context, dagRun, rootDAGRun ir.DAGRunRef) ([]AttemptAbandonment, error) {
	abandoner, ok := r.store.(DAGRunAttemptAbandoner)
	if !ok {
		return nil, ErrAttemptAbandonmentUnsupported
	}
	if rootDAGRun.Zero() {
		rootDAGRun = dagRun
	}
	return abandoner.ListAttemptAbandonments(ctx, dagRun, rootDAGRun)
}

// AttemptPreparationSchema is the version of AttemptPreparation entries this
// build writes and reads.
const AttemptPreparationSchema = 1

// AttemptPreparation is a preparation journal entry: an attempt created to be
// handed to a worker, recorded before the attempt itself. An entry that
// outlives its preparation names an attempt that may never have been
// dispatched, whether or not its status was ever written.
type AttemptPreparation struct {
	Schema    int          `json:"schema"`
	Run       ir.DAGRunRef `json:"run"`
	RootRun   ir.DAGRunRef `json:"rootRun"`
	AttemptID string       `json:"attemptId"`
	// PreparedAt is when the entry was written, RFC 3339 in UTC.
	PreparedAt string `json:"preparedAt"`
}

// DAGRunPreparationJournal is implemented by stores that journal attempts
// created with TrackPreparation.
type DAGRunPreparationJournal interface {
	// ListAttemptPreparations returns every entry still in the journal,
	// oldest first. It skips, with a warning, an entry it cannot read.
	ListAttemptPreparations(ctx context.Context) ([]AttemptPreparation, error)
	// EndAttemptPreparation removes the entry; removing a missing one is not
	// an error.
	EndAttemptPreparation(ctx context.Context, preparation AttemptPreparation) error
}

// ListAttemptPreparations lists the preparation journal.
func (r *DAGRunRepository) ListAttemptPreparations(ctx context.Context) ([]AttemptPreparation, error) {
	journal, ok := r.store.(DAGRunPreparationJournal)
	if !ok {
		return nil, ErrAttemptAbandonmentUnsupported
	}
	return journal.ListAttemptPreparations(ctx)
}

// EndAttemptPreparation removes a preparation journal entry.
func (r *DAGRunRepository) EndAttemptPreparation(ctx context.Context, preparation AttemptPreparation) error {
	journal, ok := r.store.(DAGRunPreparationJournal)
	if !ok {
		return ErrAttemptAbandonmentUnsupported
	}
	return journal.EndAttemptPreparation(ctx, preparation)
}
