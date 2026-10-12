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
	// record, not the status, says nothing ran. An execution-scoped
	// abandonment (AbandonmentScopeExecution) always has this outcome.
	AbandonmentMarkedFailed = "marked_failed"
)

// AbandonmentScopeExecution scopes a record to one execution of a reused
// attempt: a queued run or a queued retry dispatched from an attempt that
// already existed. Hiding such an attempt would hide the attempt, not the
// execution, so the execution is marked Failed instead; earlier executions'
// records and retained history are kept, and a later execution (another
// queued-at marker) is never covered.
const AbandonmentScopeExecution = "execution"

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
	// Scope is empty for an abandoned attempt, or AbandonmentScopeExecution
	// for one execution of a reused attempt, named by AbandonedExecution.
	Scope string `json:"scope,omitempty"`
	// Outcome is AbandonmentHidden or AbandonmentMarkedFailed.
	Outcome string `json:"outcome"`
	// ExpectedExecution is the execution that is the latest again after a
	// hide. PredecessorAbsent is true, and ExpectedExecution nil, when the
	// run had none. An execution-scoped record hides nothing: it has no
	// ExpectedExecution, and PredecessorAbsent says whether the run had any
	// execution before this one.
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

// Covers reports whether a claim of attemptID whose task carries
// executionMarker claims the abandoned execution. A newly created attempt's
// task has an empty marker, even when its status inherits the queued-at of
// the execution it retries; the recorded queued-at names it too. A retry
// that re-queues the attempt afterwards has a marker strictly later than any
// before it, so it is another execution. An execution-scoped record names
// its execution's marker; an empty marker is covered too, failing closed.
func (a AttemptAbandonment) Covers(attemptID, executionMarker string) bool {
	return a.AbandonedAttemptID == attemptID &&
		(executionMarker == "" || executionMarker == a.AbandonedExecution.QueuedAt)
}

// AbandonAttemptRequest asks the store to record and hide the run's latest
// attempt, which must still be the named, never-dispatched attempt.
//
// With Record.Scope AbandonmentScopeExecution it asks instead to abandon one
// execution of a reused attempt, named by Record.AbandonedExecution (its
// attempt and exact queued-at marker): the attempt must be the run's latest,
// its status Queued or NotStarted with exactly that marker and no worker.
type AbandonAttemptRequest struct {
	DAGRun     ir.DAGRunRef
	RootDAGRun ir.DAGRunRef
	// Record is written as given, except Outcome, ExpectedExecution and
	// PredecessorAbsent, which the store sets from the run under its lock,
	// and, for an attempt, AbandonedExecution.
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
	// attempt has none. Execution-scoped records are read with
	// ReadExecutionAbandonment (DAGRunExecutionAbandonmentReader). A record that exists but cannot be read, or names
	// another attempt, is an error, so a caller deciding whether to authorize
	// an execution fails closed.
	ReadAttemptAbandonment(ctx context.Context, dagRun, rootDAGRun ir.DAGRunRef, attemptID string) (*AttemptAbandonment, error)
	// ListAttemptAbandonmentsStrict reads every record of a run as
	// ReadAttemptAbandonment reads one: one result per record, an attempt's
	// own and each of its execution-scoped ones, in the store's attempt order (newest first within an attempt
	// directory format). A record that cannot be trusted is a
	// result with Err, never dropped and never hiding the others. The call
	// fails only when the run cannot be found, listed or locked.
	ListAttemptAbandonmentsStrict(ctx context.Context, dagRun, rootDAGRun ir.DAGRunRef) ([]AttemptAbandonmentResult, error)
}

// DAGRunExecutionAbandonmentReader is implemented by stores that keep
// execution-scoped abandonment records.
type DAGRunExecutionAbandonmentReader interface {
	// ReadExecutionAbandonment returns the record that covers a claim of
	// attemptID carrying executionMarker (see AttemptAbandonment.Covers),
	// the attempt's own or an execution-scoped one, or nil when none does.
	// Like ReadAttemptAbandonment it fails closed on a record it cannot
	// trust.
	ReadExecutionAbandonment(ctx context.Context, dagRun, rootDAGRun ir.DAGRunRef, attemptID, executionMarker string) (*AttemptAbandonment, error)
}

// AttemptAbandonmentResult is one attempt's record from a strict listing:
// Record when it is trusted, otherwise Err, which wraps
// ErrAttemptAbandonmentConflict.
type AttemptAbandonmentResult struct {
	AttemptID string
	Record    *AttemptAbandonment
	Err       error
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

// ReadExecutionAbandonment reads the record covering one execution's claim.
func (r *DAGRunRepository) ReadExecutionAbandonment(ctx context.Context, dagRun, rootDAGRun ir.DAGRunRef, attemptID, executionMarker string) (*AttemptAbandonment, error) {
	reader, ok := r.store.(DAGRunExecutionAbandonmentReader)
	if !ok {
		return nil, ErrAttemptAbandonmentUnsupported
	}
	return reader.ReadExecutionAbandonment(ctx, dagRun, rootDAGRun, attemptID, executionMarker)
}

// ListAttemptAbandonmentsStrict lists a run's abandonment records, reporting
// each one that cannot be trusted instead of skipping it.
func (r *DAGRunRepository) ListAttemptAbandonmentsStrict(ctx context.Context, dagRun, rootDAGRun ir.DAGRunRef) ([]AttemptAbandonmentResult, error) {
	abandoner, ok := r.store.(DAGRunAttemptAbandoner)
	if !ok {
		return nil, ErrAttemptAbandonmentUnsupported
	}
	if rootDAGRun.Zero() {
		rootDAGRun = dagRun
	}
	return abandoner.ListAttemptAbandonmentsStrict(ctx, dagRun, rootDAGRun)
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
	// QueuedAt is set for one execution of a reused attempt: the exact
	// queued-at marker its status carried when the dispatch began
	// (BeginAttemptPreparation). Empty for a newly created attempt.
	QueuedAt string `json:"queuedAt,omitempty"`
	// PreparedAt is when the entry was written, RFC 3339 in UTC.
	PreparedAt string `json:"preparedAt"`
}

// DAGRunPreparationBeginner is implemented by journals that can journal one
// execution of a reused attempt, as a dispatch of a queued run or a queued
// retry does.
type DAGRunPreparationBeginner interface {
	// BeginAttemptPreparation journals the execution of attemptID marked
	// queuedAt, under the run's data-root lock. It is refused, wrapping
	// ErrAttemptNotAbandonable, unless the attempt is the run's latest and
	// its status is Queued or NotStarted with exactly that marker and no
	// worker. Beginning an entry that exists returns it unchanged.
	BeginAttemptPreparation(ctx context.Context, run, root ir.DAGRunRef, attemptID, queuedAt string) (AttemptPreparation, error)
}

// BeginAttemptPreparation journals one execution of a reused attempt (see
// DAGRunPreparationBeginner).
func (r *DAGRunRepository) BeginAttemptPreparation(ctx context.Context, run, root ir.DAGRunRef, attemptID, queuedAt string) (AttemptPreparation, error) {
	beginner, ok := r.store.(DAGRunPreparationBeginner)
	if !ok {
		return AttemptPreparation{}, ErrAttemptAbandonmentUnsupported
	}
	return beginner.BeginAttemptPreparation(ctx, run, root, attemptID, queuedAt)
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

// DAGRunPreparationLookup is implemented by journals that can answer for one
// attempt strictly, unlike ListAttemptPreparations, which skips entries it
// cannot read.
type DAGRunPreparationLookup interface {
	// AttemptPrepared reports whether the journal holds an entry for the
	// attempt, its own or one of its executions':
	// false when it holds none, an error when the entry exists but cannot be
	// read or names another attempt.
	AttemptPrepared(ctx context.Context, run, root ir.DAGRunRef, attemptID string) (bool, error)
}

// AttemptPrepared reports whether the preparation journal holds the attempt
// (see DAGRunPreparationLookup). A store without one never abandons
// attempts and returns ErrAttemptAbandonmentUnsupported.
func (r *DAGRunRepository) AttemptPrepared(ctx context.Context, run, root ir.DAGRunRef, attemptID string) (bool, error) {
	lookup, ok := r.store.(DAGRunPreparationLookup)
	if !ok {
		return false, ErrAttemptAbandonmentUnsupported
	}
	return lookup.AttemptPrepared(ctx, run, root, attemptID)
}

// DAGRunPreparationSettler is implemented by journals that end an entry only
// once nothing of its preparation is left to judge, decided under the lock
// that abandoning and creating attempts take.
type DAGRunPreparationSettler interface {
	// EndSettledAttemptPreparation ends the entry, and reports true, when the
	// run or the attempt is gone or hidden, when the attempt is the latest
	// and has started, or when another attempt is the latest and is not
	// itself a preparation. It keeps the entry, and reports false, while the
	// attempt is the latest and not started, or the latest is another
	// preparation that may yet be abandoned, restoring this one. An entry for
	// one execution of a reused attempt (QueuedAt set) is settled once the
	// attempt is gone or hidden, its status names another execution, or the
	// execution was handed to a worker or started.
	EndSettledAttemptPreparation(ctx context.Context, preparation AttemptPreparation) (bool, error)
}

// EndSettledAttemptPreparation ends a preparation entry once it is settled
// (see DAGRunPreparationSettler).
func (r *DAGRunRepository) EndSettledAttemptPreparation(ctx context.Context, preparation AttemptPreparation) (bool, error) {
	settler, ok := r.store.(DAGRunPreparationSettler)
	if !ok {
		return false, ErrAttemptAbandonmentUnsupported
	}
	return settler.EndSettledAttemptPreparation(ctx, preparation)
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
