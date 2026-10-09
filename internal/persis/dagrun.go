// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package persis

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"time"

	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/workspace"
)

var ErrInvalidDAGRunQueryCursor = errors.New("dagrun: invalid query cursor")

// ErrLatestExecutionChanged is a conditional retry whose expected execution
// is no longer the run's latest: nothing was created.
var ErrLatestExecutionChanged = errors.New("dagrun: the run's latest execution is not the expected one")

// ExpectedExecution names one execution of a run: an attempt and the queue
// marker it ran under.
type ExpectedExecution struct {
	AttemptID string
	QueuedAt  string
}

// DAGRunStore persists DAG runs and their attempts as one consistency boundary.
type DAGRunStore interface {
	// OpenLog reads a regular log file up to its size when opened. The caller must close it.
	OpenLog(ctx context.Context, path string) (io.ReadCloser, error)
	CreateAttempt(ctx context.Context, req DAGRunCreateAttemptRequest) (dagrun.Attempt, error)
	RecentStatuses(ctx context.Context, name string, limit int) ([]ir.DAGRunStatus, error)
	LatestAttempt(ctx context.Context, query DAGRunLatestAttemptQuery) (dagrun.Attempt, error)
	QueryStatuses(ctx context.Context, query DAGRunStatusQuery) (DAGRunStatusPage, error)
	CompareAndSwapLatestAttemptStatus(ctx context.Context, req DAGRunCompareAndSwapStatusRequest) (*ir.DAGRunStatus, bool, error)
	FindAttempt(ctx context.Context, ref ir.DAGRunRef) (dagrun.Attempt, error)
	FindSubAttempt(ctx context.Context, root ir.DAGRunRef, childRunID string) (dagrun.Attempt, error)
	RemoveOldDAGRuns(ctx context.Context, req DAGRunRetentionRequest) ([]ir.DAGRunRef, error)
	RemoveDAGRun(ctx context.Context, req DAGRunRemoveRequest) error
	// PruneArtifacts removes artifact directories and index records that no
	// surviving DAG run points to.
	PruneArtifacts(ctx context.Context, req ArtifactPruneRequest) (*ArtifactPruneResult, error)
}

// DAGRunStatusQuery contains normalized backend filters for listing runs.
// Limit is zero for an unbounded query and positive otherwise.
type DAGRunStatusQuery struct {
	DAGRunID        string
	Name            string
	ExactName       string
	From            TimeInUTC
	To              TimeInUTC
	Statuses        []ir.Status
	Limit           int
	Cursor          string
	Labels          []string
	WorkspaceFilter *workspace.WorkspaceFilter
}

// DAGRunStatusPage is one forward-only page of DAG-run statuses.
type DAGRunStatusPage struct {
	Items      []*ir.DAGRunStatus
	NextCursor string
}

// DAGRunCreateAttemptRequest identifies the run and attempt to create.
// A zero RootDAGRun creates a root run; a nonzero value creates its child.
type DAGRunCreateAttemptRequest struct {
	DAG        *ir.DAG
	RootDAGRun ir.DAGRunRef
	Timestamp  time.Time
	DAGRunID   string
	AttemptID  string
	Retry      bool
	// ExpectLatest, on a retry, creates the attempt only if the run's latest
	// execution is this one and has finished; otherwise the store returns
	// ErrLatestExecutionChanged and creates nothing.
	ExpectLatest *ExpectedExecution
}

// DAGRunLatestAttemptQuery selects the newest visible attempt for a DAG.
type DAGRunLatestAttemptQuery struct {
	Name      string
	NotBefore TimeInUTC
}

// DAGRunCompareAndSwapStatusRequest describes an atomic latest-attempt status update.
type DAGRunCompareAndSwapStatusRequest struct {
	DAGRun             ir.DAGRunRef
	RootDAGRun         ir.DAGRunRef
	ExpectedAttemptID  string
	ExpectedAttemptKey string
	ExpectedStatus     ir.Status
	Mutate             func(*ir.DAGRunStatus) error
	// RetainBeforeSwap keeps an immutable copy of the latest execution (its
	// whole status and its logs) before Mutate replaces it, when that
	// execution has finished. A failure to retain refuses the swap.
	RetainBeforeSwap bool
}

// DAGRunRetentionRequest describes normalized DAG-run cleanup policy.
type DAGRunRetentionRequest struct {
	Name      string
	OlderThan TimeInUTC
	KeepRuns  int
	DryRun    bool
}

// DAGRunRemoveRequest identifies a DAG run to remove.
type DAGRunRemoveRequest struct {
	DAGRun       ir.DAGRunRef
	RejectActive bool
}

// ArtifactPruneRequest describes a sweep for orphaned artifact directories.
type ArtifactPruneRequest struct {
	// Root is the artifact tree to sweep; empty uses the store's configured
	// artifact root.
	Root string
	// ProtectedDirs are directories the sweep must never reach. A root that
	// equals or contains one of them, or the store's run history, is refused.
	ProtectedDirs []string
	// OlderThan bounds removal to entries created before it. Stores clamp it
	// to a minimum age, because a run's artifact directory exists before its
	// record does.
	OlderThan TimeInUTC
	// DryRun reports what would be removed without removing it.
	DryRun bool
}

// ArtifactPruneResult reports the paths a sweep removed, or would remove in a
// dry run.
type ArtifactPruneResult struct {
	// Dirs are run artifact directories.
	Dirs []string
	// Records are artifact index sidecars whose run is gone.
	Records []string
}

// DAGRunRepositoryOptions configures application-level DAG-run behavior.
type DAGRunRepositoryOptions struct {
	LatestStatusToday bool
	Location          *time.Location
	Now               func() time.Time
	RemovalEnqueuer   DAGRunRemovalEnqueuer
}

// DAGRunRemovalEnqueuer durably records resources before their DAG-run history is removed.
type DAGRunRemovalEnqueuer interface {
	EnqueueDAGRunRemoval(ctx context.Context, root ir.DAGRunRef, resources []ir.AgentSessionResource) error
}

// DAGRunCreateAttemptOptions configures creation of a run attempt.
type DAGRunCreateAttemptOptions struct {
	// RootDAGRun identifies the root when creating a child attempt.
	RootDAGRun ir.DAGRunRef
	// Retry indicates that the attempt retries an existing DAG run.
	Retry bool
	// AttemptID uses a caller-assigned attempt identifier when non-empty.
	AttemptID string
	// ExpectLatest makes a retry conditional on the run's latest execution
	// (see DAGRunCreateAttemptRequest).
	ExpectLatest *ExpectedExecution
}

// DAGRunLatestAttemptOptions configures a latest-attempt lookup.
type DAGRunLatestAttemptOptions struct {
	// AllHistory disables the repository's optional today-only lookup window.
	AllHistory bool
}

// DAGRunListOptions configures status listing.
type DAGRunListOptions struct {
	DAGRunID        string
	Name            string
	ExactName       string
	From            TimeInUTC
	To              TimeInUTC
	Statuses        []ir.Status
	Limit           int
	Cursor          string
	Labels          []string
	WorkspaceFilter *workspace.WorkspaceFilter
	// AllHistory disables the implicit recent-time window when no range is set.
	AllHistory bool
	// Unbounded disables the repository's result limit.
	Unbounded bool
}

// DAGRunCompareAndSwapOptions configures an atomic latest-attempt status update.
type DAGRunCompareAndSwapOptions struct {
	// RootDAGRun identifies the root containing a child attempt.
	RootDAGRun ir.DAGRunRef
	// ExpectedAttemptKey rejects an update when the persisted key differs.
	ExpectedAttemptKey string
	// RetainBeforeSwap keeps an immutable copy of the finished execution the
	// swap replaces; see DAGRunCompareAndSwapStatusRequest.
	RetainBeforeSwap bool
}

// ErrExecutionRetentionUnsupported refuses a swap that asked to retain the
// execution it replaces from a store that cannot: history is never dropped
// silently.
var ErrExecutionRetentionUnsupported = errors.New("this DAG-run store cannot retain executions")

// ExecutionRetainingStore is a DAGRunStore that honours RetainBeforeSwap and
// serves the executions it retained.
type ExecutionRetainingStore interface {
	ListRetainedExecutions(ctx context.Context, root, dagRun ir.DAGRunRef) ([]RetainedExecution, error)
	ReadRetainedExecutionFile(ctx context.Context, root, dagRun ir.DAGRunRef, executionRef, name string) ([]byte, error)
}

// RetainedExecution describes an immutable copy of one execution of a run,
// taken before a queued retry replaced it.
type RetainedExecution struct {
	Schema    int    `json:"schema"`
	Execution string `json:"execution"`
	AttemptID string `json:"attempt_id"`
	QueuedAt  string `json:"queued_at"`
	Status    string `json:"status"`
	// StatusComplete is true when the copied status is the execution's
	// terminal status.
	StatusComplete bool `json:"status_complete"`
	// LogsFinal is true only when every log stream of the execution was
	// proven finished before the copy; otherwise the logs may be partial.
	LogsFinal     bool           `json:"logs_final"`
	LogsNote      string         `json:"logs_note,omitempty"`
	RetainedAt    time.Time      `json:"retained_at"`
	StatusSHA256  string         `json:"status_sha256"`
	Files         []RetainedFile `json:"files"`
	ArtifactFiles []RetainedFile `json:"artifact_files,omitempty"`
}

// RetainedFile is a file of a retained execution: a copied log, or an
// artifact the execution published, referenced by digest.
type RetainedFile struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
	// Final is true for a log whose stream was proven finished for this
	// execution: the coordinator's <log>.final record names the execution's
	// queue marker and attempt and the copied size.
	Final bool `json:"final,omitempty"`
}

// DAGRunRetentionOptions configures retention cleanup.
type DAGRunRetentionOptions struct {
	DryRun bool
	// RetentionRuns takes precedence over OlderThan and retention days when set.
	RetentionRuns *int
	// OlderThan takes precedence over retention days when RetentionRuns is unset.
	OlderThan *time.Time
}

// DAGRunRemoveOptions configures DAG-run removal.
type DAGRunRemoveOptions struct {
	// RejectActive refuses to remove an active DAG run.
	RejectActive bool
}

// TimeInUTC wraps a time normalized to UTC.
type TimeInUTC struct{ time.Time }

// NewUTC returns t normalized to UTC.
func NewUTC(t time.Time) TimeInUTC {
	return TimeInUTC{Time: t.UTC()}
}

type dagRunListReadBatchContextKey struct{}

var nextDAGRunListReadBatchID atomic.Uint64

// DAGRunListReadBatch identifies list reads that may share the same storage work.
type DAGRunListReadBatch struct {
	id uint64
}

// NewDAGRunListReadBatch creates a new list-read batch.
func NewDAGRunListReadBatch() *DAGRunListReadBatch {
	return &DAGRunListReadBatch{id: nextDAGRunListReadBatchID.Add(1)}
}

// WithDAGRunListReadBatch associates a list-read batch with a context.
func WithDAGRunListReadBatch(ctx context.Context, batch *DAGRunListReadBatch) context.Context {
	return context.WithValue(ctx, dagRunListReadBatchContextKey{}, batch)
}

// DAGRunListReadBatchID returns the list-read batch ID associated with ctx.
func DAGRunListReadBatchID(ctx context.Context) (uint64, bool) {
	batch, ok := ctx.Value(dagRunListReadBatchContextKey{}).(*DAGRunListReadBatch)
	if !ok {
		return 0, false
	}
	return batch.id, true
}
