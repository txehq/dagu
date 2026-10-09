// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"errors"
	"fmt"

	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type attemptIdentity struct {
	attemptKey string
	claimKey   string
	workerID   string
	dagRun     ir.DAGRunRef
	root       ir.DAGRunRef
	attemptID  string
	// executionMarker is the Task.execution_marker the writer claims to belong
	// to. A queued retry reuses the attempt id and key, so only the marker
	// separates a delayed write of an earlier execution from the current one.
	executionMarker string
}

func newAttemptIdentity(
	explicitKey string,
	workerID string,
	dagRun ir.DAGRunRef,
	root ir.DAGRunRef,
	attemptID string,
	executionMarker string,
) (attemptIdentity, error) {
	if workerID == "" || dagRun.Zero() || attemptID == "" {
		return attemptIdentity{}, fmt.Errorf("worker, DAG run, and attempt identity are required")
	}
	if root.Zero() {
		root = dagRun
	}
	derivedKey := ir.GenerateAttemptKey(root.Name, root.ID, dagRun.Name, dagRun.ID, attemptID)
	if explicitKey != "" && dagRun == root && explicitKey != derivedKey {
		return attemptIdentity{}, fmt.Errorf("attempt key does not match stream metadata")
	}
	claimKey := explicitKey
	if claimKey == "" {
		claimKey = derivedKey
	}
	return attemptIdentity{
		attemptKey:      derivedKey,
		claimKey:        claimKey,
		workerID:        workerID,
		dagRun:          dagRun,
		root:            root,
		attemptID:       attemptID,
		executionMarker: executionMarker,
	}, nil
}

func logChunkIdentity(chunk *coordinatorv1.LogChunk) (attemptIdentity, error) {
	if chunk == nil {
		return attemptIdentity{}, fmt.Errorf("log chunk is required")
	}
	return newAttemptIdentity(
		chunk.AttemptKey,
		chunk.WorkerId,
		ir.NewDAGRunRef(chunk.DagName, chunk.DagRunId),
		ir.NewDAGRunRef(chunk.RootDagRunName, chunk.RootDagRunId),
		chunk.AttemptId,
		chunk.ExecutionMarker,
	)
}

func artifactChunkIdentity(chunk *coordinatorv1.ArtifactChunk) (attemptIdentity, error) {
	if chunk == nil {
		return attemptIdentity{}, fmt.Errorf("artifact chunk is required")
	}
	return newAttemptIdentity(
		chunk.AttemptKey,
		chunk.WorkerId,
		ir.NewDAGRunRef(chunk.DagName, chunk.DagRunId),
		ir.NewDAGRunRef(chunk.RootDagRunName, chunk.RootDagRunId),
		chunk.AttemptId,
		chunk.ExecutionMarker,
	)
}

func statusIdentity(workerID string, runStatus *ir.DAGRunStatus, executionMarker string) (attemptIdentity, error) {
	if runStatus == nil {
		return attemptIdentity{}, fmt.Errorf("status is required")
	}
	if workerID == "" || runStatus.DAGRun().Zero() || runStatus.AttemptID == "" {
		return attemptIdentity{}, fmt.Errorf("worker, DAG run, and attempt identity are required")
	}
	root := runStatus.Root
	if root.Zero() {
		root = runStatus.DAGRun()
	}
	attemptKey := runStatus.AttemptKey
	if attemptKey == "" {
		attemptKey = ir.GenerateAttemptKey(root.Name, root.ID, runStatus.Name, runStatus.DAGRunID, runStatus.AttemptID)
	}
	claimKey := runStatus.EffectiveClaimKey()
	if claimKey == "" {
		claimKey = attemptKey
	}
	return attemptIdentity{
		attemptKey:      attemptKey,
		claimKey:        claimKey,
		workerID:        workerID,
		dagRun:          runStatus.DAGRun(),
		root:            root,
		attemptID:       runStatus.AttemptID,
		executionMarker: executionMarker,
	}, nil
}

func (h *Handler) validateStatusLease(
	ctx context.Context,
	workerID string,
	runStatus *ir.DAGRunStatus,
	executionMarker string,
) (*dispatch.DAGRunLease, bool, error) {
	if workerID == "" {
		return nil, false, status.Error(codes.InvalidArgument, "worker, DAG run, and attempt identity are required")
	}

	identity, identityErr := statusIdentity(workerID, runStatus, executionMarker)
	if identityErr == nil {
		lease, err := h.dagRunLeaseStore.Get(ctx, identity.claimKey)
		switch {
		case err == nil:
			return lease, false, h.validateAttemptLease(lease, identity)
		case !errors.Is(err, dispatch.ErrDAGRunLeaseNotFound):
			return nil, false, status.Error(codes.Internal, "failed to load distributed run lease: "+err.Error())
		}
	}

	if !isSubDAGStatus(runStatus) {
		if identityErr != nil {
			return nil, false, status.Error(codes.InvalidArgument, identityErr.Error())
		}
		return nil, true, nil
	}
	if runStatus.ClaimKey != "" {
		return nil, false, status.Error(codes.FailedPrecondition, remoteAttemptRejectedLeaseInactive)
	}

	claimKey, lease, err := h.validateSubDAGRootLease(ctx, workerID, runStatus.Root, executionMarker)
	if err != nil {
		return nil, false, err
	}
	runStatus.ClaimKey = claimKey
	return lease, false, nil
}

func (h *Handler) validateSubDAGRootLease(
	ctx context.Context,
	workerID string,
	rootRef ir.DAGRunRef,
	executionMarker string,
) (string, *dispatch.DAGRunLease, error) {
	rootAttempt, err := h.dagRunRepository.FindAttempt(ctx, rootRef)
	if err != nil {
		if errors.Is(err, dagrun.ErrDAGRunIDNotFound) {
			return "", nil, status.Error(codes.FailedPrecondition, remoteAttemptRejectedLeaseInactive)
		}
		return "", nil, status.Error(codes.Internal, "failed to load root attempt: "+err.Error())
	}
	rootStatus, err := rootAttempt.ReadStatus(ctx)
	if err != nil {
		if errors.Is(err, dagrun.ErrNoStatusData) {
			return "", nil, status.Error(codes.FailedPrecondition, remoteAttemptRejectedLeaseInactive)
		}
		return "", nil, status.Error(codes.Internal, "failed to load root status: "+err.Error())
	}
	if rootStatus == nil || isTerminalRunStatus(rootStatus.Status) {
		return "", nil, status.Error(codes.FailedPrecondition, remoteAttemptRejectedLeaseInactive)
	}

	attemptID := rootStatus.AttemptID
	if attemptID == "" {
		attemptID = rootAttempt.ID()
	}
	attemptKey := dispatch.AttemptKeyForStatus(rootStatus, rootAttempt.ID())
	claimKey := rootStatus.EffectiveClaimKey()
	if claimKey == "" {
		claimKey = attemptKey
	}
	if attemptKey == "" || claimKey == "" {
		return "", nil, status.Error(codes.FailedPrecondition, remoteAttemptRejectedLeaseInactive)
	}
	identity := attemptIdentity{
		attemptKey:      attemptKey,
		claimKey:        claimKey,
		workerID:        workerID,
		dagRun:          rootRef,
		root:            rootRef,
		attemptID:       attemptID,
		executionMarker: executionMarker,
	}
	lease, err := h.attemptLease(ctx, identity)
	if err != nil {
		return "", nil, err
	}
	return claimKey, lease, nil
}

func isSubDAGStatus(runStatus *ir.DAGRunStatus) bool {
	return runStatus != nil && !runStatus.Root.Zero() && runStatus.Root != runStatus.DAGRun()
}

func runningTaskIdentity(workerID string, task *coordinatorv1.RunningTask) (attemptIdentity, error) {
	if task == nil || workerID == "" || task.AttemptKey == "" || task.DagName == "" || task.DagRunId == "" {
		return attemptIdentity{}, fmt.Errorf("running task identity is required")
	}
	dagRun := ir.NewDAGRunRef(task.DagName, task.DagRunId)
	root := ir.NewDAGRunRef(task.RootDagRunName, task.RootDagRunId)
	if root.Zero() {
		root = dagRun
	}
	return attemptIdentity{
		attemptKey:      task.AttemptKey,
		claimKey:        task.AttemptKey,
		workerID:        workerID,
		dagRun:          dagRun,
		root:            root,
		executionMarker: task.ExecutionMarker,
	}, nil
}

func (h *Handler) validateAttempt(ctx context.Context, identity attemptIdentity) error {
	if _, err := h.attemptLease(ctx, identity); err != nil {
		return err
	}
	return h.refuseRequeuedExecution(ctx, identity)
}

// refuseRequeuedExecution refuses a write once the run's root attempt waits in
// the queue for a later execution. Between the retry persisting the queued
// status and the next execution's claim, the earlier execution's lease still
// matches, so the lease alone would admit its late output.
//
// A write validated just before the queued status is persisted can still land
// after it; the retry's snapshot is taken under the store's lock and does not
// see it. In the live files, the next execution's positioned stream rewrites
// and truncates the log, and its first open removes the earlier .final record.
func (h *Handler) refuseRequeuedExecution(ctx context.Context, identity attemptIdentity) error {
	if h.dagRunRepository == nil {
		return nil
	}
	attempt, err := h.dagRunRepository.FindAttempt(ctx, identity.root)
	if err != nil {
		if errors.Is(err, dagrun.ErrDAGRunIDNotFound) {
			return nil
		}
		return status.Error(codes.Internal, "failed to resolve run for write validation: "+err.Error())
	}
	runStatus, err := attempt.ReadStatus(ctx)
	if err != nil {
		if errors.Is(err, dagrun.ErrNoStatusData) {
			return nil
		}
		return status.Error(codes.Internal, "failed to read run status for write validation: "+err.Error())
	}
	if runStatus != nil && runStatus.Status == ir.Queued && runStatus.QueuedAt != identity.executionMarker {
		return status.Error(codes.FailedPrecondition, remoteAttemptRejectedSuperseded)
	}
	return nil
}

func (h *Handler) attemptLease(ctx context.Context, identity attemptIdentity) (*dispatch.DAGRunLease, error) {
	if h.dagRunLeaseStore == nil {
		return nil, nil
	}
	lease, err := h.dagRunLeaseStore.Get(ctx, identity.claimKey)
	if err != nil {
		if errors.Is(err, dispatch.ErrDAGRunLeaseNotFound) || errors.Is(err, persis.ErrCorrupt) {
			return nil, status.Error(codes.FailedPrecondition, remoteAttemptRejectedLeaseInactive)
		}
		return nil, status.Error(codes.Internal, "failed to load distributed run lease: "+err.Error())
	}
	if err := h.validateAttemptLease(lease, identity); err != nil {
		return nil, err
	}
	return lease, nil
}

func (h *Handler) validateAttemptLease(lease *dispatch.DAGRunLease, identity attemptIdentity) error {
	if !lease.MatchesClaim(identity.claimKey, identity.workerID) {
		return status.Error(codes.FailedPrecondition, remoteAttemptRejectedSuperseded)
	}
	// The lease records the claimed task's marker. An empty marker matches only
	// an empty one, so a delayed write of a direct-start execution is refused
	// once the attempt has been queued and claimed again. This also covers
	// inline descendants, which write under their ancestor's claim.
	if lease.ExecutionMarker != identity.executionMarker {
		return status.Error(codes.FailedPrecondition, remoteAttemptRejectedSuperseded)
	}
	leaseRoot := lease.Root
	if leaseRoot.Zero() {
		leaseRoot = lease.DAGRun
	}
	if leaseRoot != identity.root {
		return status.Error(codes.FailedPrecondition, remoteAttemptRejectedSuperseded)
	}
	if identity.claimKey != identity.attemptKey {
		// Inline descendants inherit their dispatching ancestor's worker claim.
		return nil
	}
	if lease.DAGRun != identity.dagRun ||
		(identity.attemptID != "" && lease.AttemptID != identity.attemptID) {
		return status.Error(codes.FailedPrecondition, remoteAttemptRejectedSuperseded)
	}
	return nil
}
