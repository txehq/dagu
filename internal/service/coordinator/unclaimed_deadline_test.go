// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// The claim deadline (TXE-5923, coordinator.unclaimed_dispatch_timeout), as
// the coordinator enforces it. The dispatch store runs on a fake clock, so a
// day-long ceiling passes without waiting.

const deadlineCeiling = 24 * time.Hour

type deadlineClock struct{ ms atomic.Int64 }

func (c *deadlineClock) Now() time.Time          { return time.UnixMilli(c.ms.Load()).UTC() }
func (c *deadlineClock) set(at time.Time)        { c.ms.Store(at.UnixMilli()) }
func (c *deadlineClock) advance(d time.Duration) { c.ms.Add(d.Milliseconds()) }

type deadlineFixture struct {
	*strandedFixture
	clock   *deadlineClock
	dir     string
	start   time.Time
	ceiling time.Duration
}

func newDeadlineFixture(t *testing.T, ceiling time.Duration) *deadlineFixture {
	t.Helper()
	clock := &deadlineClock{}
	start := time.Now().UTC()
	clock.set(start)
	dir := filepath.Join(t.TempDir(), "distributed")
	dispatches := store.NewDispatchTaskStore(file.NewCollection(dir),
		store.WithDispatchClock(clock.Now), store.WithUnclaimedDispatchTimeout(ceiling))
	return &deadlineFixture{strandedFixture: newStrandedFixture(t, dispatches), clock: clock, dir: dir, start: start, ceiling: ceiling}
}

// publish enqueues the task a dispatch of attemptID publishes, now.
func (f *deadlineFixture) publish(t *testing.T, attemptID, marker string) {
	t.Helper()
	require.NoError(t, f.dispatches.Enqueue(t.Context(), &dispatch.DispatchTask{
		Operation: dispatch.DispatchOperationRetry, Target: strandedDAG, DAGRunID: strandedRun,
		AttemptID: attemptID, AttemptKey: f.attemptKey(attemptID), ExecutionMarker: marker,
	}))
}

// pass runs, at the store's time, the pass that ends dispatches past their
// claim deadline and then reconciliation of the journal, as the zombie
// detector orders them.
func (f *deadlineFixture) pass(t *testing.T) {
	t.Helper()
	f.h.expireUnclaimedDispatches(t.Context(), f.clock.Now())
	f.h.reconcileAbandonedPreparations(t.Context(), later())
}

func (f *deadlineFixture) outstanding(t *testing.T, attemptID string) bool {
	t.Helper()
	outstanding, err := f.dispatches.HasOutstandingAttempt(t.Context(), f.attemptKey(attemptID), 0)
	require.NoError(t, err)
	return outstanding
}

func (f *deadlineFixture) status(t *testing.T) *ir.DAGRunStatus {
	t.Helper()
	attempt, err := f.repository.FindAttempt(t.Context(), f.ref)
	require.NoError(t, err)
	st, err := attempt.ReadStatus(t.Context())
	require.NoError(t, err)
	return st
}

// A journaled retry nobody claims waits until its deadline, then loses its task
// and is abandoned with the same record an expired dispatch always left: the
// previous execution is the latest again, and nothing is left to claim.
func TestUnclaimedDeadline_AJournaledAttemptIsAbandonedWithARecord(t *testing.T) {
	t.Parallel()
	f := newDeadlineFixture(t, deadlineCeiling)
	attempt := f.writeAttempt(t, true, ir.NotStarted, "")
	f.publish(t, attempt, "")

	f.clock.set(f.start.Add(deadlineCeiling - time.Millisecond))
	f.pass(t)
	assert.True(t, f.outstanding(t, attempt), "before its deadline the task waits, however long")
	assert.Equal(t, attempt, f.latest(t))
	assert.Empty(t, f.records(t))

	f.clock.set(f.start.Add(deadlineCeiling))
	f.pass(t)
	assert.False(t, f.outstanding(t, attempt))
	assert.Equal(t, f.previous, f.latest(t), "the previous execution is the latest again")
	records := f.records(t)
	require.Len(t, records, 1)
	assert.Equal(t, attempt, records[0].AbandonedAttemptID)
	assert.Equal(t, persis.EvidenceAbsent, records[0].Evidence.DispatchTask)
	assert.Equal(t, abandonedPreparationDetail, records[0].Detail)
	assert.Empty(t, f.preparations(t))
	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p"})
	require.NoError(t, err)
	assert.Nil(t, claimed)
}

// A coordinator that stops after removing the task and before reconciling the
// journal leaves the entry; the next coordinator abandons the attempt.
func TestUnclaimedDeadline_ACrashAfterTheRemovalStillAbandons(t *testing.T) {
	t.Parallel()
	f := newDeadlineFixture(t, deadlineCeiling)
	attempt := f.writeAttempt(t, true, ir.NotStarted, "")
	f.publish(t, attempt, "")

	f.clock.set(f.start.Add(deadlineCeiling))
	f.h.expireUnclaimedDispatches(t.Context(), f.clock.Now())
	assert.False(t, f.outstanding(t, attempt))
	assert.Equal(t, []string{attempt}, f.preparations(t), "the entry outlives the task")

	restarted := f.restart(t)
	restarted.reconcileAbandonedPreparations(t.Context(), later())
	require.Len(t, f.records(t), 1)
	assert.Equal(t, f.previous, f.latest(t))
}

// restart is a new coordinator over the same stores: its dispatch store reads
// every record afresh.
func (f *deadlineFixture) restart(t *testing.T) *Handler {
	t.Helper()
	dispatches := store.NewDispatchTaskStore(file.NewCollection(f.dir),
		store.WithDispatchClock(f.clock.Now), store.WithUnclaimedDispatchTimeout(f.ceiling))
	h := NewHandler(HandlerConfig{
		DAGRunRepository:          f.repository,
		DispatchTaskStore:         dispatches,
		DAGRunLeaseStore:          f.leases,
		ActiveDistributedRunStore: f.h.activeDistributedRunStore,
		WorkerHeartbeatStore:      f.h.workerHeartbeatStore,
		QueueStore:                f.h.queueStore,
		Owner:                     dispatch.CoordinatorEndpoint{ID: "coord-b", Host: "127.0.0.1", Port: 50056},
	})
	t.Cleanup(func() { h.Close(context.Background()) })
	f.dispatches = dispatches
	return h
}

// A coordinator restarted past a task's deadline enforces it on its first
// pass, from the deadline the record holds.
func TestUnclaimedDeadline_ARestartedCoordinatorEnforcesOnItsFirstPass(t *testing.T) {
	t.Parallel()
	f := newDeadlineFixture(t, deadlineCeiling)
	attempt := f.writeAttempt(t, true, ir.NotStarted, "")
	f.publish(t, attempt, "")

	f.clock.set(f.start.Add(deadlineCeiling + time.Hour))
	f.ceiling = 7 * deadlineCeiling // a longer setting does not extend the task
	restarted := f.restart(t)
	restarted.expireUnclaimedDispatches(t.Context(), f.clock.Now())
	restarted.reconcileAbandonedPreparations(t.Context(), later())
	assert.False(t, f.outstanding(t, attempt))
	require.Len(t, f.records(t), 1)
}

// A queued execution the journal does not name is failed while it still waits,
// and only then loses its task. A coordinator that stops between the two
// leaves a task nobody can claim; the next pass finds the run settled and only
// removes the task, so the run is failed once.
func TestUnclaimedDeadline_AnUnjournaledExecutionFailsThenLosesItsTask(t *testing.T) {
	t.Parallel()
	f := newDeadlineFixture(t, deadlineCeiling)
	const marker = "2026-11-07T11:00:00+08:00"
	queued := f.writeQueued(t, "", marker)
	require.Empty(t, f.preparations(t), "written as a queue leaves it, unjournaled")
	f.publish(t, queued, marker)
	flaky := &failingDeletes{DispatchTaskStore: f.dispatches, fail: 1}
	f.h.dispatchTaskStore = flaky

	f.clock.set(f.start.Add(deadlineCeiling))
	f.h.expireUnclaimedDispatches(t.Context(), f.clock.Now())
	st := f.status(t)
	assert.Equal(t, ir.Failed, st.Status, "failed before its task is removed")
	assert.Contains(t, st.Error, "coordinator.unclaimed_dispatch_timeout")
	assert.Equal(t, queued, st.AttemptID)
	assert.True(t, f.outstanding(t, queued), "the removal failed; the task remains")
	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p"})
	require.NoError(t, err)
	assert.Nil(t, claimed, "and nobody can claim it")
	finishedAt := st.FinishedAt

	f.clock.advance(time.Hour)
	f.h.expireUnclaimedDispatches(t.Context(), f.clock.Now())
	assert.False(t, f.outstanding(t, queued))
	assert.Equal(t, finishedAt, f.status(t).FinishedAt, "the run is not failed again")
	assert.Empty(t, f.records(t))
}

type failingDeletes struct {
	dispatch.DispatchTaskStore
	fail int
}

func (s *failingDeletes) DeletePastClaimDeadline(ctx context.Context, u dispatch.UnclaimedDispatch, now time.Time) (bool, error) {
	if s.fail > 0 {
		s.fail--
		return false, errors.New("injected: coordinator stopped")
	}
	return s.DispatchTaskStore.DeletePastClaimDeadline(ctx, u, now)
}

// Nothing a worker holds, and nothing that is not the run's latest, is ever
// failed by a deadline: the stale task alone goes.
func TestUnclaimedDeadline_NeverEndsAnAttemptAWorkerHoldsOrANewerOne(t *testing.T) {
	t.Parallel()
	const marker = "2026-11-07T11:00:00+08:00"

	t.Run("leased", func(t *testing.T) {
		t.Parallel()
		f := newDeadlineFixture(t, deadlineCeiling)
		queued := f.writeQueued(t, "", marker)
		f.publish(t, queued, marker)
		now := time.Now().UTC().UnixMilli()
		require.NoError(t, f.leases.Upsert(t.Context(), dispatch.DAGRunLease{
			AttemptKey: f.attemptKey(queued), DAGRun: f.ref, Root: f.ref, AttemptID: queued,
			WorkerID: "worker-1", ClaimedAt: now, LastHeartbeatAt: now,
		}))
		f.clock.set(f.start.Add(deadlineCeiling))
		f.pass(t)
		assert.Equal(t, ir.Queued, f.status(t).Status)
		assert.Empty(t, f.records(t))
		assert.False(t, f.outstanding(t, queued))
	})

	t.Run("running", func(t *testing.T) {
		t.Parallel()
		f := newDeadlineFixture(t, deadlineCeiling)
		running := f.writeAttempt(t, true, ir.Running, "worker-1")
		f.publish(t, running, "")
		f.clock.set(f.start.Add(deadlineCeiling))
		f.pass(t)
		st := f.status(t)
		assert.Equal(t, ir.Running, st.Status)
		assert.Equal(t, "worker-1", st.WorkerID)
		assert.False(t, f.outstanding(t, running))
	})

	t.Run("newer attempt", func(t *testing.T) {
		t.Parallel()
		f := newDeadlineFixture(t, deadlineCeiling)
		old := f.writeQueued(t, "", marker)
		f.publish(t, old, marker)
		f.clock.advance(deadlineCeiling - time.Hour)
		newer := f.writeQueued(t, "", "2026-11-08T10:00:00+08:00")
		f.publish(t, newer, "2026-11-08T10:00:00+08:00")

		f.clock.set(f.start.Add(deadlineCeiling))
		f.pass(t)
		st := f.status(t)
		assert.Equal(t, newer, st.AttemptID)
		assert.Equal(t, ir.Queued, st.Status, "the newer attempt is not failed by the older task")
		assert.False(t, f.outstanding(t, old))
		assert.True(t, f.outstanding(t, newer), "nor does it lose its task")
	})

	t.Run("still queued", func(t *testing.T) {
		t.Parallel()
		f := newDeadlineFixture(t, deadlineCeiling)
		queued := f.writeQueued(t, "", marker)
		f.enqueue(t)
		f.publish(t, queued, marker)
		f.clock.set(f.start.Add(deadlineCeiling))
		f.pass(t)
		assert.Equal(t, ir.Queued, f.status(t).Status, "a queue that still holds the run dispatches it again")
		assert.False(t, f.outstanding(t, queued))
	})
}

// An explicit zero gives no ceiling: the task waits, claimable, however long.
func TestUnclaimedDeadline_ZeroKeepsTheTaskWaiting(t *testing.T) {
	t.Parallel()
	f := newDeadlineFixture(t, 0)
	attempt := f.writeAttempt(t, true, ir.NotStarted, "")
	f.publish(t, attempt, "")

	f.clock.set(f.start.Add(1000 * time.Hour))
	f.pass(t)
	assert.True(t, f.outstanding(t, attempt))
	assert.Equal(t, attempt, f.latest(t))
	assert.Empty(t, f.records(t))
	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p"})
	require.NoError(t, err)
	assert.NotNil(t, claimed)
}

// A task published without an execution marker, as a legacy queued task was,
// is told apart from a newer attempt of its run by its attempt id alone: the
// newer attempt is neither failed nor stripped of its task.
func TestUnclaimedDeadline_TheAttemptIDAloneKeepsANewerAttempt(t *testing.T) {
	t.Parallel()
	f := newDeadlineFixture(t, deadlineCeiling)
	old := f.writeQueued(t, "", "2026-11-07T11:00:00+08:00")
	f.publish(t, old, "")
	f.clock.advance(time.Hour)
	newer := f.writeQueued(t, "", "2026-11-07T12:00:00+08:00")
	f.publish(t, newer, "")

	f.clock.set(f.start.Add(deadlineCeiling))
	f.pass(t)
	st := f.status(t)
	assert.Equal(t, newer, st.AttemptID)
	assert.Equal(t, ir.Queued, st.Status)
	assert.False(t, f.outstanding(t, old))
	assert.True(t, f.outstanding(t, newer))
}

// The deadline bounds only the wait for a claim. A task claimed before it is
// acknowledged after it, and the run it starts is never ended by it, however
// long it runs.
func TestUnclaimedDeadline_AClaimMadeBeforeTheDeadlineStaysAlive(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	f := newDeadlineFixture(t, deadlineCeiling)
	const marker = "2026-11-07T11:00:00+08:00"
	queued := f.writeQueued(t, "", marker)
	_, err := f.h.Dispatch(t.Context(), f.queuedDispatch(t))
	require.NoError(t, err)

	f.clock.set(f.start.Add(deadlineCeiling - time.Millisecond))
	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p"})
	require.NoError(t, err)
	require.NotNil(t, claimed)

	f.clock.set(f.start.Add(deadlineCeiling + time.Second))
	f.pass(t)
	resp, err := f.h.AckTaskClaim(t.Context(), &coordinatorv1.AckTaskClaimRequest{
		ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: f.attemptKey(queued),
	})
	require.NoError(t, err)
	require.True(t, resp.Accepted, "a claim made in time is acknowledged after the deadline: %s", resp.Error)

	f.clock.set(f.start.Add(7 * deadlineCeiling))
	f.pass(t)
	assert.NotEqual(t, ir.Failed, f.status(t).Status)
	assert.Empty(t, f.records(t))
	_, err = f.leases.Get(t.Context(), f.attemptKey(queued))
	require.NoError(t, err, "the lease is not expired by the deadline")
}

// A claim no worker acknowledges is released after the reservation time. Past
// the deadline the released task is refused to the next claimant, and its
// execution ends with a record; the first claimant's late acknowledgement is
// refused too.
func TestUnclaimedDeadline_AClaimReleasedPastTheDeadlineIsNotClaimedAgain(t *testing.T) {
	registerCommandExecutorCapsForCoordinatorTest()
	f := newDeadlineFixture(t, deadlineCeiling)
	const marker = "2026-11-07T11:00:00+08:00"
	queued := f.writeQueued(t, "", marker)
	_, err := f.h.Dispatch(t.Context(), f.queuedDispatch(t))
	require.NoError(t, err)

	f.clock.set(f.start.Add(deadlineCeiling - time.Millisecond))
	claimed, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "p"})
	require.NoError(t, err)
	require.NotNil(t, claimed)

	f.clock.set(f.start.Add(deadlineCeiling + time.Hour))
	again, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-2", PollerID: "q"})
	require.NoError(t, err)
	assert.Nil(t, again, "the released task is past its deadline")
	_, err = f.dispatches.GetClaim(t.Context(), claimed.ClaimToken)
	require.ErrorIs(t, err, dispatch.ErrDispatchTaskNotFound, "the claim was released")

	f.pass(t)
	assert.False(t, f.outstanding(t, queued))
	record, err := f.repository.ReadExecutionAbandonment(t.Context(), f.ref, f.ref, queued, marker)
	require.NoError(t, err)
	require.NotNil(t, record)
	assert.Equal(t, ir.Failed, f.status(t).Status)

	resp, err := f.h.AckTaskClaim(t.Context(), &coordinatorv1.AckTaskClaimRequest{
		ClaimToken: claimed.ClaimToken, WorkerId: "worker-1", AttemptKey: f.attemptKey(queued),
	})
	require.NoError(t, err)
	assert.False(t, resp.Accepted)
}

// Workers claim an unjournaled execution while the clock crosses its deadline
// and the coordinator's pass runs: the run is either claimed and never failed,
// or failed and never claimed.
func TestUnclaimedDeadline_AnUnjournaledClaimRacesThePass(t *testing.T) {
	t.Parallel()
	const marker = "2026-11-07T11:00:00+08:00"
	var claimedRuns, failedRuns int
	for i := range 12 {
		f := newDeadlineFixture(t, deadlineCeiling)
		queued := f.writeQueued(t, "", marker)
		f.publish(t, queued, marker)
		f.clock.set(f.start.Add(deadlineCeiling - time.Millisecond))

		var claims atomic.Int32
		if i == 0 {
			// One run is claimed before the clock crosses, whatever the
			// scheduler does with the rest.
			c, err := f.dispatches.ClaimNext(t.Context(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: "first"})
			require.NoError(t, err)
			require.NotNil(t, c)
			claims.Add(1)
		}
		var wg sync.WaitGroup
		for w := range 3 {
			wg.Go(func() {
				c, err := f.dispatches.ClaimNext(context.Background(), dispatch.DispatchTaskClaim{WorkerID: "worker-1", PollerID: string(rune('a' + w))})
				if err == nil && c != nil {
					claims.Add(1)
				}
			})
		}
		wg.Go(func() {
			f.clock.advance(time.Millisecond)
			f.h.expireUnclaimedDispatches(context.Background(), f.clock.Now())
		})
		wg.Wait()
		f.h.expireUnclaimedDispatches(t.Context(), f.clock.Now())

		require.LessOrEqual(t, claims.Load(), int32(1), "iteration %d", i)
		st := f.status(t)
		if claims.Load() == 1 {
			claimedRuns++
			assert.Equal(t, ir.Queued, st.Status, "iteration %d: a claimed run is never failed", i)
		} else {
			failedRuns++
			assert.Equal(t, ir.Failed, st.Status, "iteration %d: an unclaimed run is failed", i)
			assert.False(t, f.outstanding(t, queued), "iteration %d", i)
		}
	}
	t.Logf("claimed %d, failed %d", claimedRuns, failedRuns)
	assert.Positive(t, claimedRuns)
	assert.Positive(t, failedRuns)
}
