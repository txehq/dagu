// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package store_test

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
)

// The claim deadline (TXE-5923, coordinator.unclaimed_dispatch_timeout): a
// pending task no worker claims by it is no longer handed out, and the
// coordinator removes that one record. These tests drive the store's clock.

var deadlineEpoch = time.Date(2026, 11, 7, 3, 0, 0, 0, time.UTC)

type fakeClock struct{ ms atomic.Int64 }

func newFakeClock(at time.Time) *fakeClock {
	c := &fakeClock{}
	c.set(at)
	return c
}

func (c *fakeClock) Now() time.Time               { return time.UnixMilli(c.ms.Load()).UTC() }
func (c *fakeClock) set(at time.Time)             { c.ms.Store(at.UnixMilli()) }
func (c *fakeClock) advance(d time.Duration)      { c.ms.Add(d.Milliseconds()) }
func (c *fakeClock) at(d time.Duration) time.Time { return deadlineEpoch.Add(d) }

func deadlineStore(col persis.Collection, clock *fakeClock, timeout time.Duration, opts ...store.DispatchTaskStoreOption) *store.DispatchTaskStore {
	opts = append([]store.DispatchTaskStoreOption{
		store.WithDispatchClock(clock.Now),
		store.WithUnclaimedDispatchTimeout(timeout),
		store.WithDispatchReservationTTL(time.Minute),
	}, opts...)
	return store.NewDispatchTaskStore(col, opts...)
}

func deadlineTask(runID string) *dispatch.DispatchTask {
	return &dispatch.DispatchTask{
		DAGRunID: runID, Target: "dag-" + runID, AttemptID: "attempt-" + runID, AttemptKey: "key-" + runID,
	}
}

var anyWorker = dispatch.DispatchTaskClaim{WorkerID: "w", PollerID: "p"}

func pastDeadline(t *testing.T, s *store.DispatchTaskStore, now time.Time) []dispatch.UnclaimedDispatch {
	t.Helper()
	past, err := s.ListPastClaimDeadline(context.Background(), now)
	require.NoError(t, err)
	return past
}

func runIDs(past []dispatch.UnclaimedDispatch) []string {
	ids := make([]string, 0, len(past))
	for _, u := range past {
		ids = append(ids, u.Task.DAGRunID)
	}
	return ids
}

// Up to the last millisecond before its deadline a task is claimable and not
// listed; at the deadline it is listed and never handed out.
func TestClaimDeadline_Boundary(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	enqueued := func() (*store.DispatchTaskStore, *fakeClock) {
		clock := newFakeClock(deadlineEpoch)
		s := deadlineStore(testutil.NewMemoryBackend().Collection("dispatch_tasks"), clock, time.Hour)
		require.NoError(t, s.Enqueue(ctx, deadlineTask("run")))
		return s, clock
	}

	t.Run("before", func(t *testing.T) {
		s, clock := enqueued()
		clock.set(clock.at(time.Hour - time.Millisecond))
		assert.Empty(t, pastDeadline(t, s, clock.Now()))
		claimed, err := s.ClaimNext(ctx, anyWorker)
		require.NoError(t, err)
		assert.NotNil(t, claimed, "claimable one millisecond before the deadline")
	})

	t.Run("at", func(t *testing.T) {
		s, clock := enqueued()
		clock.set(clock.at(time.Hour))
		past := pastDeadline(t, s, clock.Now())
		require.Len(t, past, 1)
		assert.Equal(t, "run", past[0].Task.DAGRunID)
		assert.Equal(t, clock.at(time.Hour), past[0].Deadline)
		claimed, err := s.ClaimNext(ctx, anyWorker)
		require.NoError(t, err)
		assert.Nil(t, claimed, "never handed out at its deadline")
		outstanding, err := s.HasOutstandingAttempt(ctx, "key-run", 0)
		require.NoError(t, err)
		assert.True(t, outstanding, "the store keeps it until the coordinator removes it")
	})
}

// A coordinator restart reads the deadline from the record, and a different
// setting after the restart does not move a deadline already given, either
// way.
func TestClaimDeadline_SurvivesRestartAndASettingChange(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	col := testutil.NewMemoryBackend().Collection("dispatch_tasks")
	clock := newFakeClock(deadlineEpoch)
	require.NoError(t, deadlineStore(col, clock, time.Hour).Enqueue(ctx, deadlineTask("run")))

	clock.set(clock.at(time.Hour))
	longer := deadlineStore(col, clock, 48*time.Hour)
	assert.Equal(t, []string{"run"}, runIDs(pastDeadline(t, longer, clock.Now())), "raising the setting does not extend it")
	unbounded := deadlineStore(col, clock, 0)
	assert.Equal(t, []string{"run"}, runIDs(pastDeadline(t, unbounded, clock.Now())), "removing the ceiling does not extend it")

	clock.set(clock.at(30 * time.Minute))
	shorter := deadlineStore(col, clock, time.Minute)
	assert.Empty(t, pastDeadline(t, shorter, clock.Now()), "lowering the setting does not shorten it")
	claimed, err := shorter.ClaimNext(ctx, anyWorker)
	require.NoError(t, err)
	assert.NotNil(t, claimed)
}

// A claim no worker acknowledges returns its task to pending with a new
// enqueue time, but the deadline its first enqueue gave it.
func TestClaimDeadline_ReleasedClaimKeepsItsDeadline(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := newFakeClock(deadlineEpoch)
	s := deadlineStore(testutil.NewMemoryBackend().Collection("dispatch_tasks"), clock, time.Hour)
	require.NoError(t, s.Enqueue(ctx, deadlineTask("run")))

	clock.set(clock.at(50 * time.Minute))
	claimed, err := s.ClaimNext(ctx, anyWorker)
	require.NoError(t, err)
	require.NotNil(t, claimed)
	assert.Empty(t, pastDeadline(t, s, clock.at(2*time.Hour)), "a claim is never listed, whatever its age")

	clock.set(clock.at(55 * time.Minute))
	_, err = s.HasOutstandingAttempt(ctx, "key-run", 0) // recycles the expired claim
	require.NoError(t, err)
	_, err = s.GetClaim(ctx, claimed.ClaimToken)
	require.ErrorIs(t, err, dispatch.ErrDispatchTaskNotFound, "the claim was released")

	clock.set(clock.at(time.Hour))
	past := pastDeadline(t, s, clock.Now())
	require.Len(t, past, 1, "the release did not move the deadline to 55m + 1h")
	assert.Equal(t, clock.at(time.Hour), past[0].Deadline)
}

// Publishing the same execution again keeps the deadline the store already
// has for it; a new attempt, and a new execution of a reused attempt, get
// their own.
func TestClaimDeadline_RepublicationKeepsANewAttemptGetsItsOwn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := newFakeClock(deadlineEpoch)
	s := deadlineStore(testutil.NewMemoryBackend().Collection("dispatch_tasks"), clock, time.Hour)

	first := deadlineTask("run")
	first.ExecutionMarker = "queued-1"
	require.NoError(t, s.Enqueue(ctx, first))

	clock.set(clock.at(30 * time.Minute))
	again := deadlineTask("run")
	again.ExecutionMarker = "queued-1"
	again.Params = "republished"
	require.NoError(t, s.Enqueue(ctx, again))
	nextExecution := deadlineTask("run")
	nextExecution.ExecutionMarker = "queued-2"
	require.NoError(t, s.Enqueue(ctx, nextExecution))
	newAttempt := deadlineTask("retry")
	require.NoError(t, s.Enqueue(ctx, newAttempt))

	byDeadline := map[time.Time][]string{}
	for _, u := range pastDeadline(t, s, clock.at(24*time.Hour)) {
		byDeadline[u.Deadline] = append(byDeadline[u.Deadline], u.Task.DAGRunID+"/"+u.Task.ExecutionMarker+"/"+u.Task.Params)
	}
	assert.ElementsMatch(t, []string{"run/queued-1/", "run/queued-1/republished"}, byDeadline[clock.at(time.Hour)])
	assert.ElementsMatch(t, []string{"run/queued-2/", "retry//"}, byDeadline[clock.at(90*time.Minute)])
}

// An explicit zero gives no deadline: the task is claimable however long it
// waits, and nothing lists it.
func TestClaimDeadline_ZeroMeansNoCeiling(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := newFakeClock(deadlineEpoch)
	s := deadlineStore(testutil.NewMemoryBackend().Collection("dispatch_tasks"), clock, 0)
	require.NoError(t, s.Enqueue(ctx, deadlineTask("run")))

	clock.set(clock.at(1000 * time.Hour))
	assert.Empty(t, pastDeadline(t, s, clock.Now()))
	claimed, err := s.ClaimNext(ctx, anyWorker)
	require.NoError(t, err)
	require.NotNil(t, claimed)
}

// Without the option the store gives the default, 24h.
func TestClaimDeadline_DefaultIs24h(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := newFakeClock(deadlineEpoch)
	s := store.NewDispatchTaskStore(testutil.NewMemoryBackend().Collection("dispatch_tasks"), store.WithDispatchClock(clock.Now))
	require.NoError(t, s.Enqueue(ctx, deadlineTask("run")))

	assert.Equal(t, 24*time.Hour, store.DefaultUnclaimedDispatchTimeout)
	assert.Empty(t, pastDeadline(t, s, clock.at(24*time.Hour-time.Millisecond)))
	assert.Len(t, pastDeadline(t, s, clock.at(24*time.Hour)), 1)
}

// A held task waits for its HoldUntil, which the coordinator enforces, and is
// never listed as past its claim deadline.
func TestClaimDeadline_HeldTaskIsNotListed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := newFakeClock(deadlineEpoch)
	s := deadlineStore(testutil.NewMemoryBackend().Collection("dispatch_tasks"), clock, time.Hour)
	held := deadlineTask("held")
	held.HoldUntil = clock.at(2 * time.Minute)
	require.NoError(t, s.Enqueue(ctx, held))

	assert.Empty(t, pastDeadline(t, s, clock.at(48*time.Hour)))
	expired, err := s.ListExpiredHeld(ctx, clock.at(48*time.Hour))
	require.NoError(t, err)
	assert.Len(t, expired, 1)
}

// putLegacyPending writes a pending record as a build from before the claim
// deadline did: no claimDeadline field.
func putLegacyPending(t *testing.T, col persis.Collection, name string, enqueuedAt int64, createdAt time.Time) {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"version":      1,
		"task":         deadlineTask(name),
		"taskFileName": "task_" + name + ".json",
		"enqueuedAt":   enqueuedAt,
	})
	require.NoError(t, err)
	require.NoError(t, col.Put(context.Background(), &persis.Record{
		ID: "pending/task_" + name, Data: data, CreatedAt: createdAt, UpdatedAt: createdAt,
	}))
}

// A record written before the field existed takes its deadline from its
// persisted enqueue time, or else its creation time, never from the present;
// with neither it fails closed. A release then writes the derived deadline,
// so it no longer moves with the re-stamped enqueue time.
func TestClaimDeadline_LegacyRecords(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	col := testutil.NewMemoryBackend().Collection("dispatch_tasks")
	clock := newFakeClock(deadlineEpoch.Add(10 * time.Hour))
	putLegacyPending(t, col, "enqueued", deadlineEpoch.UnixMilli(), deadlineEpoch.Add(time.Hour))
	putLegacyPending(t, col, "created", 0, deadlineEpoch.Add(time.Hour))
	putLegacyPending(t, col, "unknown", 0, time.Time{})
	s := deadlineStore(col, clock, 12*time.Hour)

	byRun := map[string]time.Time{}
	for _, u := range pastDeadline(t, s, deadlineEpoch.Add(100*time.Hour)) {
		byRun[u.Task.DAGRunID] = u.Deadline
	}
	assert.Equal(t, map[string]time.Time{
		"enqueued": deadlineEpoch.Add(12 * time.Hour),
		"created":  deadlineEpoch.Add(13 * time.Hour),
		"unknown":  time.UnixMilli(0).UTC(),
	}, byRun)
	assert.Equal(t, []string{"unknown"}, runIDs(pastDeadline(t, s, clock.Now())), "a record with no enqueue time is already past")

	// Claim and release the record derived from its enqueue time.
	var claimed *dispatch.ClaimedDispatchTask
	for claimed == nil || claimed.Task.DAGRunID != "enqueued" {
		next, err := s.ClaimNext(ctx, anyWorker)
		require.NoError(t, err)
		require.NotNil(t, next)
		claimed = next
	}
	clock.advance(2 * time.Minute)
	_, err := s.HasOutstandingAttempt(ctx, "key-enqueued", 0)
	require.NoError(t, err)

	reopened := deadlineStore(col, clock, 72*time.Hour)
	byRun = map[string]time.Time{}
	for _, u := range pastDeadline(t, reopened, deadlineEpoch.Add(100*time.Hour)) {
		byRun[u.Task.DAGRunID] = u.Deadline
	}
	assert.Equal(t, deadlineEpoch.Add(12*time.Hour), byRun["enqueued"], "the released record keeps the deadline it was derived with")
}

// Removal acts on exactly the record listed: not one claimed since, not one
// still before its deadline, and never another record of the same run.
func TestClaimDeadline_DeleteRemovesOnlyTheListedRecord(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	clock := newFakeClock(deadlineEpoch)
	s := deadlineStore(testutil.NewMemoryBackend().Collection("dispatch_tasks"), clock, time.Hour)
	require.NoError(t, s.Enqueue(ctx, deadlineTask("run")))

	clock.set(clock.at(time.Hour))
	past := pastDeadline(t, s, clock.Now())
	require.Len(t, past, 1)
	stale := past[0]

	// Not before its deadline, even when asked with an earlier time.
	removed, err := s.DeletePastClaimDeadline(ctx, stale, clock.at(59*time.Minute))
	require.NoError(t, err)
	assert.False(t, removed)

	// A newer attempt of the same run, enqueued now, is not touched.
	retry := deadlineTask("run")
	retry.AttemptID, retry.AttemptKey = "attempt-run-2", "key-run-2"
	require.NoError(t, s.Enqueue(ctx, retry))
	mismatched := stale
	mismatched.Task = retry
	removed, err = s.DeletePastClaimDeadline(ctx, mismatched, clock.Now())
	require.NoError(t, err)
	assert.False(t, removed, "a reference whose task differs from its record removes nothing")

	removed, err = s.DeletePastClaimDeadline(ctx, stale, clock.Now())
	require.NoError(t, err)
	assert.True(t, removed)
	removed, err = s.DeletePastClaimDeadline(ctx, stale, clock.Now())
	require.NoError(t, err)
	assert.False(t, removed, "removing it again is not an error")

	outstanding, err := s.HasOutstandingAttempt(ctx, "key-run", 0)
	require.NoError(t, err)
	assert.False(t, outstanding)
	outstanding, err = s.HasOutstandingAttempt(ctx, "key-run-2", 0)
	require.NoError(t, err)
	assert.True(t, outstanding, "the newer attempt keeps its task")

	// A claimed task's record is never removed by an earlier listing.
	claimed, err := s.ClaimNext(ctx, anyWorker)
	require.NoError(t, err)
	require.NotNil(t, claimed)
	clock.set(clock.at(3 * time.Hour))
	removed, err = s.DeletePastClaimDeadline(ctx, dispatch.UnclaimedDispatch{Task: retry, RecordID: stale.RecordID}, clock.Now())
	require.NoError(t, err)
	assert.False(t, removed)
	_, err = s.GetClaim(ctx, claimed.ClaimToken)
	require.NoError(t, err, "the claim stays")
}

// Workers claiming while the clock crosses the deadline and the coordinator
// removes the task: each task is either claimed or removed, never both and
// never neither once both have run.
func TestClaimDeadline_ConcurrentClaimAtTheDeadline(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for i := range 40 {
		clock := newFakeClock(deadlineEpoch)
		s := deadlineStore(testutil.NewMemoryBackend().Collection("dispatch_tasks"), clock, time.Hour)
		require.NoError(t, s.Enqueue(ctx, deadlineTask("run")))
		clock.set(clock.at(time.Hour - time.Millisecond))

		var claims atomic.Int32
		var removed atomic.Bool
		var wg sync.WaitGroup
		for w := range 4 {
			wg.Go(func() {
				claim := anyWorker
				claim.PollerID = string(rune('a' + w))
				if c, err := s.ClaimNext(ctx, claim); err == nil && c != nil {
					claims.Add(1)
				}
			})
		}
		wg.Go(func() {
			clock.advance(time.Millisecond)
			past, err := s.ListPastClaimDeadline(ctx, clock.Now())
			if err != nil {
				return
			}
			for _, u := range past {
				if ok, err := s.DeletePastClaimDeadline(ctx, u, clock.Now()); err == nil && ok {
					removed.Store(true)
				}
			}
		})
		wg.Wait()

		require.LessOrEqual(t, claims.Load(), int32(1), "iteration %d: claimed at most once", i)
		if claims.Load() == 1 {
			assert.False(t, removed.Load(), "iteration %d: a claimed task is never removed", i)
			continue
		}
		if !removed.Load() {
			// The removal listed before the clock crossed; a later pass does.
			past := pastDeadline(t, s, clock.Now())
			require.Len(t, past, 1, "iteration %d", i)
			ok, err := s.DeletePastClaimDeadline(ctx, past[0], clock.Now())
			require.NoError(t, err)
			require.True(t, ok, "iteration %d", i)
		}
		claimed, err := s.ClaimNext(ctx, anyWorker)
		require.NoError(t, err)
		assert.Nil(t, claimed, "iteration %d: nothing is left to claim", i)
	}
}
