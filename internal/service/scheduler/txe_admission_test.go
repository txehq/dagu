// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package scheduler

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/launcher"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

type fakeAdmitter struct {
	mu      sync.Mutex
	adm     registry.Admission
	err     error
	dropped []string
	checked []string
}

func (f *fakeAdmitter) AdmitRun(_ context.Context, name, spec string) (registry.Admission, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checked = append(f.checked, name+"|"+spec)
	return f.adm, f.err
}

func (f *fakeAdmitter) RecordDroppedRun(_ context.Context, jobID, runID string, _ registry.Admission) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dropped = append(f.dropped, jobID+"/"+runID)
	return nil
}

func (f *fakeAdmitter) ReconcileExpired(context.Context) ([]string, error) { return nil, nil }
func (f *fakeAdmitter) ReconcileEffects(context.Context) error             { return nil }
func (f *fakeAdmitter) ReconcileResourceEvents(context.Context) error      { return nil }
func (f *fakeAdmitter) RebuildResourceIndex(context.Context) error         { return nil }

func mintJobID(t *testing.T) string {
	t.Helper()
	id, err := registry.NewID(registry.PrefixJob, time.Now())
	require.NoError(t, err)
	return id
}

// A retired job's queued run is refused for every trigger type, including
// manual and webhook runs that DAG suspension lets through. The run is kept
// as aborted with the registry's reason and noted on the job.
func TestQueueProcessor_TxeRefusedQueuedRunIsAborted(t *testing.T) {
	for _, trigger := range []ir.TriggerType{ir.TriggerTypeManual, ir.TriggerTypeWebhook, ir.TriggerTypeScheduler, ir.TriggerTypeRetry} {
		t.Run(trigger.String(), func(t *testing.T) {
			jobID := mintJobID(t)
			admitter := &fakeAdmitter{adm: registry.Admission{JobID: jobID, Code: registry.AdmitRetired, Reason: "job retired: manual"}}
			f := newQueueFixture(t).
				withDAG(jobID, 1).
				withProcessor(config.Queues{}, WithRunAdmitter(admitter)).
				simulateQueue(1, false)
			f.enqueueRunWithTrigger("run-1", trigger)

			f.processor.ProcessQueueItems(f.ctx, jobID)

			items, err := f.queueStore.List(f.ctx, jobID)
			require.NoError(t, err)
			assert.Empty(t, items)
			attempt, err := f.dagRunRepository.FindAttempt(f.ctx, ir.NewDAGRunRef(jobID, "run-1"))
			require.NoError(t, err)
			status, err := attempt.ReadStatus(f.ctx)
			require.NoError(t, err)
			assert.Equal(t, ir.Aborted, status.Status)
			assert.Equal(t, "txe: job "+jobID+" retired: job retired: manual", status.Error)
			assert.Equal(t, []string{jobID + "/run-1"}, admitter.dropped)
		})
	}
}

// A registry error leaves the queued run pending: the guard fails closed.
func TestQueueProcessor_TxeAdmissionErrorKeepsRunQueued(t *testing.T) {
	jobID := mintJobID(t)
	admitter := &fakeAdmitter{err: errors.New("registry unavailable")}
	f := newQueueFixture(t).
		withDAG(jobID, 1).
		withProcessor(config.Queues{}, WithRunAdmitter(admitter)).
		simulateQueue(1, false)
	f.enqueueRunWithTrigger("run-1", ir.TriggerTypeManual)

	f.processor.ProcessQueueItems(f.ctx, jobID)

	items, err := f.queueStore.List(f.ctx, jobID)
	require.NoError(t, err)
	assert.Len(t, items, 1)
	attempt, err := f.dagRunRepository.FindAttempt(f.ctx, ir.NewDAGRunRef(jobID, "run-1"))
	require.NoError(t, err)
	status, err := attempt.ReadStatus(f.ctx)
	require.NoError(t, err)
	assert.Equal(t, ir.Queued, status.Status)
	assert.Empty(t, admitter.dropped)
}

func TestWithRunAdmission(t *testing.T) {
	jobID := mintJobID(t)
	admitter := &fakeAdmitter{adm: registry.Admission{JobID: jobID, Code: registry.AdmitPaused}}
	check := withRunAdmission(func(context.Context, string) (bool, error) { return false, nil }, admitter)

	suspended, err := check(context.Background(), "ordinary-dag")
	require.NoError(t, err)
	assert.False(t, suspended, "unregistered DAGs keep upstream behaviour")
	assert.Empty(t, admitter.checked)

	suspended, err = check(context.Background(), jobID)
	require.NoError(t, err)
	assert.True(t, suspended)

	admitter.adm = registry.Admission{Admit: true, JobID: jobID}
	suspended, err = check(context.Background(), jobID)
	require.NoError(t, err)
	assert.False(t, suspended)

	admitter.err = errors.New("boom")
	_, err = check(context.Background(), jobID)
	assert.Error(t, err, "errors propagate so callers do not dispatch")

	upstream := withRunAdmission(func(context.Context, string) (bool, error) { return true, nil }, admitter)
	suspended, err = upstream(context.Background(), jobID)
	require.NoError(t, err)
	assert.True(t, suspended, "Dagu's own suspension still applies")
}

// An admitted job run the scheduler would execute locally is dropped: jobs
// run only through their machine's worker, where the claim is recorded.
func TestQueueProcessor_TxeLocalJobRunIsDropped(t *testing.T) {
	jobID := mintJobID(t)
	admitter := &fakeAdmitter{adm: registry.Admission{Admit: true, JobID: jobID}}
	f := newQueueFixture(t).
		withDAG(jobID, 1).
		withProcessor(config.Queues{}, WithRunAdmitter(admitter)).
		simulateQueue(1, false)
	f.enqueueRunWithTrigger("run-1", ir.TriggerTypeManual)

	f.processor.ProcessQueueItems(f.ctx, jobID)

	attempt, err := f.dagRunRepository.FindAttempt(f.ctx, ir.NewDAGRunRef(jobID, "run-1"))
	require.NoError(t, err)
	status, err := attempt.ReadStatus(f.ctx)
	require.NoError(t, err)
	assert.Equal(t, ir.Aborted, status.Status)
	assert.Contains(t, status.Error, string(registry.AdmitNotOnWorker))
	assert.Equal(t, []string{jobID + "/run-1"}, admitter.dropped)
}

// A scheduled start dispatched without a queue reaches the executor
// directly; a registered job is still never launched in-process.
func TestDAGExecutor_RefusesLocalJobRun(t *testing.T) {
	jobID := mintJobID(t)
	e := NewDAGExecutor(nil, launcher.NewSubCmdBuilder(&config.Config{Paths: config.PathsConfig{Executable: "/nonexistent/dagu"}}), config.ExecutionModeLocal, "")
	dag := &ir.DAG{Name: jobID, Location: "/dags/" + jobID + ".yaml"}
	err := e.HandleJob(context.Background(), DAGEntry{DAG: dag}, dispatch.DispatchOperationStart, "run-1", ir.TriggerTypeScheduler, time.Now())
	require.ErrorIs(t, err, ErrJobRequiresWorker)

	err = e.ExecuteDAG(context.Background(), dag, dispatch.DispatchOperationRetry, "run-1", &ir.DAGRunStatus{}, ir.TriggerTypeRetry, "")
	require.ErrorIs(t, err, ErrJobRequiresWorker)
}
