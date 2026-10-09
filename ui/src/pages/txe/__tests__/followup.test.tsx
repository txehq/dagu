// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { SWRConfig } from 'swr';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { TxeApi } from '@/features/txe/api';
import { fixtureJob, fixtureProposal } from '@/features/txe/fixtures';
import { TxeApiContext } from '@/features/txe/hooks';
import type { Decision } from '@/features/txe/types';
import TxeInboxPage from '..';
import TxeJobPage from '../job';

vi.mock('@/contexts/AuthContext', () => ({
  useCanExecute: () => true,
}));

vi.mock('@/hooks/api', () => ({
  useClient: () => ({}),
}));

function renderAt(api: TxeApi, path: string) {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <TxeApiContext.Provider value={api}>
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route path="/txe" element={<TxeInboxPage />} />
            <Route path="/txe/jobs/:jobId" element={<TxeJobPage />} />
          </Routes>
        </MemoryRouter>
      </TxeApiContext.Provider>
    </SWRConfig>
  );
}

function baseApi(overrides: Partial<TxeApi> = {}): TxeApi {
  return {
    listJobs: async () => [fixtureJob()],
    getJob: async () => fixtureJob(),
    listProposals: async () => [],
    listDecisions: async () => [],
    decide: vi.fn(),
    replayDecision: vi.fn(),
    requestRetry: vi.fn(),
    listRetryStates: async () => new Map(),
    ...overrides,
  };
}

const pendingDecision: Decision = {
  decisionId: 'dec_01JTXEPENDING0000000000000',
  proposalId: 'prp_01JTXEFIXTURE00000000000001',
  proposalRevision: 1,
  bindingDigest: 'sha256:' + 'b'.repeat(64),
  jobId: 'job_volume_monitor',
  jobVersion: 3,
  ownerId: 'own_01JTXEFIXTURE00000000000000',
  verdict: 'approve',
  actor: { display: 'connor', id: 'connor' },
  client: 'dashboard',
  idempotencyKey: 'key-pending-0001',
  createdAt: '2026-10-09T10:00:00Z',
  nativeResume: 'pending',
};

afterEach(() => {
  vi.useRealTimers();
});

describe('decision follow-ups', () => {
  it('lists a job whose decision follow-up is pending', async () => {
    renderAt(
      baseApi({
        listJobs: async () => [
          fixtureJob({ pendingFollowUps: [pendingDecision.decisionId] }),
        ],
      }),
      '/txe'
    );
    expect(
      await screen.findByText('Decision follow-up pending')
    ).toBeInTheDocument();
  });

  // The replay must be the stored decision exactly, so the server treats it
  // as the same request and completes its follow-up.
  it('replays the stored decision from the job page', async () => {
    const replayDecision = vi.fn().mockResolvedValue({ ok: true });
    renderAt(
      baseApi({
        listProposals: async () => [fixtureProposal({ state: 'decided' })],
        listDecisions: async () => [pendingDecision],
        replayDecision,
      }),
      '/txe/jobs/job_volume_monitor'
    );
    fireEvent.click(
      await screen.findByRole('button', { name: 'Complete follow-up' })
    );
    await waitFor(() => expect(replayDecision).toHaveBeenCalledTimes(1));
    expect(replayDecision).toHaveBeenCalledWith(
      'job_volume_monitor',
      pendingDecision
    );
    expect(await screen.findByText('Follow-up completed.')).toBeInTheDocument();
  });
});

describe('follow-up transport failure', () => {
  // A failed request must not leave the recovery control disabled.
  it('keeps the follow-up button usable after a network error', async () => {
    const replayDecision = vi
      .fn()
      .mockRejectedValueOnce(new Error('network timeout'))
      .mockResolvedValueOnce({ ok: true });
    renderAt(
      baseApi({
        listProposals: async () => [fixtureProposal({ state: 'decided' })],
        listDecisions: async () => [pendingDecision],
        replayDecision,
      }),
      '/txe/jobs/job_volume_monitor'
    );
    const button = await screen.findByRole('button', {
      name: 'Complete follow-up',
    });
    fireEvent.click(button);
    expect(await screen.findByText('network timeout')).toBeInTheDocument();
    await waitFor(() => expect(button).not.toBeDisabled());
    fireEvent.click(button);
    await waitFor(() => expect(replayDecision).toHaveBeenCalledTimes(2));
  });
});

describe('snooze expiry', () => {
  // The registry does not change a snoozed proposal when its expiry passes,
  // so the inbox must re-evaluate on time alone.
  it('shows a snoozed proposal again once its expiry passes', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const snoozed = fixtureProposal({
      state: 'snoozed',
      snoozeUntil: new Date(Date.now() + 5_000).toISOString(),
    });
    renderAt(baseApi({ listProposals: async () => [snoozed] }), '/txe');
    expect(await screen.findByTestId('txe-inbox-empty')).toBeInTheDocument();
    await act(async () => {
      vi.advanceTimersByTime(20_000);
    });
    expect(
      await screen.findByText('Usage is at 92%. Resize the volume to 20Gi?')
    ).toBeInTheDocument();
  });
});

describe('run retry', () => {
  const failedJob = fixtureJob({
    latestRuns: [
      {
        dagName: 'job_volume_monitor',
        dagRunId: 'run-0003',
        status: 'failed',
        execution: {
          attemptId: 'run-0003-a1',
          queuedAt: '2026-10-09T12:00:00.000000001Z',
        },
      },
    ],
  });

  it('asks for a retry of the exact failed execution at the job version', async () => {
    const requestRetry = vi.fn().mockResolvedValue({ ok: true });
    renderAt(
      baseApi({ getJob: async () => failedJob, requestRetry }),
      '/txe/jobs/job_volume_monitor'
    );
    fireEvent.click(
      await screen.findByRole('button', { name: 'Retry this run' })
    );
    await waitFor(() => expect(requestRetry).toHaveBeenCalledTimes(1));
    // The execution the person reviewed is sent so a moved run is refused.
    expect(requestRetry.mock.calls[0]?.slice(0, 4)).toEqual([
      'job_volume_monitor',
      'run-0003',
      { attemptId: 'run-0003-a1', queuedAt: '2026-10-09T12:00:00.000000001Z' },
      failedJob.version,
    ]);
  });

  // Dagu's queued retry keeps the attempt ID and records a later queue
  // marker: that is a new execution, so it is offered for a retry again.
  it('offers a re-queued execution of a retried attempt', async () => {
    renderAt(
      baseApi({
        getJob: async () =>
          fixtureJob({
            latestRuns: [
              {
                dagName: 'job_volume_monitor',
                dagRunId: 'run-0003',
                status: 'failed',
                execution: {
                  attemptId: 'run-0003-a1',
                  queuedAt: '2026-10-09T12:00:05.000000001Z',
                },
              },
            ],
          }),
        listRetryStates: async () =>
          new Map([
            [
              'run-0003',
              {
                runId: 'run-0003',
                proposalId: 'prp_r',
                attemptId: 'run-0003-a1',
                queuedAt: '2026-10-09T12:00:00.000000001Z',
                status: 'succeeded' as const,
                receipt: 'run-0003-a1-8e2c4a1b9f0d3e57',
              },
            ],
          ]),
      }),
      '/txe/jobs/job_volume_monitor'
    );
    expect(
      await screen.findByRole('button', { name: 'Retry this run' })
    ).toBeInTheDocument();
  });

  // A recorded request is not a retry: it waits for the reviewer, and the
  // run is not offered again meanwhile.
  it('shows a requested retry as waiting, not done', async () => {
    renderAt(
      baseApi({
        getJob: async () => failedJob,
        listRetryStates: async () =>
          new Map([
            [
              'run-0003',
              {
                runId: 'run-0003',
                proposalId: 'prp_r',
                attemptId: 'run-0003-a1',
                queuedAt: '2026-10-09T12:00:00.000000001Z',
                status: 'requested' as const,
              },
            ],
          ]),
      }),
      '/txe/jobs/job_volume_monitor'
    );
    expect(
      await screen.findByText(
        'Retry requested; waiting for the reviewer to dispatch it'
      )
    ).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Retry this run' })
    ).not.toBeInTheDocument();
  });
});

describe('dispatched retry', () => {
  // The registry accepts a successful dispatch only with the new execution it
  // observed, so the receipt names a real execution; the run's own status is
  // shown beside it and never read as the job succeeding.
  it('names the observed execution and shows the run status separately', async () => {
    renderAt(
      baseApi({
        getJob: async () =>
          fixtureJob({
            latestRuns: [
              {
                dagName: 'job_volume_monitor',
                dagRunId: 'run-0003',
                status: 'running',
                execution: {
                  attemptId: 'run-0003-a2',
                  queuedAt: '',
                  ref: 'run-0003-a2-0123456789abcdef',
                },
              },
            ],
          }),
        listRetryStates: async () =>
          new Map([
            [
              'run-0003',
              {
                runId: 'run-0003',
                proposalId: 'prp_r',
                attemptId: 'run-0003-a1',
                queuedAt: '',
                status: 'succeeded' as const,
                receipt: 'run-0003-a2-0123456789abcdef',
              },
            ],
          ]),
      }),
      '/txe/jobs/job_volume_monitor'
    );
    const retry = await screen.findByTestId('txe-run-retry');
    expect(retry).toHaveTextContent(
      'Retry dispatched as execution run-0003-a2-0123456789abcdef'
    );
    expect(retry).toHaveTextContent('run is now running');
    expect(retry).not.toHaveTextContent('Retried');
  });
});
