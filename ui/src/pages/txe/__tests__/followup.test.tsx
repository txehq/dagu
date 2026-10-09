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
