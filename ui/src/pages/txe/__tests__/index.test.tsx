// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { SWRConfig } from 'swr';
import { describe, expect, it, vi } from 'vitest';

import type { TxeApi } from '@/features/txe/api';
import { fixtureJob, fixtureProposal } from '@/features/txe/fixtures';
import { TxeApiContext } from '@/features/txe/hooks';
import type { DecisionRequest, Proposal } from '@/features/txe/types';
import TxeInboxPage from '..';

vi.mock('@/contexts/AuthContext', () => ({
  useCanExecute: () => true,
}));

vi.mock('@/hooks/api', () => ({
  useClient: () => ({}),
}));

// fakeApi keeps proposals in memory and applies the server's revision check,
// so the page is exercised against the same refusal it gets in production.
function fakeApi(initial: Proposal[]) {
  let proposals = initial;
  const decide = vi.fn(
    async (_jobId: string, proposalId: string, request: DecisionRequest) => {
      const current = proposals.find((p) => p.proposalId === proposalId);
      if (!current || current.revision !== request.expectedProposalRevision) {
        return { ok: false as const, status: 409, message: 'stale_binding' };
      }
      proposals = proposals.map((p) =>
        p.proposalId === proposalId
          ? { ...p, state: 'decided' as const, revision: p.revision + 1 }
          : p
      );
      return { ok: true as const };
    }
  );
  const api: TxeApi = {
    listJobs: async () => [fixtureJob()],
    getJob: async () => fixtureJob(),
    listProposals: async () => proposals,
    listDecisions: async () => [],
    decide,
  };
  return { api, decide };
}

function renderPage(api: TxeApi) {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <TxeApiContext.Provider value={api}>
        <MemoryRouter>
          <TxeInboxPage />
        </MemoryRouter>
      </TxeApiContext.Provider>
    </SWRConfig>
  );
}

describe('TxeInboxPage', () => {
  it('shows a proposal with context and removes it once decided', async () => {
    const { api, decide } = fakeApi([fixtureProposal()]);
    renderPage(api);

    expect(
      await screen.findByText('Usage is at 92%. Resize the volume to 20Gi?')
    ).toBeInTheDocument();
    expect(
      screen.getByText('Watch the fixture volume until the migration finishes.')
    ).toBeInTheDocument();
    expect(screen.getByText('usage.json')).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Reject' }));
    fireEvent.click(screen.getByRole('button', { name: 'Record decision' }));

    await waitFor(() => expect(decide).toHaveBeenCalledTimes(1));
    expect(decide.mock.calls[0]?.[2]).toMatchObject({
      verdict: 'reject',
      expectedProposalRevision: 1,
    });
    expect(await screen.findByTestId('txe-inbox-empty')).toBeInTheDocument();
  });
});

describe('TxeInboxPage refused decisions', () => {
  // The refused proposal leaves the inbox on reload, so the refusal must stay
  // visible at page level rather than vanish with its card.
  it('keeps a notice after a stale proposal disappears', async () => {
    let proposals: Proposal[] = [fixtureProposal()];
    const api: TxeApi = {
      listJobs: async () => [fixtureJob()],
      getJob: async () => fixtureJob(),
      listProposals: async () => proposals,
      listDecisions: async () => [],
      decide: vi.fn(async () => {
        proposals = [{ ...proposals[0]!, state: 'superseded' as const }];
        return {
          ok: false as const,
          status: 409,
          message: 'proposal is not open',
        };
      }),
    };
    renderPage(api);
    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    fireEvent.click(screen.getByRole('button', { name: 'Record decision' }));
    expect(await screen.findByTestId('txe-inbox-empty')).toBeInTheDocument();
    expect(screen.getByTestId('txe-decision-refused')).toHaveTextContent(
      'Usage is at 92%. Resize the volume to 20Gi?'
    );
  });
});
