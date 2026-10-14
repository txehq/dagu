// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { SWRConfig } from 'swr';
import { describe, expect, it, vi } from 'vitest';

import {
  TxeAccessActorKind,
  TxeAccessPermission,
  TxeAccessResourceKind,
  TxeShareState,
} from '@/api/v1/schema';
import TxeJobPage from '@/pages/txe/job';

import { mayDecide, type Share, type TxeAccessApi } from '../access';
import type { TxeApi } from '../api';
import { fixtureJob, fixtureProposal } from '../fixtures';
import { TxeAccessApiContext, TxeApiContext } from '../hooks';
import type { JobAccess } from '../types';

vi.mock('@/contexts/AuthContext', () => ({
  useCanExecute: () => true,
}));

vi.mock('@/hooks/api', () => ({
  useClient: () => ({}),
}));

vi.mock('@/contexts/ConfigContext', () => ({
  useConfig: () => ({ authMode: 'builtin' }),
}));

const JOB = 'job_volume_monitor';

function share(id: string, jobId: string, state = TxeShareState.active): Share {
  return {
    share_id: id,
    owner_id: 'own_A',
    resource: { kind: TxeAccessResourceKind.job, id: jobId },
    grantee: { owner_id: 'own_B', display_name: 'Bo' },
    permissions: [TxeAccessPermission.view],
    generation: 1,
    state,
    granted: {
      at: '2026-10-14T12:00:00Z',
      by: { kind: TxeAccessActorKind.person },
    },
  };
}

function accessApi(overrides: Partial<TxeAccessApi> = {}): TxeAccessApi {
  return {
    requestAccess: vi.fn(),
    listRequests: vi.fn(),
    listOwners: vi.fn(),
    createOwner: vi.fn(),
    approve: vi.fn(),
    listBindings: vi.fn(),
    revoke: vi.fn(),
    listShares: vi.fn(async () => ({
      granted: [share('shr_1', JOB), share('shr_other', 'job_other')],
      received: [],
    })),
    shareJob: vi.fn(async () => share('shr_2', JOB)),
    revokeShare: vi.fn(async () => undefined),
    ...overrides,
  };
}

function renderJob(access: JobAccess | undefined, shares = accessApi()) {
  const api = {
    getJob: async () => fixtureJob({ access }),
    listProposals: async () => [fixtureProposal()],
    listDecisions: async () => [],
    listRetryStates: async () => new Map(),
  } as unknown as TxeApi;
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <TxeApiContext.Provider value={api}>
        <TxeAccessApiContext.Provider value={shares}>
          <MemoryRouter initialEntries={[`/txe/jobs/${JOB}`]}>
            <Routes>
              <Route path="/txe/jobs/:jobId" element={<TxeJobPage />} />
            </Routes>
          </MemoryRouter>
        </TxeAccessApiContext.Provider>
      </TxeApiContext.Provider>
    </SWRConfig>
  );
}

const OWNER: JobAccess = {
  via: 'owner',
  permissions: ['view', 'author', 'execute', 'approve', 'administer'],
};

describe('mayDecide', () => {
  it('follows approve where the hub labels owner or share access', () => {
    expect(mayDecide({ access: OWNER }, false)).toBe(true);
    expect(
      mayDecide({ access: { via: 'share', permissions: ['view'] } }, true)
    ).toBe(false);
    expect(
      mayDecide({ access: { via: 'share', permissions: ['approve'] } }, false)
    ).toBe(true);
  });

  it('keeps the hub role without a label, and for the administrator', () => {
    expect(mayDecide({}, true)).toBe(true);
    expect(mayDecide({}, false)).toBe(false);
    expect(
      mayDecide(
        { access: { via: 'platform_admin', permissions: ['view'] } },
        true
      )
    ).toBe(true);
  });
});

describe('the job page and sharing', () => {
  it('lets the owner see and grant shares of this job only', async () => {
    const shares = accessApi();
    renderJob(OWNER, shares);

    const rows = await screen.findAllByTestId('txe-share');
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent('Bo');
    expect(rows[0]).toHaveTextContent('own_B');
    // administer is never offered.
    expect(
      screen.queryByRole('checkbox', { name: 'administer' })
    ).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText('Owner id'), {
      target: { value: ' own_B ' },
    });
    fireEvent.click(screen.getByRole('checkbox', { name: 'approve' }));
    fireEvent.click(screen.getByRole('button', { name: 'Share' }));

    await waitFor(() =>
      expect(shares.shareJob).toHaveBeenCalledWith(JOB, 'own_B', [
        TxeAccessPermission.view,
        TxeAccessPermission.approve,
      ])
    );
    // The hub names the grantee; the page did not guess.
    expect(await screen.findByRole('status')).toHaveTextContent(
      'Shared with Bo.'
    );
  });

  it('says why a share was refused', async () => {
    const shares = accessApi({
      shareJob: vi.fn(async () => {
        throw new Error('not_found');
      }),
    });
    renderJob(OWNER, shares);

    await screen.findByTestId('txe-sharing');
    fireEvent.change(screen.getByLabelText('Owner id'), {
      target: { value: 'own_NOPE' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Share' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The job was not shared: not_found'
    );
  });

  it('revokes a share only with a reason', async () => {
    const shares = accessApi();
    renderJob(OWNER, shares);

    fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }));
    const confirm = screen.getByRole('button', { name: 'Confirm revoke' });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Reason'), {
      target: { value: 'done reviewing' },
    });
    fireEvent.click(confirm);

    await waitFor(() =>
      expect(shares.revokeShare).toHaveBeenCalledWith('shr_1', 'done reviewing')
    );
  });

  it('marks a shared job, offers no sharing, and no decision without approve', async () => {
    const shares = accessApi();
    renderJob(
      {
        via: 'share',
        sharedBy: { ownerId: 'own_A', displayName: 'Ada' },
        permissions: ['view'],
      },
      shares
    );

    expect(await screen.findByTestId('txe-shared-with-you')).toHaveTextContent(
      'Shared with you by Ada'
    );
    expect(screen.queryByTestId('txe-sharing')).not.toBeInTheDocument();
    expect(shares.listShares).not.toHaveBeenCalled();
    expect(
      screen.queryByRole('button', { name: 'Record decision' })
    ).not.toBeInTheDocument();
  });

  it('offers the decision on a share that grants approve', async () => {
    renderJob({
      via: 'share',
      sharedBy: { ownerId: 'own_A', displayName: 'Ada' },
      permissions: ['view', 'approve'],
    });

    expect(
      await screen.findByRole('button', { name: 'Record decision' })
    ).toBeInTheDocument();
  });

  it('shows no sharing panel without an access label', async () => {
    renderJob(undefined);

    await screen.findByTestId('txe-job');
    expect(screen.queryByTestId('txe-sharing')).not.toBeInTheDocument();
  });
});
