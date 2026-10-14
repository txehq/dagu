// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { SWRConfig } from 'swr';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  TxeIdentityAuthz_mode,
  TxeIdentityPrincipalClass,
  TxeIdentityRequestState,
  TxeIdentityScopeKind,
  TxeIdentityState,
} from '@/api/v1/schema';
import { sseManager } from '@/hooks/SSEManager';
import TxeJobPage from '@/pages/txe/job';

import { TxeApiError, type TxeApi } from '../api';
import { TxeApiContext } from '../hooks';
import { TxePersonGate, type TxeIdentity } from '../identity';

const mocks = vi.hoisted(() => ({
  get: vi.fn(),
  authMode: { value: 'builtin' },
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    isAuthenticated: true,
    token: 'token-a',
    logout: vi.fn(() => Promise.resolve('local')),
  }),
  useCanExecute: () => true,
}));

vi.mock('@/contexts/ConfigContext', () => ({
  useConfig: () => ({ authMode: mocks.authMode.value }),
}));

vi.mock('@/hooks/api', () => ({
  useClient: () => ({ GET: mocks.get }),
}));

function identity(overrides: Partial<TxeIdentity>): TxeIdentity {
  return {
    contract: 1,
    authz_mode: TxeIdentityAuthz_mode.enforce,
    principal: {
      class: TxeIdentityPrincipalClass.person,
      issuer: 'https://idp.example',
      subject: 'sub-a',
      shown: { username: 'ada' },
    },
    state: TxeIdentityState.unbound,
    owners: [],
    scope: { kind: TxeIdentityScopeKind.unbound, unbound_reason: 'unbound' },
    platform_admin: false,
    is_person: true,
    ...overrides,
  };
}

function answer(body: TxeIdentity) {
  mocks.get.mockResolvedValue({ data: body, response: { status: 200 } });
}

function renderGate() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <MemoryRouter>
        <TxePersonGate personApp={<p data-testid="person-app" />}>
          <p data-testid="dashboard" />
        </TxePersonGate>
      </MemoryRouter>
    </SWRConfig>
  );
}

describe('TxePersonGate', () => {
  let setRefused: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    mocks.get.mockReset();
    setRefused = vi.spyOn(sseManager, 'setRefused');
  });

  afterEach(() => {
    setRefused.mockRestore();
    sseManager.setRefused(false);
    mocks.authMode.value = 'builtin';
  });

  it('shows a person who acts for nobody only that they have no access', async () => {
    answer(identity({}));
    renderGate();

    expect(await screen.findByTestId('txe-no-access')).toHaveTextContent(
      'You are signed in as ada'
    );
    // Asking for access is not wired yet: the person is told whom to ask.
    expect(
      screen.queryByRole('button', { name: 'Request access' })
    ).not.toBeInTheDocument();
    expect(screen.getByTestId('txe-no-access')).toHaveTextContent(
      'Ask the platform administrator to give your account access.'
    );
    expect(screen.queryByTestId('dashboard')).not.toBeInTheDocument();
    expect(screen.queryByTestId('person-app')).not.toBeInTheDocument();
    expect(setRefused).toHaveBeenCalledWith(true);
  });

  it('shows a person whose request awaits approval that it is pending', async () => {
    answer(
      identity({
        state: TxeIdentityState.pending,
        request: {
          state: TxeIdentityRequestState.pending,
          requested_at: '2026-10-14T12:00:00Z',
          generation: 1,
        },
      })
    );
    renderGate();

    expect(await screen.findByTestId('txe-access-pending')).toBeInTheDocument();
    expect(screen.queryByTestId('dashboard')).not.toBeInTheDocument();
  });

  it('gives a person who acts for an owner the TXE pages only', async () => {
    answer(
      identity({
        state: TxeIdentityState.bound,
        owners: [{ owner_id: 'own_a', display_name: 'Ada' }],
        scope: { kind: TxeIdentityScopeKind.owner },
      })
    );
    renderGate();

    expect(await screen.findByTestId('person-app')).toBeInTheDocument();
    expect(screen.queryByTestId('dashboard')).not.toBeInTheDocument();
    expect(setRefused).toHaveBeenCalledWith(true);
  });

  it.each([
    [
      'the platform administrator',
      identity({
        principal: {
          class: TxeIdentityPrincipalClass.platform_admin,
          shown: { username: 'admin' },
        },
        scope: { kind: TxeIdentityScopeKind.platform_admin },
        platform_admin: true,
        is_person: false,
      }),
    ],
    [
      'a builtin user',
      identity({
        principal: {
          class: TxeIdentityPrincipalClass.legacy,
          shown: { username: 'vera' },
        },
        scope: { kind: TxeIdentityScopeKind.unbound, unbound_reason: 'legacy' },
        is_person: false,
      }),
    ],
  ])('gives %s the dashboard as before', async (_who, body) => {
    answer(body);
    renderGate();

    expect(await screen.findByTestId('dashboard')).toBeInTheDocument();
    expect(setRefused).toHaveBeenCalledWith(false);
  });

  it('gives the dashboard as before when the identity cannot be read', async () => {
    mocks.get.mockResolvedValue({
      error: { message: 'provider_unavailable' },
      response: { status: 503 },
    });
    sseManager.setRefused(true);
    renderGate();

    expect(await screen.findByTestId('dashboard')).toBeInTheDocument();
    expect(setRefused).toHaveBeenLastCalledWith(false);
  });

  it('does not ask the hub without builtin authentication', async () => {
    mocks.authMode.value = 'none';
    renderGate();

    expect(await screen.findByTestId('dashboard')).toBeInTheDocument();
    expect(mocks.get).not.toHaveBeenCalled();
  });
});

describe('TxeJobPage for a job the caller may not see', () => {
  it('says the job is not found or not shared, not the server text', async () => {
    const missing = async () => {
      throw new TxeApiError(404, 'job job_x not found');
    };
    const api = {
      getJob: missing,
      listProposals: missing,
      listDecisions: missing,
      listRetryStates: async () => new Map(),
    } as unknown as TxeApi;
    render(
      <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
        <TxeApiContext.Provider value={api}>
          <MemoryRouter initialEntries={['/txe/jobs/job_x']}>
            <Routes>
              <Route path="/txe/jobs/:jobId" element={<TxeJobPage />} />
            </Routes>
          </MemoryRouter>
        </TxeApiContext.Provider>
      </SWRConfig>
    );

    expect(await screen.findByTestId('txe-job-not-found')).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByText('job job_x not found')).not.toBeInTheDocument()
    );
  });
});
