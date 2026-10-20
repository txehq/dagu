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
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  TxeIdentityAuthz_mode,
  TxeIdentityPrincipalClass,
  TxeIdentityRequestState,
  TxeIdentityScopeKind,
  TxeIdentityState,
} from '@/api/v1/schema';
import { sseManager } from '@/hooks/SSEManager';
import { setPersonSignal } from '../personSignal';
import TxeJobPage from '@/pages/txe/job';

import { TxeApiError, type TxeApi } from '../api';
import type { TxeAccessApi } from '../access';
import { TxeAccessApiContext, TxeApiContext } from '../hooks';
import { TxePersonGate, type TxeIdentity } from '../identity';

const mocks = vi.hoisted(() => ({
  get: vi.fn(),
  authMode: { value: 'builtin' },
  token: { value: 'token-a' },
  requestAccess: vi.fn(),
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    isAuthenticated: true,
    token: mocks.token.value,
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
    // The hub answers is_person only for a person bound to an owner; a
    // person who acts for nobody is still a person by class.
    is_person: false,
    ...overrides,
  };
}

function answer(body: TxeIdentity) {
  mocks.get.mockResolvedValue({ data: body, response: { status: 200 } });
}

function gate() {
  return (
    <TxePersonGate personApp={<p data-testid="person-app" />}>
      <p data-testid="dashboard" />
    </TxePersonGate>
  );
}

// withCache renders the gate on one SWR cache, which a rerender keeps, as a
// browser keeps its cache from one session to the next.
function withCache(cache: Map<unknown, unknown>) {
  return (
    <SWRConfig value={{ provider: () => cache as never, dedupingInterval: 0 }}>
      <TxeAccessApiContext.Provider
        value={
          { requestAccess: mocks.requestAccess } as unknown as TxeAccessApi
        }
      >
        <MemoryRouter>{gate()}</MemoryRouter>
      </TxeAccessApiContext.Provider>
    </SWRConfig>
  );
}

function renderGate(cache: Map<unknown, unknown> = new Map()) {
  return render(withCache(cache));
}

describe('TxePersonGate', () => {
  let setRefused: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    mocks.get.mockReset();
    mocks.requestAccess.mockReset();
    setRefused = vi.spyOn(sseManager, 'setRefused');
  });

  afterEach(() => {
    setRefused.mockRestore();
    sseManager.setRefused(false);
    setPersonSignal(undefined);
    mocks.authMode.value = 'builtin';
    mocks.token.value = 'token-a';
  });

  it('shows a person who acts for nobody only that they have no access', async () => {
    answer(identity({}));
    renderGate();

    expect(await screen.findByTestId('txe-no-access')).toHaveTextContent(
      'You are signed in as ada'
    );
    // Nothing is asked for on display.
    expect(mocks.requestAccess).not.toHaveBeenCalled();
    expect(screen.queryByTestId('dashboard')).not.toBeInTheDocument();
    expect(screen.queryByTestId('person-app')).not.toBeInTheDocument();
    expect(setRefused).toHaveBeenCalledWith(true);
  });

  it('asks for access when the person presses the button, then shows it pending', async () => {
    answer(identity({}));
    mocks.requestAccess.mockImplementationOnce(async () => {
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
    });
    renderGate();

    fireEvent.click(
      await screen.findByRole('button', { name: 'Request access' })
    );

    expect(await screen.findByTestId('txe-access-pending')).toBeInTheDocument();
    expect(mocks.requestAccess).toHaveBeenCalledTimes(1);
  });

  it('says why a request for access was not recorded', async () => {
    answer(identity({}));
    mocks.requestAccess.mockRejectedValueOnce(
      new Error('provider_unavailable')
    );
    renderGate();

    fireEvent.click(
      await screen.findByRole('button', { name: 'Request access' })
    );

    expect(await screen.findByTestId('txe-no-access-error')).toHaveTextContent(
      'The request was not recorded: provider_unavailable'
    );
    expect(
      screen.getByRole('button', { name: 'Request access' })
    ).toBeEnabled();
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
        is_person: true,
      })
    );
    renderGate();

    expect(await screen.findByTestId('person-app')).toBeInTheDocument();
    expect(screen.queryByTestId('dashboard')).not.toBeInTheDocument();
    expect(setRefused).toHaveBeenCalledWith(true);
    // The app shell then leaves out what the hub refuses a person.
    expect(sessionStorage.getItem('dagu_txe_person')).toBe('1');
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
    expect(sessionStorage.getItem('dagu_txe_person')).toBe('0');
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

  it('gives the dashboard with streams when the identity request fails', async () => {
    mocks.get.mockRejectedValue(new TypeError('Failed to fetch'));
    sseManager.setRefused(true);
    renderGate();

    expect(await screen.findByTestId('dashboard')).toBeInTheDocument();
    expect(setRefused).toHaveBeenLastCalledWith(false);
  });

  it('ignores a late answer for the session before', async () => {
    let answerA: (value: unknown) => void = () => {};
    mocks.get.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          answerA = resolve;
        })
    );
    const cache = new Map();
    const view = renderGate(cache);

    // Session A (a person) is still being read when session B signs in.
    mocks.token.value = 'token-b';
    mocks.get.mockResolvedValueOnce({
      data: identity({
        principal: {
          class: TxeIdentityPrincipalClass.legacy,
          shown: { username: 'vera' },
        },
        scope: { kind: TxeIdentityScopeKind.unbound, unbound_reason: 'legacy' },
        is_person: false,
      }),
      response: { status: 200 },
    });
    view.rerender(withCache(cache));
    expect(await screen.findByTestId('dashboard')).toBeInTheDocument();

    await act(async () => {
      answerA({ data: identity({}), response: { status: 200 } });
    });

    expect(screen.getByTestId('dashboard')).toBeInTheDocument();
    expect(screen.queryByTestId('txe-no-access')).not.toBeInTheDocument();
    expect(setRefused).not.toHaveBeenCalledWith(true);
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
