// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { SWRConfig } from 'swr';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  TxeAccessActorKind,
  TxeBindingRequestState,
  TxeBindingState,
} from '@/api/v1/schema';
import type {
  Binding,
  BindingRequest,
  Owner,
  TxeAccessApi,
} from '@/features/txe/access';
import { TxeApiError } from '@/features/txe/api';
import { TxeAccessApiContext } from '@/features/txe/hooks';
import TxeAccessPage from '../access';

vi.mock('@/hooks/api', () => ({
  useClient: () => ({}),
}));

// The signed-in caller, as GET /txe/identity reads it; the builtin
// administrator unless a test says otherwise.
const builtinAdmin = {
  principal: { class: 'platform_admin', shown: { username: 'admin' } },
  platform_admin: true,
  is_person: false,
  state: 'unbound',
  owners: [],
};
const identity = vi.hoisted(() => ({
  value: undefined as unknown,
  isLoading: false,
  error: undefined as unknown,
  reload: vi.fn(),
}));
vi.mock('@/features/txe/identity', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/features/txe/identity')>()),
  useTxeIdentity: () => ({
    identity: identity.value,
    isLoading: identity.isLoading,
    error: identity.error,
    reload: identity.reload,
  }),
}));

vi.mock('@/contexts/ConfigContext', () => ({
  useConfig: () => ({ authMode: 'builtin' }),
}));

beforeEach(() => {
  identity.value = builtinAdmin;
  identity.isLoading = false;
  identity.error = undefined;
});

// sso is an allowlisted SSO administrator with the given identity.
function sso(subject: string, extra: Record<string, unknown> = {}) {
  return {
    principal: {
      class: 'platform_admin',
      issuer: 'https://idp.example',
      subject,
      shown: {},
    },
    platform_admin: true,
    is_person: false,
    state: 'unbound',
    owners: [],
    ...extra,
  };
}

const stamp = {
  at: '2026-10-14T12:00:00Z',
  by: { kind: TxeAccessActorKind.platform_admin, name: 'admin' },
};

function owner(id: string, name: string): Owner {
  return {
    schema: 1,
    owner_id: id,
    display_name: name,
    created: { at: stamp.at },
  } as unknown as Owner;
}

const request: BindingRequest = {
  issuer: 'https://idp.example',
  subject: 'sub-ada',
  shown: { username: 'ada' },
  state: TxeBindingRequestState.pending,
  requested_at: '2026-10-14T12:00:00Z',
  generation: 3,
};

function binding(id: string, state: TxeBindingState): Binding {
  return {
    binding_id: id,
    issuer: 'https://idp.example',
    subject: 'sub-bo',
    owner_id: 'own_A',
    generation: 1,
    request_generation: 1,
    state,
    bound: stamp,
    shown: { username: 'bo' },
  };
}

function fakeAccess(overrides: Partial<TxeAccessApi> = {}) {
  const api: TxeAccessApi = {
    requestAccess: vi.fn(),
    listRequests: vi.fn(async () => [request]),
    listOwners: vi.fn(async () => [owner('own_A', 'Team A')]),
    createOwner: vi.fn(async (name: string) => owner('own_NEW', name)),
    approve: vi.fn(async () => binding('bnd_1', TxeBindingState.active)),
    listBindings: vi.fn(async () => [binding('bnd_0', TxeBindingState.active)]),
    revoke: vi.fn(async () => undefined),
    listShares: vi.fn(async () => ({ granted: [], received: [] })),
    shareJob: vi.fn(),
    revokeShare: vi.fn(),
    ...overrides,
  };
  return api;
}

function renderPage(api: TxeAccessApi) {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <TxeAccessApiContext.Provider value={api}>
        <MemoryRouter>
          <TxeAccessPage />
        </MemoryRouter>
      </TxeAccessApiContext.Provider>
    </SWRConfig>
  );
}

describe('TxeAccessPage', () => {
  it('approves a request for the owner the administrator picks', async () => {
    const api = fakeAccess();
    renderPage(api);

    const row = await screen.findByTestId('txe-access-request');
    expect(row).toHaveTextContent('ada');
    expect(row).toHaveTextContent('https://idp.example · sub-ada');
    const approve = screen.getByRole('button', { name: 'Approve' });
    // Nothing is preselected: the owner is always the administrator's choice.
    expect(approve).toBeDisabled();

    fireEvent.change(screen.getByLabelText('Owner'), {
      target: { value: 'own_A' },
    });
    fireEvent.click(approve);

    await waitFor(() => expect(api.approve).toHaveBeenCalledTimes(1));
    expect(api.approve).toHaveBeenCalledWith('own_A', request);
    expect(api.createOwner).not.toHaveBeenCalled();
    await waitFor(() => expect(api.listRequests).toHaveBeenCalledTimes(2));
  });

  it('creates a new owner first, and on a conflict re-reads and retries with the same owner', async () => {
    const approve = vi
      .fn()
      .mockRejectedValueOnce(new TxeApiError(409, 'stale_generation'))
      .mockResolvedValueOnce(binding('bnd_1', TxeBindingState.active));
    // The hub moved the request on: the re-read carries a new generation.
    const moved = { ...request, generation: 4 };
    const listRequests = vi
      .fn()
      .mockResolvedValueOnce([request])
      .mockResolvedValue([moved]);
    const api = fakeAccess({ approve, listRequests });
    renderPage(api);

    await screen.findByTestId('txe-access-request');
    fireEvent.change(screen.getByLabelText('Owner'), {
      target: { value: '__new__' },
    });
    fireEvent.change(screen.getByLabelText('New owner name'), {
      target: { value: 'Ada Lovelace' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }));

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The request changed since this page read it (stale_generation).'
    );
    expect(api.createOwner).toHaveBeenCalledWith('Ada Lovelace');
    expect(approve).toHaveBeenLastCalledWith('own_NEW', request);
    await waitFor(() => expect(listRequests).toHaveBeenCalledTimes(2));

    fireEvent.click(screen.getByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(approve).toHaveBeenCalledTimes(2));
    expect(api.createOwner).toHaveBeenCalledTimes(1);
    expect(approve).toHaveBeenLastCalledWith('own_NEW', moved);
  });

  it('shows a request that arrives while the page is open', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      const listRequests = vi
        .fn()
        .mockResolvedValueOnce([])
        .mockResolvedValue([request]);
      renderPage(fakeAccess({ listRequests }));

      expect(
        await screen.findByTestId('txe-access-no-requests')
      ).toBeInTheDocument();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(15_000);
      });

      expect(await screen.findByTestId('txe-access-request')).toHaveTextContent(
        'ada'
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it('reads the page again on Refresh', async () => {
    const listRequests = vi
      .fn()
      .mockResolvedValueOnce([])
      .mockResolvedValue([request]);
    renderPage(fakeAccess({ listRequests }));

    await screen.findByTestId('txe-access-no-requests');
    fireEvent.click(screen.getByRole('button', { name: /refresh/i }));

    expect(await screen.findByTestId('txe-access-request')).toBeInTheDocument();
  });

  it('revokes a binding only with a reason', async () => {
    const api = fakeAccess({
      listBindings: vi.fn(async () => [
        binding('bnd_0', TxeBindingState.active),
        binding('bnd_9', TxeBindingState.revoked),
      ]),
    });
    renderPage(api);

    const rows = await screen.findAllByTestId('txe-access-binding');
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent('Team A');
    expect(rows[1]).toHaveTextContent('Revoked');
    // A revoked binding offers nothing more.
    expect(screen.getAllByRole('button', { name: 'Revoke' })).toHaveLength(1);

    fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
    const confirm = screen.getByRole('button', { name: 'Confirm revoke' });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText('Reason'), {
      target: { value: 'left the team' },
    });
    fireEvent.click(confirm);

    await waitFor(() =>
      expect(api.revoke).toHaveBeenCalledWith('own_A', 'bnd_0', 'left the team')
    );
  });

  it('says when nobody is waiting', async () => {
    renderPage(fakeAccess({ listRequests: vi.fn(async () => []) }));
    expect(
      await screen.findByTestId('txe-access-no-requests')
    ).toBeInTheDocument();
  });

  it('shows why the page could not be read', async () => {
    renderPage(
      fakeAccess({
        listRequests: vi.fn(async () => {
          throw new TxeApiError(403, 'forbidden');
        }),
      })
    );
    expect(await screen.findByText('forbidden')).toBeInTheDocument();
  });
});

describe('TxeAccessPage for an SSO administrator', () => {
  afterEach(() => {
    identity.reload.mockReset();
  });

  // Until the hub says who the caller is, any row could be its own: nothing
  // is approved, and no owner is created, from it.
  it('offers no approval while the identity is being read', async () => {
    identity.value = undefined;
    identity.isLoading = true;
    renderPage(fakeAccess());

    expect(
      await screen.findByTestId('txe-access-identity-unknown')
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Approve' })).toBeDisabled();
    expect(screen.getByLabelText('Owner')).toBeDisabled();
  });

  it('offers no approval when the identity could not be read', async () => {
    identity.value = undefined;
    identity.error = new Error('unavailable');
    renderPage(fakeAccess());

    expect(
      await screen.findByTestId('txe-access-identity-unknown')
    ).toHaveTextContent('could not be read');
    expect(screen.getByRole('button', { name: 'Approve' })).toBeDisabled();
  });

  // The hub refuses an administrator's approval of its own request (403).
  it("offers no approval of the administrator's own request", async () => {
    identity.value = sso('sub-ada', { state: 'pending' });
    renderPage(fakeAccess());

    expect(
      await screen.findByTestId('txe-access-own-request')
    ).toHaveTextContent('Another platform administrator has to approve it.');
    expect(
      screen.queryByRole('button', { name: 'Approve' })
    ).not.toBeInTheDocument();
    expect(screen.queryByTestId('txe-access-request-own')).toBeNull();
  });

  it("approves another person's request as before", async () => {
    identity.value = sso('sub-root', {
      is_person: true,
      state: 'bound',
      owners: [{ owner_id: 'own_A', display_name: 'Team A' }],
    });
    renderPage(fakeAccess());

    expect(
      await screen.findByRole('button', { name: 'Approve' })
    ).toBeInTheDocument();
    expect(screen.queryByTestId('txe-access-own-request')).toBeNull();
    expect(screen.queryByTestId('txe-access-request-own')).toBeNull();
  });

  it('asks for access for an administrator who acts for no owner, on its press only', async () => {
    identity.value = sso('sub-root');
    const api = fakeAccess({ listRequests: vi.fn(async () => []) });
    renderPage(api);

    const own = await screen.findByTestId('txe-access-request-own');
    expect(api.requestAccess).not.toHaveBeenCalled();
    fireEvent.click(
      within(own).getByRole('button', { name: 'Request access for yourself' })
    );
    await waitFor(() => expect(api.requestAccess).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(identity.reload).toHaveBeenCalled());
  });

  it('offers the builtin administrator no request of its own', async () => {
    identity.value = {
      principal: { class: 'platform_admin', shown: { username: 'admin' } },
      platform_admin: true,
      is_person: false,
      state: 'unbound',
      owners: [],
    };
    renderPage(fakeAccess({ listRequests: vi.fn(async () => []) }));

    expect(
      await screen.findByTestId('txe-access-no-requests')
    ).toBeInTheDocument();
    expect(screen.queryByTestId('txe-access-request-own')).toBeNull();
  });
});
