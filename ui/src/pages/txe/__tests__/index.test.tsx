// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { SWRConfig } from 'swr';
import { describe, expect, it, vi } from 'vitest';

import type { TxeApi } from '@/features/txe/api';
import { fixtureJob, fixtureProposal } from '@/features/txe/fixtures';
import { TxeEnrolmentApiContext, TxeApiContext } from '@/features/txe/hooks';
import type { TxeEnrolmentApi } from '@/features/txe/enrolment';
import type { DecisionRequest, Proposal } from '@/features/txe/types';
import TxeInboxPage from '..';

vi.mock('@/contexts/AuthContext', () => ({
  useCanExecute: () => true,
}));

vi.mock('@/hooks/api', () => ({
  useClient: () => ({}),
}));

// Who the hub takes the caller to be; unset is a caller that is not a person
// signed in through the identity provider.
const identity = vi.hoisted(() => ({
  value: undefined as unknown,
}));
vi.mock('@/features/txe/identity', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/features/txe/identity')>()),
  useTxeIdentity: () => ({ identity: identity.value }),
}));

// The hub signs people in individually, so decisions are offered.
const authMode = vi.hoisted(() => ({ value: 'builtin' }));
vi.mock('@/contexts/ConfigContext', () => ({
  useConfig: () => ({ authMode: authMode.value }),
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
    replayDecision: vi.fn(),
    requestRetry: vi.fn(),
    listRetryStates: async () => new Map(),
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
      replayDecision: vi.fn(),
      requestRetry: vi.fn(),
      listRetryStates: async () => new Map(),
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

// With no authentication or basic auth, the hub cannot tell a person from a
// reviewer holding the same access: the inbox says why decisions are
// unavailable and offers none, while the context stays readable.
describe('TxeInboxPage without person authentication', () => {
  it.each(['none', 'basic'])(
    'offers no decision under %s auth',
    async (mode) => {
      authMode.value = mode;
      try {
        const { api, decide } = fakeApi([fixtureProposal()]);
        renderPage(api);
        expect(
          await screen.findByText('Usage is at 92%. Resize the volume to 20Gi?')
        ).toBeInTheDocument();
        expect(
          screen.getByTestId('txe-decision-auth-notice')
        ).toBeInTheDocument();
        expect(
          screen.queryByRole('button', { name: 'Record decision' })
        ).not.toBeInTheDocument();
        expect(decide).not.toHaveBeenCalled();
      } finally {
        authMode.value = 'builtin';
      }
    }
  );

  it('shows no notice under builtin auth', async () => {
    const { api } = fakeApi([fixtureProposal()]);
    renderPage(api);
    await screen.findByText('Usage is at 92%. Resize the volume to 20Gi?');
    expect(
      screen.queryByTestId('txe-decision-auth-notice')
    ).not.toBeInTheDocument();
  });
});

describe('TxeInboxPage for a person with no jobs', () => {
  function noJobs(): TxeApi {
    return { ...fakeApi([]).api, listJobs: async () => [] };
  }

  it('tells a person where jobs will come from', async () => {
    // What the hub answers for a person bound to an owner with no jobs yet.
    identity.value = {
      principal: { class: 'person', shown: {} },
      state: 'bound',
      is_person: true,
    };
    try {
      renderPage(noJobs());
      expect(await screen.findByTestId('txe-inbox-first')).toBeInTheDocument();
      expect(screen.queryByTestId('txe-inbox-empty')).not.toBeInTheDocument();
    } finally {
      identity.value = undefined;
    }
  });

  it('keeps the usual empty text for any other caller', async () => {
    renderPage(noJobs());
    expect(await screen.findByTestId('txe-inbox-empty')).toBeInTheDocument();
    expect(screen.queryByTestId('txe-inbox-first')).not.toBeInTheDocument();
  });
});

describe('TxeInboxPage for a shared job', () => {
  it('says who shared it, and offers no decision without approve', async () => {
    const { api } = fakeApi([fixtureProposal()]);
    const shared = fixtureJob({
      access: {
        via: 'share',
        sharedBy: { ownerId: 'own_A', displayName: 'Ada' },
        permissions: ['view'],
      },
    });
    renderPage({ ...api, listJobs: async () => [shared] });

    expect(await screen.findByTestId('txe-shared-with-you')).toHaveTextContent(
      'Shared with you by Ada'
    );
    expect(
      screen.getByText('You do not have permission to decide this proposal.')
    ).toBeInTheDocument();
  });
});

describe('TxeInboxPage and machine enrolment', () => {
  function renderWithMachines(listMachines: TxeEnrolmentApi['listMachines']) {
    // The machine's one application is unexpired and not enrolled.
    const enrolment = {
      listMachines,
      listApplications: async (machineId: string) => [
        {
          machine_id: machineId,
          class: 'worker',
          issuer: 'https://idp.example',
          subject: 'sub-ada',
          client_id: 'dagu-worker',
          received_at: new Date().toISOString(),
          credential_expires: new Date(Date.now() + 3_600_000).toISOString(),
        },
      ],
      listEnrolments: async () => [],
    } as unknown as TxeEnrolmentApi;
    return render(
      <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
        <TxeApiContext.Provider value={fakeApi([]).api}>
          <TxeEnrolmentApiContext.Provider value={enrolment}>
            <MemoryRouter>
              <TxeInboxPage />
            </MemoryRouter>
          </TxeEnrolmentApiContext.Provider>
        </TxeApiContext.Provider>
      </SWRConfig>
    );
  }

  const pending = async () => [
    {
      machine_id: 'mch_1',
      owner_id: 'own_A',
      display_name: 'ada-laptop',
      pending_applications: 1,
    },
  ];

  // An allowlisted SSO administrator bound to an owner approves that owner's
  // machines as its person (TXE-4710); the builtin administrator acts for
  // nobody.
  it("tells a bound SSO administrator when their owner's machine awaits approval", async () => {
    identity.value = {
      principal: {
        class: 'platform_admin',
        issuer: 'https://idp.example',
        subject: 'sub-root',
        shown: {},
      },
      platform_admin: true,
      state: 'bound',
      is_person: true,
      owners: [{ owner_id: 'own_A', display_name: 'Ada' }],
    };
    try {
      renderWithMachines(pending);
      expect(
        await screen.findByTestId('txe-pending-enrolments')
      ).toBeInTheDocument();
    } finally {
      identity.value = undefined;
    }
  });

  it('asks the builtin administrator for no machines', async () => {
    identity.value = {
      principal: { class: 'platform_admin', shown: { username: 'admin' } },
      platform_admin: true,
      state: 'unbound',
      is_person: false,
      owners: [],
    };
    const listMachines = vi.fn(pending);
    try {
      renderWithMachines(listMachines);
      expect(await screen.findByTestId('txe-inbox-empty')).toBeInTheDocument();
      expect(listMachines).not.toHaveBeenCalled();
    } finally {
      identity.value = undefined;
    }
  });

  it('tells a person when a machine of their owner awaits approval', async () => {
    identity.value = {
      principal: { class: 'person', shown: {} },
      state: 'bound',
      is_person: true,
      owners: [{ owner_id: 'own_A', display_name: 'Ada' }],
    };
    try {
      renderWithMachines(async () => [
        {
          machine_id: 'mch_1',
          owner_id: 'own_A',
          display_name: 'ada-laptop',
          pending_applications: 1,
        },
      ]);
      expect(
        await screen.findByTestId('txe-pending-enrolments')
      ).toHaveTextContent(
        'A machine enrolment application is awaiting your approval.'
      );
    } finally {
      identity.value = undefined;
    }
  });

  it('does not ask for machines for any other caller', async () => {
    const listMachines = vi.fn(async () => []);
    renderWithMachines(listMachines);

    expect(await screen.findByTestId('txe-inbox-empty')).toBeInTheDocument();
    expect(listMachines).not.toHaveBeenCalled();
    expect(screen.queryByTestId('txe-pending-enrolments')).toBeNull();
  });
});
