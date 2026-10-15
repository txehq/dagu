// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react';
import React from 'react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { SWRConfig, useSWRConfig } from 'swr';
import { describe, expect, it, vi } from 'vitest';

import {
  TxeEnrolmentApplicationClass,
  TxeEnrolmentClass,
  TxeEnrolmentState,
} from '@/api/v1/schema';
import { PendingEnrolmentsNotice } from '@/features/txe/components/PendingEnrolmentsNotice';
import {
  awaitingApproval,
  TxeRefusal,
  type Enrolment,
  type EnrolmentApplication,
  type MachineSummary,
  type TxeEnrolmentApi,
} from '@/features/txe/enrolment';
import { TxeEnrolmentApiContext } from '@/features/txe/hooks';

import TxeMachinesPage from '../machines';

vi.mock('@/hooks/api', () => ({
  useClient: () => ({}),
}));

const HOUR = 3_600_000;

function machine(overrides: Partial<MachineSummary> = {}): MachineSummary {
  return {
    machine_id: 'mch_ada_laptop',
    owner_id: 'own_ada',
    display_name: 'ada-laptop',
    ...overrides,
  };
}

function application(
  overrides: Partial<EnrolmentApplication> = {}
): EnrolmentApplication {
  return {
    machine_id: 'mch_ada_laptop',
    class: TxeEnrolmentApplicationClass.worker,
    issuer: 'https://idp.example/realms/r',
    subject: 'sub-ada',
    client_id: 'dagu-worker',
    received_at: new Date().toISOString(),
    credential_expires: new Date(Date.now() + HOUR).toISOString(),
    ...overrides,
  };
}

// The enrolment the hub makes from an application when it is approved.
function enrolmentOf(
  a: EnrolmentApplication,
  state = TxeEnrolmentState.active
): Enrolment {
  return {
    machine_id: a.machine_id,
    class: TxeEnrolmentClass.worker,
    owner_id: 'own_ada',
    issuer: a.issuer,
    subject: a.subject,
    client_id: a.client_id,
    generation: 1,
    state,
    enrolled: { at: new Date().toISOString() } as never,
  };
}

type Fake = {
  machines: MachineSummary[] | (() => Promise<MachineSummary[]>);
  applications?: Record<string, EnrolmentApplication[]>;
  enrolments?: Record<string, Enrolment[]>;
  failDetails?: boolean;
};

type FakeApi = TxeEnrolmentApi & {
  listApplications: ReturnType<typeof vi.fn>;
  listEnrolments: ReturnType<typeof vi.fn>;
};

function api(fake: Fake): FakeApi {
  const fail = async () => {
    throw new TxeRefusal(503, 'unavailable', undefined);
  };
  return {
    listMachines: vi.fn(
      typeof fake.machines === 'function'
        ? fake.machines
        : async () => fake.machines as MachineSummary[]
    ),
    listApplications: vi.fn(
      fake.failDetails
        ? fail
        : async (id: string) => fake.applications?.[id] ?? []
    ),
    listEnrolments: vi.fn(
      fake.failDetails
        ? fail
        : async (id: string) => fake.enrolments?.[id] ?? []
    ),
  } as never;
}

function renderAt(
  element: React.ReactElement,
  enrolment: TxeEnrolmentApi,
  onError: (err: unknown) => void = () => undefined
) {
  return render(
    <SWRConfig
      value={{ provider: () => new Map(), dedupingInterval: 0, onError }}
    >
      <TxeEnrolmentApiContext.Provider value={enrolment}>
        <MemoryRouter initialEntries={['/start']}>
          <Routes>
            <Route path="/start" element={element} />
            <Route path="/txe/machines" element={<p>machines page</p>} />
            <Route
              path="/txe/machines/:machineId"
              element={<p>approval page</p>}
            />
          </Routes>
        </MemoryRouter>
      </TxeEnrolmentApiContext.Provider>
    </SWRConfig>
  );
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 50));

describe('awaitingApproval', () => {
  it('leaves out an application already enrolled, and an expired one', () => {
    const approved = application();
    const waiting = application({ subject: 'sub-carl' });
    const expired = application({
      subject: 'sub-dan',
      credential_expires: new Date(Date.now() - 1000).toISOString(),
    });

    expect(
      awaitingApproval([approved, waiting, expired], [enrolmentOf(approved)])
    ).toEqual([waiting]);
  });

  it('still counts an application whose enrolment is only pending or was revoked', () => {
    const a = application();

    expect(
      awaitingApproval([a], [enrolmentOf(a, TxeEnrolmentState.pending)])
    ).toEqual([a]);
    expect(
      awaitingApproval([a], [enrolmentOf(a, TxeEnrolmentState.revoked)])
    ).toEqual([a]);
  });
});

describe('the machines page', () => {
  it('says how many applications await approval on each machine', async () => {
    const fake = api({
      machines: [
        machine({ pending_applications: 1 }),
        machine({
          machine_id: 'mch_ada_desktop',
          display_name: 'ada-desktop',
          pending_applications: 0,
        }),
        machine({ machine_id: 'mch_ada_ci', display_name: 'ada-ci' }),
      ],
      applications: { mch_ada_laptop: [application()] },
    });
    renderAt(<TxeMachinesPage />, fake);

    const rows = await screen.findAllByTestId('txe-machine-row');
    expect(rows).toHaveLength(3);
    expect(
      await within(rows[0]!).findByText('1 awaiting approval')
    ).toBeInTheDocument();
    expect(within(rows[1]!).queryByText(/awaiting|on file/)).toBeNull();
    expect(within(rows[2]!).queryByText(/awaiting|on file/)).toBeNull();
    // Only the machine with a count is read further.
    expect(fake.listApplications).toHaveBeenCalledTimes(1);
    expect(fake.listApplications).toHaveBeenCalledWith('mch_ada_laptop');
  });

  // The hub keeps an approved application on file until its credential
  // expires, and counts it in pending_applications meanwhile.
  it('says nothing awaits approval when the application was already approved', async () => {
    const approved = application();
    const fake = api({
      machines: [machine({ pending_applications: 1 })],
      applications: { mch_ada_laptop: [approved] },
      enrolments: { mch_ada_laptop: [enrolmentOf(approved)] },
    });
    renderAt(<TxeMachinesPage />, fake);

    const row = await screen.findByTestId('txe-machine-row');
    await waitFor(() => expect(fake.listEnrolments).toHaveBeenCalled());
    await settle();
    expect(within(row).queryByText(/awaiting|pending|on file/)).toBeNull();
  });

  it('counts several applications awaiting approval', async () => {
    renderAt(
      <TxeMachinesPage />,
      api({
        machines: [machine({ pending_applications: 3 })],
        applications: {
          mch_ada_laptop: [
            application(),
            application({ subject: 'sub-carl' }),
            application({ client_id: 'dagu-reviewer' }),
          ],
        },
      })
    );

    expect(await screen.findByText('3 awaiting approval')).toBeInTheDocument();
  });

  it('says only how many are on file when they cannot be read', async () => {
    renderAt(
      <TxeMachinesPage />,
      api({
        machines: [machine({ pending_applications: 2 })],
        failDetails: true,
      })
    );

    expect(
      await screen.findByText('2 applications on file')
    ).toBeInTheDocument();
    expect(screen.queryByText(/awaiting/)).toBeNull();
  });

  // SWR keeps the previous counts when a refresh fails.
  it('says only how many are on file when a refresh fails after a positive count', async () => {
    const listApplications = vi
      .fn()
      .mockResolvedValueOnce([application()])
      .mockRejectedValue(new TxeRefusal(503, 'unavailable', undefined));
    const fake = api({ machines: [machine({ pending_applications: 1 })] });
    fake.listApplications = listApplications;
    renderAt(<TxeMachinesPage />, fake);

    expect(await screen.findByText('1 awaiting approval')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /refresh/i }));

    expect(
      await screen.findByText('1 application on file')
    ).toBeInTheDocument();
    expect(screen.queryByText(/awaiting/)).toBeNull();
  });

  // SWR's default comparison sees every two Maps as equal; counts must
  // update when only the enrolments change.
  it('updates the badge when an application is approved between reads', async () => {
    const waiting = application();
    const listEnrolments = vi
      .fn()
      .mockResolvedValueOnce([])
      .mockResolvedValue([enrolmentOf(waiting)]);
    const fake = api({
      machines: [machine({ pending_applications: 1 })],
      applications: { mch_ada_laptop: [waiting] },
    });
    fake.listEnrolments = listEnrolments;
    renderAt(<TxeMachinesPage />, fake);

    expect(await screen.findByText('1 awaiting approval')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /refresh/i }));

    await waitFor(() => expect(listEnrolments).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.queryByText(/awaiting/)).toBeNull());
  });

  it('falls back only for the machine whose reads failed', async () => {
    const fake = api({
      machines: [
        machine({ pending_applications: 1 }),
        machine({
          machine_id: 'mch_broken',
          display_name: 'broken',
          pending_applications: 2,
        }),
      ],
      applications: { mch_ada_laptop: [application()] },
    });
    const ok = fake.listApplications.getMockImplementation() as (
      id: string
    ) => Promise<EnrolmentApplication[]>;
    fake.listApplications.mockImplementation(async (id: string) => {
      if (id === 'mch_broken') throw new TxeRefusal(503, 'x', undefined);
      return ok(id);
    });
    renderAt(<TxeMachinesPage />, fake);

    const rows = await screen.findAllByTestId('txe-machine-row');
    expect(
      await within(rows[0]!).findByText('1 awaiting approval')
    ).toBeInTheDocument();
    expect(
      await within(rows[1]!).findByText('2 applications on file')
    ).toBeInTheDocument();
    expect(within(rows[1]!).queryByText(/awaiting/)).toBeNull();
  });

  it('opens the approval page of a machine', async () => {
    renderAt(<TxeMachinesPage />, api({ machines: [machine()] }));

    fireEvent.click(await screen.findByText('ada-laptop'));

    expect(await screen.findByText('approval page')).toBeInTheDocument();
  });

  // An unbound person, or one whose owner has no machines, gets none.
  it('gives the order a machine is registered and enrolled in when there is none', async () => {
    renderAt(<TxeMachinesPage />, api({ machines: [] }));

    const empty = await screen.findByTestId('txe-machines-empty');
    expect(empty).toHaveTextContent('the worker installer has registered it');
    expect(empty).toHaveTextContent('dagu txe enrol --client-id');
    expect(screen.queryByTestId('txe-machine-row')).toBeNull();
  });

  it('says the machines could not be read, and lists none', async () => {
    renderAt(
      <TxeMachinesPage />,
      api({
        machines: async () => {
          throw new TxeRefusal(
            503,
            'the owner store could not be read',
            undefined
          );
        },
      })
    );

    expect(
      await screen.findByText(
        'The machines could not be read: the owner store could not be read'
      )
    ).toBeInTheDocument();
    expect(screen.queryByTestId('txe-machine-row')).toBeNull();
    expect(screen.queryByTestId('txe-machines-empty')).toBeNull();
  });

  it('still reports a failed read globally', async () => {
    const onError = vi.fn();
    renderAt(
      <TxeMachinesPage />,
      api({
        machines: async () => {
          throw new TxeRefusal(503, 'unavailable', undefined);
        },
      }),
      onError
    );

    await waitFor(() => expect(onError).toHaveBeenCalled());
  });
});

describe('the pending enrolments notice', () => {
  it('points to the machines when applications await approval', async () => {
    renderAt(
      <PendingEnrolmentsNotice />,
      api({
        machines: [
          machine({ pending_applications: 1 }),
          machine({ machine_id: 'mch_2', pending_applications: 1 }),
        ],
        applications: {
          mch_ada_laptop: [application()],
          mch_2: [application({ machine_id: 'mch_2' })],
        },
      })
    );

    const notice = await screen.findByTestId('txe-pending-enrolments');
    expect(notice).toHaveTextContent(
      '2 machine enrolment applications are awaiting your approval.'
    );
    fireEvent.click(within(notice).getByText('Review machines'));
    expect(await screen.findByText('machines page')).toBeInTheDocument();
  });

  it('says one application awaits approval', async () => {
    renderAt(
      <PendingEnrolmentsNotice />,
      api({
        machines: [machine({ pending_applications: 1 })],
        applications: { mch_ada_laptop: [application()] },
      })
    );

    expect(
      await screen.findByText(
        'A machine enrolment application is awaiting your approval.'
      )
    ).toBeInTheDocument();
  });

  // The regression the TXE-4365 report found: an approved application the
  // hub still counts must not tell the person an approval is waiting.
  it('says nothing for an application already approved but not yet expired', async () => {
    const approved = application();
    const fake = api({
      machines: [machine({ pending_applications: 1 })],
      applications: { mch_ada_laptop: [approved] },
      enrolments: { mch_ada_laptop: [enrolmentOf(approved)] },
    });
    renderAt(<PendingEnrolmentsNotice />, fake);

    await waitFor(() => expect(fake.listEnrolments).toHaveBeenCalled());
    await settle();
    expect(screen.queryByTestId('txe-pending-enrolments')).toBeNull();
  });

  it.each<[string, Fake]>([
    ['no machine', { machines: [] }],
    ['no count', { machines: [machine()] }],
    ['a count of 0', { machines: [machine({ pending_applications: 0 })] }],
    [
      'a failed list',
      {
        machines: async () => {
          throw new TxeRefusal(503, 'unavailable', undefined);
        },
      },
    ],
    [
      'failed application reads',
      { machines: [machine({ pending_applications: 1 })], failDetails: true },
    ],
  ])('shows nothing with %s', async (_, fake) => {
    renderAt(<PendingEnrolmentsNotice />, api(fake));

    await settle();
    expect(screen.queryByTestId('txe-pending-enrolments')).toBeNull();
  });

  it('asks nothing further for machines without a count', async () => {
    const fake = api({ machines: [machine(), machine({ machine_id: 'm2' })] });
    renderAt(<PendingEnrolmentsNotice />, fake);

    await settle();
    expect(fake.listApplications).not.toHaveBeenCalled();
    expect(fake.listEnrolments).not.toHaveBeenCalled();
  });

  // SWR keeps the last good data when a refresh fails.
  it('hides the notice when a refresh fails after a positive count', async () => {
    const listMachines = vi
      .fn()
      .mockResolvedValueOnce([machine({ pending_applications: 1 })])
      .mockRejectedValue(new TxeRefusal(503, 'unavailable', undefined));
    const fake = api({
      machines: listMachines,
      applications: { mch_ada_laptop: [application()] },
    });
    function Revalidate() {
      const { mutate } = useSWRConfig();
      return (
        <button onClick={() => void mutate(['txe', 'machines'])}>
          revalidate
        </button>
      );
    }
    renderAt(
      <>
        <PendingEnrolmentsNotice />
        <Revalidate />
      </>,
      fake
    );

    expect(
      await screen.findByTestId('txe-pending-enrolments')
    ).toBeInTheDocument();
    fireEvent.click(screen.getByText('revalidate'));

    await waitFor(() => expect(listMachines).toHaveBeenCalledTimes(2));
    await waitFor(() =>
      expect(screen.queryByTestId('txe-pending-enrolments')).toBeNull()
    );
  });

  it('updates the notice when the enrolments change between reads', async () => {
    const first = application();
    // First read: approved. Second read: revoked, so it awaits approval again.
    const listEnrolments = vi
      .fn()
      .mockResolvedValueOnce([enrolmentOf(first)])
      .mockResolvedValue([enrolmentOf(first, TxeEnrolmentState.revoked)]);
    const fake = api({
      machines: [machine({ pending_applications: 1 })],
      applications: { mch_ada_laptop: [first] },
    });
    fake.listEnrolments = listEnrolments;
    function Revalidate() {
      const { mutate } = useSWRConfig();
      return (
        <button
          onClick={() =>
            void mutate(['txe', 'awaiting-approval', 'mch_ada_laptop'])
          }
        >
          revalidate
        </button>
      );
    }
    renderAt(
      <>
        <PendingEnrolmentsNotice />
        <Revalidate />
      </>,
      fake
    );

    await waitFor(() => expect(listEnrolments).toHaveBeenCalledTimes(1));
    await settle();
    expect(screen.queryByTestId('txe-pending-enrolments')).toBeNull();
    fireEvent.click(screen.getByText('revalidate'));

    expect(
      await screen.findByTestId('txe-pending-enrolments')
    ).toBeInTheDocument();
  });

  it("still counts the machines whose reads succeeded when another's fail", async () => {
    const fake = api({
      machines: [
        machine({ pending_applications: 1 }),
        machine({ machine_id: 'mch_broken', pending_applications: 1 }),
      ],
      applications: { mch_ada_laptop: [application()] },
    });
    const ok = fake.listEnrolments.getMockImplementation() as (
      id: string
    ) => Promise<Enrolment[]>;
    fake.listEnrolments.mockImplementation(async (id: string) => {
      if (id === 'mch_broken') throw new TxeRefusal(503, 'x', undefined);
      return ok(id);
    });
    renderAt(<PendingEnrolmentsNotice />, fake);

    expect(
      await screen.findByText(
        'A machine enrolment application is awaiting your approval.'
      )
    ).toBeInTheDocument();
  });

  it('keeps a failed read out of the global error notices', async () => {
    const onError = vi.fn();
    renderAt(
      <PendingEnrolmentsNotice />,
      api({
        machines: [machine({ pending_applications: 1 })],
        failDetails: true,
      }),
      onError
    );

    await settle();
    expect(onError).not.toHaveBeenCalled();
  });
});
