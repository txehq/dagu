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

import { PendingEnrolmentsNotice } from '@/features/txe/components/PendingEnrolmentsNotice';
import {
  TxeRefusal,
  type MachineSummary,
  type TxeEnrolmentApi,
} from '@/features/txe/enrolment';
import { pendingCount, TxeEnrolmentApiContext } from '@/features/txe/hooks';

import TxeMachinesPage from '../machines';

vi.mock('@/hooks/api', () => ({
  useClient: () => ({}),
}));

function machine(overrides: Partial<MachineSummary> = {}): MachineSummary {
  return {
    machine_id: 'mch_ada_laptop',
    owner_id: 'own_ada',
    display_name: 'ada-laptop',
    ...overrides,
  };
}

function api(listMachines: TxeEnrolmentApi['listMachines']): TxeEnrolmentApi {
  return { listMachines } as unknown as TxeEnrolmentApi;
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

describe('pendingCount', () => {
  it('adds only the counts the hub reported', () => {
    expect(pendingCount(undefined)).toBe(0);
    expect(
      pendingCount([
        machine({ pending_applications: 2 }),
        machine({ pending_applications: 0 }),
        machine(),
      ])
    ).toBe(2);
  });
});

describe('the machines page', () => {
  it('lists each machine the hub returns, with its pending applications', async () => {
    renderAt(
      <TxeMachinesPage />,
      api(async () => [
        machine({ pending_applications: 1 }),
        machine({
          machine_id: 'mch_ada_desktop',
          display_name: 'ada-desktop',
          pending_applications: 0,
        }),
        machine({ machine_id: 'mch_ada_ci', display_name: 'ada-ci' }),
      ])
    );

    const rows = await screen.findAllByTestId('txe-machine-row');
    expect(rows).toHaveLength(3);
    expect(within(rows[0]!).getByText('ada-laptop')).toBeInTheDocument();
    expect(
      within(rows[0]!).getByText('1 pending application')
    ).toBeInTheDocument();
    // A count of 0, or no count at all, is not shown as waiting.
    expect(within(rows[1]!).queryByText(/pending/)).toBeNull();
    expect(within(rows[2]!).queryByText(/pending/)).toBeNull();
  });

  it('counts several pending applications', async () => {
    renderAt(
      <TxeMachinesPage />,
      api(async () => [machine({ pending_applications: 3 })])
    );

    expect(
      await screen.findByText('3 pending applications')
    ).toBeInTheDocument();
  });

  it('opens the approval page of a machine', async () => {
    renderAt(
      <TxeMachinesPage />,
      api(async () => [machine()])
    );

    fireEvent.click(await screen.findByText('ada-laptop'));

    expect(await screen.findByText('approval page')).toBeInTheDocument();
  });

  // An unbound person, or one whose owner has no machines, gets none.
  it('says how to enrol a machine when there is none', async () => {
    renderAt(
      <TxeMachinesPage />,
      api(async () => [])
    );

    expect(await screen.findByTestId('txe-machines-empty')).toHaveTextContent(
      'dagu txe enrol'
    );
    expect(screen.queryByTestId('txe-machine-row')).toBeNull();
  });

  it('says the machines could not be read, and lists none', async () => {
    renderAt(
      <TxeMachinesPage />,
      api(async () => {
        throw new TxeRefusal(
          503,
          'the owner store could not be read',
          undefined
        );
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
});

describe('the pending enrolments notice', () => {
  it('points to the machines when applications wait', async () => {
    renderAt(
      <PendingEnrolmentsNotice />,
      api(async () => [
        machine({ pending_applications: 1 }),
        machine({ machine_id: 'mch_2', pending_applications: 1 }),
      ])
    );

    const notice = await screen.findByTestId('txe-pending-enrolments');
    expect(notice).toHaveTextContent(
      '2 machine applications are waiting for enrolment approval.'
    );
    fireEvent.click(within(notice).getByText('Review machines'));
    expect(await screen.findByText('machines page')).toBeInTheDocument();
  });

  it('says one machine waits', async () => {
    renderAt(
      <PendingEnrolmentsNotice />,
      api(async () => [machine({ pending_applications: 1 })])
    );

    expect(
      await screen.findByText('A machine is waiting for enrolment approval.')
    ).toBeInTheDocument();
  });

  it.each([
    ['no machine', async () => []],
    ['no count', async () => [machine()]],
    ['a count of 0', async () => [machine({ pending_applications: 0 })]],
    [
      'a failed read',
      async () => {
        throw new TxeRefusal(503, 'unavailable', undefined);
      },
    ],
  ] as [string, TxeEnrolmentApi['listMachines']][])(
    'shows nothing with %s',
    async (_, listMachines) => {
      renderAt(<PendingEnrolmentsNotice />, api(listMachines));

      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(screen.queryByTestId('txe-pending-enrolments')).toBeNull();
    }
  );

  // SWR keeps the last good list when a refresh fails.
  it('hides the notice when a refresh fails after a positive count', async () => {
    const listMachines = vi
      .fn()
      .mockResolvedValueOnce([machine({ pending_applications: 1 })])
      .mockRejectedValue(new TxeRefusal(503, 'unavailable', undefined));
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
      api(listMachines)
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

  it('keeps a failed read out of the global error notices', async () => {
    const onError = vi.fn();
    renderAt(
      <PendingEnrolmentsNotice />,
      api(async () => {
        throw new TxeRefusal(503, 'unavailable', undefined);
      }),
      onError
    );

    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(onError).not.toHaveBeenCalled();
  });

  it('still reports a failed read on the machines page', async () => {
    const onError = vi.fn();
    renderAt(
      <TxeMachinesPage />,
      api(async () => {
        throw new TxeRefusal(503, 'unavailable', undefined);
      }),
      onError
    );

    await waitFor(() => expect(onError).toHaveBeenCalled());
  });
});
