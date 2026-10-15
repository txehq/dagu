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
import { SWRConfig } from 'swr';
import { describe, expect, it, vi } from 'vitest';

import {
  TxeEnrolmentApplicationClass,
  TxeEnrolmentClass,
  TxeEnrolmentState,
} from '@/api/v1/schema';
import {
  TxeRefusal,
  type Enrolment,
  type EnrolmentApplication,
  type TxeEnrolmentApi,
} from '@/features/txe/enrolment';
import { TxeEnrolmentApiContext } from '@/features/txe/hooks';

import TxeMachinePage from '../machine';

vi.mock('@/hooks/api', () => ({
  useClient: () => ({}),
}));

const MACHINE = 'mch_01TESTMACHINE';
const HOUR = 3_600_000;

function application(
  overrides: Partial<EnrolmentApplication> = {}
): EnrolmentApplication {
  return {
    machine_id: MACHINE,
    class: TxeEnrolmentApplicationClass.worker,
    issuer: 'http://127.0.0.1:18647/realms/synthetic',
    subject: 'sub-ada',
    client_id: 'dagu-worker',
    received_at: new Date(Date.now() - 60_000).toISOString(),
    credential_expires: new Date(Date.now() + HOUR).toISOString(),
    ...overrides,
  };
}

function enrolment(overrides: Partial<Enrolment> = {}): Enrolment {
  return {
    machine_id: MACHINE,
    class: TxeEnrolmentClass.worker,
    owner_id: 'own_ada',
    issuer: 'http://127.0.0.1:18647/realms/synthetic',
    subject: 'sub-ada',
    client_id: 'dagu-worker',
    generation: 1,
    state: TxeEnrolmentState.active,
    enrolled: { at: new Date().toISOString(), by: 'ada' } as never,
    ...overrides,
  };
}

function enrolmentApi(
  overrides: Partial<TxeEnrolmentApi> = {}
): TxeEnrolmentApi {
  return {
    getMachine: vi.fn(async () => ({
      schema: 1,
      machine_id: MACHINE,
      owner_id: 'own_ada',
      display_name: 'ada-laptop',
      created: { at: new Date().toISOString() } as never,
    })),
    listApplications: vi.fn(async () => [application()]),
    enrol: vi.fn(async () => enrolment()),
    listEnrolments: vi.fn(async () => []),
    revokeEnrolment: vi.fn(async () =>
      enrolment({ state: TxeEnrolmentState.revoked })
    ),
    ...overrides,
  };
}

function renderPage(api: TxeEnrolmentApi, query = '') {
  return render(
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      <TxeEnrolmentApiContext.Provider value={api}>
        <MemoryRouter initialEntries={[`/txe/machines/${MACHINE}${query}`]}>
          <Routes>
            <Route
              path="/txe/machines/:machineId"
              element={<TxeMachinePage />}
            />
          </Routes>
        </MemoryRouter>
      </TxeEnrolmentApiContext.Provider>
    </SWRConfig>
  );
}

describe('the machine enrolment page', () => {
  it('shows the identity an application signed in with, and nothing secret', async () => {
    renderPage(enrolmentApi());

    const row = await screen.findByTestId('txe-enrolment-application');
    expect(screen.getByText('ada-laptop')).toBeInTheDocument();
    expect(within(row).getByText('worker')).toBeInTheDocument();
    expect(within(row).getByText('dagu-worker')).toBeInTheDocument();
    expect(
      within(row).getByText('http://127.0.0.1:18647/realms/synthetic')
    ).toBeInTheDocument();
    expect(within(row).getByText('sub-ada')).toBeInTheDocument();
    // An application carries no credential, and the page offers nothing to
    // copy back to the machine.
    expect(document.body.textContent).not.toMatch(/token|secret|password/i);
    expect(screen.queryByRole('button', { name: /copy/i })).toBeNull();
  });

  it('approves with exactly the identity that was read, after confirming', async () => {
    const api = enrolmentApi();
    renderPage(api);

    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    expect(api.enrol).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Confirm approval' }));

    await waitFor(() => expect(api.enrol).toHaveBeenCalledTimes(1));
    expect(api.enrol).toHaveBeenCalledWith(
      expect.objectContaining({
        machine_id: MACHINE,
        class: 'worker',
        client_id: 'dagu-worker',
        issuer: 'http://127.0.0.1:18647/realms/synthetic',
        subject: 'sub-ada',
      })
    );
    // The page reads the machine again after approving.
    await waitFor(() => expect(api.listEnrolments).toHaveBeenCalledTimes(2));
  });

  // The hub answers conflict for three different things, and its message is
  // the recovery: read again, revoke the class's enrolment first, or use a
  // client of the machine's own.
  it.each([
    'the application on file is not the one you read; read it again',
    'the machine is already enrolled for this class, or being enrolled, with another credential; revoke that enrolment first',
    "this credential's client already belongs to another machine or class; it is not reassigned. Each machine and class needs a provider client of its own",
  ])('shows the hub conflict as it says it: %s', async (message) => {
    const api = enrolmentApi({
      enrol: vi.fn(async () => {
        throw new TxeRefusal(409, message, 'conflict');
      }),
    });
    renderPage(api);

    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm approval' }));

    expect(
      await screen.findByText(
        `Not approved: ${message}. The machine's applications and enrolments have been read again.`
      )
    ).toBeInTheDocument();
    await waitFor(() => expect(api.listApplications).toHaveBeenCalledTimes(2));
  });

  // The machine re-applies while it waits, renewing its credential under the
  // same identity: an expiry while confirming must not block approval.
  it('approves the renewed credential of the identity that was read', async () => {
    const renewed = application({
      received_at: new Date().toISOString(),
      credential_expires: new Date(Date.now() + HOUR).toISOString(),
    });
    const listApplications = vi
      .fn()
      .mockResolvedValueOnce([
        application({
          credential_expires: new Date(Date.now() + 300).toISOString(),
        }),
      ])
      .mockResolvedValue([renewed]);
    const api = enrolmentApi({ listApplications });
    renderPage(api);

    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    await new Promise((resolve) => setTimeout(resolve, 500));
    fireEvent.click(screen.getByRole('button', { name: /refresh/i }));
    await waitFor(() => expect(listApplications).toHaveBeenCalledTimes(2));

    const confirm = await screen
      .findByRole('button', { name: 'Confirm approval' })
      .catch(async () => {
        fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
        return screen.getByRole('button', { name: 'Confirm approval' });
      });
    fireEvent.click(confirm);

    await waitFor(() =>
      expect(api.enrol).toHaveBeenCalledWith(
        expect.objectContaining({
          subject: 'sub-ada',
          credential_expires: renewed.credential_expires,
        })
      )
    );
  });

  it('closes an open confirmation whose credential expired, and keeps it closable', async () => {
    renderPage(
      enrolmentApi({
        listApplications: vi.fn(async () => [
          application({
            credential_expires: new Date(Date.now() + 300).toISOString(),
          }),
        ]),
      })
    );

    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    // No refresh: the row notices the expiry by itself.

    expect(
      await screen.findByText(/This application's credential has expired/)
    ).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Confirm approval' })
    ).toBeNull();
  });

  // Seen on the live hub: a machine applied again with another person's
  // sign-in while the confirmation was open, and the refreshed list would
  // have been approved instead of the one that was read.
  it('never approves an application that changed while confirming', async () => {
    const listApplications = vi
      .fn()
      .mockResolvedValueOnce([application()])
      .mockResolvedValue([application({ subject: 'sub-carl' })]);
    const api = enrolmentApi({ listApplications });
    renderPage(api);

    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    expect(
      screen.getByRole('button', { name: 'Confirm approval' })
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: /refresh/i }));

    expect(
      await screen.findByText(/applied again with another identity/)
    ).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Confirm approval' })
    ).toBeNull();
    expect(screen.getByText('sub-carl')).toBeInTheDocument();
    expect(api.enrol).not.toHaveBeenCalled();
  });

  it('sends the identity read at confirmation, not a later refresh of it', async () => {
    const listApplications = vi
      .fn()
      .mockResolvedValueOnce([application()])
      .mockResolvedValue([
        application({ received_at: new Date().toISOString() }),
      ]);
    const api = enrolmentApi({ listApplications });
    renderPage(api);

    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    fireEvent.click(screen.getByRole('button', { name: /refresh/i }));
    await waitFor(() => expect(listApplications).toHaveBeenCalledTimes(2));
    // The same identity applying again keeps the confirmation open.
    fireEvent.click(screen.getByRole('button', { name: 'Confirm approval' }));

    await waitFor(() =>
      expect(api.enrol).toHaveBeenCalledWith(
        expect.objectContaining({ subject: 'sub-ada' })
      )
    );
  });

  it('shows an application already enrolled as approved, with nothing to approve', async () => {
    renderPage(
      enrolmentApi({
        listEnrolments: vi.fn(async () => [enrolment({ generation: 3 })]),
      })
    );

    expect(
      await screen.findByText('Approved: enrolled as generation 3.')
    ).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve' })).toBeNull();
  });

  it('offers approval again once that enrolment is revoked', async () => {
    renderPage(
      enrolmentApi({
        listEnrolments: vi.fn(async () => [
          enrolment({ state: TxeEnrolmentState.revoked }),
        ]),
      })
    );

    expect(
      await screen.findByRole('button', { name: 'Approve' })
    ).toBeInTheDocument();
  });

  it('says the machine must apply again when its credential went stale', async () => {
    const api = enrolmentApi({
      enrol: vi.fn(async () => {
        throw new TxeRefusal(409, 'expired', 'credential_stale');
      }),
    });
    renderPage(api);

    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm approval' }));

    expect(
      await screen.findByText(/dagu txe enrol --resume/)
    ).toBeInTheDocument();
  });

  it('offers no approval for an application whose credential has expired', async () => {
    renderPage(
      enrolmentApi({
        listApplications: vi.fn(async () => [
          application({
            credential_expires: new Date(Date.now() - 1000).toISOString(),
          }),
        ]),
      })
    );

    await screen.findByTestId('txe-enrolment-application');
    expect(screen.queryByRole('button', { name: 'Approve' })).toBeNull();
    expect(screen.getByText(/before approving\./)).toBeInTheDocument();
  });

  it('shows the hub refusal of an approval as it is', async () => {
    renderPage(
      enrolmentApi({
        enrol: vi.fn(async () => {
          throw new TxeRefusal(
            403,
            'only a person acting for the owner may do this',
            'forbidden'
          );
        }),
      })
    );

    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm approval' }));

    expect(
      await screen.findByText(
        'Not approved: only a person acting for the owner may do this'
      )
    ).toBeInTheDocument();
  });

  // The hub gives the same 404 for another owner's machine as for one that
  // does not exist.
  it('says only that the machine is not found on a 404', async () => {
    renderPage(
      enrolmentApi({
        getMachine: vi.fn(async () => {
          throw new TxeRefusal(404, 'not found', 'not_found');
        }),
      })
    );

    expect(await screen.findByText('Machine not found')).toBeInTheDocument();
    expect(
      screen.getByText(/does not exist, or it is not one of your owner's/)
    ).toBeInTheDocument();
    expect(screen.queryByTestId('txe-enrolment-application')).toBeNull();
  });

  it('sends an unbound caller to ask for access', async () => {
    renderPage(
      enrolmentApi({
        getMachine: vi.fn(async () => {
          throw new TxeRefusal(403, 'acts for no owner', 'unbound');
        }),
      })
    );

    expect(
      await screen.findByText('You act for no owner yet. Ask for access first.')
    ).toBeInTheDocument();
  });

  it('keeps the enrolments when the applications are refused', async () => {
    renderPage(
      enrolmentApi({
        listApplications: vi.fn(async () => {
          throw new TxeRefusal(404, 'not found', 'not_found');
        }),
        listEnrolments: vi.fn(async () => [enrolment()]),
      })
    );

    expect(
      await screen.findByText(/can see and approve its applications/)
    ).toBeInTheDocument();
    expect(await screen.findByTestId('txe-enrolment')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Approve' })).toBeNull();
  });

  it('revokes an enrolment only with a reason', async () => {
    const api = enrolmentApi({
      listEnrolments: vi.fn(async () => [enrolment()]),
    });
    renderPage(api);

    const row = await screen.findByTestId('txe-enrolment');
    fireEvent.click(within(row).getByRole('button', { name: 'Revoke' }));
    const confirm = within(row).getByRole('button', { name: 'Confirm revoke' });
    expect(confirm).toBeDisabled();
    fireEvent.change(within(row).getByLabelText('Reason'), {
      target: { value: 'laptop retired' },
    });
    fireEvent.click(confirm);

    await waitFor(() =>
      expect(api.revokeEnrolment).toHaveBeenCalledWith(
        MACHINE,
        'worker',
        'laptop retired'
      )
    );
  });

  // A pending enrolment is a reservation an interrupted approval left; it
  // blocks another credential until it is revoked.
  it('revokes a pending enrolment too', async () => {
    const api = enrolmentApi({
      listEnrolments: vi.fn(async () => [
        enrolment({ state: TxeEnrolmentState.pending }),
      ]),
    });
    renderPage(api);

    const row = await screen.findByTestId('txe-enrolment');
    fireEvent.click(within(row).getByRole('button', { name: 'Revoke' }));
    fireEvent.change(within(row).getByLabelText('Reason'), {
      target: { value: 'interrupted approval' },
    });
    fireEvent.click(
      within(row).getByRole('button', { name: 'Confirm revoke' })
    );

    await waitFor(() =>
      expect(api.revokeEnrolment).toHaveBeenCalledWith(
        MACHINE,
        'worker',
        'interrupted approval'
      )
    );
  });

  it('offers no revoke for a revoked enrolment', async () => {
    renderPage(
      enrolmentApi({
        listEnrolments: vi.fn(async () => [
          enrolment({ state: TxeEnrolmentState.revoked }),
        ]),
      })
    );

    const row = await screen.findByTestId('txe-enrolment');
    expect(within(row).queryByRole('button', { name: 'Revoke' })).toBeNull();
  });

  it('marks the application the link names', async () => {
    renderPage(
      enrolmentApi({
        listApplications: vi.fn(async () => [
          application(),
          application({
            class: TxeEnrolmentApplicationClass.reviewer,
            client_id: 'dagu-reviewer',
          }),
        ]),
      }),
      '?class=reviewer&client_id=dagu-reviewer'
    );

    await waitFor(() =>
      expect(screen.getAllByTestId('txe-enrolment-application')).toHaveLength(2)
    );
    const [worker, reviewer] = screen.getAllByTestId(
      'txe-enrolment-application'
    );
    expect(worker).not.toHaveClass('border-primary');
    expect(reviewer).toHaveClass('border-primary');
  });
});
