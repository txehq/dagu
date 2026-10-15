// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { describe, expect, it, vi } from 'vitest';

import { TxeEnrolmentApplicationClass } from '@/api/v1/schema';

import { createTxeEnrolmentApi, TxeRefusal } from '../enrolment';

const application = {
  machine_id: 'mch_1',
  class: TxeEnrolmentApplicationClass.worker,
  issuer: 'https://idp.example/realms/r',
  subject: 'sub-1',
  client_id: 'dagu-worker',
  received_at: '2026-10-15T00:00:00Z',
  credential_expires: '2026-10-15T00:05:00Z',
};

describe('createTxeEnrolmentApi', () => {
  it('approves with only the class, client and identity read on the application', async () => {
    const POST = vi.fn(async () => ({
      data: { machine_id: 'mch_1' },
      response: new Response(),
    }));
    const api = createTxeEnrolmentApi({ POST } as never);

    await api.enrol(application);

    expect(POST).toHaveBeenCalledWith('/txe/machines/{machineId}/enrolments', {
      params: { path: { machineId: 'mch_1' } },
      body: {
        class: 'worker',
        client_id: 'dagu-worker',
        issuer: 'https://idp.example/realms/r',
        subject: 'sub-1',
      },
    });
  });

  it.each([
    [409, 'conflict'],
    [409, 'credential_stale'],
    [403, 'unbound'],
    [403, 'forbidden'],
    [404, 'not_found'],
  ])('keeps the hub status %i and reason %s', async (status, code) => {
    const POST = vi.fn(async () => ({
      error: { code: 'x', message: 'refused', details: { code } },
      response: new Response(null, { status }),
    }));
    const api = createTxeEnrolmentApi({ POST } as never);

    const err = await api.enrol(application).catch((e: unknown) => e);

    expect(err).toBeInstanceOf(TxeRefusal);
    expect(err).toMatchObject({ status, code, message: 'refused' });
  });

  it('revokes one class with a reason', async () => {
    const POST = vi.fn(async () => ({
      data: { state: 'revoked' },
      response: new Response(),
    }));
    const api = createTxeEnrolmentApi({ POST } as never);

    await api.revokeEnrolment('mch_1', 'reviewer', 'retired');

    expect(POST).toHaveBeenCalledWith(
      '/txe/machines/{machineId}/enrolments/{class}/revoke',
      {
        params: { path: { machineId: 'mch_1', class: 'reviewer' } },
        body: { reason: 'retired' },
      }
    );
  });
});
