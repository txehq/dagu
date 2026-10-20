// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { renderHook, waitFor } from '@testing-library/react';
import React from 'react';
import { SWRConfig } from 'swr';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  TxeAccessPermission,
  TxeIdentityAuthz_mode,
  TxeIdentityPrincipalClass,
  TxeJobAccessVia,
} from '@/api/v1/schema';

import { useJobRunAllowed } from '../runAccess';

const JOB = 'job_01M4XEETKWKZX504BK65ADBVYB';
const mode = vi.hoisted(() => ({ current: 'enforce' as string | undefined }));
const principal = vi.hoisted(() => ({ current: 'platform_admin' }));
const GET = vi.fn();

vi.mock('@/hooks/api', () => ({
  useClient: () => ({ GET }),
}));

vi.mock('../identity', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../identity')>()),
  useTxeIdentity: () => ({
    identity: mode.current
      ? { authz_mode: mode.current, principal: { class: principal.current } }
      : undefined,
  }),
}));

function wrapper({ children }: { children: React.ReactNode }) {
  return (
    <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
      {children}
    </SWRConfig>
  );
}

function answer(permissions: TxeAccessPermission[], via: TxeJobAccessVia) {
  GET.mockResolvedValue({
    data: { job_id: JOB, access: { via, permissions } },
  });
}

beforeEach(() => {
  GET.mockReset();
  mode.current = TxeIdentityAuthz_mode.enforce;
  principal.current = TxeIdentityPrincipalClass.platform_admin;
});

describe('useJobRunAllowed', () => {
  it("lets the job's owner run it", async () => {
    answer(
      [
        TxeAccessPermission.view,
        TxeAccessPermission.author,
        TxeAccessPermission.execute,
      ],
      TxeJobAccessVia.owner
    );
    const { result } = renderHook(() => useJobRunAllowed(JOB), { wrapper });

    await waitFor(() => expect(result.current).toBe(true));
    expect(GET).toHaveBeenCalledWith('/txe/jobs/{jobId}', {
      params: { path: { jobId: JOB } },
    });
  });

  it.each([
    ['a view-only share', TxeJobAccessVia.share],
    ['the platform administrator', TxeJobAccessVia.platform_admin],
  ])('does not let %s run it', async (_who, via) => {
    answer([TxeAccessPermission.view], via);
    const { result } = renderHook(() => useJobRunAllowed(JOB), { wrapper });

    await waitFor(() => expect(result.current).toBe(false));
  });

  // The hub decides a person by owner in every mode: a view-only share is
  // refused in off and observe too.
  it.each([TxeIdentityAuthz_mode.observe, TxeIdentityAuthz_mode.off])(
    'does not let a person with a view-only share run it in mode %s',
    async (m) => {
      mode.current = m;
      principal.current = TxeIdentityPrincipalClass.person;
      answer([TxeAccessPermission.view], TxeJobAccessVia.share);
      const { result } = renderHook(() => useJobRunAllowed(JOB), { wrapper });

      await waitFor(() => expect(result.current).toBe(false));
    }
  );

  // Any other caller is held to the answer only in enforce: in observe the hub
  // lets the action through, though access is decided as enforce would.
  it.each([
    TxeIdentityAuthz_mode.observe,
    TxeIdentityAuthz_mode.off,
    undefined,
  ])('says nothing to the platform administrator in mode %s', async (m) => {
    mode.current = m;
    answer([TxeAccessPermission.view], TxeJobAccessVia.share);
    const { result } = renderHook(() => useJobRunAllowed(JOB), { wrapper });

    await new Promise((r) => setTimeout(r, 20));
    expect(result.current).toBeUndefined();
    expect(GET).not.toHaveBeenCalled();
  });

  it("says nothing for a DAG that is not a job's", async () => {
    const { result } = renderHook(() => useJobRunAllowed('example-dag'), {
      wrapper,
    });

    await new Promise((r) => setTimeout(r, 20));
    expect(result.current).toBeUndefined();
    expect(GET).not.toHaveBeenCalled();
  });

  it('says nothing when the job cannot be read', async () => {
    GET.mockResolvedValue({ error: { message: 'unavailable' } });
    const { result } = renderHook(() => useJobRunAllowed(JOB), { wrapper });

    await waitFor(() => expect(GET).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 20));
    expect(result.current).toBeUndefined();
  });

  it('says nothing when the read fails outright', async () => {
    GET.mockRejectedValue(new Error('network'));
    const { result } = renderHook(() => useJobRunAllowed(JOB), { wrapper });

    await waitFor(() => expect(GET).toHaveBeenCalled());
    await new Promise((r) => setTimeout(r, 20));
    expect(result.current).toBeUndefined();
  });
});
