// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import useSWR from 'swr';

import { TxeAccessPermission, TxeIdentityAuthz_mode } from '@/api/v1/schema';
import { useClient } from '@/hooks/api';
import { I18nText } from '@/i18n/I18nText';
import { useI18n } from '@/i18n/I18nProvider';

import { useTxeIdentity } from './identity';

// A job's DAG is named by its job id.
const JOB_DAG_NAME = /^job_[0-9A-Z]{26}$/;

// useJobRunAllowed is whether the hub lets the caller run, stop and retry the
// job DAG `name`. It is false only when the hub enforces owner authorization
// and its own answer for the job (GET /txe/jobs/{id} access) does not grant
// execute. Otherwise it is undefined and a page offers its controls as before:
// in off and observe the hub lets the action through, a DAG that is not a
// job's has no such answer, and a failed read says nothing. Display only; the
// hub decides every action.
export function useJobRunAllowed(
  name: string | undefined
): boolean | undefined {
  const { identity } = useTxeIdentity();
  const client = useClient();
  const enforced = identity?.authz_mode === TxeIdentityAuthz_mode.enforce;
  const jobId = name && JOB_DAG_NAME.test(name) ? name : undefined;
  const { data } = useSWR(
    enforced && jobId ? ['txe', 'job-access', jobId] : null,
    async () => {
      const res = await client.GET('/txe/jobs/{jobId}', {
        params: { path: { jobId: jobId as string } },
      });
      return res.data?.access ?? null;
    },
    { onError: () => undefined, shouldRetryOnError: false }
  );
  if (!enforced || !data) return undefined;
  return data.permissions.includes(TxeAccessPermission.execute);
}

// ViewOnly stands in for the run controls of a job the caller may only view.
export function ViewOnly(): React.ReactElement {
  const { ts } = useI18n();
  return (
    <span
      data-testid="txe-view-only"
      className="text-xs text-muted-foreground"
      title={ts('The hub does not let you run, stop or retry this job.')}
    >
      <I18nText text="View only" />
    </span>
  );
}
