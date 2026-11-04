// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import useSWR from 'swr';

import {
  TxeAccessPermission,
  TxeIdentityAuthz_mode,
  TxeJobAccessVia,
} from '@/api/v1/schema';
import { useClient } from '@/hooks/api';
import { I18nText } from '@/i18n/I18nText';
import { useI18n } from '@/i18n/I18nProvider';

import { isTxePerson, useTxeIdentity } from './identity';

// How often the job's access is read again while a page is open.
export const ACCESS_REFRESH_MS = 10_000;

// A job's DAG is named by its job id.
const JOB_DAG_NAME = /^job_[0-9A-Z]{26}$/;

// The hub's answer for a job, as the dashboard reads it: how the caller
// reaches the job and with which permissions. A 404 is an answer with no
// permissions; a job with no label is null.
type JobAccessAnswer = {
  via?: TxeJobAccessVia;
  permissions: string[];
};

// useJobAccessAnswer reads the hub's own answer for the job DAG `name`
// (GET /txe/jobs/{id} access) when that answer binds the caller: always for
// a person signed in through the identity provider, whom the hub decides by
// owner in every mode, and for any other caller only in enforce (in observe
// the hub lets them through, in off it gives no answer). It is undefined
// when the answer does not bind the caller, the DAG is not a job's, the hub
// has not answered yet, or the job carries no label; a failed read keeps the
// last answer.
function useJobAccessAnswer(
  name: string | undefined
): JobAccessAnswer | undefined {
  const { identity } = useTxeIdentity();
  const client = useClient();
  const binding =
    identity?.authz_mode === TxeIdentityAuthz_mode.enforce ||
    isTxePerson(identity);
  const jobId = name && JOB_DAG_NAME.test(name) ? name : undefined;
  const { data } = useSWR<JobAccessAnswer | null>(
    binding && jobId ? ['txe', 'job-access', jobId] : null,
    async () => {
      const res = await client.GET('/txe/jobs/{jobId}', {
        params: { path: { jobId: jobId as string } },
      });
      // A failed read keeps the last answer (SWR keeps data on a throw), so a
      // passing error never brings back controls the hub refused.
      // The hub's 404 is definitive: the job is gone or no longer shared,
      // so nothing may be run from it.
      if (res.response?.status === 404) {
        return { permissions: [] as string[] };
      }
      if (res.error || !res.data) {
        throw new Error('job access could not be read');
      }
      return res.data.access ?? null;
    },
    // A share can change while the page is open: read it again, as the
    // other TXE pages do.
    {
      onError: () => undefined,
      // A failed read keeps the last answer and is tried again, so polling
      // goes on once the hub answers.
      shouldRetryOnError: true,
      errorRetryInterval: ACCESS_REFRESH_MS,
      refreshInterval: ACCESS_REFRESH_MS,
    }
  );
  if (!binding || !data) return undefined;
  return data;
}

// useJobRunAllowed is whether the hub lets the caller run, stop and retry the
// job DAG `name`. It is false only when the hub's binding answer for the job
// does not grant execute. Otherwise it is undefined and a page offers its
// controls as before. Display only; the hub decides every action.
export function useJobRunAllowed(
  name: string | undefined
): boolean | undefined {
  const access = useJobAccessAnswer(name);
  if (!access) return undefined;
  return access.permissions.includes(TxeAccessPermission.execute);
}

// useJobProfileHeld is whether the hub holds the caller to the job DAG's own
// runtime profile: a caller the hub's binding answer labels as reaching the
// job as its owner or through a share runs it as that owner's person, and a
// person names no profile (TXE-4704; a bound administrator on its owner's
// DAG, TXE-4710). The platform administrator is not held, and nor is anyone
// the answer does not bind. Display only: the hub refuses a named profile
// either way (TXE-4753).
export function useJobProfileHeld(
  name: string | undefined
): boolean | undefined {
  const access = useJobAccessAnswer(name);
  if (!access) return undefined;
  return access.via !== TxeJobAccessVia.platform_admin;
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
