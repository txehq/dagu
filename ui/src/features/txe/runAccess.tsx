// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
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

// readJobAccess is the hub's own answer for one job (GET /txe/jobs/{id}
// access). The hub's 404 is definitive: the job is gone or no longer
// shared, so nothing may be run from it. A job with no label is null. A
// failed read throws, so SWR keeps the last answer and a passing error never
// brings back controls the hub refused.
async function readJobAccess(
  client: ReturnType<typeof useClient>,
  jobId: string
): Promise<JobAccessAnswer | null> {
  const res = await client.GET('/txe/jobs/{jobId}', {
    params: { path: { jobId } },
  });
  if (res.response?.status === 404) {
    return { permissions: [] as string[] };
  }
  if (res.error || !res.data) {
    throw new Error('job access could not be read');
  }
  return res.data.access ?? null;
}

// A share can change while the page is open: the answer is read again, as
// the other TXE pages do, and a failed read is tried again, so polling goes
// on once the hub answers.
const accessSWROptions = {
  onError: () => undefined,
  shouldRetryOnError: true,
  errorRetryInterval: ACCESS_REFRESH_MS,
  refreshInterval: ACCESS_REFRESH_MS,
};

// useAccessBinding says whether the hub's answer for a job binds the caller:
// always for a person signed in through the identity provider, whom the hub
// decides by owner in every mode, and for any other caller only in enforce
// (in observe the hub lets them through, in off it gives no answer).
function useAccessBinding(): boolean {
  const { identity } = useTxeIdentity();
  return (
    identity?.authz_mode === TxeIdentityAuthz_mode.enforce ||
    isTxePerson(identity)
  );
}

// useJobAccessAnswer reads the hub's own answer for the job DAG `name` when
// that answer binds the caller. It is undefined when the answer does not
// bind the caller, the DAG is not a job's, the hub has not answered yet, or
// the job carries no label.
function useJobAccessAnswer(
  name: string | undefined
): JobAccessAnswer | undefined {
  const binding = useAccessBinding();
  const client = useClient();
  const jobId = name && JOB_DAG_NAME.test(name) ? name : undefined;
  const { data } = useSWR<JobAccessAnswer | null>(
    binding && jobId ? ['txe', 'job-access', jobId] : null,
    () => readJobAccess(client, jobId as string),
    accessSWROptions
  );
  if (!binding || !data) return undefined;
  return data;
}

// A read of several jobs' answers, numbered in the order the reads were
// made: a later read's answers are newer than an earlier read's, whatever
// order they arrive in or are served from the cache.
type JobsAccessRead = {
  readAt: number;
  answers: Record<string, JobAccessAnswer | null>;
};
let jobsAccessReads = 0;

// useJobsRunAllowed is useJobRunAllowed for every job DAG among `names` at
// once: a map from a job's DAG name to whether the hub lets the caller run
// it, with an entry only where the hub's binding answer exists. A name that
// is not a job's, a job with no label, and every name when the answer does
// not bind the caller have no entry, and a page offers its controls for them
// as before. The hub is asked once per distinct job per read, however many
// items name it, so a queue page's lookups stay bounded by the jobs it
// shows (TXE-4754). A job's answer is replaced only by a newer read's: it
// is kept while the set of jobs changes, as a page loads more items or an
// item leaves, while a read fails, and when a set the page showed before is
// served again from the cache, so a control the hub refused does not come
// back between reads. Display only; the hub decides every action.
export function useJobsRunAllowed(
  names: readonly string[]
): ReadonlyMap<string, boolean> {
  const binding = useAccessBinding();
  const client = useClient();
  const jobIds = React.useMemo(
    () => [...new Set(names.filter((name) => JOB_DAG_NAME.test(name)))].sort(),
    [names]
  );
  const key = jobIds.join('\u0000');
  const { data } = useSWR<JobsAccessRead>(
    binding && jobIds.length > 0 ? ['txe', 'jobs-access', key] : null,
    async () => {
      const readAt = ++jobsAccessReads;
      const answers = await Promise.all(
        jobIds.map((jobId) => readJobAccess(client, jobId))
      );
      return {
        readAt,
        answers: Object.fromEntries(
          jobIds.map((jobId, i) => [jobId, answers[i] ?? null])
        ),
      };
    },
    accessSWROptions
  );
  // Each job's newest answer, with the read it came from. Kept in a ref so
  // a read for a changed set of jobs, pending, failed or served stale from
  // the cache, leaves every newer answer as it is.
  const known = React.useRef(
    new Map<string, { allowed: boolean; readAt: number }>()
  );
  return React.useMemo(() => {
    if (data) {
      for (const [jobId, answer] of Object.entries(data.answers)) {
        const held = known.current.get(jobId);
        if (held && held.readAt > data.readAt) continue;
        if (answer) {
          known.current.set(jobId, {
            allowed: answer.permissions.includes(TxeAccessPermission.execute),
            readAt: data.readAt,
          });
        } else {
          known.current.delete(jobId);
        }
      }
    }
    const allowed = new Map<string, boolean>();
    if (!binding) return allowed;
    for (const jobId of jobIds) {
      const held = known.current.get(jobId);
      if (held) allowed.set(jobId, held.allowed);
    }
    return allowed;
  }, [binding, data, jobIds]);
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
