// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import useSWR, { useSWRConfig } from 'swr';

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
// order they arrive in or are served from the cache. A job whose own read
// failed is absent: the others' answers are published, and it keeps its
// previous answer. A read in which every job failed throws instead, so SWR
// keeps the last read and tries again.
type JobsAccessRead = {
  readAt: number;
  answers: Record<string, JobAccessAnswer | null>;
};
let jobsAccessReads = 0;

async function readJobsAccess(
  client: ReturnType<typeof useClient>,
  jobIds: readonly string[]
): Promise<JobsAccessRead> {
  const readAt = ++jobsAccessReads;
  const settled = await Promise.allSettled(
    jobIds.map((jobId) => readJobAccess(client, jobId))
  );
  const answers: Record<string, JobAccessAnswer | null> = {};
  settled.forEach((result, i) => {
    if (result.status === 'fulfilled') {
      answers[jobIds[i] as string] = result.value;
    }
  });
  if (Object.keys(answers).length === 0) {
    throw new Error('job access could not be read');
  }
  return { readAt, answers };
}

// Each job's newest answer, with the read it came from, kept beside the SWR
// cache the reads went through and for the signed-in principal the hub
// answered: it lives as long as that cache does, across the pages that
// mount and unmount, so a refusal is not forgotten when a later read for the
// job failed and the cache holds only the jobs that answered. Another
// principal signing in on the same cache starts with none of them: an
// answer is the hub's to one caller. A test's own cache keeps its own.
type KnownAnswer = { allowed: boolean; readAt: number };
const knownByCache = new WeakMap<
  object,
  Map<string, Map<string, KnownAnswer>>
>();

function knownAnswers(
  cache: object,
  principal: string
): Map<string, KnownAnswer> {
  let byPrincipal = knownByCache.get(cache);
  if (!byPrincipal) {
    byPrincipal = new Map();
    knownByCache.set(cache, byPrincipal);
  }
  let known = byPrincipal.get(principal);
  if (!known) {
    known = new Map();
    byPrincipal.set(principal, known);
  }
  return known;
}

// useJobsRunAllowed is useJobRunAllowed for every job DAG among `names` at
// once: a map from a job's DAG name to whether the hub lets the caller run
// it, with an entry only where the hub's binding answer exists. A name that
// is not a job's, a job with no label, and every name when the answer does
// not bind the caller have no entry, and a page offers its controls for them
// as before. The hub is asked once per distinct job per read, however many
// items name it, so a queue page's lookups stay bounded by the jobs it
// shows (TXE-4754). A job's answer is replaced only by a newer read's: it
// is kept while the set of jobs changes, as a page loads more items or an
// item leaves, while a read fails, when a set the page showed before is
// served again from the cache, and across the page's remounts, so a
// control the hub refused does not come back between reads. Display only;
// the hub decides every action.
export function useJobsRunAllowed(
  names: readonly string[]
): ReadonlyMap<string, boolean> {
  const binding = useAccessBinding();
  const { identity } = useTxeIdentity();
  const principal = [
    identity?.principal?.class,
    identity?.principal?.issuer,
    identity?.principal?.subject,
    identity?.principal?.username,
  ]
    .map((part) => part ?? '')
    .join('\u0000');
  const client = useClient();
  const { cache } = useSWRConfig();
  const jobIds = React.useMemo(
    () => [...new Set(names.filter((name) => JOB_DAG_NAME.test(name)))].sort(),
    [names]
  );
  const key = jobIds.join('\u0000');
  // The read is the principal's as well: another sign-in on the same page
  // is not served a previous principal's answers from the cache.
  const { data } = useSWR<JobsAccessRead>(
    binding && jobIds.length > 0
      ? ['txe', 'jobs-access', principal, key]
      : null,
    () => readJobsAccess(client, jobIds),
    accessSWROptions
  );
  return React.useMemo(() => {
    const known = knownAnswers(cache, principal);
    if (data) {
      for (const [jobId, answer] of Object.entries(data.answers)) {
        const held = known.get(jobId);
        if (held && held.readAt > data.readAt) continue;
        if (answer) {
          known.set(jobId, {
            allowed: answer.permissions.includes(TxeAccessPermission.execute),
            readAt: data.readAt,
          });
        } else {
          known.delete(jobId);
        }
      }
    }
    const allowed = new Map<string, boolean>();
    if (!binding) return allowed;
    for (const jobId of jobIds) {
      const held = known.get(jobId);
      if (held) allowed.set(jobId, held.allowed);
    }
    return allowed;
  }, [binding, cache, data, jobIds, principal]);
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
