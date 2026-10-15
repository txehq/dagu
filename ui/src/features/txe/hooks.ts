// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import useSWR from 'swr';

import { useConfig } from '@/contexts/ConfigContext';
import { useClient } from '@/hooks/api';

import { createTxeAccessApi, type TxeAccessApi } from './access';
import { createTxeApi, type TxeApi } from './api';
import {
  awaitingApproval,
  createTxeEnrolmentApi,
  type MachineSummary,
  type TxeEnrolmentApi,
} from './enrolment';
import { sameRetryStates } from './retry';
import type { Decision, Proposal, TxeJob } from './types';

const REFRESH_MS = 10_000;
// A machine re-applies at most once a minute while it waits for approval.
const MACHINES_REFRESH_MS = 15_000;

export const TxeApiContext = React.createContext<TxeApi | null>(null);

// usePersonDecisions reports whether this hub can attribute a decision to a
// person. Only builtin authentication signs people in individually; with no
// authentication, or with basic auth's one shared credential, the hub cannot
// tell a person from a reviewer holding the same access, so it refuses human
// decisions and the dashboard does not offer them.
export function usePersonDecisions(): boolean {
  const config = useConfig();
  return config?.authMode === 'builtin';
}

// useTxeApi returns the injected API (tests, fixtures) or one bound to the
// configured server.
export function useTxeApi(): TxeApi {
  const injected = React.useContext(TxeApiContext);
  const client = useClient();
  return React.useMemo(
    () => injected ?? createTxeApi(client),
    [injected, client]
  );
}

export const TxeAccessApiContext = React.createContext<TxeAccessApi | null>(
  null
);

// useTxeAccessApi returns the injected access API (tests) or one bound to the
// configured server.
export function useTxeAccessApi(): TxeAccessApi {
  const injected = React.useContext(TxeAccessApiContext);
  const client = useClient();
  return React.useMemo(
    () => injected ?? createTxeAccessApi(client),
    [injected, client]
  );
}

export const TxeEnrolmentApiContext =
  React.createContext<TxeEnrolmentApi | null>(null);

// useTxeEnrolmentApi returns the injected enrolment API (tests) or one bound
// to the configured server.
export function useTxeEnrolmentApi(): TxeEnrolmentApi {
  const injected = React.useContext(TxeEnrolmentApiContext);
  const client = useClient();
  return React.useMemo(
    () => injected ?? createTxeEnrolmentApi(client),
    [injected, client]
  );
}

// useTxeMachines lists the machines the hub lets the caller see, with the
// pending enrolment applications counted for a person of their owner. A
// quiet read keeps a failure to itself instead of the dashboard's global
// error notice: its caller shows nothing rather than an error.
export function useTxeMachines({ quiet = false }: { quiet?: boolean } = {}) {
  const api = useTxeEnrolmentApi();
  return useSWR(['txe', 'machines'], () => api.listMachines(), {
    refreshInterval: MACHINES_REFRESH_MS,
    ...(quiet ? { onError: () => undefined } : {}),
  });
}

// useAwaitingApproval counts, per machine, the applications that really
// await approval. The hub's pending_applications also counts an application
// it already approved (it stays on file until its credential expires), so
// for a machine with a count above 0 the applications and enrolments are
// read, as the approval page reads them. Machines without a count, or with
// 0, cost no request.
export function useAwaitingApproval(
  machines: MachineSummary[] | undefined,
  { quiet = false }: { quiet?: boolean } = {}
) {
  const api = useTxeEnrolmentApi();
  const ids = (machines ?? [])
    .filter((m) => (m.pending_applications ?? 0) > 0)
    .map((m) => m.machine_id)
    .sort();
  return useSWR(
    ids.length > 0 ? ['txe', 'awaiting-approval', ids.join(',')] : null,
    async () => {
      const counts = await Promise.all(
        ids.map(async (id) => {
          const [applications, enrolments] = await Promise.all([
            api.listApplications(id),
            api.listEnrolments(id),
          ]);
          return [
            id,
            awaitingApproval(applications, enrolments).length,
          ] as const;
        })
      );
      return new Map<string, number>(counts);
    },
    {
      refreshInterval: MACHINES_REFRESH_MS,
      ...(quiet ? { onError: () => undefined } : {}),
    }
  );
}

export type InboxData = { jobs: TxeJob[]; proposals: Proposal[] };

export function useInboxData() {
  const api = useTxeApi();
  return useSWR<InboxData>(
    ['txe', 'inbox'],
    async () => {
      const jobs = await api.listJobs();
      const proposals = (
        await Promise.all(jobs.map((job) => api.listProposals(job.jobId)))
      ).flat();
      return { jobs, proposals };
    },
    { refreshInterval: REFRESH_MS }
  );
}

export function useRetryStates(jobId: string | undefined) {
  const api = useTxeApi();
  return useSWR(
    jobId ? ['txe', 'retries', jobId] : null,
    () => api.listRetryStates(jobId as string),
    // SWR's default comparison sees every two Maps as equal, which would
    // keep the first retry states loaded on screen for good.
    { refreshInterval: REFRESH_MS, compare: sameRetryStates }
  );
}

export type JobDetailData = {
  job: TxeJob;
  proposals: Proposal[];
  decisions: Decision[];
};

export function useJobDetail(jobId: string | undefined) {
  const api = useTxeApi();
  return useSWR<JobDetailData>(
    jobId ? ['txe', 'job', jobId] : null,
    async () => {
      const id = jobId as string;
      const [job, proposals, decisions] = await Promise.all([
        api.getJob(id),
        api.listProposals(id),
        api.listDecisions(id),
      ]);
      return { job, proposals, decisions };
    },
    { refreshInterval: REFRESH_MS }
  );
}
