// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import useSWR from 'swr';

import { useClient } from '@/hooks/api';

import { createTxeApi, type TxeApi } from './api';
import { sameRetryStates } from './retry';
import type { Decision, Proposal, TxeJob } from './types';

const REFRESH_MS = 10_000;

export const TxeApiContext = React.createContext<TxeApi | null>(null);

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
