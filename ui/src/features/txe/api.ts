// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { getAuthToken, handleAuthResponse } from '@/lib/authSession';
import { fetchWithTimeout } from '@/lib/requestTimeout';

import type { DecisionSubmitResult } from './components/DecisionPanel';
import type { Decision, DecisionRequest, Proposal, TxeJob } from './types';

// TxeApi is the dashboard's view of /api/v1/txe. Pages depend on this
// interface so tests and fixtures can supply records without a server.
export interface TxeApi {
  listJobs(): Promise<TxeJob[]>;
  getJob(jobId: string): Promise<TxeJob>;
  listProposals(jobId: string): Promise<Proposal[]>;
  listDecisions(jobId: string): Promise<Decision[]>;
  decide(proposalId: string, request: DecisionRequest): Promise<DecisionSubmitResult>;
}

export class TxeApiError extends Error {
  constructor(
    readonly status: number,
    message: string
  ) {
    super(message);
  }
}

async function errorMessage(response: Response): Promise<string> {
  const body = (await response.json().catch(() => ({}))) as {
    message?: string;
    code?: string;
  };
  return body.message ?? body.code ?? `Request failed (${response.status})`;
}

export function createTxeApi(apiURL: string): TxeApi {
  const base = `${apiURL.replace(/\/$/, '')}/txe`;

  const request = async (path: string, init?: RequestInit): Promise<Response> => {
    const headers = new Headers(init?.headers);
    const token = getAuthToken();
    if (token) headers.set('Authorization', `Bearer ${token}`);
    if (init?.body) headers.set('Content-Type', 'application/json');
    const response = await fetchWithTimeout(`${base}${path}`, { ...init, headers });
    handleAuthResponse(response);
    return response;
  };

  const getJSON = async <T,>(path: string): Promise<T> => {
    const response = await request(path);
    if (!response.ok) {
      throw new TxeApiError(response.status, await errorMessage(response));
    }
    return (await response.json()) as T;
  };

  const enc = encodeURIComponent;

  return {
    listJobs: async () =>
      (await getJSON<{ jobs: TxeJob[] }>('/jobs')).jobs ?? [],
    getJob: (jobId) => getJSON<TxeJob>(`/jobs/${enc(jobId)}`),
    listProposals: async (jobId) =>
      (await getJSON<{ proposals: Proposal[] }>(`/jobs/${enc(jobId)}/proposals`))
        .proposals ?? [],
    listDecisions: async (jobId) =>
      (await getJSON<{ decisions: Decision[] }>(`/jobs/${enc(jobId)}/decisions`))
        .decisions ?? [],
    decide: async (proposalId, body) => {
      const response = await request(`/proposals/${enc(proposalId)}/decisions`, {
        method: 'POST',
        body: JSON.stringify(body),
      });
      if (response.ok) return { ok: true };
      return {
        ok: false,
        status: response.status,
        message: await errorMessage(response),
      };
    },
  };
}
