// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import {
  TxeRetryRequestMode,
  type components,
  type paths,
} from '@/api/v1/schema';
import type { Client } from 'openapi-fetch';

import { toDecision, toDecisionBody, toJob, toProposal } from './adapt';
import type { DecisionSubmitResult } from './components/DecisionPanel';
import { retryStates, type RetryIntent, type RetryState } from './retry';
import type {
  Decision,
  DecisionRequest,
  Execution,
  Proposal,
  TxeJob,
} from './types';

type ApiJob = components['schemas']['TxeJob'];

// TxeApi is the dashboard's view of /api/v1/txe. Pages depend on this
// interface so tests and fixtures can supply records without a server.
export interface TxeApi {
  listJobs(): Promise<TxeJob[]>;
  getJob(jobId: string): Promise<TxeJob>;
  listProposals(jobId: string): Promise<Proposal[]>;
  listDecisions(jobId: string): Promise<Decision[]>;
  decide(
    jobId: string,
    proposalId: string,
    request: DecisionRequest
  ): Promise<DecisionSubmitResult>;
  // replayDecision repeats a stored decision exactly, which completes a
  // follow-up the server reported as pending.
  replayDecision(
    jobId: string,
    decision: Decision
  ): Promise<DecisionSubmitResult>;
  // requestRetry asks for one exact execution of a run to be republished
  // or run again. It records the decision only; the job's machine carries it
  // out through the action journal. execution is the run execution the
  // person reviewed; the server refuses the request if the run has since
  // moved to another execution. The intent is always named: "republish"
  // publishes what the execution sealed and never runs the job, through the
  // hub's own republish endpoint (an older hub has none and refuses it);
  // "rerun" runs the job again on purpose. The dashboard never sends a
  // retry that names no intent.
  requestRetry(
    jobId: string,
    runId: string,
    execution: Execution,
    expectedJobVersion: number,
    idempotencyKey: string,
    intent: RetryIntent
  ): Promise<DecisionSubmitResult>;
  // ownerRepublish reports whether the hub takes a person's republish
  // request (it lists the owner_republish capability).
  ownerRepublish(): Promise<boolean>;
  // listRetryStates returns the newest retry of each run of the job.
  listRetryStates(jobId: string): Promise<Map<string, RetryState>>;
}

export class TxeApiError extends Error {
  constructor(
    readonly status: number,
    message: string
  ) {
    super(message);
  }
}

type ErrorBody = { message?: string; details?: { code?: string } } | undefined;

function failure(response: Response, error: unknown): TxeApiError {
  const body = error as ErrorBody;
  return new TxeApiError(
    response.status,
    body?.message ??
      body?.details?.code ??
      `Request failed (${response.status})`
  );
}

// How many recent runs a job view shows.
const RECENT_RUNS = 5;

export function createTxeApi(client: Client<paths>): TxeApi {
  const loadJob = async (jobId: string): Promise<TxeJob> => {
    const jobRes = await client.GET('/txe/jobs/{jobId}', {
      params: { path: { jobId } },
    });
    if (!jobRes.data) throw failure(jobRes.response, jobRes.error);
    return assemble(jobRes.data);
  };

  // assemble adds the job's version context and native run history. A job
  // whose DAG has no runs yet simply shows none.
  const assemble = async (job: ApiJob): Promise<TxeJob> => {
    const [versionRes, runsRes] = await Promise.all([
      client.GET('/txe/jobs/{jobId}/versions/{version}', {
        params: { path: { jobId: job.job_id, version: job.version } },
      }),
      client.GET('/dags/{fileName}/dag-runs', {
        params: { path: { fileName: job.job_id } },
      }),
    ]);
    const runs = (runsRes.data?.dagRuns ?? []).slice(0, RECENT_RUNS);
    return toJob(job, versionRes.data, runs);
  };

  const decide: TxeApi['decide'] = async (jobId, proposalId, request) => {
    const res = await client.POST(
      '/txe/jobs/{jobId}/proposals/{proposalId}/decisions',
      {
        params: { path: { jobId, proposalId } },
        body: toDecisionBody(request),
      }
    );
    if (res.data) return { ok: true };
    const err = failure(res.response, res.error);
    return { ok: false, status: err.status, message: err.message };
  };

  return {
    listJobs: async () => {
      const res = await client.GET('/txe/jobs', {});
      if (!res.data) throw failure(res.response, res.error);
      return Promise.all(res.data.jobs.map(assemble));
    },
    getJob: loadJob,
    listProposals: async (jobId) => {
      const [jobRes, res] = await Promise.all([
        client.GET('/txe/jobs/{jobId}', { params: { path: { jobId } } }),
        client.GET('/txe/jobs/{jobId}/proposals', {
          params: { path: { jobId } },
        }),
      ]);
      if (!res.data) throw failure(res.response, res.error);
      const ownerId = jobRes.data?.owner_id ?? '';
      return [...res.data.open, ...res.data.finished].map((p) =>
        toProposal(p, ownerId, jobId)
      );
    },
    listDecisions: async (jobId) => {
      const [jobRes, res, proposals] = await Promise.all([
        client.GET('/txe/jobs/{jobId}', { params: { path: { jobId } } }),
        client.GET('/txe/jobs/{jobId}/decisions', {
          params: { path: { jobId } },
        }),
        client.GET('/txe/jobs/{jobId}/proposals', {
          params: { path: { jobId } },
        }),
      ]);
      if (!res.data || !jobRes.data) {
        throw failure(res.response, res.error ?? jobRes.error);
      }
      const job = jobRes.data;
      // A decision is bound to the job version of the proposal it answers.
      const versionOf = new Map<string, number>();
      for (const p of [
        ...(proposals.data?.open ?? []),
        ...(proposals.data?.finished ?? []),
      ]) {
        versionOf.set(p.proposal_id, p.job_version);
      }
      return res.data.decisions.map((d) =>
        toDecision(d, job, versionOf.get(d.proposal_id) ?? job.version)
      );
    },
    decide,
    requestRetry: async (
      jobId,
      runId,
      execution,
      expectedJobVersion,
      idempotencyKey,
      intent
    ) => {
      const body = {
        attempt_id: execution.attemptId,
        queued_at: execution.queuedAt,
        expected_job_version: expectedJobVersion,
        idempotency_key: idempotencyKey,
      };
      // The person dashboard is the hub's own: requests go to the local
      // node.
      const params = {
        path: { jobId, runId },
        query: { remoteNode: 'local' },
      };
      const res =
        intent === 'republish'
          ? await client.POST(
              '/txe/jobs/{jobId}/runs/{runId}/republish-requests',
              { params, body }
            )
          : await client.POST('/txe/jobs/{jobId}/runs/{runId}/retry-requests', {
              params,
              body: { ...body, mode: TxeRetryRequestMode.rerun },
            });
      if (res.data) return { ok: true };
      const err = failure(res.response, res.error);
      return { ok: false, status: err.status, message: err.message };
    },
    ownerRepublish: async () => {
      const res = await client.GET('/txe/installation', {
        params: { query: { remoteNode: 'local' } },
      });
      if (!res.data) throw failure(res.response, res.error);
      return res.data.capabilities.includes('owner_republish');
    },
    listRetryStates: async (jobId) => {
      const [proposals, actions] = await Promise.all([
        client.GET('/txe/jobs/{jobId}/proposals', {
          params: { path: { jobId } },
        }),
        client.GET('/txe/jobs/{jobId}/actions', {
          params: { path: { jobId } },
        }),
      ]);
      if (!proposals.data) throw failure(proposals.response, proposals.error);
      if (!actions.data) throw failure(actions.response, actions.error);
      return retryStates(
        [...proposals.data.open, ...proposals.data.finished],
        [...actions.data.in_flight, ...actions.data.archived]
      );
    },
    replayDecision: (jobId, d) =>
      decide(jobId, d.proposalId, {
        expectedProposalRevision: d.proposalRevision,
        bindingDigest: d.bindingDigest,
        verdict: d.verdict,
        instructions: d.instructions,
        snoozeUntil: d.snoozeUntil,
        idempotencyKey: d.idempotencyKey,
      }),
  };
}
