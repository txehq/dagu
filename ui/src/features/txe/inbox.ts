// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type {
  DecisionRequest,
  Verdict,
  InboxItem,
  Proposal,
  RunRef,
  TxeJob,
  WaitingOn,
} from './types';

const FAILED_RUN_STATUSES = new Set(['failed', 'aborted', 'rejected']);

// Longest snooze the decision API accepts; the server enforces the same bound.
export const MAX_SNOOZE_MS = 30 * 24 * 60 * 60 * 1000;

const WAITING_ORDER: Record<WaitingOn, number> = {
  person: 0,
  credentials: 1,
  machine: 2,
  agent: 3,
};

// isProposalActionable reports whether a proposal needs a human now. A snoozed
// proposal returns once its explicit expiry passes.
export function isProposalActionable(proposal: Proposal, now: Date): boolean {
  if (proposal.state === 'open') return true;
  if (proposal.state !== 'snoozed' || !proposal.snoozeUntil) return false;
  return new Date(proposal.snoozeUntil).getTime() <= now.getTime();
}

function latestFailedRun(job: TxeJob): RunRef | undefined {
  const latest = job.latestRuns[0];
  return latest && FAILED_RUN_STATUSES.has(latest.status) ? latest : undefined;
}

// buildInbox derives exception items: actionable proposals first, then jobs
// that need a person, cannot run on their machine, or whose latest run failed.
// Retired and completed jobs only surface through an actionable proposal.
export function buildInbox(
  jobs: TxeJob[],
  proposals: Proposal[],
  now: Date
): InboxItem[] {
  const jobsById = new Map(jobs.map((job) => [job.jobId, job]));
  const items: InboxItem[] = [];
  const covered = new Set<string>();

  for (const proposal of proposals) {
    const job = jobsById.get(proposal.jobId);
    if (!job || !isProposalActionable(proposal, now)) continue;
    covered.add(job.jobId);
    items.push({
      reason: 'proposal',
      job,
      proposal,
      waitingOn: proposal.waitingOn,
      failedRun: latestFailedRun(job),
    });
  }

  for (const job of jobs) {
    if (covered.has(job.jobId)) continue;
    if (job.lifecycle === 'retired' || job.lifecycle === 'completed') continue;
    // An auth failure can be reported only as an exception: a missing
    // credential may stop a run before any step records a status.
    const exceptions = job.exceptions ?? [];
    const authFailure =
      job.availability === 'auth_required' ||
      exceptions.some((e) => e.state === 'auth_required' || e.kind === 'auth');
    if (authFailure) {
      items.push({
        reason: 'unavailable',
        job,
        waitingOn: 'credentials',
        exceptions,
      });
    } else if (
      job.availability === 'worker_offline' ||
      job.availability === 'stale'
    ) {
      items.push({
        reason: 'unavailable',
        job,
        waitingOn: 'machine',
        exceptions,
      });
    } else if (exceptions.length > 0) {
      items.push({ reason: 'exception', job, waitingOn: 'agent', exceptions });
    } else if (job.lifecycle === 'needs_human') {
      items.push({ reason: 'needs_human', job, waitingOn: 'person' });
    } else {
      const failedRun = latestFailedRun(job);
      if (failedRun) {
        items.push({
          reason: 'run-failed',
          job,
          waitingOn: 'agent',
          failedRun,
        });
      }
    }
  }

  return items.sort((a, b) => {
    const order = WAITING_ORDER[a.waitingOn] - WAITING_ORDER[b.waitingOn];
    if (order !== 0) return order;
    return freshnessTime(b.job) - freshnessTime(a.job);
  });
}

function freshnessTime(job: TxeJob): number {
  const at = job.lastObservationAt ?? job.latestRuns[0]?.finishedAt;
  return at ? new Date(at).getTime() : 0;
}

// staleness describes how old the last real observation is.
export function staleness(
  job: TxeJob,
  now: Date
): { observedAt?: string; ageMs?: number } {
  const observedAt = job.lastObservationAt ?? job.latestRuns[0]?.finishedAt;
  if (!observedAt) return {};
  return { observedAt, ageMs: now.getTime() - new Date(observedAt).getTime() };
}

export type DecisionDraft = {
  verdict: Verdict;
  instructions?: string;
  snoozeUntil?: string;
};

// buildDecisionRequest binds a response to the exact proposal revision and
// binding digest the person reviewed, so the server can refuse it after any
// material change. It returns an error message instead of a request when the
// draft is incomplete.
export function buildDecisionRequest(
  proposal: Proposal,
  draft: DecisionDraft,
  idempotencyKey: string,
  now: Date
): { request: DecisionRequest } | { error: string } {
  if (!proposal.allowedVerdicts.includes(draft.verdict)) {
    return { error: `This proposal does not accept "${draft.verdict}".` };
  }
  const instructions = draft.instructions?.trim();
  if (draft.verdict === 'redirect' && !instructions) {
    return { error: 'Redirect needs revised instructions.' };
  }
  const request: DecisionRequest = {
    expectedProposalRevision: proposal.revision,
    bindingDigest: proposal.bindingDigest,
    verdict: draft.verdict,
    idempotencyKey,
  };
  if (instructions) request.instructions = instructions;
  if (draft.verdict === 'snooze') {
    if (!draft.snoozeUntil) {
      return { error: 'Snooze needs an explicit expiry.' };
    }
    const until = new Date(draft.snoozeUntil);
    if (Number.isNaN(until.getTime())) {
      return { error: 'Snooze expiry is not a valid time.' };
    }
    const delta = until.getTime() - now.getTime();
    if (delta <= 0) return { error: 'Snooze expiry must be in the future.' };
    if (delta > MAX_SNOOZE_MS) {
      return { error: 'Snooze expiry must be within 30 days.' };
    }
    request.snoozeUntil = until.toISOString();
  }
  return { request };
}
