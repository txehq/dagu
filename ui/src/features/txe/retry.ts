// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { components } from '@/api/v1/schema';

type ApiProposal = components['schemas']['TxeProposal'];
type ApiAction = components['schemas']['TxeAction'];

export const ACTION_RETRY_RUN = 'dagu.retry_run';

// RetryStatus is what a person may conclude about a requested retry. It is
// "requested" until the reviewer is granted the action, and only
// "succeeded" with the receipt of the new attempt; saving the decision alone
// never means the retry ran.
export type RetryStatus =
  | 'requested'
  | 'executing'
  | 'succeeded'
  | 'failed'
  | 'uncertain'
  | 'not-applied'
  | 'rejected';

export type RetryState = {
  runId: string;
  proposalId: string;
  status: RetryStatus;
  receipt?: string;
  attempt?: number;
};

function runIdOf(p: ApiProposal): string | undefined {
  const params = p.action.params as { run_id?: unknown } | undefined;
  return typeof params?.run_id === 'string' ? params.run_id : undefined;
}

function statusOf(a: ApiAction): RetryStatus {
  switch (a.state) {
    case 'executing':
      return 'executing';
    case 'succeeded':
      return 'succeeded';
    case 'failed':
      return 'failed';
    case 'not_applied':
      return 'not-applied';
    case 'uncertain':
    case 'escalated':
      return 'uncertain';
  }
  return 'uncertain';
}

// retryStates derives, for each run with a retry proposal, the state of its
// newest retry from the proposal and the registry's action journal.
export function retryStates(
  proposals: ApiProposal[],
  actions: ApiAction[]
): Map<string, RetryState> {
  const byProposal = new Map<string, ApiAction>();
  for (const a of actions) {
    if (!a.proposal_id) continue;
    const cur = byProposal.get(a.proposal_id);
    if (!cur || a.attempt > cur.attempt) byProposal.set(a.proposal_id, a);
  }
  const out = new Map<string, RetryState>();
  const newestFirst = [...proposals].sort((x, y) =>
    y.created.at.localeCompare(x.created.at)
  );
  for (const p of newestFirst) {
    if (p.action.name !== ACTION_RETRY_RUN) continue;
    const runId = runIdOf(p);
    if (!runId || out.has(runId)) continue;
    const action = byProposal.get(p.proposal_id);
    let status: RetryStatus = 'requested';
    if (action) status = statusOf(action);
    else if (
      p.state === 'rejected' ||
      p.state === 'superseded' ||
      p.state === 'closed'
    ) {
      status = 'rejected';
    }
    out.set(runId, {
      runId,
      proposalId: p.proposal_id,
      status,
      receipt: action?.receipt,
      attempt: action?.attempt,
    });
  }
  return out;
}

const LABELS: Record<RetryStatus, string> = {
  requested: 'Retry requested; waiting for the reviewer to run it',
  executing: 'Retry running',
  succeeded: 'Retried',
  failed: 'Retry failed',
  uncertain: 'Retry outcome unknown; it will be reconciled before any repeat',
  'not-applied': 'Retry did not take effect',
  rejected: 'Retry not performed',
};

export function retryLabel(state: RetryState): string {
  return LABELS[state.status];
}

// canRequestRetry reports whether the dashboard offers a retry of a run: it
// must have finished without success (the server counts a partial success
// as success) and have no retry yet. A run gets one retry request per job
// version: the registry refuses a second one, whatever became of the first.
export function canRequestRetry(
  runStatus: string,
  state: RetryState | undefined
): boolean {
  const finishedUnsuccessfully =
    runStatus === 'failed' ||
    runStatus === 'aborted' ||
    runStatus === 'rejected';
  return finishedUnsuccessfully && !state;
}
