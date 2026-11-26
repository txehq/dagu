// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import type { components } from '@/api/v1/schema';

import type { Execution } from './types';

type ApiProposal = components['schemas']['TxeProposal'];
type ApiAction = components['schemas']['TxeAction'];

export const ACTION_RETRY_RUN = 'dagu.retry_run';

// RetryStatus is what a person may conclude about a requested retry. It is
// "requested" until the reviewer is granted the action, and only
// "succeeded" with the receipt of the new execution; saving the decision
// alone never means the retry ran.
export type RetryStatus =
  | 'requested'
  | 'executing'
  | 'succeeded'
  | 'failed'
  | 'uncertain'
  | 'not-applied'
  | 'rejected';

// RetryIntent is what a person asks a retry to do: publish the result the
// execution sealed without running the job ("republish"), or run the job
// again on purpose ("rerun"). A retry recorded with neither is
// "unspecified": the job's machine runs it again only for an execution that
// sealed nothing.
export type RetryIntent = 'republish' | 'rerun';

// The stored steps of a dagu.retry_run (registry.RetryStepPublish and
// registry.RetryStepRun). Since TXE-7629 a person's explicit rerun is stored
// as step "run"; a record written before it carries rerun: true instead.
export const RETRY_STEP_PUBLISH = 'publish';
export const RETRY_STEP_RUN = 'run';

// retryIntentOf is the one decoder of a stored retry's intent, for every
// reader of dagu.retry_run params. It reads step "publish" as a republish,
// step "run" or the legacy rerun field as a rerun, and anything else as
// unspecified, as registry.RetryRunParams.Intent does.
export function retryIntentOf(
  params: Record<string, unknown> | undefined
): RetryIntent | 'unspecified' {
  if (params?.step === RETRY_STEP_PUBLISH) return 'republish';
  if (params?.step === RETRY_STEP_RUN) return 'rerun';
  if (params?.rerun === true || params?.rerun === 'true') return 'rerun';
  return 'unspecified';
}

export type RetryState = {
  runId: string;
  intent: RetryIntent | 'unspecified';
  // attemptId and queuedAt name the failed execution this retry was bound
  // to; a proposal recorded before queue markers were bound has none, which
  // the hub stored as never queued.
  attemptId?: string;
  queuedAt: string;
  proposalId: string;
  status: RetryStatus;
  receipt?: string;
  attempt?: number;
};

function paramsOf(p: ApiProposal): {
  runId?: string;
  attemptId?: string;
  queuedAt: string;
  intent: RetryState['intent'];
} {
  const params = p.action.params as Record<string, unknown> | undefined;
  return {
    intent: retryIntentOf(params),
    runId: typeof params?.run_id === 'string' ? params.run_id : undefined,
    attemptId:
      typeof params?.attempt_id === 'string' ? params.attempt_id : undefined,
    queuedAt: typeof params?.queued_at === 'string' ? params.queued_at : '',
  };
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
    const { runId, attemptId, queuedAt, intent } = paramsOf(p);
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
      intent,
      attemptId,
      queuedAt,
      proposalId: p.proposal_id,
      status,
      receipt: action?.receipt,
      attempt: action?.attempt,
    });
  }
  return out;
}

// The action a retry decision authorizes is the dispatch of a native retry,
// so these labels describe the dispatch. A dispatched retry says nothing
// about whether the retried run then succeeded; that is the run's own status.
const LABELS: Record<RetryStatus, string> = {
  requested: 'Retry requested; waiting for the reviewer to dispatch it',
  executing: 'Retry being dispatched',
  succeeded: 'Retry dispatched',
  failed: 'Retry dispatch failed',
  uncertain:
    'Retry dispatch outcome unknown; it will be reconciled before any repeat',
  'not-applied': 'Retry was not dispatched',
  rejected: 'Retry not performed',
};

// A republish publishes a sealed result and never runs the job, so its
// labels say republish, not retry.
const REPUBLISH_LABELS: Record<RetryStatus, string> = {
  requested:
    "Republish requested; waiting for the job's machine to dispatch it",
  executing: 'Republish being dispatched',
  succeeded: 'Republish dispatched',
  failed: 'Republish dispatch failed',
  uncertain:
    'Republish dispatch outcome unknown; it will be reconciled before any repeat',
  'not-applied': 'Republish was not dispatched',
  rejected: 'Republish not performed',
};

export function retryLabel(state: RetryState): string {
  return state.intent === 'republish'
    ? REPUBLISH_LABELS[state.status]
    : LABELS[state.status];
}

// offeredIntents is what the dashboard offers for a run: its latest
// execution must have finished without success (the server counts a partial
// success as success). With no request bound to that execution, both intents
// are offered. A request bound to it that was settled with nothing run (its
// dispatch failed or was not applied, or the proposal was rejected or
// superseded) leaves the intents it did not ask for (TXE-7515): an
// unspecified retry the job's machine refused for a sealed execution leaves
// both, a republish that could not publish leaves the rerun. A request still
// waiting, being dispatched, unresolved or dispatched leaves none. A native
// retry starts a new execution, so once a retried execution has failed too,
// the run is offered again.
export function offeredIntents(
  runStatus: string,
  execution: Execution | undefined,
  state: RetryState | undefined
): RetryIntent[] {
  const finishedUnsuccessfully =
    runStatus === 'failed' ||
    runStatus === 'aborted' ||
    runStatus === 'rejected';
  if (!finishedUnsuccessfully || !execution) return [];
  const all: RetryIntent[] = ['republish', 'rerun'];
  if (
    !state ||
    state.attemptId !== execution.attemptId ||
    state.queuedAt !== execution.queuedAt
  ) {
    return all;
  }
  const settledWithNothingRun =
    state.status === 'failed' ||
    state.status === 'not-applied' ||
    state.status === 'rejected';
  if (!settledWithNothingRun) return [];
  return all.filter((intent) => intent !== state.intent);
}

// canRequestRetry reports whether the dashboard offers any request for a
// run (see offeredIntents).
export function canRequestRetry(
  runStatus: string,
  execution: Execution | undefined,
  state: RetryState | undefined
): boolean {
  return offeredIntents(runStatus, execution, state).length > 0;
}

// sameRetryStates reports whether two loads of retry states are the same, so
// a refresh re-renders exactly when a retry changed.
export function sameRetryStates(
  a: Map<string, RetryState> | undefined,
  b: Map<string, RetryState> | undefined
): boolean {
  if (a === b) return true;
  if (!a || !b || a.size !== b.size) return false;
  for (const [runId, state] of a) {
    const other = b.get(runId);
    if (!other || JSON.stringify(state) !== JSON.stringify(other)) return false;
  }
  return true;
}
