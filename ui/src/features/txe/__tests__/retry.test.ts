// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { describe, expect, it } from 'vitest';

import type { components } from '@/api/v1/schema';

import {
  canRequestRetry,
  offeredIntents,
  retryLabel,
  retryStates,
  sameRetryStates,
  type RetryState,
} from '../retry';

type ApiProposal = components['schemas']['TxeProposal'];
type ApiAction = components['schemas']['TxeAction'];

const stamp = (at: string) => ({ at, by: { kind: 'human', id: 'connor' } });

function proposal(
  id: string,
  runId: string,
  at: string,
  state = 'decided'
): ApiProposal {
  return {
    proposal_id: id,
    job_version: 2,
    package_digest: 'sha256:' + 'a'.repeat(64),
    binding_digest: 'sha256:' + 'b'.repeat(64),
    revision: 2,
    state,
    action: {
      name: 'dagu.retry_run',
      params: {
        run_id: runId,
        attempt_id: runId + '-a1',
        queued_at: '2026-10-09T12:00:00Z',
      },
    },
    created: stamp(at),
    updated: stamp(at),
  } as unknown as ApiProposal;
}

function action(
  proposalId: string,
  state: string,
  receipt?: string
): ApiAction {
  return {
    action_id: 'act_' + proposalId,
    kind: 'approved',
    proposal_id: proposalId,
    state,
    attempt: 1,
    receipt,
  } as unknown as ApiAction;
}

describe('retryStates', () => {
  it('is only requested until the reviewer is granted the action', () => {
    const states = retryStates(
      [proposal('prp_1', 'run-1', '2026-10-09T10:00:00Z')],
      []
    );
    expect(states.get('run-1')?.status).toBe('requested');
    expect(retryLabel(states.get('run-1')!)).toContain(
      'waiting for the reviewer to dispatch'
    );
  });

  it('reports success only with the receipt from the action journal', () => {
    const states = retryStates(
      [proposal('prp_1', 'run-1', '2026-10-09T10:00:00Z')],
      [action('prp_1', 'succeeded', 'attempt-2')]
    );
    expect(states.get('run-1')).toMatchObject({
      status: 'succeeded',
      receipt: 'attempt-2',
    });
  });

  it('never presents an uncertain or escalated outcome as done', () => {
    for (const s of ['uncertain', 'escalated']) {
      const states = retryStates(
        [proposal('prp_1', 'run-1', '2026-10-09T10:00:00Z')],
        [action('prp_1', s)]
      );
      expect(states.get('run-1')?.status).toBe('uncertain');
    }
  });

  it('carries the execution the retry was bound to', () => {
    const states = retryStates(
      [proposal('prp_1', 'run-1', '2026-10-09T10:00:00Z')],
      []
    );
    expect(states.get('run-1')).toMatchObject({
      attemptId: 'run-1-a1',
      queuedAt: '2026-10-09T12:00:00Z',
    });
  });

  it('uses the newest retry of a run', () => {
    const states = retryStates(
      [
        proposal('prp_old', 'run-1', '2026-10-09T09:00:00Z'),
        proposal('prp_new', 'run-1', '2026-10-09T10:00:00Z'),
      ],
      [action('prp_old', 'failed')]
    );
    expect(states.get('run-1')).toMatchObject({
      proposalId: 'prp_new',
      status: 'requested',
    });
  });
});

// TXE-7515: a retry's intent is read from its stored parameters, and a
// republish is labelled as one.
describe('retry intent', () => {
  const withParams = (extra: Record<string, unknown>): ApiProposal => {
    const p = proposal('prp_i', 'run-i', '2026-10-09T12:00:00Z');
    p.action.params = { ...(p.action.params as object), ...extra };
    return p;
  };
  it('reads republish, rerun and unspecified', () => {
    expect(
      retryStates([withParams({ step: 'publish' })], []).get('run-i')?.intent
    ).toBe('republish');
    expect(
      retryStates([withParams({ rerun: true })], []).get('run-i')?.intent
    ).toBe('rerun');
    expect(retryStates([withParams({})], []).get('run-i')?.intent).toBe(
      'unspecified'
    );
  });
  it('labels a republish as one', () => {
    const state = retryStates([withParams({ step: 'publish' })], []).get(
      'run-i'
    )!;
    expect(retryLabel(state)).toMatch(/^Republish requested/);
    const rerun = retryStates([withParams({ rerun: true })], []).get('run-i')!;
    expect(retryLabel(rerun)).toMatch(/^Retry requested/);
  });
});

describe('canRequestRetry', () => {
  const q1 = '2026-10-09T12:00:00Z';
  const q2 = '2026-10-09T12:00:05Z';
  const exec = (attemptId: string, queuedAt = q1) => ({ attemptId, queuedAt });
  const bound = (status: RetryState['status']): RetryState => ({
    runId: 'r',
    intent: 'unspecified',
    proposalId: 'p',
    attemptId: 'a1',
    queuedAt: q1,
    status,
  });

  it('offers a retry of a failed latest execution with none bound to it', () => {
    expect(canRequestRetry('failed', exec('a1'), undefined)).toBe(true);
    expect(canRequestRetry('succeeded', exec('a1'), undefined)).toBe(false);
    expect(canRequestRetry('partially_succeeded', exec('a1'), undefined)).toBe(
      false
    );
    expect(canRequestRetry('running', exec('a1'), undefined)).toBe(false);
    // Without Dagu's execution identity there is nothing to bind a retry to.
    expect(canRequestRetry('failed', undefined, undefined)).toBe(false);
  });

  it('allows one request per execution while it may run', () => {
    for (const status of [
      'requested',
      'executing',
      'uncertain',
      'succeeded',
    ] as const) {
      expect(canRequestRetry('failed', exec('a1'), bound(status))).toBe(false);
    }
    // The retried execution failed too: the run may be retried again,
    // whether the retry added an attempt or re-queued the same one.
    expect(canRequestRetry('failed', exec('a2'), bound('succeeded'))).toBe(
      true
    );
    expect(canRequestRetry('failed', exec('a1', q2), bound('succeeded'))).toBe(
      true
    );
  });
});

// TXE-7515: a request settled with nothing run leaves the intents it did
// not ask for.
describe('offeredIntents', () => {
  const q1 = '2026-10-09T12:00:00Z';
  const exec = { attemptId: 'a1', queuedAt: q1 };
  const settled = (
    intent: RetryState['intent'],
    status: RetryState['status']
  ): RetryState => ({
    runId: 'r',
    intent,
    proposalId: 'p',
    attemptId: 'a1',
    queuedAt: q1,
    status,
  });

  it('offers both with nothing bound', () => {
    expect(offeredIntents('failed', exec, undefined)).toEqual([
      'republish',
      'rerun',
    ]);
    expect(offeredIntents('succeeded', exec, undefined)).toEqual([]);
  });

  it('leaves the other intents after a request with nothing run', () => {
    for (const status of ['failed', 'not-applied', 'rejected'] as const) {
      expect(
        offeredIntents('failed', exec, settled('unspecified', status))
      ).toEqual(['republish', 'rerun']);
      expect(
        offeredIntents('failed', exec, settled('republish', status))
      ).toEqual(['rerun']);
      expect(offeredIntents('failed', exec, settled('rerun', status))).toEqual([
        'republish',
      ]);
    }
  });

  it('offers nothing while a request may run', () => {
    for (const status of [
      'requested',
      'executing',
      'uncertain',
      'succeeded',
    ] as const) {
      expect(
        offeredIntents('failed', exec, settled('republish', status))
      ).toEqual([]);
    }
  });
});

describe('sameRetryStates', () => {
  const st = (status: RetryState['status']): RetryState => ({
    runId: 'r',
    intent: 'unspecified',
    proposalId: 'p',
    attemptId: 'a1',
    queuedAt: '',
    status,
  });
  it('compares the states, not the Map objects', () => {
    expect(sameRetryStates(new Map(), new Map([['r', st('requested')]]))).toBe(
      false
    );
    expect(
      sameRetryStates(
        new Map([['r', st('requested')]]),
        new Map([['r', st('succeeded')]])
      )
    ).toBe(false);
    expect(
      sameRetryStates(
        new Map([['r', st('requested')]]),
        new Map([['r', st('requested')]])
      )
    ).toBe(true);
  });
});
