// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { describe, expect, it } from 'vitest';

import type { components } from '@/api/v1/schema';

import { canRequestRetry, retryLabel, retryStates } from '../retry';

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
    action: { name: 'dagu.retry_run', params: { run_id: runId } },
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

describe('canRequestRetry', () => {
  it('offers a retry only of a finished, unsuccessful run with none pending', () => {
    expect(canRequestRetry('failed', undefined)).toBe(true);
    expect(canRequestRetry('succeeded', undefined)).toBe(false);
    expect(canRequestRetry('partially_succeeded', undefined)).toBe(false);
    expect(canRequestRetry('running', undefined)).toBe(false);
    expect(
      canRequestRetry('failed', {
        runId: 'r',
        proposalId: 'p',
        status: 'requested',
      })
    ).toBe(false);
    expect(
      canRequestRetry('failed', {
        runId: 'r',
        proposalId: 'p',
        status: 'uncertain',
      })
    ).toBe(false);
    // The registry refuses a second request for the same run and version.
    expect(
      canRequestRetry('failed', {
        runId: 'r',
        proposalId: 'p',
        status: 'failed',
      })
    ).toBe(false);
  });
});
