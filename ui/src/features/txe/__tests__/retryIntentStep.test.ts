// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { describe, expect, it } from 'vitest';

import type { components } from '@/api/v1/schema';

import { offeredIntents, retryLabel, retryStates } from '../retry';
import type { Execution } from '../types';

type ApiProposal = components['schemas']['TxeProposal'];

// TXE-8597: since TXE-7629 the hub stores a person's explicit rerun as step
// "run" (registry.RetryStepRun); records written before it carry the legacy
// rerun field. The UI reads both as a rerun, so a rerun already requested is
// never shown as unspecified and offered again.
function retryProposal(
  params: Record<string, unknown>,
  state = 'decided'
): ApiProposal {
  const stamp = { at: '2026-11-26T08:00:00Z', by: { kind: 'human', id: 'p' } };
  return {
    proposal_id: 'prp_step',
    job_version: 2,
    package_digest: 'sha256:' + 'a'.repeat(64),
    binding_digest: 'sha256:' + 'b'.repeat(64),
    revision: 1,
    state,
    action: {
      name: 'dagu.retry_run',
      params: {
        run_id: 'run-s',
        attempt_id: 'run-s-a1',
        queued_at: '2026-11-26T07:00:00Z',
        ...params,
      },
    },
    created: stamp,
    updated: stamp,
  } as unknown as ApiProposal;
}

const intentOf = (params: Record<string, unknown>) =>
  retryStates([retryProposal(params)], []).get('run-s')?.intent;

describe('retry intent from the stored step (TXE-8597)', () => {
  it('reads step "run" as a rerun', () => {
    expect(intentOf({ step: 'run' })).toBe('rerun');
  });

  it('still reads the legacy rerun field as a rerun', () => {
    expect(intentOf({ rerun: true })).toBe('rerun');
    expect(intentOf({ rerun: 'true' })).toBe('rerun');
  });

  it('reads step "publish" as a republish and nothing as unspecified', () => {
    expect(intentOf({ step: 'publish' })).toBe('republish');
    expect(intentOf({})).toBe('unspecified');
    expect(intentOf({ step: 'transform' })).toBe('unspecified');
  });

  it('labels a step-run retry as a rerun request', () => {
    const state = retryStates([retryProposal({ step: 'run' })], []).get(
      'run-s'
    )!;
    expect(retryLabel(state)).toMatch(/^Retry requested/);
  });

  // A rerun settled with nothing run (here, rejected) leaves only the
  // republish; read as unspecified it would offer Run again, which the hub's
  // ProposeRetry refuses as the same request.
  it('does not offer Run again after a step-run rerun was rejected', () => {
    const exec = {
      attemptId: 'run-s-a1',
      queuedAt: '2026-11-26T07:00:00Z',
    } as unknown as Execution;
    const state = retryStates(
      [retryProposal({ step: 'run' }, 'rejected')],
      []
    ).get('run-s')!;
    expect(state.status).toBe('rejected');
    expect(offeredIntents('failed', exec, state)).toEqual(['republish']);
  });
});
