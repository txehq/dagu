// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { describe, expect, it } from 'vitest';

import { fixtureJob, fixtureProposal } from '../fixtures';
import {
  buildDecisionRequest,
  buildInbox,
  isProposalActionable,
} from '../inbox';

const now = new Date('2026-10-09T10:00:00Z');

describe('buildInbox', () => {
  it('lists an open proposal with its job context', () => {
    const items = buildInbox([fixtureJob()], [fixtureProposal()], now);
    expect(items).toHaveLength(1);
    expect(items[0]).toMatchObject({
      reason: 'proposal',
      waitingOn: 'person',
      proposal: { proposalId: 'prp_01JTXEFIXTURE00000000000001' },
    });
  });

  it('hides a snoozed proposal until its expiry passes', () => {
    const snoozed = fixtureProposal({
      state: 'snoozed',
      snoozeUntil: '2026-10-09T12:00:00Z',
    });
    expect(buildInbox([fixtureJob()], [snoozed], now)).toHaveLength(0);
    expect(
      isProposalActionable(snoozed, new Date('2026-10-09T12:00:01Z'))
    ).toBe(true);
  });

  it('omits decided and superseded proposals', () => {
    const proposals = [
      fixtureProposal({ state: 'decided' }),
      fixtureProposal({ proposalId: 'prp_2', state: 'superseded' }),
    ];
    expect(buildInbox([fixtureJob()], proposals, now)).toHaveLength(0);
  });

  it('distinguishes credentials, machine and failed-run exceptions', () => {
    const jobs = [
      fixtureJob({ jobId: 'job_auth', availability: 'auth_required' }),
      fixtureJob({ jobId: 'job_offline', availability: 'worker_offline' }),
      fixtureJob({
        jobId: 'job_failed',
        latestRuns: [
          { dagName: 'job_failed', dagRunId: 'r1', status: 'failed' },
        ],
      }),
      fixtureJob({ jobId: 'job_ok' }),
      fixtureJob({
        jobId: 'job_retired',
        lifecycle: 'retired',
        availability: 'worker_offline',
      }),
    ];
    const items = buildInbox(jobs, [], now);
    expect(items.map((item) => [item.job.jobId, item.waitingOn])).toEqual([
      ['job_auth', 'credentials'],
      ['job_offline', 'machine'],
      ['job_failed', 'agent'],
    ]);
  });
});

describe('buildDecisionRequest', () => {
  const proposal = fixtureProposal({
    revision: 4,
    bindingDigest: 'c'.repeat(64),
  });

  it('binds the reviewed revision and digest', () => {
    const result = buildDecisionRequest(
      proposal,
      { verdict: 'approve' },
      'k1',
      now
    );
    expect(result).toEqual({
      request: {
        expectedProposalRevision: 4,
        bindingDigest: 'c'.repeat(64),
        verdict: 'approve',
        idempotencyKey: 'k1',
      },
    });
  });

  it('requires instructions for redirect', () => {
    expect(
      buildDecisionRequest(
        proposal,
        { verdict: 'redirect', instructions: '  ' },
        'k',
        now
      )
    ).toEqual({ error: 'Redirect needs revised instructions.' });
  });

  it('requires a future snooze expiry within 30 days', () => {
    expect(
      buildDecisionRequest(proposal, { verdict: 'snooze' }, 'k', now)
    ).toEqual({
      error: 'Snooze needs an explicit expiry.',
    });
    expect(
      buildDecisionRequest(
        proposal,
        { verdict: 'snooze', snoozeUntil: '2026-10-09T09:00:00Z' },
        'k',
        now
      )
    ).toEqual({ error: 'Snooze expiry must be in the future.' });
    expect(
      buildDecisionRequest(
        proposal,
        { verdict: 'snooze', snoozeUntil: '2026-12-01T00:00:00Z' },
        'k',
        now
      )
    ).toEqual({ error: 'Snooze expiry must be within 30 days.' });
    const ok = buildDecisionRequest(
      proposal,
      { verdict: 'snooze', snoozeUntil: '2026-10-10T10:00:00Z' },
      'k',
      now
    );
    expect(ok).toMatchObject({
      request: { snoozeUntil: '2026-10-10T10:00:00.000Z' },
    });
  });

  it('rejects a response the proposal does not allow', () => {
    expect(
      buildDecisionRequest(proposal, { verdict: 'pause' }, 'k', now)
    ).toEqual({
      error: 'This proposal does not accept "pause".',
    });
  });
});
