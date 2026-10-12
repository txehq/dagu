// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Synthetic records for tests and UI development. IDs and digests are fake.

import type { Proposal, TxeJob } from './types';

export const OWNER_ID = 'own_01JTXEFIXTURE00000000000000';

export function fixtureJob(overrides: Partial<TxeJob> = {}): TxeJob {
  return {
    jobId: 'job_volume_monitor',
    ownerId: OWNER_ID,
    projectId: 'prj_01JTXEFIXTURE00000000000000',
    version: 3,
    packageDigest: 'a'.repeat(64),
    title: 'Volume monitor',
    purpose: 'Watch the fixture volume until the migration finishes.',
    targets: [
      {
        kind: 'k8s.persistentvolume',
        stableId: 'pv-uid-0001',
        displayName: 'fixture-volume',
        context: 'fixture-cluster',
      },
    ],
    expectedOutcomes: ['Volume reports Bound and usage below 80%'],
    schedule: {
      cron: '*/15 * * * *',
      timezone: 'Australia/Perth',
      reviewCadence: 'hourly',
    },
    lifecycle: 'active',
    availability: 'ready',
    lastObservationAt: '2026-10-09T09:45:00Z',
    latestRuns: [
      {
        dagName: 'job_volume_monitor',
        dagRunId: 'run-0003',
        status: 'succeeded',
        finishedAt: '2026-10-09T09:45:00Z',
      },
    ],
    machineId: 'mch_01JTXEFIXTURE00000000000000',
    ...overrides,
  };
}

export function fixtureProposal(overrides: Partial<Proposal> = {}): Proposal {
  return {
    proposalId: 'prp_01JTXEFIXTURE00000000000001',
    ownerId: OWNER_ID,
    jobId: 'job_volume_monitor',
    jobVersion: 3,
    packageDigest: 'a'.repeat(64),
    action: {
      name: 'resize-volume',
      target: { kind: 'k8s.persistentvolume', stableId: 'pv-uid-0001' },
      params: { sizeGi: 20 },
    },
    bindingDigest: 'b'.repeat(64),
    revision: 1,
    state: 'open',
    question: 'Usage is at 92%. Resize the volume to 20Gi?',
    rationale: 'Three consecutive runs show growth of 4% per hour.',
    evidence: {
      runIds: ['run-0003'],
      artifacts: [
        {
          dagName: 'job_volume_monitor',
          dagRunId: 'run-0003',
          path: 'usage.json',
        },
      ],
      observedAt: '2026-10-09T09:45:00Z',
    },
    waitingOn: 'person',
    allowedVerdicts: ['approve', 'reject', 'redirect', 'snooze', 'retire'],
    nativeTask: {
      dagName: 'txe_review_job_volume_monitor',
      dagRunId: 'review-0007',
      stepId: 'decide',
    },
    createdAt: '2026-10-09T09:50:00Z',
    ...overrides,
  };
}
