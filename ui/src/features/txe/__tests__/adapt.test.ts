// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { describe, expect, it } from 'vitest';

import type { components } from '@/api/v1/schema';

import { toDecisionBody, toJob, toProposal } from '../adapt';
import { buildInbox } from '../inbox';

type ApiJob = components['schemas']['TxeJob'];
type ApiVersion = components['schemas']['TxeJobVersion'];
type ApiProposal = components['schemas']['TxeProposal'];

const stamp = { at: '2026-10-09T09:50:00Z', by: { kind: 'cli', id: 'cc2' } };

// apiJob is a job aggregate as GET /txe/jobs/{jobId} returns it: snake_case,
// purpose and targets on the version, an auth exception and no runs.
const apiJob = {
  schema: 1,
  job_id: 'job_01JTXE',
  owner_id: 'own_01JTXE',
  project_id: 'prj_01JTXE',
  machine_id: 'mch_01JTXE',
  version: 2,
  package_digest: 'sha256:' + 'a'.repeat(64),
  lifecycle: 'active',
  availability: {
    state: 'auth_required',
    detail: 'kubeconfig-dev not readable by the worker',
    observed_at: '2026-10-09T09:58:00Z',
  },
  exceptions: {
    exc_1: {
      exception_id: 'exc_1',
      kind: 'auth',
      state: 'auth_required',
      detail: 'kubeconfig-dev not readable by the worker',
      created: stamp,
    },
    exc_old: {
      exception_id: 'exc_old',
      kind: 'worker_offline',
      detail: 'resolved earlier',
      created: stamp,
      resolved_at: '2026-10-09T09:00:00Z',
    },
  },
} as unknown as ApiJob;

const apiVersion = {
  title: 'PVC health',
  purpose: 'Watch the dev PVC until the migration finishes',
  version: 2,
  targets: [
    {
      kind: 'k8s.pvc',
      stable_id: { uid: 'u-1', cluster_uid: 'c-1' },
      display_name: 'data',
    },
  ],
  schedule: { cron: '*/15 * * * *', timezone: 'Australia/Perth' },
  review_policy: { cadence: 'hourly' },
} as unknown as ApiVersion;

describe('toJob', () => {
  it('maps version context, availability and only unresolved exceptions', () => {
    const job = toJob(apiJob, apiVersion, []);
    expect(job).toMatchObject({
      jobId: 'job_01JTXE',
      title: 'PVC health',
      purpose: 'Watch the dev PVC until the migration finishes',
      availability: 'auth_required',
      availabilityDetail: 'kubeconfig-dev not readable by the worker',
      targets: [{ kind: 'k8s.pvc', stableId: 'cluster_uid=c-1,uid=u-1' }],
      schedule: { reviewCadence: 'hourly' },
    });
    expect(job.exceptions?.map((e) => e.exceptionId)).toEqual(['exc_1']);
    expect(
      buildInbox([job], [], new Date('2026-10-09T10:00:00Z'))[0]
    ).toMatchObject({
      waitingOn: 'credentials',
    });
  });
});

describe('toProposal and toDecisionBody', () => {
  it('round-trips the binding the person reviewed', () => {
    const proposal = toProposal(
      {
        proposal_id: 'prp_1',
        job_version: 2,
        package_digest: apiJob.package_digest,
        binding_digest: 'sha256:' + 'b'.repeat(64),
        revision: 3,
        state: 'open',
        question: 'Resize?',
        waiting_on: 'person',
        allowed_verdicts: ['approve', 'reject'],
        action: {
          name: 'resize',
          target: { kind: 'k8s.pvc', stable_id: { uid: 'u-1' } },
          params: { size_gi: 20 },
        },
        native_task: {
          dag: 'txe-decide-01JTXE',
          run_id: 'r1',
          step_id: 'decide',
        },
        created: stamp,
        updated: stamp,
      } as unknown as ApiProposal,
      'own_01JTXE',
      'job_01JTXE'
    );
    expect(proposal.allowedVerdicts).toEqual(['approve', 'reject']);
    expect(proposal.nativeTask).toEqual({
      dagName: 'txe-decide-01JTXE',
      dagRunId: 'r1',
      stepId: 'decide',
    });
    expect(
      toDecisionBody({
        expectedProposalRevision: proposal.revision,
        bindingDigest: proposal.bindingDigest,
        verdict: 'approve',
        idempotencyKey: 'k-00000001',
      })
    ).toEqual({
      expected_proposal_revision: 3,
      binding_digest: 'sha256:' + 'b'.repeat(64),
      verdict: 'approve',
      idempotency_key: 'k-00000001',
      instructions: undefined,
      snooze_until: undefined,
    });
  });
});
