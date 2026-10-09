// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Maps /api/v1/txe records (snake_case, the registry's stored shape) and
// native run history onto the dashboard's view model.

import type { components } from '@/api/v1/schema';

import type {
  Decision,
  DecisionRequest,
  JobAvailability,
  Proposal,
  RunRef,
  TargetIdentity,
  TxeJob,
  WaitingOn,
} from './types';

type ApiJob = components['schemas']['TxeJob'];
type ApiVersion = components['schemas']['TxeJobVersion'];
type ApiProposal = components['schemas']['TxeProposal'];
type ApiDecision = components['schemas']['TxeDecision'];
type ApiTarget = components['schemas']['TxeTarget'];
type ApiRun = components['schemas']['DAGRunSummary'];
type ApiDecisionRequest = components['schemas']['TxeDecisionRequest'];

// A stable ID is a map such as {cluster_uid, namespace, uid}; it is shown in
// a fixed key order so the same identity always reads the same way.
function stableIdText(stableId: Record<string, string>): string {
  return Object.keys(stableId)
    .sort()
    .map((key) => `${key}=${stableId[key]}`)
    .join(',');
}

export function toTarget(t: ApiTarget): TargetIdentity {
  return {
    kind: t.kind,
    stableId: stableIdText(t.stable_id),
    displayName: t.display_name,
    context: t.environment,
  };
}

export function toRun(r: ApiRun): RunRef {
  return {
    dagName: r.name,
    dagRunId: r.dagRunId,
    status: r.statusLabel,
    startedAt: r.startedAt || undefined,
    finishedAt: r.finishedAt || undefined,
  };
}

const WAITING: readonly WaitingOn[] = [
  'person',
  'agent',
  'credentials',
  'machine',
];

export function toProposal(
  p: ApiProposal,
  ownerId: string,
  jobId: string
): Proposal {
  const waitingOn = WAITING.find((w) => w === p.waiting_on) ?? 'person';
  return {
    proposalId: p.proposal_id,
    ownerId,
    jobId,
    jobVersion: p.job_version,
    packageDigest: p.package_digest,
    action: {
      name: p.action.name,
      target: p.action.target
        ? toTarget(p.action.target)
        : { kind: '-', stableId: '-' },
      params: (p.action.params ?? {}) as Record<string, unknown>,
    },
    bindingDigest: p.binding_digest,
    revision: p.revision,
    state: p.state,
    snoozeUntil: p.snooze_until,
    question: p.question ?? p.action.name,
    rationale: p.rationale,
    evidence: {
      runIds: p.evidence?.run_ids ?? [],
      artifacts: (p.evidence?.artifact_refs ?? []).map((a) => ({
        dagName: a.dag,
        dagRunId: a.run_id,
        path: a.path,
      })),
      observedAt: p.evidence?.observed_at,
    },
    waitingOn,
    allowedVerdicts:
      p.allowed_verdicts && p.allowed_verdicts.length > 0
        ? p.allowed_verdicts
        : [
            'approve',
            'reject',
            'redirect',
            'retry',
            'pause',
            'snooze',
            'retire',
          ],
    nativeTask: p.native_task
      ? {
          dagName: p.native_task.dag,
          dagRunId: p.native_task.run_id,
          stepId: p.native_task.step_id,
        }
      : undefined,
    createdAt: p.created.at,
  };
}

export function toDecision(
  d: ApiDecision,
  job: Pick<ApiJob, 'job_id' | 'owner_id' | 'native_resumes'>,
  jobVersion: number
): Decision {
  return {
    decisionId: d.decision_id,
    proposalId: d.proposal_id,
    proposalRevision: d.proposal_revision,
    bindingDigest: d.binding_digest,
    jobId: job.job_id,
    jobVersion,
    ownerId: job.owner_id,
    verdict: d.verdict,
    instructions: d.instructions,
    snoozeUntil: d.snooze_until,
    actor: { display: d.actor.id, id: d.actor.id },
    client: d.actor.client === 'cli' ? 'cli' : 'dashboard',
    idempotencyKey: d.idempotency_key ?? '',
    createdAt: d.decided_at,
    // The stored decision keeps the state it was written with; the job's
    // pending list says whether native completion is still outstanding.
    nativeResume:
      job.native_resumes?.[d.decision_id] !== undefined
        ? 'pending'
        : d.native_resume === 'pending'
          ? 'completed'
          : (d.native_resume ?? 'none'),
  };
}

export function toJob(
  job: ApiJob,
  version: ApiVersion | undefined,
  runs: ApiRun[]
): TxeJob {
  const exceptions = Object.values(job.exceptions ?? {})
    .filter((e) => !e.resolved_at)
    .map((e) => ({
      exceptionId: e.exception_id,
      kind: e.kind,
      state: e.state as JobAvailability | undefined,
      detail: e.detail,
      evidence: e.evidence,
      createdAt: e.created.at,
    }));
  const latestRuns = runs.map(toRun);
  return {
    jobId: job.job_id,
    ownerId: job.owner_id,
    projectId: job.project_id,
    version: job.version,
    packageDigest: job.package_digest,
    title: version?.title ?? job.job_id,
    purpose: version?.purpose ?? '',
    origin: version?.origin
      ? {
          repo: version.origin.repo,
          commit: version.origin.commit,
          sessionRef: version.origin.session,
        }
      : undefined,
    targets: (version?.targets ?? []).map(toTarget),
    expectedOutcomes: version?.expected_outcome?.success_criteria,
    schedule: version?.schedule
      ? {
          cron: version.schedule.cron,
          timezone: version.schedule.timezone,
          reviewCadence: version.review_policy?.cadence,
        }
      : undefined,
    lifecycle: job.lifecycle,
    availability: job.availability.state as JobAvailability,
    availabilityDetail: job.availability.detail,
    availabilityObservedAt: job.availability.observed_at,
    exceptions,
    lastObservationAt:
      job.availability.observed_at ?? latestRuns[0]?.finishedAt,
    latestRuns,
    machineId: job.machine_id,
    retirement: job.retirement
      ? {
          reason: job.retirement.reason,
          at: job.retirement.at,
          actor: job.retirement.actor.id,
        }
      : undefined,
  };
}

export function toDecisionBody(r: DecisionRequest): ApiDecisionRequest {
  return {
    expected_proposal_revision: r.expectedProposalRevision,
    binding_digest: r.bindingDigest,
    verdict: r.verdict as ApiDecisionRequest['verdict'],
    idempotency_key: r.idempotencyKey,
    instructions: r.instructions,
    snooze_until: r.snoozeUntil,
  };
}
