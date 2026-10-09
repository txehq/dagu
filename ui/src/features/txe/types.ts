// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Shapes of the TXE job registry and decision API (/api/v1/txe). They mirror
// the agreed record contract until the generated OpenAPI types replace them.

export type JobLifecycle =
  | 'active'
  | 'paused'
  | 'needs_human'
  | 'completed'
  | 'retired';

export type JobAvailability =
  | 'ready'
  | 'worker_offline'
  | 'auth_required'
  | 'target_unreachable'
  | 'stale';

export type WaitingOn = 'person' | 'agent' | 'credentials' | 'machine';

export type ProposalState =
  | 'open'
  | 'snoozed'
  | 'decided'
  | 'superseded'
  | 'executed'
  | 'rejected'
  // Closed by the system, for example when a superseded proposal's decide
  // task is released; never a person's decision.
  | 'closed';

export type Verdict =
  | 'approve'
  | 'reject'
  | 'redirect'
  | 'snooze'
  | 'retry'
  | 'pause'
  | 'retire';

export type TargetIdentity = {
  kind: string;
  stableId: string;
  displayName?: string;
  context?: string;
  namespace?: string;
};

export type RunRef = {
  dagName: string;
  dagRunId: string;
  status: string;
  startedAt?: string;
  finishedAt?: string;
  error?: string;
};

export type ArtifactRef = {
  dagName: string;
  dagRunId: string;
  path: string;
};

// JobException is an open, actionable problem reported for a job, such as a
// missing local login on its machine. Detail is sanitized by the reporter.
export type JobException = {
  exceptionId: string;
  kind: string;
  state?: JobAvailability;
  detail: string;
  evidence?: string[];
  createdAt: string;
};

export type TxeJob = {
  jobId: string;
  ownerId: string;
  projectId: string;
  version: number;
  packageDigest: string;
  title: string;
  purpose: string;
  origin?: { repo?: string; commit?: string; sessionRef?: string };
  targets: TargetIdentity[];
  expectedOutcomes?: string[];
  schedule?: { cron?: string; timezone?: string; reviewCadence?: string };
  lifecycle: JobLifecycle;
  availability: JobAvailability;
  availabilityDetail?: string;
  availabilityObservedAt?: string;
  exceptions?: JobException[];
  // Decisions stored whose native follow-up has not completed yet.
  pendingFollowUps?: string[];
  lastObservationAt?: string;
  latestRuns: RunRef[];
  machineId?: string;
  retirement?: { reason: string; at: string; actor?: string };
};

export type Proposal = {
  proposalId: string;
  ownerId: string;
  jobId: string;
  jobVersion: number;
  packageDigest: string;
  action: {
    name: string;
    target: TargetIdentity;
    params: Record<string, unknown>;
  };
  bindingDigest: string;
  revision: number;
  state: ProposalState;
  snoozeUntil?: string;
  question: string;
  rationale?: string;
  evidence: {
    runIds: string[];
    artifacts: ArtifactRef[];
    observedAt?: string;
  };
  waitingOn: WaitingOn;
  allowedVerdicts: Verdict[];
  nativeTask?: { dagName: string; dagRunId: string; stepId: string };
  createdBy?: {
    reviewerClaimId?: string;
    client?: string;
    sessionRef?: string;
  };
  createdAt: string;
};

export type Decision = {
  decisionId: string;
  proposalId: string;
  proposalRevision: number;
  bindingDigest: string;
  jobId: string;
  jobVersion: number;
  ownerId: string;
  verdict: Verdict;
  instructions?: string;
  snoozeUntil?: string;
  actor: { display: string; id?: string };
  client: 'dashboard' | 'cli';
  idempotencyKey: string;
  createdAt: string;
  nativeResume: 'none' | 'pending' | 'completed';
  effectRef?: string;
};

export type DecisionRequest = {
  expectedProposalRevision: number;
  bindingDigest: string;
  verdict: Verdict;
  instructions?: string;
  snoozeUntil?: string;
  idempotencyKey: string;
};

export type InboxReason =
  | 'proposal'
  | 'needs_human'
  | 'unavailable'
  | 'run-failed'
  | 'exception'
  | 'follow-up';

export type InboxItem = {
  reason: InboxReason;
  job: TxeJob;
  proposal?: Proposal;
  waitingOn: WaitingOn;
  failedRun?: RunRef;
  exceptions?: JobException[];
};
