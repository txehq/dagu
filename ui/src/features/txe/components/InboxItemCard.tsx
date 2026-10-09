// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import { Link } from 'react-router-dom';

import { Badge } from '@/components/ui/badge';
import { RelativeTime } from '@/components/ui/relative-time';
import { I18nText } from '@/i18n/I18nText';

import type { InboxItem, WaitingOn } from '../types';

const WAITING_LABELS: Record<WaitingOn, string> = {
  person: 'Waiting on you',
  agent: 'Waiting on agent review',
  credentials: 'Local login required',
  machine: 'Worker offline',
};

const REASON_LABELS: Record<InboxItem['reason'], string> = {
  proposal: 'Proposed action',
  needs_human: 'Needs a decision',
  unavailable: 'Cannot run',
  'run-failed': 'Latest run failed',
  exception: 'Problem reported',
};

export function dagRunPath(dagName: string, dagRunId: string): string {
  return `/dag-runs/${encodeURIComponent(dagName)}/${encodeURIComponent(dagRunId)}`;
}

type Props = {
  item: InboxItem;
  children?: React.ReactNode;
};

// InboxItemCard shows why a job needs attention with the context a person
// needs to act: purpose, target identity, freshness, evidence and the
// proposed action.
export function InboxItemCard({ item, children }: Props): React.ReactElement {
  const { job, proposal, failedRun } = item;
  const exceptions = item.exceptions ?? [];
  const observedAt =
    proposal?.evidence.observedAt ??
    job.lastObservationAt ??
    job.latestRuns[0]?.finishedAt;

  return (
    <article
      className="space-y-3 rounded-md border border-border p-4"
      data-testid="txe-inbox-item"
      aria-label={job.title}
    >
      <header className="flex flex-wrap items-center gap-2">
        <Link
          to={`/txe/jobs/${encodeURIComponent(job.jobId)}`}
          className="font-medium hover:underline"
        >
          {job.title}
        </Link>
        <Badge variant="outline">
          <I18nText text={REASON_LABELS[item.reason]} />
        </Badge>
        <Badge variant={item.waitingOn === 'person' ? 'warning' : 'secondary'}>
          <I18nText text={WAITING_LABELS[item.waitingOn]} />
        </Badge>
        <span className="text-xs text-muted-foreground">
          {job.lifecycle} · v{job.version}
        </span>
      </header>

      <p className="text-sm">{job.purpose}</p>

      <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-xs">
        <dt className="text-muted-foreground">
          <I18nText text="Targets" />
        </dt>
        <dd>
          {job.targets.map((target) => (
            <span key={`${target.kind}:${target.stableId}`} className="mr-2">
              {target.displayName ?? target.stableId}{' '}
              <span className="text-muted-foreground">
                ({target.kind} {target.stableId})
              </span>
            </span>
          ))}
        </dd>
        <dt className="text-muted-foreground">
          <I18nText text="Last observation" />
        </dt>
        <dd>
          <RelativeTime timestamp={observedAt} fallback="never" />
        </dd>
        {failedRun && (
          <>
            <dt className="text-muted-foreground">
              <I18nText text="Failed run" />
            </dt>
            <dd>
              <Link
                className="hover:underline"
                to={dagRunPath(failedRun.dagName, failedRun.dagRunId)}
              >
                {failedRun.dagRunId}
              </Link>{' '}
              {failedRun.error}
            </dd>
          </>
        )}
      </dl>

      {(exceptions.length > 0 ||
        (job.availability !== 'ready' && job.availabilityDetail)) && (
        <section
          className="space-y-1 rounded-md border border-warning/30 bg-warning/5 p-3 text-xs"
          data-testid="txe-exceptions"
        >
          {job.availability !== 'ready' && job.availabilityDetail && (
            <p>
              <span className="font-medium">{job.availability}</span>:{' '}
              {job.availabilityDetail}
              {job.machineId && (
                <span className="text-muted-foreground">
                  {' '}
                  · {job.machineId}
                </span>
              )}
            </p>
          )}
          {exceptions.map((exception) => (
            <div key={exception.exceptionId}>
              <p>
                <span className="font-medium">{exception.kind}</span>:{' '}
                {exception.detail}{' '}
                <span className="text-muted-foreground">
                  <RelativeTime timestamp={exception.createdAt} />
                </span>
              </p>
              {exception.evidence && exception.evidence.length > 0 && (
                <p className="text-muted-foreground">
                  {exception.evidence.join(' · ')}
                </p>
              )}
            </div>
          ))}
        </section>
      )}

      {proposal && (
        <section className="space-y-2 rounded-md bg-muted/40 p-3">
          <p className="text-sm font-medium">{proposal.question}</p>
          {proposal.rationale && (
            <p className="text-xs text-muted-foreground">
              {proposal.rationale}
            </p>
          )}
          <p className="text-xs">
            <I18nText text="Action" />: <code>{proposal.action.name}</code>{' '}
            <code>{JSON.stringify(proposal.action.params)}</code>{' '}
            <span className="text-muted-foreground">
              → {proposal.action.target.kind} {proposal.action.target.stableId}
            </span>
          </p>
          {(proposal.evidence.runIds.length > 0 ||
            proposal.evidence.artifacts.length > 0) && (
            <ul className="text-xs">
              {proposal.evidence.runIds.map((runId) => (
                <li key={runId}>
                  <Link
                    className="hover:underline"
                    to={dagRunPath(job.jobId, runId)}
                  >
                    run {runId}
                  </Link>
                </li>
              ))}
              {proposal.evidence.artifacts.map((artifact) => (
                <li key={`${artifact.dagRunId}:${artifact.path}`}>
                  <Link
                    className="hover:underline"
                    to={dagRunPath(artifact.dagName, artifact.dagRunId)}
                  >
                    {artifact.path}
                  </Link>
                </li>
              ))}
            </ul>
          )}
          {children}
        </section>
      )}
    </article>
  );
}
