// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import { Link, useParams } from 'react-router-dom';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { RelativeTime } from '@/components/ui/relative-time';
import { AppBarContext } from '@/contexts/AppBarContext';
import { useCanExecute } from '@/contexts/AuthContext';
import { I18nText } from '@/i18n/I18nText';

import { DecisionPanel } from '@/features/txe/components/DecisionPanel';
import { dagRunPath } from '@/features/txe/components/InboxItemCard';
import { RunRetry } from '@/features/txe/components/RunRetry';
import { useJobDetail, useRetryStates, useTxeApi } from '@/features/txe/hooks';
import { isProposalActionable } from '@/features/txe/inbox';
import type { Decision, Proposal } from '@/features/txe/types';

function DecisionHistory({
  decisions,
  onReplay,
}: {
  decisions: Decision[];
  onReplay: (d: Decision) => Promise<string | null>;
}) {
  const [replaying, setReplaying] = React.useState<string | null>(null);
  const [outcome, setOutcome] = React.useState<Record<string, string>>({});
  if (decisions.length === 0) {
    return (
      <p className="text-xs text-muted-foreground">
        <I18nText text="No decisions recorded." />
      </p>
    );
  }
  return (
    <ul className="space-y-1 text-xs" data-testid="txe-decision-history">
      {decisions.map((decision) => (
        <li key={decision.decisionId}>
          <Badge variant="outline">{decision.verdict}</Badge>{' '}
          {decision.actor.display} ·{' '}
          <RelativeTime timestamp={decision.createdAt} /> · rev{' '}
          {decision.proposalRevision} · v{decision.jobVersion}
          {decision.snoozeUntil && <> · until {decision.snoozeUntil}</>}
          {decision.nativeResume === 'pending' && (
            <span className="ml-2" data-testid="txe-follow-up-pending">
              <span className="text-warning">
                <I18nText text="follow-up pending" />
              </span>{' '}
              <Button
                type="button"
                size="xs"
                variant="outline"
                disabled={replaying === decision.decisionId}
                onClick={async () => {
                  setReplaying(decision.decisionId);
                  let message: string | null;
                  try {
                    message = await onReplay(decision);
                  } catch (error) {
                    // A transport failure must leave the control usable.
                    message =
                      error instanceof Error ? error.message : String(error);
                  } finally {
                    setReplaying(null);
                  }
                  setOutcome((o) => ({
                    ...o,
                    [decision.decisionId]: message ?? 'Follow-up completed.',
                  }));
                }}
              >
                <I18nText text="Complete follow-up" />
              </Button>
              {outcome[decision.decisionId] && (
                <span className="ml-2 text-muted-foreground">
                  {outcome[decision.decisionId]}
                </span>
              )}
            </span>
          )}
          {decision.instructions && (
            <p className="whitespace-pre-wrap pl-2 text-muted-foreground">
              {decision.instructions}
            </p>
          )}
        </li>
      ))}
    </ul>
  );
}

function ProposalSection({
  proposal,
  decisions,
  canDecide,
  onChanged,
}: {
  proposal: Proposal;
  decisions: Decision[];
  canDecide: boolean;
  onChanged: () => Promise<unknown>;
}) {
  const api = useTxeApi();
  const actionable = isProposalActionable(proposal, new Date());
  return (
    <section
      className="space-y-2 rounded-md border border-border p-3"
      data-testid="txe-proposal"
    >
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium">{proposal.question}</span>
        <Badge variant={actionable ? 'warning' : 'default'}>
          {proposal.state}
        </Badge>
        <span className="text-xs text-muted-foreground">
          rev {proposal.revision} · bound to v{proposal.jobVersion}
        </span>
        {proposal.state === 'snoozed' && proposal.snoozeUntil && (
          <span className="text-xs">
            <I18nText text="Snoozed until" />{' '}
            <RelativeTime timestamp={proposal.snoozeUntil} />
          </span>
        )}
      </div>
      <p className="text-xs">
        <code>{proposal.action.name}</code>{' '}
        <code>{JSON.stringify(proposal.action.params)}</code> →{' '}
        {proposal.action.target.kind} {proposal.action.target.stableId}
      </p>
      {actionable && (
        <DecisionPanel
          proposal={proposal}
          canDecide={canDecide}
          onSubmit={async (request) => {
            const result = await api.decide(
              proposal.jobId,
              proposal.proposalId,
              request
            );
            if (result.ok) await onChanged();
            return result;
          }}
          onStale={() => void onChanged()}
        />
      )}
      <DecisionHistory
        decisions={decisions.filter(
          (d) => d.proposalId === proposal.proposalId
        )}
        onReplay={async (d) => {
          const result = await api.replayDecision(proposal.jobId, d);
          await onChanged();
          return result.ok ? null : result.message;
        }}
      />
    </section>
  );
}

// TxeJobPage shows a registered job's durable context: purpose, origin,
// targets, schedule, lifecycle, recent runs and its decision history.
export default function TxeJobPage(): React.ReactElement {
  const { jobId } = useParams<{ jobId: string }>();
  const appBarContext = React.useContext(AppBarContext);
  const canDecide = useCanExecute();
  const { data, error, mutate } = useJobDetail(jobId);
  const api = useTxeApi();
  const { data: retries, mutate: mutateRetries } = useRetryStates(jobId);

  React.useEffect(() => {
    appBarContext.setTitle(data?.job.title ?? 'Job');
  }, [appBarContext, data?.job.title]);

  if (error) {
    return (
      <Alert variant="destructive" className="m-4">
        <AlertDescription>
          {error instanceof Error ? error.message : String(error)}
        </AlertDescription>
      </Alert>
    );
  }
  if (!data) {
    return (
      <p className="p-4 text-sm text-muted-foreground">
        <I18nText text="Loading…" />
      </p>
    );
  }

  const { job, proposals, decisions } = data;
  // The newest of the job's own observation and any proposal's evidence, so
  // the job page and the inbox report the same freshness.
  const lastObservation = [
    job.lastObservationAt,
    ...proposals.map((p) => p.evidence.observedAt),
  ]
    .filter((at): at is string => Boolean(at))
    .sort()
    .pop();
  return (
    <div className="mx-auto max-w-5xl space-y-4 p-4" data-testid="txe-job">
      <header className="space-y-1">
        <Link to="/txe" className="text-xs hover:underline">
          ← <I18nText text="Job inbox" />
        </Link>
        <h1 className="text-lg font-semibold">{job.title}</h1>
        <div className="flex flex-wrap gap-2 text-xs">
          <Badge>{job.lifecycle}</Badge>
          <Badge variant={job.availability === 'ready' ? 'success' : 'warning'}>
            {job.availability}
          </Badge>
          <span className="text-muted-foreground">
            {job.jobId} · v{job.version} · {job.packageDigest.slice(0, 19)}…
          </span>
        </div>
      </header>

      <p className="text-sm">{job.purpose}</p>

      <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-xs">
        <dt className="text-muted-foreground">
          <I18nText text="Origin" />
        </dt>
        <dd>
          {[
            job.origin?.repo,
            job.origin?.commit?.slice(0, 12),
            job.origin?.sessionRef,
          ]
            .filter(Boolean)
            .join(' · ') || '-'}
        </dd>
        <dt className="text-muted-foreground">
          <I18nText text="Targets" />
        </dt>
        <dd>
          {job.targets
            .map(
              (t) => `${t.displayName ?? t.stableId} (${t.kind} ${t.stableId})`
            )
            .join(', ')}
        </dd>
        <dt className="text-muted-foreground">
          <I18nText text="Schedule" />
        </dt>
        <dd>
          {job.schedule?.cron ?? '-'} {job.schedule?.timezone}
          {job.schedule?.reviewCadence && (
            <> · review {job.schedule.reviewCadence}</>
          )}
        </dd>
        <dt className="text-muted-foreground">
          <I18nText text="Expected outcomes" />
        </dt>
        <dd>{job.expectedOutcomes?.join('; ') || '-'}</dd>
        <dt className="text-muted-foreground">
          <I18nText text="Last observation" />
        </dt>
        <dd>
          <RelativeTime timestamp={lastObservation} fallback="never" />
        </dd>
        {job.retirement && (
          <>
            <dt className="text-muted-foreground">
              <I18nText text="Retired" />
            </dt>
            <dd>
              {job.retirement.reason} · {job.retirement.at}
              {job.retirement.actor && <> · {job.retirement.actor}</>}
            </dd>
          </>
        )}
      </dl>

      <section className="space-y-1">
        <h2 className="text-sm font-semibold">
          <I18nText text="Recent runs" />
        </h2>
        <ul className="text-xs">
          {job.latestRuns.map((run) => (
            <li key={run.dagRunId}>
              <Link
                className="hover:underline"
                to={dagRunPath(run.dagName, run.dagRunId)}
              >
                {run.dagRunId}
              </Link>{' '}
              {run.status}{' '}
              <RelativeTime timestamp={run.finishedAt ?? run.startedAt} />
              {run.error && (
                <span className="text-destructive"> {run.error}</span>
              )}
              <RunRetry
                dagName={run.dagName}
                runId={run.dagRunId}
                runStatus={run.status}
                execution={run.execution}
                state={retries?.get(run.dagRunId)}
                canDecide={canDecide}
                onRequest={async (key) => {
                  // The button is offered only for a run with a known
                  // execution; the request names exactly that one.
                  if (!run.execution) {
                    return {
                      ok: false,
                      status: 0,
                      message: 'this run has no execution to retry',
                    };
                  }
                  const result = await api.requestRetry(
                    job.jobId,
                    run.dagRunId,
                    run.execution,
                    job.version,
                    key
                  );
                  await mutateRetries();
                  return result;
                }}
              />
            </li>
          ))}
        </ul>
      </section>

      <section className="space-y-2">
        <h2 className="text-sm font-semibold">
          <I18nText text="Proposals and decisions" />
        </h2>
        {proposals.length === 0 && (
          <p className="text-xs text-muted-foreground">
            <I18nText text="No proposals." />
          </p>
        )}
        {proposals.map((proposal) => (
          <ProposalSection
            key={proposal.proposalId}
            proposal={proposal}
            decisions={decisions}
            canDecide={canDecide}
            onChanged={() => mutate()}
          />
        ))}
      </section>
    </div>
  );
}
