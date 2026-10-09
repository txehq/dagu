// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { AlertTriangle } from 'lucide-react';
import React from 'react';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { I18nText } from '@/i18n/I18nText';

import { buildDecisionRequest } from '../inbox';
import type { DecisionRequest, Verdict, Proposal } from '../types';

export type DecisionSubmitResult =
  | { ok: true }
  | { ok: false; status: number; message: string };

type Props = {
  proposal: Proposal;
  canDecide: boolean;
  onSubmit: (request: DecisionRequest) => Promise<DecisionSubmitResult>;
  // Called after the server refuses a decision because the proposal changed,
  // so the caller can reload the current revision.
  onStale: () => void;
  now?: () => Date;
};

const RESPONSE_LABELS: Record<Verdict, string> = {
  approve: 'Approve',
  reject: 'Reject',
  redirect: 'Redirect',
  snooze: 'Snooze',
  retry: 'Retry',
  pause: 'Pause job',
  retire: 'Retire job',
};

function newIdempotencyKey(): string {
  return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
}

export function DecisionPanel({
  proposal,
  canDecide,
  onSubmit,
  onStale,
  now = () => new Date(),
}: Props): React.ReactElement {
  const [verdict, setVerdict] = React.useState<Verdict | null>(null);
  const [instructions, setInstructions] = React.useState('');
  const [snoozeUntil, setSnoozeUntil] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);
  const [stale, setStale] = React.useState(false);
  const [submitting, setSubmitting] = React.useState(false);
  // One key per reviewed revision and draft: a retried submit of the same
  // draft replays safely, a changed draft is a new decision attempt.
  const keyRef = React.useRef<string>(newIdempotencyKey());

  // A new revision or proposal discards the draft: a choice made against the
  // previous revision must never be submitted against the new one. The stale
  // notice stays until the person chooses again.
  React.useEffect(() => {
    setVerdict(null);
    setInstructions('');
    setSnoozeUntil('');
    setError(null);
    keyRef.current = newIdempotencyKey();
  }, [proposal.proposalId, proposal.revision, proposal.bindingDigest]);

  const resetAttempt = () => {
    setError(null);
    keyRef.current = newIdempotencyKey();
  };

  const choose = (next: Verdict) => {
    setVerdict(next);
    setStale(false);
    resetAttempt();
  };

  const submit = async () => {
    if (!verdict) return;
    const built = buildDecisionRequest(
      proposal,
      {
        verdict,
        instructions,
        snoozeUntil: snoozeUntil
          ? new Date(snoozeUntil).toISOString()
          : undefined,
      },
      keyRef.current,
      now()
    );
    if ('error' in built) {
      setError(built.error);
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      const result = await onSubmit(built.request);
      if (!result.ok) {
        if (result.status === 409) {
          setStale(true);
          onStale();
        }
        setError(result.message);
      }
    } finally {
      setSubmitting(false);
    }
  };

  if (!canDecide) {
    return (
      <p className="text-sm text-muted-foreground">
        <I18nText text="You do not have permission to decide this proposal." />
      </p>
    );
  }

  return (
    <div className="space-y-3" data-testid="txe-decision-panel">
      <div className="flex flex-wrap gap-2">
        {proposal.allowedVerdicts.map((option) => (
          <Button
            key={option}
            type="button"
            size="sm"
            variant={verdict === option ? 'primary' : 'outline'}
            onClick={() => choose(option)}
            aria-pressed={verdict === option}
          >
            <I18nText text={RESPONSE_LABELS[option]} />
          </Button>
        ))}
      </div>

      {verdict === 'redirect' && (
        <Textarea
          aria-label="Revised instructions"
          placeholder="Revised instructions for the next review"
          value={instructions}
          onChange={(event) => {
            setInstructions(event.target.value);
            resetAttempt();
          }}
        />
      )}
      {verdict === 'snooze' && (
        <Input
          aria-label="Snooze until"
          type="datetime-local"
          value={snoozeUntil}
          onChange={(event) => {
            setSnoozeUntil(event.target.value);
            resetAttempt();
          }}
        />
      )}

      {stale && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertDescription>
            <I18nText text="This proposal changed after you reviewed it. Review the current revision before deciding." />
          </AlertDescription>
        </Alert>
      )}
      {error && !stale && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}

      <Button
        type="button"
        size="sm"
        disabled={!verdict || submitting}
        onClick={() => void submit()}
      >
        <I18nText text="Record decision" />
      </Button>
      <p className="text-xs text-muted-foreground">
        <I18nText
          text="Bound to revision {revision} of this proposal."
          values={{ revision: proposal.revision }}
        />
      </p>
    </div>
  );
}
