// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';

import { Button } from '@/components/ui/button';
import { I18nText } from '@/i18n/I18nText';

import type { DecisionSubmitResult } from './DecisionPanel';
import { canRequestRetry, retryLabel, type RetryState } from '../retry';

type Props = {
  runStatus: string;
  state?: RetryState;
  canDecide: boolean;
  onRequest: (idempotencyKey: string) => Promise<DecisionSubmitResult>;
};

function newKey(): string {
  return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
}

// RunRetry offers "Retry this run" for a finished, unsuccessful run and shows
// the state of its newest retry. A request is a recorded decision: the
// reviewer performs it, and it reads as retried only with a receipt.
export function RunRetry({
  runStatus,
  state,
  canDecide,
  onRequest,
}: Props): React.ReactElement | null {
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  // One key per offered retry: a resubmission after a failure replays the
  // same request instead of asking twice.
  const keyRef = React.useRef(newKey());

  const offer = canDecide && canRequestRetry(runStatus, state);
  if (!offer && !state) return null;

  return (
    <span className="ml-2" data-testid="txe-run-retry">
      {state && (
        <span className="text-muted-foreground">
          <I18nText text={retryLabel(state)} />
          {state.receipt && <> · {state.receipt}</>}
        </span>
      )}
      {offer && (
        <Button
          type="button"
          size="xs"
          variant="outline"
          className="ml-2"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            setError(null);
            try {
              const result = await onRequest(keyRef.current);
              if (result.ok) keyRef.current = newKey();
              else setError(result.message);
            } catch (e) {
              setError(e instanceof Error ? e.message : String(e));
            } finally {
              setBusy(false);
            }
          }}
        >
          <I18nText text="Retry this run" />
        </Button>
      )}
      {error && (
        <span role="alert" className="ml-2 text-destructive">
          {error}
        </span>
      )}
    </span>
  );
}
