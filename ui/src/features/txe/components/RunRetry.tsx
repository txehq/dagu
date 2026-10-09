// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';

import { Link } from 'react-router-dom';

import { Button } from '@/components/ui/button';
import { I18nText } from '@/i18n/I18nText';

import type { DecisionSubmitResult } from './DecisionPanel';
import { canRequestRetry, retryLabel, type RetryState } from '../retry';
import type { Execution } from '../types';
import { dagRunPath } from './InboxItemCard';

type Props = {
  dagName: string;
  runId: string;
  runStatus: string;
  execution?: Execution;
  state?: RetryState;
  canDecide: boolean;
  onRequest: (idempotencyKey: string) => Promise<DecisionSubmitResult>;
};

function newKey(): string {
  return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
}

// RunRetry offers "Retry this run" for a finished, unsuccessful run and shows
// the state of its newest retry. A request is a recorded decision: the
// reviewer dispatches it, and it reads as dispatched only once the action
// journal records the dispatch with the new execution the registry observed;
// the run's own status, linked beside it, says how the retried run went.
export function RunRetry({
  dagName,
  runId,
  runStatus,
  execution,
  state,
  canDecide,
  onRequest,
}: Props): React.ReactElement | null {
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  // One key per offered retry of one execution: a resubmission after a
  // failure or a lost response replays the same request instead of asking
  // twice, while a retry of a later execution is a new request with a key of
  // its own (the server refuses a key reused for another execution).
  const executionKey = execution
    ? `${execution.attemptId}\n${execution.queuedAt}`
    : '';
  const keyRef = React.useRef({ execution: executionKey, key: newKey() });
  if (keyRef.current.execution !== executionKey) {
    keyRef.current = { execution: executionKey, key: newKey() };
  }

  const offer = canDecide && canRequestRetry(runStatus, execution, state);
  if (!offer && !state) return null;

  return (
    <span className="ml-2" data-testid="txe-run-retry">
      {state && (
        <span className="text-muted-foreground">
          <I18nText text={retryLabel(state)} />
          {/* The registry accepts a successful dispatch only with the new
              execution it observed, so this receipt is a real execution. */}
          {state.status === 'succeeded' && state.receipt && (
            <>
              {' '}
              <I18nText
                text="as execution {execution}"
                values={{ execution: state.receipt }}
              />
            </>
          )}
          {state.status === 'succeeded' && (
            <>
              {' · '}
              <Link className="hover:underline" to={dagRunPath(dagName, runId)}>
                <I18nText
                  text="run is now {status}"
                  values={{ status: runStatus }}
                />
              </Link>
            </>
          )}
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
              const sent = keyRef.current;
              const result = await onRequest(sent.key);
              if (!result.ok) setError(result.message);
              else if (keyRef.current === sent) {
                keyRef.current = { execution: sent.execution, key: newKey() };
              }
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
