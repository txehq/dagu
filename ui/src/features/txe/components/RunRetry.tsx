// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';

import { Link } from 'react-router-dom';

import { Button } from '@/components/ui/button';
import { I18nText } from '@/i18n/I18nText';

import type { DecisionSubmitResult } from './DecisionPanel';
import {
  offeredIntents,
  retryLabel,
  type RetryIntent,
  type RetryState,
} from '../retry';
import type { Execution } from '../types';
import { dagRunPath } from './InboxItemCard';

type Props = {
  dagName: string;
  runId: string;
  runStatus: string;
  execution?: Execution;
  state?: RetryState;
  canDecide: boolean;
  // canRepublish is whether the hub takes a person's republish request.
  canRepublish: boolean;
  onRequest: (
    intent: RetryIntent,
    idempotencyKey: string
  ) => Promise<DecisionSubmitResult>;
};

function newKey(): string {
  return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;
}

// RunRetry offers two distinct requests for a finished, unsuccessful run,
// and shows the state of its newest one (TXE-7515):
//
//   - "Publish sealed result" publishes what the execution sealed, without
//     running the job. If that result is no longer intact on the job's
//     machine, nothing is published. It is offered only where the hub takes
//     it.
//   - "Run again" runs the job's script again as a new execution, after a
//     confirmation that says so: any external effect repeats, and a result
//     the execution sealed is superseded and never published.
//
// There is no retry that names neither. A request is a recorded decision:
// the job's machine dispatches it, and it reads as dispatched only once the
// action journal records the dispatch with the new execution the registry
// observed; the run's own status, linked beside it, says how it went.
export function RunRetry({
  dagName,
  runId,
  runStatus,
  execution,
  state,
  canDecide,
  canRepublish,
  onRequest,
}: Props): React.ReactElement | null {
  const [busy, setBusy] = React.useState(false);
  const [confirming, setConfirming] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  // One key per offered request of one intent for one execution: a
  // resubmission after a failure or a lost response replays the same request
  // instead of asking twice, while a request of a later execution, or of the
  // other intent, has a key of its own (the server refuses a key reused for
  // another request).
  const executionKey = execution
    ? `${execution.attemptId}\n${execution.queuedAt}`
    : '';
  const keyRef = React.useRef({
    execution: executionKey,
    keys: { republish: newKey(), rerun: newKey() },
  });
  if (keyRef.current.execution !== executionKey) {
    keyRef.current = {
      execution: executionKey,
      keys: { republish: newKey(), rerun: newKey() },
    };
  }

  const intents = canDecide ? offeredIntents(runStatus, execution, state) : [];
  const offerRepublish = canRepublish && intents.includes('republish');
  const offerRerun = intents.includes('rerun');
  const offer = offerRepublish || offerRerun;
  if (!offer && !state) return null;

  const send = async (intent: RetryIntent) => {
    setBusy(true);
    setError(null);
    try {
      const sent = keyRef.current;
      const result = await onRequest(intent, sent.keys[intent]);
      if (!result.ok) setError(result.message);
      else {
        setConfirming(false);
        if (keyRef.current === sent) {
          keyRef.current = {
            execution: sent.execution,
            keys: { ...sent.keys, [intent]: newKey() },
          };
        }
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

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
      {offerRepublish && !confirming && (
        <Button
          type="button"
          size="xs"
          variant="outline"
          className="ml-2"
          disabled={busy}
          title="Publishes the result this execution sealed. The job is not run again. If that result is no longer intact on the job's machine, nothing is published."
          onClick={() => void send('republish')}
        >
          <I18nText text="Publish sealed result" />
        </Button>
      )}
      {offerRerun && !confirming && (
        <Button
          type="button"
          size="xs"
          variant="outline"
          className="ml-2"
          disabled={busy}
          onClick={() => {
            setError(null);
            setConfirming(true);
          }}
        >
          <I18nText text="Run again" />
        </Button>
      )}
      {offerRerun && confirming && (
        <span role="group" aria-label="Confirm running the job again">
          <span className="ml-2">
            <I18nText text="Runs the job's script again as a new execution. Any external effect the job has happens again. A result this execution sealed is superseded and never published." />
          </span>
          <Button
            type="button"
            size="xs"
            variant="destructive"
            className="ml-2"
            disabled={busy}
            onClick={() => void send('rerun')}
          >
            <I18nText text="Run the job again" />
          </Button>
          <Button
            type="button"
            size="xs"
            variant="outline"
            className="ml-2"
            disabled={busy}
            onClick={() => setConfirming(false)}
          >
            <I18nText text="Cancel" />
          </Button>
        </span>
      )}
      {error && (
        <span role="alert" className="ml-2 text-destructive">
          {error}
        </span>
      )}
    </span>
  );
}
