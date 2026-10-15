// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import { Link } from 'react-router-dom';

import { Badge } from '@/components/ui/badge';
import { RefreshButton } from '@/components/ui/refresh-button';
import { useAwaitingApproval, useTxeMachines } from '@/features/txe/hooks';
import { I18nText } from '@/i18n/I18nText';

// MachineBadge says how many applications await the person's approval. The
// hub's count also includes an application it already approved, so the badge
// waits for the applications and enrolments to be read; if that read fails,
// it says only how many applications are on file.
function MachineBadge({
  onFile,
  awaiting,
  failed,
}: {
  onFile: number;
  awaiting: number | undefined;
  failed: boolean;
}): React.ReactElement | null {
  if (onFile <= 0) return null;
  // A failed read outranks counts cached from an earlier one: they may
  // still claim an approval the hub has since made.
  if (failed) {
    return (
      <Badge variant="outline" className="ml-auto">
        <I18nText
          text={
            onFile === 1
              ? '1 application on file'
              : '{count} applications on file'
          }
          values={{ count: String(onFile) }}
        />
      </Badge>
    );
  }
  if (!awaiting) return null;
  return (
    <Badge variant="warning" className="ml-auto">
      <I18nText
        text={
          awaiting === 1 ? '1 awaiting approval' : '{count} awaiting approval'
        }
        values={{ count: String(awaiting) }}
      />
    </Badge>
  );
}

// TxeMachinesPage lists the machines the hub lets the caller see: for a
// person, their owner's machines, with the enrolment applications waiting
// for them to approve. Each opens the machine's approval page. The hub
// decides what is listed; an unbound caller gets none.
export default function TxeMachinesPage(): React.ReactElement {
  const { data, error, isLoading, mutate } = useTxeMachines();
  const awaiting = useAwaitingApproval(error ? undefined : data);

  return (
    <div className="mx-auto max-w-3xl space-y-4 p-4" data-testid="txe-machines">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">
          <I18nText text="Machines" />
        </h1>
        <RefreshButton
          onRefresh={async () => {
            await Promise.all([mutate(), awaiting.mutate()]);
          }}
        />
      </div>
      {error && (
        <p className="text-sm text-destructive" role="alert">
          <I18nText
            text="The machines could not be read: {reason}"
            values={{
              reason: error instanceof Error ? error.message : String(error),
            }}
          />
        </p>
      )}
      {isLoading && !data && (
        <p className="text-sm text-muted-foreground">
          <I18nText text="Loading…" />
        </p>
      )}
      {data && data.length === 0 && (
        <p
          className="text-sm text-muted-foreground"
          data-testid="txe-machines-empty"
        >
          <I18nText text="No machines yet. A machine is listed once the worker installer has registered it for your owner. Then run `dagu txe enrol --client-id <its worker client>` on that machine, and its application appears here to approve." />
        </p>
      )}
      {data && data.length > 0 && (
        <ul className="divide-y rounded-md border">
          {data.map((m) => (
            <li key={m.machine_id} data-testid="txe-machine-row">
              <Link
                to={`/txe/machines/${encodeURIComponent(m.machine_id)}`}
                className="flex flex-wrap items-center gap-3 p-3 hover:bg-muted/50"
              >
                <span className="font-medium">{m.display_name}</span>
                <span className="font-mono text-xs text-muted-foreground">
                  {m.machine_id}
                </span>
                <MachineBadge
                  onFile={m.pending_applications ?? 0}
                  awaiting={awaiting.data?.[m.machine_id] ?? undefined}
                  failed={
                    Boolean(awaiting.error) ||
                    awaiting.data?.[m.machine_id] === null
                  }
                />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
