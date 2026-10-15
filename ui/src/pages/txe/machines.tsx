// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import { Link } from 'react-router-dom';

import { Badge } from '@/components/ui/badge';
import { RefreshButton } from '@/components/ui/refresh-button';
import { useTxeMachines } from '@/features/txe/hooks';
import { I18nText } from '@/i18n/I18nText';

// TxeMachinesPage lists the machines the hub lets the caller see: for a
// person, their owner's machines, with the enrolment applications waiting
// for them to approve. Each opens the machine's approval page. The hub
// decides what is listed; an unbound caller gets none.
export default function TxeMachinesPage(): React.ReactElement {
  const { data, error, isLoading, mutate } = useTxeMachines();

  return (
    <div className="mx-auto max-w-3xl space-y-4 p-4" data-testid="txe-machines">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">
          <I18nText text="Machines" />
        </h1>
        <RefreshButton
          onRefresh={async () => {
            await mutate();
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
          <I18nText text="No machines yet. Run `dagu txe enrol` on a machine to enrol it; its application then appears here." />
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
                {(m.pending_applications ?? 0) > 0 && (
                  <Badge variant="warning" className="ml-auto">
                    <I18nText
                      text={
                        m.pending_applications === 1
                          ? '1 pending application'
                          : '{count} pending applications'
                      }
                      values={{ count: String(m.pending_applications) }}
                    />
                  </Badge>
                )}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
