// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { RefreshButton } from '@/components/ui/refresh-button';
import { AppBarContext } from '@/contexts/AppBarContext';
import { useCanExecute } from '@/contexts/AuthContext';
import { I18nText } from '@/i18n/I18nText';

import { DecisionPanel } from '@/features/txe/components/DecisionPanel';
import { InboxItemCard } from '@/features/txe/components/InboxItemCard';
import { useInboxData, useTxeApi } from '@/features/txe/hooks';
import { buildInbox } from '@/features/txe/inbox';

// TxeInboxPage lists registered jobs that need attention, with the context
// and proposed action needed to decide.
export default function TxeInboxPage(): React.ReactElement {
  const appBarContext = React.useContext(AppBarContext);
  const canDecide = useCanExecute();
  const api = useTxeApi();
  const { data, error, isLoading, mutate } = useInboxData();

  React.useEffect(() => {
    appBarContext.setTitle('Job inbox');
  }, [appBarContext]);

  const items = React.useMemo(
    () => (data ? buildInbox(data.jobs, data.proposals, new Date()) : []),
    [data]
  );

  return (
    <div className="mx-auto max-w-5xl space-y-4 p-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">
          <I18nText text="Job inbox" />
        </h1>
        <RefreshButton
          onRefresh={async () => {
            await mutate();
          }}
        />
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>
            {error instanceof Error ? error.message : String(error)}
          </AlertDescription>
        </Alert>
      )}
      {isLoading && !data && (
        <p className="text-sm text-muted-foreground">
          <I18nText text="Loading…" />
        </p>
      )}
      {data && items.length === 0 && (
        <p
          className="text-sm text-muted-foreground"
          data-testid="txe-inbox-empty"
        >
          <I18nText text="Nothing needs your attention." />
        </p>
      )}

      {items.map((item) => (
        <InboxItemCard
          key={`${item.job.jobId}:${item.proposal?.proposalId ?? item.reason}`}
          item={item}
        >
          {item.proposal && (
            <DecisionPanel
              proposal={item.proposal}
              canDecide={canDecide}
              onSubmit={async (request) => {
                const result = await api.decide(
                  item.job.jobId,
                  item.proposal!.proposalId,
                  request
                );
                if (result.ok) await mutate();
                return result;
              }}
              onStale={() => void mutate()}
            />
          )}
        </InboxItemCard>
      ))}
    </div>
  );
}
