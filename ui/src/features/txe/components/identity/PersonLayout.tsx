// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import { Link } from 'react-router-dom';

import { LanguageSelector } from '@/components/LanguageSelector';
import { UserMenu } from '@/components/UserMenu';
import { useConfig } from '@/contexts/ConfigContext';
import { useI18n } from '@/i18n/I18nProvider';
import { I18nText } from '@/i18n/I18nText';

import { useTxeIdentity } from '../../identity';

// PersonLayout frames the pages a person signed in through the identity
// provider can reach. It loads nothing from the dashboard's other routes,
// which the hub refuses a person.
export function PersonLayout({
  children,
}: {
  children: React.ReactNode;
}): React.ReactElement {
  const config = useConfig();
  const { t } = useI18n();
  const { identity } = useTxeIdentity();
  return (
    <div className="flex min-h-screen flex-col bg-background">
      <header className="flex h-12 items-center gap-3 overflow-hidden border-b border-sidebar-border bg-sidebar px-4 text-sidebar-foreground">
        <span className="shrink-0 font-semibold tracking-tight">
          {config.title || 'Dagu'}
        </span>
        {/* On a narrow screen the links scroll, and the account stays. */}
        <nav className="flex min-w-0 flex-1 items-center gap-4 overflow-x-auto whitespace-nowrap">
          <Link to="/txe" className="text-sm hover:underline">
            <I18nText text="Job inbox" />
          </Link>
          <Link to="/dags" className="text-sm hover:underline">
            <I18nText text="Workflows" />
          </Link>
          <Link to="/dag-runs" className="text-sm hover:underline">
            <I18nText text="Executions" />
          </Link>
          <Link to="/queues" className="text-sm hover:underline">
            <I18nText text="Queues" />
          </Link>
          <Link to="/txe/machines" className="text-sm hover:underline">
            <I18nText text="Machines" />
          </Link>
          <Link to="/integrations" className="text-sm hover:underline">
            {t('navigation.developerSetup')}
          </Link>
        </nav>
        <div className="flex shrink-0 items-center gap-2">
          <LanguageSelector variant="sidebar" compact />
          <div className="w-28 sm:w-40">
            <UserMenu
              side="bottom"
              actingFor={identity?.owners[0]?.display_name}
            />
          </div>
        </div>
      </header>
      <main className="flex-1 overflow-auto">{children}</main>
    </div>
  );
}
