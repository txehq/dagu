// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';

import { I18nText } from '@/i18n/I18nText';

// EmptyPrivateInbox is the inbox of an account that has access but no jobs
// of its own and none shared with it, such as an engineer's first day.
export function EmptyPrivateInbox(): React.ReactElement {
  return (
    <section className="space-y-1" data-testid="txe-inbox-first">
      <p className="text-sm font-medium">
        <I18nText text="You have no jobs yet" />
      </p>
      <p className="text-sm text-muted-foreground">
        <I18nText text="Jobs you register appear here, and so do jobs another engineer shares with you." />
      </p>
    </section>
  );
}
