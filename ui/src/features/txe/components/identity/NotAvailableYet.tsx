// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import { Link } from 'react-router-dom';

import { Button } from '@/components/ui/button';
import { I18nText } from '@/i18n/I18nText';

// NotAvailableYet stands in for a dashboard page that the hub does not yet
// serve to a person signed in through the identity provider (workflows, runs,
// queues, events and the rest).
export function NotAvailableYet(): React.ReactElement {
  return (
    <section className="space-y-3" data-testid="txe-not-available">
      <h1 className="text-lg font-semibold">
        <I18nText text="Not available yet" />
      </h1>
      <p className="text-sm text-muted-foreground">
        <I18nText text="This page is not available yet to an account signed in through single sign-on. Your jobs are in the job inbox." />
      </p>
      <Button asChild variant="outline">
        <Link to="/txe">
          <I18nText text="Go to the job inbox" />
        </Link>
      </Button>
    </section>
  );
}
