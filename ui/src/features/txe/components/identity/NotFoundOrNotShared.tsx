// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import { Link } from 'react-router-dom';

import { I18nText } from '@/i18n/I18nText';

// NotFoundOrNotShared is what a job page shows when the hub answers that the
// job is not there. The hub gives the same answer for a job that does not
// exist and for one the caller may not see, so this says the same for both.
export function NotFoundOrNotShared(): React.ReactElement {
  return (
    <section className="space-y-2" data-testid="txe-job-not-found">
      <Link to="/txe" className="text-xs hover:underline">
        ← <I18nText text="Job inbox" />
      </Link>
      <h1 className="text-lg font-semibold">
        <I18nText text="Job not found" />
      </h1>
      <p className="text-sm text-muted-foreground">
        <I18nText text="This job does not exist, or it has not been shared with you." />
      </p>
    </section>
  );
}
