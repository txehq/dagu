// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';

import { Button } from '@/components/ui/button';
import { RelativeTime } from '@/components/ui/relative-time';
import { useI18n } from '@/i18n/I18nProvider';
import { I18nTemplate } from '@/i18n/I18nTemplate';
import { I18nText } from '@/i18n/I18nText';

type Props = {
  // requestedAt is when the hub recorded the request (RFC 3339).
  requestedAt: string;
  onSignOut: () => void;
};

// AccessRequestPending is shown to a signed-in account whose request for
// access is recorded and not yet approved.
export function AccessRequestPending({
  requestedAt,
  onSignOut,
}: Props): React.ReactElement {
  const { t } = useI18n();
  return (
    <section className="space-y-3" data-testid="txe-access-pending">
      <h1 className="text-lg font-semibold">
        <I18nText text="Access requested" />
      </h1>
      <p className="text-sm">
        <I18nTemplate
          text="Your request was recorded {time}. The platform administrator has to approve it before this server shows you any jobs."
          values={{ time: <RelativeTime timestamp={requestedAt} /> }}
        />
      </p>
      <Button variant="outline" onClick={onSignOut}>
        {t('auth.signOut')}
      </Button>
    </section>
  );
}
