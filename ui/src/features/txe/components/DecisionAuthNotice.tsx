// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { I18nText } from '@/i18n/I18nText';

// DecisionAuthNotice explains why decisions are not offered on a hub whose
// authentication cannot identify a person.
export function DecisionAuthNotice(): React.ReactElement {
  return (
    <Alert data-testid="txe-decision-auth-notice">
      <AlertDescription>
        <I18nText text="Decisions are unavailable: this hub's authentication cannot tell a person from a reviewer or job holding the same access. A person must sign in under builtin authentication to approve, reject, redirect, snooze or retry." />
      </AlertDescription>
    </Alert>
  );
}
