// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';

import { Button } from '@/components/ui/button';
import { useI18n } from '@/i18n/I18nProvider';
import { I18nText } from '@/i18n/I18nText';

type Props = {
  // username is the account's name as the hub's own user record holds it,
  // shown as text. Nothing is matched or decided on it.
  username?: string;
  // onRequestAccess records a request for the signed-in account. It runs only
  // when the person presses the button, never on display.
  onRequestAccess: () => void;
  requesting?: boolean;
  // requestError is why the last request was not recorded.
  requestError?: string;
  onSignOut: () => void;
};

// NoAccessYet is shown to a signed-in account that the hub has not given
// access to anything: no jobs, no inbox, only a way to ask for access.
export function NoAccessYet({
  username,
  onRequestAccess,
  requesting = false,
  requestError,
  onSignOut,
}: Props): React.ReactElement {
  const { t } = useI18n();
  const who = username?.trim() || undefined;
  return (
    <section className="space-y-3" data-testid="txe-no-access">
      <h1 className="text-lg font-semibold">
        <I18nText text="You have no access yet" />
      </h1>
      <p className="text-sm">
        {who ? (
          <I18nText
            text="You are signed in as {who}, but this server has not given your account access to any jobs."
            values={{ who }}
          />
        ) : (
          <I18nText text="You are signed in, but this server has not given your account access to any jobs." />
        )}
      </p>
      <p className="text-sm text-muted-foreground">
        <I18nText text="Request access, and the platform administrator can approve it." />
      </p>
      {requestError && (
        <p
          className="text-sm text-destructive"
          role="alert"
          data-testid="txe-no-access-error"
        >
          <I18nText
            text="The request was not recorded: {message}"
            values={{ message: requestError }}
          />
        </p>
      )}
      <div className="flex gap-2">
        <Button onClick={onRequestAccess} disabled={requesting}>
          {requesting ? (
            <I18nText text="Requesting…" />
          ) : (
            <I18nText text="Request access" />
          )}
        </Button>
        <Button variant="outline" onClick={onSignOut}>
          {t('auth.signOut')}
        </Button>
      </div>
    </section>
  );
}
