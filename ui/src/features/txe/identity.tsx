// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import { useNavigate } from 'react-router-dom';
import useSWR from 'swr';

import { TxeIdentityState, type components } from '@/api/v1/schema';
import { useAuth } from '@/contexts/AuthContext';
import { useConfig } from '@/contexts/ConfigContext';
import { useClient } from '@/hooks/api';
import { sseManager } from '@/hooks/SSEManager';

import { AccessRequestPending } from './components/identity/AccessRequestPending';
import { NoAccessYet } from './components/identity/NoAccessYet';

export type TxeIdentity = components['schemas']['TxeIdentity'];

// How often a person waiting for access asks again, so an approval shows
// without a reload.
const WAITING_REFRESH_MS = 30_000;

// useTxeIdentity reads who the hub takes the signed-in caller to be
// (GET /txe/identity). It is read only with builtin authentication, the only
// mode in which a person signs in individually. Nothing here is derived from
// an email address or a name.
export function useTxeIdentity(): {
  identity: TxeIdentity | undefined;
  isLoading: boolean;
  error: unknown;
} {
  const config = useConfig();
  const { isAuthenticated, token } = useAuth();
  const client = useClient();
  const enabled = config.authMode === 'builtin' && isAuthenticated;
  const { data, error, isLoading } = useSWR<TxeIdentity>(
    enabled ? ['txe', 'identity', token] : null,
    async () => {
      const res = await client.GET('/txe/identity');
      if (!res.data) {
        // Not known to be a person: the dashboard is shown as before, with
        // its streams, even after a person signed out in this browser.
        sseManager.setRefused(false);
        throw new Error(
          res.error?.message ?? `Request failed (${res.response.status})`
        );
      }
      // The hub refuses every event stream to a person. It is decided here,
      // before any page that would open one is shown.
      sseManager.setRefused(res.data.is_person);
      return res.data;
    },
    {
      refreshInterval: (latest) =>
        latest?.is_person && latest.state !== TxeIdentityState.bound
          ? WAITING_REFRESH_MS
          : 0,
    }
  );
  return { identity: data, isLoading: enabled && isLoading, error };
}

// TxePersonGate shows a person signed in through the identity provider only
// what the hub lets a person reach: nothing until the account acts for an
// owner, then the TXE pages (personApp). Every other caller, and any caller
// whose identity could not be read, gets the dashboard as before (children).
// This is presentation only; the hub refuses a person everything else.
export function TxePersonGate({
  children,
  personApp,
}: {
  children: React.ReactNode;
  personApp: React.ReactNode;
}): React.ReactElement | null {
  const { identity, isLoading } = useTxeIdentity();
  const { logout } = useAuth();
  const navigate = useNavigate();

  const signOut = React.useCallback(async () => {
    const result = await logout();
    navigate(
      result === 'unconfirmed' ? '/login?signout=unconfirmed' : '/login'
    );
  }, [logout, navigate]);

  if (isLoading) {
    return null;
  }
  if (!identity?.is_person) {
    return <>{children}</>;
  }
  if (identity.state === TxeIdentityState.bound) {
    return <>{personApp}</>;
  }
  return (
    <div className="mx-auto max-w-lg p-8">
      {identity.state === TxeIdentityState.pending && identity.request ? (
        <AccessRequestPending
          requestedAt={identity.request.requested_at}
          onSignOut={() => void signOut()}
        />
      ) : (
        <NoAccessYet
          username={identity.principal.shown.username}
          onSignOut={() => void signOut()}
        />
      )}
    </div>
  );
}
