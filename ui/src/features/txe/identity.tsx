// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import { useNavigate } from 'react-router-dom';
import useSWR from 'swr';

import {
  TxeIdentityPrincipalClass,
  TxeIdentityState,
  type components,
} from '@/api/v1/schema';
import { useAuth } from '@/contexts/AuthContext';
import { useConfig } from '@/contexts/ConfigContext';
import { useClient } from '@/hooks/api';
import { sseManager } from '@/hooks/SSEManager';

import { AccessRequestPending } from './components/identity/AccessRequestPending';
import { useTxeAccessApi } from './hooks';
import { NoAccessYet } from './components/identity/NoAccessYet';

export type TxeIdentity = components['schemas']['TxeIdentity'];

// isTxePerson reports a person signed in through the identity provider, bound
// or not: the caller the hub refuses every route but /txe and every stream.
// It is the principal's class, as the hub decides it. is_person is narrower:
// a person acting for an owner, whose decisions count as a person's.
export function isTxePerson(identity: TxeIdentity | undefined): boolean {
  return identity?.principal.class === TxeIdentityPrincipalClass.person;
}

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
  reload: () => Promise<unknown>;
} {
  const config = useConfig();
  const { isAuthenticated, token } = useAuth();
  const client = useClient();
  const enabled = config.authMode === 'builtin' && isAuthenticated;
  const { data, error, isLoading, mutate } = useSWR<TxeIdentity>(
    enabled ? ['txe', 'identity', token] : null,
    async () => {
      const res = await client.GET('/txe/identity');
      if (!res.data) {
        throw new Error(
          res.error?.message ?? `Request failed (${res.response.status})`
        );
      }
      return res.data;
    },
    {
      refreshInterval: (latest) =>
        isTxePerson(latest) && latest?.state !== TxeIdentityState.bound
          ? WAITING_REFRESH_MS
          : 0,
    }
  );
  return {
    identity: data,
    isLoading: enabled && isLoading,
    error,
    reload: mutate,
  };
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
  const { identity, isLoading, reload } = useTxeIdentity();
  const { logout } = useAuth();
  const access = useTxeAccessApi();
  const [requesting, setRequesting] = React.useState(false);
  const [requestError, setRequestError] = React.useState<string>();
  const navigate = useNavigate();

  // The hub refuses every event stream to a person. The refusal follows the
  // identity of the current session only, so a late answer for an earlier
  // session cannot set it, and a caller whose identity could not be read
  // gets streams as before.
  const isPerson = isTxePerson(identity);
  React.useEffect(() => {
    if (!isLoading) {
      sseManager.setRefused(isPerson);
    }
  }, [isLoading, isPerson]);

  const signOut = React.useCallback(async () => {
    const result = await logout();
    navigate(
      result === 'unconfirmed' ? '/login?signout=unconfirmed' : '/login'
    );
  }, [logout, navigate]);

  // Asking for access happens only on the person's press, never on display.
  const requestAccess = async () => {
    setRequesting(true);
    setRequestError(undefined);
    try {
      await access.requestAccess();
      await reload();
    } catch (err) {
      setRequestError(err instanceof Error ? err.message : String(err));
    } finally {
      setRequesting(false);
    }
  };

  if (isLoading) {
    return null;
  }
  if (!identity || !isPerson) {
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
          onRequestAccess={() => void requestAccess()}
          requesting={requesting}
          requestError={requestError}
          onSignOut={() => void signOut()}
        />
      )}
    </div>
  );
}
