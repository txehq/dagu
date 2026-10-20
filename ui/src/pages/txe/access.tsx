// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import useSWR from 'swr';

import { TxeBindingState } from '@/api/v1/schema';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { RefreshButton } from '@/components/ui/refresh-button';
import { RelativeTime } from '@/components/ui/relative-time';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { AppBarContext } from '@/contexts/AppBarContext';
import { useI18n } from '@/i18n/I18nProvider';
import { I18nText } from '@/i18n/I18nText';

import type { Binding, BindingRequest, Owner } from '@/features/txe/access';
import { TxeApiError } from '@/features/txe/api';
import { useTxeAccessApi } from '@/features/txe/hooks';
import {
  isSSOAdministrator,
  useTxeIdentity,
  type TxeIdentity,
} from '@/features/txe/identity';

// NEW_OWNER is the owner choice that creates an owner before binding.
const NEW_OWNER = '__new__';

// How often the page re-reads requests and bindings while it is open.
const REFRESH_MS = 15_000;

const selectClass =
  'h-8 rounded-md border border-border bg-surface px-2 text-xs text-foreground focus:border-ring focus:outline-none';

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// Who: the username the hub recorded for the person, never matched, and the
// identity it is bound by.
function Identity({
  shown,
  issuer,
  subject,
}: {
  shown: { username?: string };
  issuer: string;
  subject: string;
}): React.ReactElement {
  return (
    <div className="space-y-0.5">
      <div className="text-sm font-medium">{shown.username || '—'}</div>
      <div className="font-mono text-xs text-muted-foreground break-all">
        {issuer} · {subject}
      </div>
    </div>
  );
}

// isOwnRequest is whether the request is the signed-in administrator's own,
// which the hub lets only another administrator approve.
function isOwnRequest(
  identity: TxeIdentity | undefined,
  request: BindingRequest
): boolean {
  return (
    isSSOAdministrator(identity) &&
    identity?.principal.issuer === request.issuer &&
    identity?.principal.subject === request.subject
  );
}

function RequestRow({
  request,
  owners,
  own,
  onChanged,
}: {
  request: BindingRequest;
  owners: Owner[];
  // own is the signed-in administrator's own request.
  own: boolean;
  // onChanged re-reads the page, after an approval or a conflict.
  onChanged: () => Promise<void>;
}): React.ReactElement {
  const { ts } = useI18n();
  const access = useTxeAccessApi();
  const [ownerId, setOwnerId] = React.useState('');
  const [newOwnerName, setNewOwnerName] = React.useState('');
  // created is the owner this row made, reused if the binding then fails, so
  // a retry does not make a second owner.
  const [created, setCreated] = React.useState<Owner>();
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string>();
  const creating = ownerId === NEW_OWNER;
  const ready = creating ? newOwnerName.trim() !== '' : ownerId !== '';

  const approve = async () => {
    setBusy(true);
    setError(undefined);
    try {
      // The administrator names the owner; nothing is matched by name.
      let target = ownerId;
      if (creating) {
        const owner =
          created ?? (await access.createOwner(newOwnerName.trim()));
        setCreated(owner);
        target = owner.owner_id;
      }
      await access.approve(target, request);
      await onChanged();
    } catch (err) {
      const conflict = err instanceof TxeApiError && err.status === 409;
      setError(
        conflict
          ? ts(
              'The request changed since this page read it ({reason}). The list has been read again; approve again.',
              { reason: (err as TxeApiError).message }
            )
          : errorText(err)
      );
      // A conflict means the request moved on: the next attempt must use the
      // generation the hub holds now.
      if (conflict) {
        await onChanged().catch(() => undefined);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <TableRow data-testid="txe-access-request">
      <TableCell>
        <Identity
          shown={request.shown}
          issuer={request.issuer}
          subject={request.subject}
        />
      </TableCell>
      <TableCell className="text-xs">
        <RelativeTime timestamp={request.requested_at} />
      </TableCell>
      <TableCell>
        {own ? (
          <p
            className="text-xs text-muted-foreground"
            data-testid="txe-access-own-request"
          >
            <I18nText text="This is your own request. Another platform administrator has to approve it." />
          </p>
        ) : (
          <div className="flex flex-wrap items-center gap-2">
            <select
              aria-label={ts('Owner')}
              className={selectClass}
              value={ownerId}
              onChange={(e) => setOwnerId(e.target.value)}
              disabled={busy}
            >
              <option value="">{ts('Choose an owner…')}</option>
              {owners.map((owner) => (
                <option key={owner.owner_id} value={owner.owner_id}>
                  {owner.display_name} ({owner.owner_id})
                </option>
              ))}
              <option value={NEW_OWNER}>{ts('New owner…')}</option>
            </select>
            {creating && (
              <Input
                aria-label={ts('New owner name')}
                className="h-8 w-48 text-xs"
                placeholder={ts('New owner name')}
                value={newOwnerName}
                onChange={(e) => setNewOwnerName(e.target.value)}
                disabled={busy || created !== undefined}
              />
            )}
            <Button
              size="sm"
              onClick={() => void approve()}
              disabled={!ready || busy}
            >
              <I18nText text="Approve" />
            </Button>
          </div>
        )}
        {error && (
          <p className="mt-1 text-xs text-destructive" role="alert">
            {error}
          </p>
        )}
      </TableCell>
    </TableRow>
  );
}

function BindingRow({
  binding,
  ownerName,
  onRevoked,
}: {
  binding: Binding;
  ownerName: string;
  onRevoked: () => Promise<void>;
}): React.ReactElement {
  const { ts } = useI18n();
  const access = useTxeAccessApi();
  const [revoking, setRevoking] = React.useState(false);
  const [reason, setReason] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string>();
  const active = binding.state === TxeBindingState.active;

  const revoke = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await access.revoke(binding.owner_id, binding.binding_id, reason.trim());
      setRevoking(false);
      setReason('');
      await onRevoked();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <TableRow data-testid="txe-access-binding">
      <TableCell>
        <Identity
          shown={binding.shown}
          issuer={binding.issuer}
          subject={binding.subject}
        />
      </TableCell>
      <TableCell className="text-sm">{ownerName}</TableCell>
      <TableCell className="text-xs">
        <RelativeTime timestamp={binding.bound.at} />
      </TableCell>
      <TableCell>
        {active ? (
          <Badge variant="success">
            <I18nText text="Active" />
          </Badge>
        ) : (
          <Badge variant="outline">
            <I18nText text="Revoked" />
          </Badge>
        )}
      </TableCell>
      <TableCell>
        {active && !revoking && (
          <Button size="sm" variant="outline" onClick={() => setRevoking(true)}>
            <I18nText text="Revoke" />
          </Button>
        )}
        {active && revoking && (
          <div className="flex flex-wrap items-center gap-2">
            <Input
              aria-label={ts('Reason')}
              className="h-8 w-48 text-xs"
              placeholder={ts('Reason')}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              disabled={busy}
            />
            <Button
              size="sm"
              variant="destructive"
              onClick={() => void revoke()}
              disabled={reason.trim() === '' || busy}
            >
              <I18nText text="Confirm revoke" />
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setRevoking(false)}
              disabled={busy}
            >
              <I18nText text="Cancel" />
            </Button>
          </div>
        )}
        {error && (
          <p className="mt-1 text-xs text-destructive" role="alert">
            {error}
          </p>
        )}
      </TableCell>
    </TableRow>
  );
}

type AccessData = {
  requests: BindingRequest[];
  owners: Owner[];
  bindings: Binding[];
};

// TxeAccessPage is the platform administrator's view of who may act for which
// owner: pending binding requests to approve, and bindings to revoke.
export default function TxeAccessPage(): React.ReactElement {
  const appBarContext = React.useContext(AppBarContext);
  const access = useTxeAccessApi();
  const { identity, reload: reloadIdentity } = useTxeIdentity();
  const [requesting, setRequesting] = React.useState(false);
  const [requestError, setRequestError] = React.useState<string>();
  const { data, error, mutate } = useSWR<AccessData>(
    ['txe', 'access'],
    async () => {
      const [requests, owners] = await Promise.all([
        access.listRequests(),
        access.listOwners(),
      ]);
      const bindings = (
        await Promise.all(owners.map((o) => access.listBindings(o.owner_id)))
      ).flat();
      return { requests, owners, bindings };
    },
    { refreshInterval: REFRESH_MS }
  );
  const reload = async () => {
    await mutate();
  };

  React.useEffect(() => {
    appBarContext.setTitle('Access requests');
  }, [appBarContext]);

  // An SSO administrator who acts for no owner may ask to be bound, as a
  // person does; another administrator approves it.
  const mayRequestOwn =
    isSSOAdministrator(identity) &&
    !identity?.is_person &&
    !identity?.request &&
    !data?.requests.some((r) => isOwnRequest(identity, r));
  const requestOwn = async () => {
    setRequesting(true);
    setRequestError(undefined);
    try {
      await access.requestAccess();
      await Promise.all([reload(), reloadIdentity()]);
    } catch (err) {
      setRequestError(errorText(err));
    } finally {
      setRequesting(false);
    }
  };

  const ownerName = (ownerId: string) =>
    data?.owners.find((o) => o.owner_id === ownerId)?.display_name ?? ownerId;

  return (
    <div className="mx-auto max-w-5xl space-y-6 p-4">
      <div className="flex items-center justify-between">
        <h1 className="text-lg font-semibold">
          <I18nText text="Access requests" />
        </h1>
        <RefreshButton onRefresh={reload} />
      </div>
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{errorText(error)}</AlertDescription>
        </Alert>
      )}
      {!data && !error && (
        <p className="text-sm text-muted-foreground">
          <I18nText text="Loading…" />
        </p>
      )}
      {data && mayRequestOwn && (
        <section className="space-y-2" data-testid="txe-access-request-own">
          <p className="text-sm text-muted-foreground">
            <I18nText text="You administer this hub but act for no owner, so you have no machines or jobs of your own. Ask to be bound to an owner; another platform administrator approves it." />
          </p>
          <Button
            size="sm"
            variant="outline"
            onClick={() => void requestOwn()}
            disabled={requesting}
          >
            <I18nText text="Request access for yourself" />
          </Button>
          {requestError && (
            <p className="text-xs text-destructive" role="alert">
              {requestError}
            </p>
          )}
        </section>
      )}
      {data && (
        <>
          <section className="space-y-2">
            <h2 className="text-sm font-semibold">
              <I18nText text="Waiting for approval" />
            </h2>
            {data.requests.length === 0 ? (
              <p
                className="text-sm text-muted-foreground"
                data-testid="txe-access-no-requests"
              >
                <I18nText text="Nobody is waiting for access." />
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>
                      <I18nText text="Account" />
                    </TableHead>
                    <TableHead>
                      <I18nText text="Requested" />
                    </TableHead>
                    <TableHead>
                      <I18nText text="Approve for" />
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.requests.map((request) => (
                    <RequestRow
                      key={`${request.issuer}|${request.subject}`}
                      request={request}
                      owners={data.owners}
                      own={isOwnRequest(identity, request)}
                      onChanged={reload}
                    />
                  ))}
                </TableBody>
              </Table>
            )}
          </section>
          <section className="space-y-2">
            <h2 className="text-sm font-semibold">
              <I18nText text="Bound accounts" />
            </h2>
            {data.bindings.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                <I18nText text="No account is bound to an owner yet." />
              </p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>
                      <I18nText text="Account" />
                    </TableHead>
                    <TableHead>
                      <I18nText text="Owner" />
                    </TableHead>
                    <TableHead>
                      <I18nText text="Bound" />
                    </TableHead>
                    <TableHead>
                      <I18nText text="State" />
                    </TableHead>
                    <TableHead />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.bindings.map((binding) => (
                    <BindingRow
                      key={binding.binding_id}
                      binding={binding}
                      ownerName={ownerName(binding.owner_id)}
                      onRevoked={reload}
                    />
                  ))}
                </TableBody>
              </Table>
            )}
          </section>
        </>
      )}
    </div>
  );
}
