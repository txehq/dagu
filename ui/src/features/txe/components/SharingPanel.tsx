// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import useSWR from 'swr';

import {
  TxeAccessPermission,
  TxeAccessResourceKind,
  TxeShareState,
} from '@/api/v1/schema';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { RelativeTime } from '@/components/ui/relative-time';
import { useI18n } from '@/i18n/I18nProvider';
import { I18nText } from '@/i18n/I18nText';

import type { Share, SharePermission } from '../access';
import { useTxeAccessApi } from '../hooks';

// The permissions an owner may share. administer is never shared.
const SHAREABLE: SharePermission[] = [
  TxeAccessPermission.view,
  TxeAccessPermission.author,
  TxeAccessPermission.execute,
  TxeAccessPermission.approve,
];

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function ShareRow({
  share,
  onRevoked,
}: {
  share: Share;
  onRevoked: () => Promise<void>;
}): React.ReactElement {
  const { ts } = useI18n();
  const access = useTxeAccessApi();
  const [revoking, setRevoking] = React.useState(false);
  const [reason, setReason] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string>();
  const active = share.state === TxeShareState.active;

  const revoke = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await access.revokeShare(share.share_id, reason.trim());
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
    <li className="space-y-1 py-2" data-testid="txe-share">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="font-medium">{share.grantee.display_name}</span>
        <span className="font-mono text-xs text-muted-foreground">
          {share.grantee.owner_id}
        </span>
        {share.permissions.map((p) => (
          <Badge key={p} variant="outline">
            {p}
          </Badge>
        ))}
        <span className="text-xs text-muted-foreground">
          <RelativeTime timestamp={share.granted.at} />
        </span>
        {!active && (
          <Badge variant="default">
            <I18nText text="Revoked" />
          </Badge>
        )}
        {active && !revoking && (
          <Button size="sm" variant="outline" onClick={() => setRevoking(true)}>
            <I18nText text="Revoke" />
          </Button>
        )}
      </div>
      {active && revoking && (
        <div className="flex flex-wrap items-center gap-2">
          <Input
            aria-label={ts('Reason')}
            className="h-8 w-56 text-xs"
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
        <p className="text-xs text-destructive" role="alert">
          {error}
        </p>
      )}
    </li>
  );
}

// SharingPanel lets the job's owner share it with another owner, named by
// its exact owner id (there is no directory of owners), and revoke shares.
export function SharingPanel({ jobId }: { jobId: string }): React.ReactElement {
  const { ts } = useI18n();
  const access = useTxeAccessApi();
  const { data, error, mutate } = useSWR(['txe', 'shares'], () =>
    access.listShares()
  );
  const [grantee, setGrantee] = React.useState('');
  const [permissions, setPermissions] = React.useState<SharePermission[]>([
    TxeAccessPermission.view,
  ]);
  const [busy, setBusy] = React.useState(false);
  const [grantError, setGrantError] = React.useState<string>();
  const [granted, setGranted] = React.useState<string>();

  const shares = (data?.granted ?? []).filter(
    (s) =>
      s.resource.kind === TxeAccessResourceKind.job && s.resource.id === jobId
  );
  const reload = async () => {
    await mutate();
  };
  const toggle = (p: SharePermission) =>
    setPermissions((current) =>
      current.includes(p) ? current.filter((x) => x !== p) : [...current, p]
    );

  const share = async () => {
    setBusy(true);
    setGrantError(undefined);
    setGranted(undefined);
    try {
      const created = await access.shareJob(
        jobId,
        grantee.trim(),
        SHAREABLE.filter((p) => permissions.includes(p))
      );
      // The hub names the grantee; the person typed only an id.
      setGranted(created.grantee.display_name);
      setGrantee('');
      await reload();
    } catch (err) {
      setGrantError(errorText(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="space-y-2" data-testid="txe-sharing">
      <h2 className="text-sm font-semibold">
        <I18nText text="Sharing" />
      </h2>
      <p className="text-xs text-muted-foreground">
        <I18nText text="Share this job with another owner by their exact owner id. Sharing never transfers ownership, and you can revoke it." />
      </p>
      {error && (
        <p className="text-xs text-destructive" role="alert">
          {errorText(error)}
        </p>
      )}
      {data && shares.length === 0 && (
        <p className="text-sm text-muted-foreground">
          <I18nText text="This job is not shared." />
        </p>
      )}
      {shares.length > 0 && (
        <ul className="divide-y">
          {shares.map((s) => (
            <ShareRow key={s.share_id} share={s} onRevoked={reload} />
          ))}
        </ul>
      )}
      <div className="flex flex-wrap items-center gap-3">
        <Input
          aria-label={ts('Owner id')}
          className="h-8 w-72 font-mono text-xs"
          placeholder="own_…"
          value={grantee}
          onChange={(e) => setGrantee(e.target.value)}
          disabled={busy}
        />
        {SHAREABLE.map((p) => (
          <label key={p} className="flex items-center gap-1 text-xs">
            <input
              type="checkbox"
              checked={permissions.includes(p)}
              onChange={() => toggle(p)}
              disabled={busy}
            />
            {p}
          </label>
        ))}
        <Button
          size="sm"
          onClick={() => void share()}
          disabled={grantee.trim() === '' || permissions.length === 0 || busy}
        >
          <I18nText text="Share" />
        </Button>
      </div>
      {granted && (
        <p className="text-xs text-muted-foreground" role="status">
          <I18nText text="Shared with {owner}." values={{ owner: granted }} />
        </p>
      )}
      {grantError && (
        <p className="text-xs text-destructive" role="alert">
          <I18nText
            text="The job was not shared: {message}"
            values={{ message: grantError }}
          />
        </p>
      )}
    </section>
  );
}
