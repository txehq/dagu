// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import useSWR from 'swr';

import { TxeEnrolmentState } from '@/api/v1/schema';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { RefreshButton } from '@/components/ui/refresh-button';
import { RelativeTime } from '@/components/ui/relative-time';
import {
  TxeRefusal,
  type Enrolment,
  type EnrolmentApplication,
} from '@/features/txe/enrolment';
import { useTxeEnrolmentApi } from '@/features/txe/hooks';
import { useI18n } from '@/i18n/I18nProvider';
import { I18nText } from '@/i18n/I18nText';

// How often the page re-reads the machine's applications and enrolments: a
// machine re-applies at most once a minute while it waits.
const REFRESH_MS = 10_000;

function code(err: unknown): string | undefined {
  return err instanceof TxeRefusal ? err.code : undefined;
}

function status(err: unknown): number | undefined {
  return err instanceof TxeRefusal ? err.status : undefined;
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// Identity is the identity an application or enrolment was signed in with,
// shown in full so the person can check it is the sign-in they made.
function Identity({
  issuer,
  subject,
  clientId,
}: {
  issuer: string;
  subject: string;
  clientId: string;
}): React.ReactElement {
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5 text-xs">
      <dt className="text-muted-foreground">
        <I18nText text="Client" />
      </dt>
      <dd className="font-mono break-all">{clientId}</dd>
      <dt className="text-muted-foreground">
        <I18nText text="Issuer" />
      </dt>
      <dd className="font-mono break-all">{issuer}</dd>
      <dt className="text-muted-foreground">
        <I18nText text="Subject" />
      </dt>
      <dd className="font-mono break-all">{subject}</dd>
    </dl>
  );
}

// Identified is what an approval names: the application's key (class and
// client) and the identity it was signed in with.
type Identified = Pick<
  EnrolmentApplication,
  'class' | 'client_id' | 'issuer' | 'subject'
>;

function sameIdentity(a: Identified, b: Identified): boolean {
  return (
    a.class === b.class &&
    a.client_id === b.client_id &&
    a.issuer === b.issuer &&
    a.subject === b.subject
  );
}

function ApplicationRow({
  application,
  enrolledAs,
  highlighted,
  onChanged,
}: {
  application: EnrolmentApplication;
  // enrolledAs is the active enrolment of exactly this application, if any:
  // the hub keeps an application on file after approving it.
  enrolledAs: Enrolment | undefined;
  highlighted: boolean;
  onChanged: () => Promise<void>;
}): React.ReactElement {
  const api = useTxeEnrolmentApi();
  // readAs is the identity the person read when opening the confirmation.
  // The list refreshes while it is open, and the machine may apply again: with
  // the same identity that only renews the credential, but with another
  // person's sign-in it is no longer the application being confirmed.
  const [readAs, setReadAs] = React.useState<Identified>();
  const [busy, setBusy] = React.useState(false);
  const [outcome, setOutcome] = React.useState<
    | { kind: 'refused'; reason: string }
    | { kind: 'conflict'; reason: string }
    | { kind: 'changed' }
    | { kind: 'stale' }
  >();
  // Re-render when the credential expires, so the row says so even when no
  // refresh brings new data.
  const [, setExpiryTick] = React.useState(0);
  React.useEffect(() => {
    const ms = Date.parse(application.credential_expires) - Date.now();
    if (!(ms > 0)) return;
    const timer = setTimeout(() => setExpiryTick((n) => n + 1), ms + 50);
    return () => clearTimeout(timer);
  }, [application.credential_expires]);
  const expired = Date.parse(application.credential_expires) <= Date.now();
  const changed = readAs !== undefined && !sameIdentity(readAs, application);

  React.useEffect(() => {
    if (!readAs || busy) return;
    if (changed) {
      setReadAs(undefined);
      setOutcome({ kind: 'changed' });
    } else if (expired) {
      // An expired credential cannot be approved; the row says what to do.
      setReadAs(undefined);
    }
  }, [busy, changed, expired, readAs]);

  const approve = async () => {
    // Send only the identity that was read; the current application carries
    // it with its latest credential, or the confirmation is not approved.
    if (!readAs || changed) {
      setReadAs(undefined);
      setOutcome({ kind: 'changed' });
      return;
    }
    setBusy(true);
    setOutcome(undefined);
    try {
      await api.enrol(application);
      setReadAs(undefined);
    } catch (err) {
      setReadAs(undefined);
      // The hub answers conflict for an application that changed, for a
      // class already enrolled with another credential, and for a client
      // that belongs to another machine; its message says which.
      if (code(err) === 'conflict')
        setOutcome({ kind: 'conflict', reason: errorText(err) });
      else if (code(err) === 'credential_stale') setOutcome({ kind: 'stale' });
      else setOutcome({ kind: 'refused', reason: errorText(err) });
    } finally {
      // Read again either way: an approval moves the application to the
      // enrolments, and a refusal means what is on file has changed.
      await onChanged().catch(() => undefined);
      setBusy(false);
    }
  };

  return (
    <li
      className={`space-y-2 rounded-md border p-3 ${highlighted ? 'border-primary' : ''}`}
      data-testid="txe-enrolment-application"
    >
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Badge variant="outline">{application.class}</Badge>
        <span className="text-xs text-muted-foreground">
          <I18nText text="Applied" />{' '}
          <RelativeTime timestamp={application.received_at} />
        </span>
        <span className="text-xs text-muted-foreground">
          <I18nText text="Credential expires" />{' '}
          <RelativeTime timestamp={application.credential_expires} />
        </span>
      </div>
      <Identity
        issuer={application.issuer}
        subject={application.subject}
        clientId={application.client_id}
      />
      {enrolledAs && !readAs ? (
        <p className="text-xs text-muted-foreground">
          <I18nText
            text="Approved: enrolled as generation {generation}."
            values={{ generation: String(enrolledAs.generation) }}
          />
        </p>
      ) : expired ? (
        <p className="text-xs text-muted-foreground">
          <I18nText text="This application's credential has expired. Run `dagu txe enrol --resume` on the machine (or keep `--wait` running) before approving." />
        </p>
      ) : readAs ? (
        <div className="space-y-2">
          <p className="text-xs">
            <I18nText
              text="Approve this machine as a {class} client of your owner, signed in with exactly the identity above?"
              values={{ class: readAs.class }}
            />
          </p>
          <div className="flex gap-2">
            <Button size="sm" onClick={() => void approve()} disabled={busy}>
              <I18nText text="Confirm approval" />
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setReadAs(undefined)}
              disabled={busy}
            >
              <I18nText text="Cancel" />
            </Button>
          </div>
        </div>
      ) : (
        <Button
          size="sm"
          onClick={() => {
            setOutcome(undefined);
            setReadAs({
              class: application.class,
              client_id: application.client_id,
              issuer: application.issuer,
              subject: application.subject,
            });
          }}
          disabled={busy}
        >
          <I18nText text="Approve" />
        </Button>
      )}
      {outcome?.kind === 'conflict' && (
        <p className="text-xs text-destructive" role="alert">
          <I18nText
            text="Not approved: {reason}. The machine's applications and enrolments have been read again."
            values={{ reason: outcome.reason }}
          />
        </p>
      )}
      {outcome?.kind === 'changed' && (
        <p className="text-xs text-destructive" role="alert">
          <I18nText text="Not approved: the machine applied again with another identity while you were confirming. Check the identity above before approving." />
        </p>
      )}
      {outcome?.kind === 'stale' && (
        <p className="text-xs text-destructive" role="alert">
          <I18nText text="Not approved: the machine's credential has expired. Run `dagu txe enrol --resume` on the machine (or keep `--wait` running), then approve the new application." />
        </p>
      )}
      {outcome?.kind === 'refused' && (
        <p className="text-xs text-destructive" role="alert">
          <I18nText
            text="Not approved: {reason}"
            values={{ reason: outcome.reason }}
          />
        </p>
      )}
    </li>
  );
}

function EnrolmentRow({
  enrolment,
  onChanged,
}: {
  enrolment: Enrolment;
  onChanged: () => Promise<void>;
}): React.ReactElement {
  const { ts } = useI18n();
  const api = useTxeEnrolmentApi();
  const [revoking, setRevoking] = React.useState(false);
  const [reason, setReason] = React.useState('');
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string>();
  const active = enrolment.state === TxeEnrolmentState.active;
  // A pending enrolment is a reservation an interrupted approval left; it
  // blocks another credential for the class until it is revoked too.
  const revocable = enrolment.state !== TxeEnrolmentState.revoked;

  const revoke = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await api.revokeEnrolment(
        enrolment.machine_id,
        enrolment.class,
        reason.trim()
      );
      setRevoking(false);
      setReason('');
    } catch (err) {
      setError(errorText(err));
    } finally {
      await onChanged().catch(() => undefined);
      setBusy(false);
    }
  };

  return (
    <li className="space-y-2 py-2" data-testid="txe-enrolment">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Badge variant="outline">{enrolment.class}</Badge>
        <Badge variant={active ? 'success' : 'default'}>
          {enrolment.state}
        </Badge>
        <span className="text-xs text-muted-foreground">
          <I18nText
            text="Generation {generation}"
            values={{ generation: String(enrolment.generation) }}
          />{' '}
          · <RelativeTime timestamp={enrolment.enrolled.at} />
        </span>
        {revocable && !revoking && (
          <Button size="sm" variant="outline" onClick={() => setRevoking(true)}>
            <I18nText text="Revoke" />
          </Button>
        )}
      </div>
      <Identity
        issuer={enrolment.issuer}
        subject={enrolment.subject}
        clientId={enrolment.client_id}
      />
      {revocable && revoking && (
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

// RefusedMachine says why the hub would not show this machine. The hub gives
// the same 404 for a machine that does not exist and for another owner's.
function RefusedMachine({ error }: { error: unknown }): React.ReactElement {
  let text = errorText(error);
  if (status(error) === 404) {
    text =
      "This machine does not exist, or it is not one of your owner's machines.";
  } else if (code(error) === 'unbound') {
    text = 'You act for no owner yet. Ask for access first.';
  } else if (status(error) === 403) {
    text = "Only a person acting for the machine's owner can see it.";
  }
  return (
    <section className="space-y-2" data-testid="txe-machine-not-found">
      <Link to="/txe" className="text-xs hover:underline">
        ← <I18nText text="Job inbox" />
      </Link>
      <h1 className="text-lg font-semibold">
        <I18nText text="Machine not found" />
      </h1>
      <p className="text-sm text-muted-foreground">
        <I18nText text={text} />
      </p>
    </section>
  );
}

// TxeMachinePage is where a person of a machine's owner approves the
// machine's enrolment, after `dagu txe enrol` applied from it, and revokes
// an enrolment. The page shows no secret: an application carries the
// identity the machine signed in with, never its credential.
export default function TxeMachinePage(): React.ReactElement {
  const { machineId = '' } = useParams();
  const [searchParams] = useSearchParams();
  const api = useTxeEnrolmentApi();
  const wantedClass = searchParams.get('class');
  const wantedClient = searchParams.get('client_id');

  const machine = useSWR(['txe', 'machine', machineId], () =>
    api.getMachine(machineId)
  );
  const applications = useSWR(
    machine.data ? ['txe', 'enrolment-applications', machineId] : null,
    () => api.listApplications(machineId),
    { refreshInterval: REFRESH_MS }
  );
  const enrolments = useSWR(
    machine.data ? ['txe', 'enrolments', machineId] : null,
    () => api.listEnrolments(machineId),
    { refreshInterval: REFRESH_MS }
  );
  const reload = async () => {
    await Promise.all([applications.mutate(), enrolments.mutate()]);
  };

  if (machine.error) {
    return (
      <div className="mx-auto max-w-lg p-8">
        <RefusedMachine error={machine.error} />
      </div>
    );
  }
  if (!machine.data) {
    return (
      <div className="p-8 text-sm text-muted-foreground">
        <I18nText text="Loading…" />
      </div>
    );
  }

  const pending = applications.data ?? [];
  return (
    <div className="mx-auto max-w-3xl space-y-6 p-4" data-testid="txe-machine">
      <header className="space-y-1">
        <Link to="/txe" className="text-xs hover:underline">
          ← <I18nText text="Job inbox" />
        </Link>
        <div className="flex items-center justify-between gap-2">
          <h1 className="text-lg font-semibold">{machine.data.display_name}</h1>
          <RefreshButton onRefresh={reload} />
        </div>
        <p className="font-mono text-xs text-muted-foreground">
          {machine.data.machine_id}
        </p>
      </header>

      <section className="space-y-2">
        <h2 className="text-sm font-semibold">
          <I18nText text="Waiting for approval" />
        </h2>
        <p className="text-xs text-muted-foreground">
          <I18nText text="A machine applies with `dagu txe enrol`. Approve only an application you started: check that its client, issuer and subject are the ones the command printed." />
        </p>
        {applications.error && (
          <p className="text-xs text-destructive" role="alert">
            {status(applications.error) === 404 ||
            status(applications.error) === 403 ? (
              <I18nText text="Only a person acting for the machine's owner can see and approve its applications." />
            ) : (
              errorText(applications.error)
            )}
          </p>
        )}
        {applications.data && pending.length === 0 && (
          <p className="text-sm text-muted-foreground">
            <I18nText text="No application is waiting." />
          </p>
        )}
        {pending.length > 0 && (
          <ul className="space-y-2">
            {pending.map((a) => (
              <ApplicationRow
                key={`${a.class}|${a.client_id}`}
                application={a}
                enrolledAs={enrolments.data?.find(
                  (e) =>
                    e.state === TxeEnrolmentState.active &&
                    String(e.class) === String(a.class) &&
                    e.client_id === a.client_id &&
                    e.issuer === a.issuer &&
                    e.subject === a.subject
                )}
                highlighted={
                  a.class === wantedClass && a.client_id === wantedClient
                }
                onChanged={reload}
              />
            ))}
          </ul>
        )}
      </section>

      <section className="space-y-2">
        <h2 className="text-sm font-semibold">
          <I18nText text="Enrolments" />
        </h2>
        {enrolments.error && (
          <p className="text-xs text-destructive" role="alert">
            {errorText(enrolments.error)}
          </p>
        )}
        {enrolments.data && enrolments.data.length === 0 && (
          <p className="text-sm text-muted-foreground">
            <I18nText text="This machine is not enrolled." />
          </p>
        )}
        {enrolments.data && enrolments.data.length > 0 && (
          <ul className="divide-y">
            {enrolments.data.map((e) => (
              <EnrolmentRow
                key={`${e.class}|${e.generation}`}
                enrolment={e}
                onChanged={reload}
              />
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
