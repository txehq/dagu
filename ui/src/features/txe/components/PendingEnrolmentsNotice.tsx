// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import { Link } from 'react-router-dom';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { I18nText } from '@/i18n/I18nText';

import { useAwaitingApproval, useTxeMachines } from '../hooks';

// PendingEnrolmentsNotice tells a person in the job inbox that machines of
// their owner are waiting for enrolment approval, so the approval page is
// found without the link `dagu txe enrol` printed. It shows nothing while
// none waits, or when a read failed: the Machines page reports that. An
// application the hub already approved is not counted.
export function PendingEnrolmentsNotice(): React.ReactElement | null {
  const machines = useTxeMachines({ quiet: true });
  const awaiting = useAwaitingApproval(
    machines.error ? undefined : machines.data,
    { quiet: true }
  );
  // SWR keeps the last good data when a refresh fails; a count it can no
  // longer confirm is not shown. A machine whose own reads failed adds
  // nothing; the others still count.
  const count =
    machines.error || awaiting.error || !awaiting.data
      ? 0
      : Object.values(awaiting.data).reduce<number>(
          (sum, n) => sum + (n ?? 0),
          0
        );
  if (count === 0) return null;
  return (
    <Alert data-testid="txe-pending-enrolments">
      <AlertDescription>
        <I18nText
          text={
            count === 1
              ? 'A machine enrolment application is awaiting your approval.'
              : '{count} machine enrolment applications are awaiting your approval.'
          }
          values={{ count: String(count) }}
        />{' '}
        <Link to="/txe/machines" className="font-medium underline">
          <I18nText text="Review machines" />
        </Link>
      </AlertDescription>
    </Alert>
  );
}
