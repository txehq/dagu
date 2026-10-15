// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';
import { Link } from 'react-router-dom';

import { Alert, AlertDescription } from '@/components/ui/alert';
import { I18nText } from '@/i18n/I18nText';

import { pendingCount, useTxeMachines } from '../hooks';

// PendingEnrolmentsNotice tells a person in the job inbox that machines of
// their owner are waiting for enrolment approval, so the approval page is
// found without the link `dagu txe enrol` printed. It shows nothing while
// none waits, or when the last read failed: the Machines page reports that.
export function PendingEnrolmentsNotice(): React.ReactElement | null {
  const { data, error } = useTxeMachines({ quiet: true });
  // SWR keeps the last good list when a refresh fails; a count it can no
  // longer confirm is not shown.
  const count = error ? 0 : pendingCount(data);
  if (count === 0) return null;
  return (
    <Alert data-testid="txe-pending-enrolments">
      <AlertDescription>
        <I18nText
          text={
            count === 1
              ? 'A machine is waiting for enrolment approval.'
              : '{count} machine applications are waiting for enrolment approval.'
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
