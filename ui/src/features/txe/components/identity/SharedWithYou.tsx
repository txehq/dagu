// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';

import { Badge } from '@/components/ui/badge';
import { I18nText } from '@/i18n/I18nText';

type Props = {
  // ownerName is the display name of the owner who shared the job, as the
  // hub reports it.
  ownerName: string;
};

// SharedWithYou marks a job that belongs to another owner and was shared with
// the signed-in account. It is a label; what the account may do is the hub's.
export function SharedWithYou({ ownerName }: Props): React.ReactElement {
  return (
    <Badge variant="info" data-testid="txe-shared-with-you">
      <I18nText
        text="Shared with you by {owner}"
        values={{ owner: ownerName }}
      />
    </Badge>
  );
}
