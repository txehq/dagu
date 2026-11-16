// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { RotateCcw } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

import ActionButton from '@/components/ui/action-button';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { I18nText } from '@/i18n/I18nText';

import { txeJobRetryPath } from '../jobDagName';

type Props = {
  /** The registered job's id, which is its DAG's name. */
  jobId: string;
  label?: boolean | 'wide';
  'data-ww-action'?: string;
};

/**
 * TxeJobRetryButton stands where a run page offers Retry, on a registered TXE
 * job's run. The hub retries such a run only by carrying out a person's TXE
 * decision (TXE-7517), so the generic Retry would always be refused; this
 * button opens the job's TXE page instead, where "Run again" and "Publish
 * sealed result" are.
 */
export function TxeJobRetryButton({
  jobId,
  label,
  'data-ww-action': mark,
}: Props) {
  const navigate = useNavigate();
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span>
          <ActionButton
            label={label}
            icon={<RotateCcw className="h-4 w-4" />}
            data-ww-action={mark}
            data-testid="txe-job-retry"
            onClick={() => navigate(txeJobRetryPath(jobId))}
            className="cursor-pointer"
          >
            <I18nText text={'Retry in TXE'} />
          </ActionButton>
        </span>
      </TooltipTrigger>
      <TooltipContent>
        <p>
          <I18nText
            text={
              "A TXE job's run is retried from its job page: Run again or Publish sealed result"
            }
          />
        </p>
      </TooltipContent>
    </Tooltip>
  );
}
