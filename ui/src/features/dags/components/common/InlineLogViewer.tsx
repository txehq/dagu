// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

import { useEffect, useRef } from 'react';
import { useRemoteNode } from '@/contexts/RemoteNodeContext';
import { useQuery } from '@/hooks/api';
import { whenEnabled } from '@/hooks/queryUtils';
import { AnsiLine } from '@/lib/ansi';
import { components, Stream } from '../../../../api/v1/schema';
import { I18nText } from '@/i18n/I18nText';

// How often a step's log is fetched again while the step can still write to it.
const LIVE_LOG_REFRESH_MS = 2000;

/**
 * Simple inline log viewer - no controls, just logs
 *
 * The log is fetched again every two seconds only while `live` is set: while
 * the step is running or retrying. A finished, failed or waiting step's log is
 * fetched once, plus once more when the step stops, so its last lines are
 * shown; a page left open on a finished run does not keep asking for it.
 */
export function InlineLogViewer({
  dagName,
  dagRunId,
  stepName,
  stream,
  dagRun,
  live,
}: {
  dagName: string;
  dagRunId: string;
  stepName: string;
  stream: components['schemas']['Stream'];
  dagRun?: components['schemas']['DAGRunDetails'];
  live: boolean;
}) {
  const remoteNode = useRemoteNode();
  const refreshInterval = live ? LIVE_LOG_REFRESH_MS : 0;

  // Determine if this is a sub DAG run - check both rootDAGRunId AND rootDAGRunName
  const isSubDAGRun =
    dagRun &&
    dagRun.rootDAGRunId &&
    dagRun.rootDAGRunName &&
    dagRun.rootDAGRunId !== dagRun.dagRunId;

  // Fetch sub-DAG-run step log (only when isSubDAGRun is true)
  const subDAGQuery = useQuery(
    '/dag-runs/{name}/{dagRunId}/sub-dag-runs/{subDAGRunId}/steps/{stepName}/log',
    whenEnabled(!!isSubDAGRun, {
      params: {
        query: {
          remoteNode,
          stream,
          tail: 100,
        },
        path: {
          name: dagRun?.rootDAGRunName as string,
          dagRunId: dagRun?.rootDAGRunId as string,
          subDAGRunId: dagRun?.dagRunId as string,
          stepName,
        },
      },
    }),
    {
      refreshInterval,
      revalidateOnFocus: false,
    }
  );

  // Fetch regular DAG-run step log (only when isSubDAGRun is false)
  const dagRunQuery = useQuery(
    '/dag-runs/{name}/{dagRunId}/steps/{stepName}/log',
    whenEnabled(!isSubDAGRun, {
      params: {
        query: {
          remoteNode,
          stream,
          tail: 100,
        },
        path: {
          name: dagName,
          dagRunId,
          stepName,
        },
      },
    }),
    {
      refreshInterval,
      revalidateOnFocus: false,
    }
  );

  // Use the appropriate query based on whether this is a sub-DAG-run
  const { data, isLoading, mutate } = isSubDAGRun ? subDAGQuery : dagRunQuery;

  // When the step stops, fetch once more: the last poll may predate its last
  // lines.
  const wasLive = useRef(live);
  useEffect(() => {
    if (wasLive.current && !live) {
      void mutate();
    }
    wasLive.current = live;
  }, [live, mutate]);

  // Process log content
  const content = data?.content || '';
  const lines = content ? content.split('\n') : [];
  const totalLines = data?.totalLines || 0;
  const lineCount = data?.lineCount || 0;

  return (
    <div className="bg-muted rounded overflow-hidden border border-border">
      {isLoading && !data ? (
        <div className="text-muted-foreground text-xs py-4 px-3">
          <I18nText text={'Loading logs...'} />
        </div>
      ) : lines.length === 0 ? (
        <div className="text-muted-foreground text-xs py-4 px-3">
          <I18nText text={'<No log output>'} />
        </div>
      ) : (
        <div className="overflow-x-auto max-h-[400px] overflow-y-auto">
          <pre className="font-mono text-xs text-foreground p-2">
            {lines.map((line, index) => {
              const lineNumber = totalLines - lineCount + index + 1;
              return (
                <div key={index} className="flex px-1 py-0.5">
                  <span className="text-muted-foreground mr-3 select-none w-12 text-right flex-shrink-0">
                    {lineNumber}
                  </span>
                  <span className="whitespace-pre-wrap break-all flex-grow">
                    {line ? <AnsiLine text={line} /> : ' '}
                  </span>
                </div>
              );
            })}
          </pre>
        </div>
      )}
    </div>
  );
}

export { Stream };
