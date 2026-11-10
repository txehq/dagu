// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

import type { useClient } from '@/hooks/api';

/**
 * How a run's runtime profile state compares with the state a step run of
 * the workflow would take now, as the server decides it
 * (`POST /dags/{fileName}/reuse-runtime`): only `same` may be reused without
 * the user naming the run. The browser never sees, holds or derives an
 * identity (TXE-6145).
 */
export type RuntimeMatch = 'same' | 'different' | 'unknown';

/** The most runs that one request compares (the server's bound). */
export const MAX_RUNTIME_RUNS = 50;

type Client = ReturnType<typeof useClient>;

/**
 * Asks the server how each run compares. `spec` is the unsaved text when the
 * step runs from it: the server then decides as for that draft. A failed
 * request answers `unknown` for its runs: no automatic reuse.
 */
export async function requestReuseRuntime(
  client: Client,
  p: {
    fileName: string;
    dagName: string;
    remoteNode: string;
    runIds: readonly string[];
    spec?: string;
  }
): Promise<Record<string, RuntimeMatch>> {
  const ids = [...new Set(p.runIds)];
  const answers: Record<string, RuntimeMatch> = Object.fromEntries(
    ids.map((id) => [id, 'unknown' as RuntimeMatch])
  );
  for (let at = 0; at < ids.length; at += MAX_RUNTIME_RUNS) {
    const chunk = ids.slice(at, at + MAX_RUNTIME_RUNS);
    try {
      const { data } = await client.POST('/dags/{fileName}/reuse-runtime', {
        params: {
          path: { fileName: p.fileName },
          query: { remoteNode: p.remoteNode },
        },
        body: {
          runIds: chunk,
          ...(p.spec !== undefined ? { spec: p.spec, name: p.dagName } : {}),
        },
      });
      for (const run of data?.runs ?? []) {
        if (chunk.includes(run.dagRunId)) answers[run.dagRunId] = run.runtime;
      }
    } catch {
      // Unknown: the runs of the chunk stay unknown.
    }
  }
  return answers;
}
