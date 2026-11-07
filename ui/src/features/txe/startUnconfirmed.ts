// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// startUnconfirmedRunId is the run the hub handed over without seeing it
// start (504 start_unconfirmed, TXE-4712), or undefined for any other answer.
export function startUnconfirmedRunId(error: unknown): string | undefined {
  const details = (error as { details?: Record<string, unknown> } | undefined)
    ?.details;
  const runId = details?.dag_run_id;
  return details?.code === 'start_unconfirmed' && typeof runId === 'string'
    ? runId
    : undefined;
}

// StartUnconfirmedError carries that run from a start path that throws on a
// failed answer, so the caller follows the run and never starts it again.
export class StartUnconfirmedError extends Error {
  readonly runId: string;

  constructor(runId: string) {
    super(`The start of run ${runId} was not confirmed`);
    this.name = 'StartUnconfirmedError';
    this.runId = runId;
  }
}
