// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// A job's DAG is named by its job id.
export const JOB_DAG_NAME = /^job_[0-9A-Z]{26}$/;

// isTxeJobDAGName reports whether `name` is a registered TXE job's DAG,
// whose runs the hub retries only through a TXE decision (TXE-7517).
export function isTxeJobDAGName(
  name: string | undefined | null
): name is string {
  return !!name && JOB_DAG_NAME.test(name);
}

// txeJobRetryPath is the TXE job page, where a job's run is retried by a
// decision: "Run again" or "Publish sealed result".
export function txeJobRetryPath(jobId: string): string {
  return `/txe/jobs/${encodeURIComponent(jobId)}`;
}
