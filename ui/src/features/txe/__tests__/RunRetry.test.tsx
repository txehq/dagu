// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

import { RunRetry } from '../components/RunRetry';
import type { RetryState } from '../retry';

const q1 = '2026-10-09T12:00:00.000000001Z';
const q2 = '2026-10-09T12:00:05.000000001Z';

function view(
  queuedAt: string,
  onRequest: (
    key: string
  ) => Promise<{ ok: false; status: number; message: string } | { ok: true }>,
  state?: RetryState
) {
  return (
    <MemoryRouter>
      <RunRetry
        dagName="job_volume_monitor"
        runId="run-0003"
        runStatus="failed"
        execution={{ attemptId: 'run-0003-a1', queuedAt }}
        state={state}
        canDecide
        onRequest={onRequest}
      />
    </MemoryRouter>
  );
}

describe('RunRetry idempotency keys', () => {
  // A lost response leaves the request recorded under its key. Asking again
  // about the same execution reuses that key so the server replays it; once
  // the run has moved to a new execution, a retry of it is a new request.
  it('keeps the key for one execution and takes a new one for the next', async () => {
    const onRequest = vi
      .fn()
      .mockResolvedValue({ ok: false, status: 0, message: 'network error' });
    const { rerender } = render(view(q1, onRequest));
    const button = () => screen.getByRole('button', { name: 'Retry this run' });

    fireEvent.click(button());
    await waitFor(() => expect(onRequest).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(button()).not.toBeDisabled());
    fireEvent.click(button());
    await waitFor(() => expect(onRequest).toHaveBeenCalledTimes(2));
    expect(onRequest.mock.calls[1]?.[0]).toBe(onRequest.mock.calls[0]?.[0]);

    // The lost request ran: the retried execution is the same attempt
    // re-queued, and it failed again.
    rerender(
      view(q2, onRequest, {
        runId: 'run-0003',
        proposalId: 'prp_r',
        attemptId: 'run-0003-a1',
        queuedAt: q1,
        status: 'succeeded',
        receipt: 'run-0003-a1-8e2c4a1b9f0d3e57',
      })
    );
    await waitFor(() => expect(button()).not.toBeDisabled());
    fireEvent.click(button());
    await waitFor(() => expect(onRequest).toHaveBeenCalledTimes(3));
    expect(onRequest.mock.calls[2]?.[0]).not.toBe(onRequest.mock.calls[0]?.[0]);
  });
});
