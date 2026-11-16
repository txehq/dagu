// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

import { RunRetry } from '../components/RunRetry';
import type { RetryIntent, RetryState } from '../retry';

const q1 = '2026-10-09T12:00:00.000000001Z';
const q2 = '2026-10-09T12:00:05.000000001Z';

type Result = { ok: false; status: number; message: string } | { ok: true };

function view(
  queuedAt: string,
  onRequest: (intent: RetryIntent, key: string) => Promise<Result>,
  state?: RetryState,
  canRepublish = true
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
        canRepublish={canRepublish}
        onRequest={onRequest}
      />
    </MemoryRouter>
  );
}

const republishButton = () =>
  screen.getByRole('button', { name: 'Publish sealed result' });
const runAgainButton = () => screen.getByRole('button', { name: 'Run again' });
const confirmButton = () =>
  screen.getByRole('button', { name: 'Run the job again' });

// TXE-7515: the dashboard offers two distinct requests and never a retry
// that names neither.
describe('RunRetry intents', () => {
  it('offers no ambiguous retry', () => {
    render(view(q1, vi.fn()));
    expect(
      screen.queryByRole('button', { name: 'Retry this run' })
    ).not.toBeInTheDocument();
    expect(republishButton()).toBeInTheDocument();
    expect(runAgainButton()).toBeInTheDocument();
  });

  it('publishes the sealed result without running the job', async () => {
    const onRequest = vi.fn().mockResolvedValue({ ok: true });
    render(view(q1, onRequest));
    expect(republishButton()).toHaveAttribute(
      'title',
      expect.stringContaining('The job is not run again')
    );
    fireEvent.click(republishButton());
    await waitFor(() => expect(onRequest).toHaveBeenCalledTimes(1));
    expect(onRequest.mock.calls[0]?.[0]).toBe('republish');
  });

  it('offers no republish where the hub does not take one', () => {
    render(view(q1, vi.fn(), undefined, false));
    expect(
      screen.queryByRole('button', { name: 'Publish sealed result' })
    ).not.toBeInTheDocument();
    expect(runAgainButton()).toBeInTheDocument();
  });

  it('runs the job again only after a confirmation that names its effects', async () => {
    const onRequest = vi.fn().mockResolvedValue({ ok: true });
    render(view(q1, onRequest));
    fireEvent.click(runAgainButton());
    expect(onRequest).not.toHaveBeenCalled();
    expect(
      screen.getByText(/Any external effect the job has happens again/)
    ).toBeInTheDocument();
    expect(
      screen.getByText(/superseded and never published/)
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onRequest).not.toHaveBeenCalled();
    expect(runAgainButton()).toBeInTheDocument();

    fireEvent.click(runAgainButton());
    fireEvent.click(confirmButton());
    await waitFor(() => expect(onRequest).toHaveBeenCalledTimes(1));
    expect(onRequest.mock.calls[0]?.[0]).toBe('rerun');
  });
});

// TXE-7515: a republish the job's machine could not carry out leaves the
// explicit rerun on offer for the same execution, and not the republish.
describe('RunRetry after a request with nothing run', () => {
  it('offers the other intent', () => {
    render(
      view(q1, vi.fn(), {
        runId: 'run-0003',
        intent: 'republish',
        proposalId: 'prp_r',
        attemptId: 'run-0003-a1',
        queuedAt: q1,
        status: 'failed',
      })
    );
    expect(runAgainButton()).toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Publish sealed result' })
    ).not.toBeInTheDocument();
    expect(screen.getByText(/Republish dispatch failed/)).toBeInTheDocument();
  });
});

describe('RunRetry idempotency keys', () => {
  // A lost response leaves the request recorded under its key. Asking again
  // about the same execution with the same intent reuses that key so the
  // server replays it; the other intent, or a new execution, is a new
  // request with a key of its own.
  it('keeps the key for one intent of one execution and takes a new one otherwise', async () => {
    const onRequest = vi
      .fn()
      .mockResolvedValue({ ok: false, status: 0, message: 'network error' });
    const { rerender } = render(view(q1, onRequest));

    fireEvent.click(republishButton());
    await waitFor(() => expect(onRequest).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(republishButton()).not.toBeDisabled());
    fireEvent.click(republishButton());
    await waitFor(() => expect(onRequest).toHaveBeenCalledTimes(2));
    expect(onRequest.mock.calls[1]?.[1]).toBe(onRequest.mock.calls[0]?.[1]);

    fireEvent.click(runAgainButton());
    fireEvent.click(confirmButton());
    await waitFor(() => expect(onRequest).toHaveBeenCalledTimes(3));
    expect(onRequest.mock.calls[2]?.[0]).toBe('rerun');
    expect(onRequest.mock.calls[2]?.[1]).not.toBe(onRequest.mock.calls[0]?.[1]);
    await waitFor(() => expect(confirmButton()).not.toBeDisabled());
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));

    // The lost request ran: the retried execution is the same attempt
    // re-queued, and it failed again.
    rerender(
      view(q2, onRequest, {
        runId: 'run-0003',
        intent: 'republish',
        proposalId: 'prp_r',
        attemptId: 'run-0003-a1',
        queuedAt: q1,
        status: 'succeeded',
        receipt: 'run-0003-a1-8e2c4a1b9f0d3e57',
      })
    );
    await waitFor(() => expect(republishButton()).not.toBeDisabled());
    fireEvent.click(republishButton());
    await waitFor(() => expect(onRequest).toHaveBeenCalledTimes(4));
    expect(onRequest.mock.calls[3]?.[1]).not.toBe(onRequest.mock.calls[0]?.[1]);
    expect(screen.getByText(/Republish dispatched/)).toBeInTheDocument();
  });
});
