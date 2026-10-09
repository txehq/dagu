// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { DecisionPanel } from '../components/DecisionPanel';
import { fixtureProposal } from '../fixtures';

const now = () => new Date('2026-10-09T10:00:00Z');

describe('DecisionPanel', () => {
  it('submits an approval bound to the reviewed revision', async () => {
    const onSubmit = vi.fn().mockResolvedValue({ ok: true });
    render(
      <DecisionPanel
        proposal={fixtureProposal({ revision: 2 })}
        canDecide
        onSubmit={onSubmit}
        onStale={vi.fn()}
        now={now}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }));
    fireEvent.click(screen.getByRole('button', { name: 'Record decision' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
    expect(onSubmit.mock.calls[0]?.[0]).toMatchObject({
      verdict: 'approve',
      expectedProposalRevision: 2,
      bindingDigest: 'b'.repeat(64),
    });
  });

  it('reuses the idempotency key when the same draft is resubmitted', async () => {
    const onSubmit = vi
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 503, message: 'unavailable' })
      .mockResolvedValueOnce({ ok: true });
    render(
      <DecisionPanel
        proposal={fixtureProposal()}
        canDecide
        onSubmit={onSubmit}
        onStale={vi.fn()}
        now={now}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: 'Reject' }));
    const record = screen.getByRole('button', { name: 'Record decision' });
    fireEvent.click(record);
    await screen.findByRole('alert');
    fireEvent.click(record);
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(2));
    expect(onSubmit.mock.calls[1]?.[0]?.idempotencyKey).toBe(
      onSubmit.mock.calls[0]?.[0]?.idempotencyKey
    );
  });

  it('requires instructions before a redirect is sent', async () => {
    const onSubmit = vi.fn().mockResolvedValue({ ok: true });
    render(
      <DecisionPanel
        proposal={fixtureProposal()}
        canDecide
        onSubmit={onSubmit}
        onStale={vi.fn()}
        now={now}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: 'Redirect' }));
    fireEvent.click(screen.getByRole('button', { name: 'Record decision' }));
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Redirect needs revised instructions.'
    );
    expect(onSubmit).not.toHaveBeenCalled();

    fireEvent.change(screen.getByLabelText('Revised instructions'), {
      target: { value: 'Collect node events before resizing.' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Record decision' }));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledTimes(1));
    expect(onSubmit.mock.calls[0]?.[0]?.instructions).toBe(
      'Collect node events before resizing.'
    );
  });

  it('reports a stale proposal and asks the caller to reload', async () => {
    const onStale = vi.fn();
    render(
      <DecisionPanel
        proposal={fixtureProposal()}
        canDecide
        onSubmit={vi.fn().mockResolvedValue({
          ok: false,
          status: 409,
          message: 'stale_binding',
        })}
        onStale={onStale}
        now={now}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }));
    fireEvent.click(screen.getByRole('button', { name: 'Record decision' }));
    expect(
      await screen.findByText(
        'This proposal changed after you reviewed it. Review the current revision before deciding.'
      )
    ).toBeInTheDocument();
    expect(onStale).toHaveBeenCalledTimes(1);
  });

  // A verdict chosen against one revision must not carry over to the reloaded
  // revision; the person has to review and choose again.
  it('discards the draft when the proposal revision changes', async () => {
    const onSubmit = vi
      .fn()
      .mockResolvedValue({ ok: false, status: 409, message: 'stale_binding' });
    const { rerender } = render(
      <DecisionPanel
        proposal={fixtureProposal({ revision: 1 })}
        canDecide
        onSubmit={onSubmit}
        onStale={vi.fn()}
        now={now}
      />
    );
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }));
    fireEvent.click(screen.getByRole('button', { name: 'Record decision' }));
    await screen.findByText(/This proposal changed/);

    rerender(
      <DecisionPanel
        proposal={fixtureProposal({
          revision: 2,
          bindingDigest: 'd'.repeat(64),
        })}
        canDecide
        onSubmit={onSubmit}
        onStale={vi.fn()}
        now={now}
      />
    );
    expect(screen.getByRole('button', { name: 'Approve' })).toHaveAttribute(
      'aria-pressed',
      'false'
    );
    expect(
      screen.getByRole('button', { name: 'Record decision' })
    ).toBeDisabled();
    expect(screen.getByText(/This proposal changed/)).toBeInTheDocument();
    expect(onSubmit).toHaveBeenCalledTimes(1);
  });

  it('offers retry only on the typed retry proposals', () => {
    render(
      <DecisionPanel
        proposal={fixtureProposal({
          allowedVerdicts: ['approve', 'retry', 'reject'],
        })}
        canDecide
        onSubmit={vi.fn()}
        onStale={vi.fn()}
        now={now}
      />
    );
    expect(
      screen.queryByRole('button', { name: /Retry/ })
    ).not.toBeInTheDocument();
  });

  it('names the two meanings of retry differently', () => {
    const { rerender } = render(
      <DecisionPanel
        proposal={fixtureProposal({
          action: {
            name: 'dagu.retry_run',
            target: { kind: 'dagu.run', stableId: 'run-0003' },
            params: { run_id: 'run-0003' },
          },
          allowedVerdicts: ['retry', 'reject'],
        })}
        canDecide
        onSubmit={vi.fn()}
        onStale={vi.fn()}
        now={now}
      />
    );
    expect(
      screen.getByRole('button', { name: 'Retry this run' })
    ).toBeInTheDocument();
    expect(
      screen.queryByTestId('txe-uncertain-effect')
    ).not.toBeInTheDocument();

    rerender(
      <DecisionPanel
        proposal={fixtureProposal({
          proposalId: 'prp_uncertain',
          action: {
            name: 'txe.uncertain_effect',
            target: { kind: 'k8s.pv', stableId: 'pv-uid-0001' },
            params: {},
          },
          allowedVerdicts: ['approve', 'redirect', 'retry', 'reject'],
        })}
        canDecide
        onSubmit={vi.fn()}
        onStale={vi.fn()}
        now={now}
      />
    );
    expect(
      screen.getByRole('button', {
        name: 'Confirm it did not take effect and allow one retry',
      })
    ).toBeInTheDocument();
    // An escalation is never executed: no approve or redirect.
    expect(
      screen.queryByRole('button', { name: 'Approve' })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('button', { name: 'Redirect' })
    ).not.toBeInTheDocument();
    expect(screen.getByTestId('txe-uncertain-effect')).toHaveTextContent(
      'It has not proved the effect is absent.'
    );
  });

  it('shows no controls without permission', () => {
    render(
      <DecisionPanel
        proposal={fixtureProposal()}
        canDecide={false}
        onSubmit={vi.fn()}
        onStale={vi.fn()}
      />
    );
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });
});
