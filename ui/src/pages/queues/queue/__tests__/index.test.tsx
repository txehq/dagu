// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { components, QueueType } from '@/api/v1/schema';
import { AppBarContext } from '@/contexts/AppBarContext';
import QueueDetailsPage from '..';

const { clientMock, getMock, useQueryMock } = vi.hoisted(() => {
  const get = vi.fn();
  return {
    clientMock: { GET: get },
    getMock: get,
    useQueryMock: vi.fn(),
  };
});

vi.mock('@/hooks/api', () => ({
  useClient: () => clientMock,
  useQuery: useQueryMock,
}));

vi.mock('@/contexts/ConfigContext', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/contexts/ConfigContext')>()),
  useConfig: () => ({
    tz: 'UTC',
    tzOffsetInSec: 0,
    permissions: { runDags: true, writeDags: true },
  }),
}));

const runAccess = vi.hoisted(() => ({
  allowed: undefined as boolean | undefined,
  byJob: new Map<string, boolean>(),
}));
vi.mock('@/features/txe/runAccess', () => ({
  useJobRunAllowed: () => runAccess.allowed,
  useJobsRunAllowed: () => runAccess.byJob,
  ViewOnly: () => <span>View only</span>,
}));

const cappedZeroQueue: components['schemas']['Queue'] = {
  name: 'running-heavy-q',
  type: QueueType.dag_based,
  maxConcurrency: 1,
  runningCount: 0,
  queuedCount: 0,
  queuedCountCapped: true,
  running: [],
};

function renderPage(queue: components['schemas']['Queue']): {
  rerender: () => void;
} {
  useQueryMock.mockReturnValue({
    data: queue,
    error: null,
    isLoading: false,
    isValidating: false,
    mutate: vi.fn(),
  });

  // The tree is built afresh on each render, so a rerender reads the mocks
  // again.
  const tree = () => (
    <MemoryRouter initialEntries={[`/queues/${queue.name}`]}>
      <AppBarContext.Provider
        value={
          {
            selectedRemoteNode: 'local',
            setTitle: vi.fn(),
          } as never
        }
      >
        <Routes>
          <Route path="/queues/:name" element={<QueueDetailsPage />} />
        </Routes>
      </AppBarContext.Provider>
    </MemoryRouter>
  );
  const result = render(tree());
  return { rerender: () => result.rerender(tree()) };
}

// A registered job's queue is named by its job id; its runs are dequeued only
// by a caller the hub lets run the job (TXE-4740).
describe('QueueDetailsPage for a job the caller may only view', () => {
  const jobQueue: components['schemas']['Queue'] = {
    name: 'job_01M4XEETKWKZX504BK65ADBVYB',
    type: QueueType.dag_based,
    maxConcurrency: 1,
    runningCount: 0,
    queuedCount: 1,
    queuedCountCapped: false,
    running: [],
  };
  const item = {
    name: 'job_01M4XEETKWKZX504BK65ADBVYB',
    dagRunId: 'run-1',
    status: 5,
    statusLabel: 'queued',
    queuedAt: '2026-10-21T00:00:00Z',
    startedAt: '',
    finishedAt: '',
  };

  beforeEach(() => {
    getMock.mockReset();
    useQueryMock.mockReset();
    runAccess.byJob = new Map();
    getMock.mockResolvedValue({ data: { items: [item] }, error: undefined });
  });

  it('offers no selection or dequeue', async () => {
    runAccess.allowed = false;
    try {
      renderPage(jobQueue);

      expect(await screen.findByText('View only')).toBeVisible();
      expect(
        screen.queryByRole('button', { name: /Dequeue selected/ })
      ).toBeNull();
      expect(
        screen.queryByRole('button', { name: 'Select all loaded' })
      ).toBeNull();
    } finally {
      runAccess.allowed = undefined;
    }
  });

  it('closes an open confirmation when access is revoked', async () => {
    runAccess.allowed = true;
    try {
      const view = renderPage(jobQueue);
      fireEvent.click(
        await screen.findByRole('button', { name: 'Select all loaded' })
      );
      fireEvent.click(screen.getByRole('button', { name: /Dequeue selected/ }));
      expect(await screen.findByRole('dialog')).toBeInTheDocument();

      runAccess.allowed = false;
      view.rerender();
      await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    } finally {
      runAccess.allowed = undefined;
    }
  });

  it('offers dequeue to a caller the hub lets run the job', async () => {
    runAccess.allowed = true;
    try {
      renderPage(jobQueue);

      expect(
        await screen.findByRole('button', { name: /Dequeue selected/ })
      ).toBeInTheDocument();
      expect(screen.queryByText('View only')).toBeNull();
    } finally {
      runAccess.allowed = undefined;
    }
  });
});

// A custom or shared queue holds runs of several jobs; each item is
// selected, counted and dequeued only when the hub lets the caller run its
// job (TXE-4754). An item with no answer is offered as before.
describe('QueueDetailsPage for a queue of several jobs', () => {
  const OWN = 'job_01M4XEETKWKZX504BK65ADBVYB';
  const SHARED_VIEW_ONLY = 'job_01M4XEETKWKZX504BK65ADBVYC';
  const customQueue: components['schemas']['Queue'] = {
    name: 'nightly-batch',
    type: QueueType.global,
    maxConcurrency: 2,
    runningCount: 0,
    queuedCount: 3,
    queuedCountCapped: false,
    running: [],
  };
  const queuedItem = (name: string, dagRunId: string) => ({
    name,
    dagRunId,
    status: 5,
    statusLabel: 'queued',
    queuedAt: '2026-10-21T00:00:00Z',
    startedAt: '',
    finishedAt: '',
  });
  const items = [
    queuedItem(OWN, 'run-own'),
    queuedItem(SHARED_VIEW_ONLY, 'run-shared'),
    queuedItem('nightly', 'run-plain'),
  ];

  beforeEach(() => {
    getMock.mockReset();
    useQueryMock.mockReset();
    getMock.mockResolvedValue({ data: { items }, error: undefined });
    runAccess.allowed = undefined;
    runAccess.byJob = new Map([
      [OWN, true],
      [SHARED_VIEW_ONLY, false],
    ]);
  });

  it('lets only items the caller may run be selected, and counts only those', async () => {
    const view = renderPage(customQueue);

    const own = await screen.findByRole('checkbox', {
      name: `Select ${OWN} run-own`,
    });
    const shared = screen.getByRole('checkbox', {
      name: `Select ${SHARED_VIEW_ONLY} run-shared`,
    });
    const plain = screen.getByRole('checkbox', {
      name: 'Select nightly run-plain',
    });
    expect(own).toBeEnabled();
    expect(plain).toBeEnabled();
    expect(shared).toBeDisabled();
    expect(shared.closest('div')).toHaveAttribute(
      'title',
      'The hub does not let you run this job.'
    );
    expect(screen.queryByText('View only')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Select all loaded' }));
    expect(await screen.findByText('2 selected of 3 loaded')).toBeVisible();
    expect(own).toBeChecked();
    expect(plain).toBeChecked();
    expect(shared).not.toBeChecked();

    fireEvent.click(screen.getByRole('button', { name: /Dequeue selected/ }));
    const dialog = await screen.findByRole('dialog');
    expect(dialog).toHaveTextContent('2 selected DAG runs');

    // A selected item's access revoked while the confirmation is open:
    // nothing snapshotted may still be submitted.
    runAccess.byJob = new Map([
      [OWN, false],
      [SHARED_VIEW_ONLY, false],
    ]);
    view.rerender();
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(await screen.findByText('1 selected of 3 loaded')).toBeVisible();
  });

  it('offers nothing to select when the caller may run none of the jobs', async () => {
    runAccess.byJob = new Map([
      [OWN, false],
      [SHARED_VIEW_ONLY, false],
    ]);
    getMock.mockResolvedValue({
      data: { items: items.slice(0, 2) },
      error: undefined,
    });
    renderPage(customQueue);

    expect(
      await screen.findByRole('checkbox', { name: `Select ${OWN} run-own` })
    ).toBeDisabled();
    expect(
      screen.getByRole('button', { name: 'Select all loaded' })
    ).toBeDisabled();
    expect(
      screen.getByRole('button', { name: /Dequeue selected/ })
    ).toBeDisabled();
  });
});

describe('QueueDetailsPage', () => {
  beforeEach(() => {
    getMock.mockReset();
    useQueryMock.mockReset();
    runAccess.byJob = new Map();
    getMock.mockResolvedValue({
      data: { items: [] },
      error: undefined,
    });
  });

  it('loads items when a capped lower-bound count is zero', async () => {
    getMock.mockResolvedValueOnce({
      data: { items: [], nextCursor: 'cursor-1' },
      error: undefined,
    });

    renderPage(cappedZeroQueue);

    await waitFor(() => {
      expect(getMock).toHaveBeenCalledWith(
        '/queues/{name}/items',
        expect.any(Object)
      );
    });
    expect(
      await screen.findByText(
        'No visible queued items were returned for this queue.'
      )
    ).toBeVisible();
    expect(
      screen.queryByText('No queued items in this queue.')
    ).not.toBeInTheDocument();

    expect(getMock).toHaveBeenCalledTimes(1);
    fireEvent.click(screen.getByRole('button', { name: 'Continue scanning' }));

    await waitFor(() => {
      expect(getMock).toHaveBeenCalledTimes(2);
    });
    expect(getMock).toHaveBeenNthCalledWith(
      2,
      '/queues/{name}/items',
      expect.objectContaining({
        params: expect.objectContaining({
          query: expect.objectContaining({ cursor: 'cursor-1' }),
        }),
      })
    );
  });

  it('does not load items when an exact count is zero', async () => {
    renderPage({ ...cappedZeroQueue, queuedCountCapped: undefined });

    expect(
      await screen.findByText('No queued items in this queue.')
    ).toBeVisible();
    expect(getMock).not.toHaveBeenCalled();
  });
});
