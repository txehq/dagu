// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

import { render, screen, waitFor } from '@testing-library/react';
import React from 'react';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AppBarContext } from '@/contexts/AppBarContext';
import { PersonScopeContext } from '@/features/txe/personScope';
import { useQuery } from '@/hooks/api';
import { WorkspaceKind } from '@/lib/workspace';
import DAGDetails from '..';

vi.mock('@/features/dags/components/dag-details', () => ({
  DAGHeader: () => <div>Header</div>,
  DAGDetailsContent: vi.fn(
    ({ activeTab, fillHeight, currentDAGRun, dagRunId }) => (
      <div
        data-active-tab={activeTab}
        data-fill-height={String(fillHeight)}
        data-testid="dag-details-content"
      >
        {currentDAGRun
          ? `Output for ${currentDAGRun.dagRunId}`
          : `Loading ${dagRunId}`}
      </div>
    )
  ),
}));

vi.mock('@/hooks/api', () => ({
  useQuery: vi.fn(),
}));

vi.mock('@/hooks/useDAGSSE', () => ({
  useDAGSSE: vi.fn(() => ({})),
}));

vi.mock('@/hooks/useDAGRunSSE', () => ({
  useDAGRunSSE: vi.fn(() => ({})),
}));

vi.mock('@/hooks/useSubDAGRunSSE', () => ({
  useSubDAGRunSSE: vi.fn(() => ({})),
}));

vi.mock('@/hooks/useSSECacheSync', () => ({
  sseFallbackOptions: vi.fn(() => ({})),
  useSSECacheSync: vi.fn(),
}));

const useQueryMock = useQuery as unknown as {
  mockImplementation: (fn: (path: string) => unknown) => void;
};

const appBarValue = {
  selectedRemoteNode: 'local',
  workspaceSelection: { kind: WorkspaceKind.all },
} as never;

const dagData = {
  dag: {
    name: 'release-notes',
    artifacts: { enabled: true },
  },
  latestDAGRun: {
    name: 'release-notes',
    dagRunId: 'run-1',
    artifactsAvailable: true,
  },
  localDags: [],
};

function LocationProbe() {
  const location = useLocation();
  return (
    <span data-testid="location">{location.pathname + location.search}</span>
  );
}

function renderPage(
  initialEntry = '/dags/release-notes',
  personScope = false,
  appBar = appBarValue
) {
  render(
    <PersonScopeContext.Provider value={personScope}>
      <MemoryRouter initialEntries={[initialEntry]}>
        <AppBarContext.Provider value={appBar}>
          <LocationProbe />
          <Routes>
            <Route path="/dags/:fileName" element={<DAGDetails />} />
            <Route path="/dags/:fileName/:tab" element={<DAGDetails />} />
          </Routes>
        </AppBarContext.Provider>
      </MemoryRouter>
    </PersonScopeContext.Provider>
  );
}

describe('DAGDetails page', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useQueryMock.mockImplementation((path) => {
      if (path === '/dags/{fileName}') {
        return {
          data: dagData,
          mutate: vi.fn(),
        } as never;
      }

      return {
        data: undefined,
        mutate: vi.fn(),
      } as never;
    });
  });

  it('uses full-height layout for DAG details content', () => {
    renderPage();

    const content = screen.getByTestId('dag-details-content');
    expect(content).toHaveAttribute('data-fill-height', 'true');
    expect(content.parentElement).toHaveClass('min-h-0');
    expect(content.parentElement).toHaveClass('flex-1');
  });

  it('falls back to the latest run when a pinned run is missing', () => {
    renderPage('/dags/release-notes?dagRunId=missing&dagRunName=release-notes');

    expect(screen.getByText('Output for run-1')).toBeVisible();
  });

  it('redirects the legacy docs tab to the Wiki tab', async () => {
    renderPage('/dags/release-notes/docs?remoteNode=edge');

    expect(screen.getByTestId('dag-details-content')).toHaveAttribute(
      'data-active-tab',
      'wiki'
    );
    await waitFor(() => {
      expect(screen.getByTestId('location')).toHaveTextContent(
        '/dags/release-notes/wiki?remoteNode=edge'
      );
    });
  });

  // The fork does not offer incidents: the tab's URL shows the status tab
  // of the same run.
  it('sends the incidents tab to the status tab of the same run', async () => {
    renderPage(
      '/dags/release-notes/incidents?dagRunId=run-1&dagRunName=release-notes'
    );

    expect(screen.getByTestId('dag-details-content')).toHaveAttribute(
      'data-active-tab',
      'status'
    );
    await waitFor(() => {
      expect(screen.getByTestId('location')).toHaveTextContent(
        '/dags/release-notes?dagRunId=run-1&dagRunName=release-notes'
      );
    });
  });

  // The hub refuses a person a DAG's webhook, settings and notification
  // settings, so a person is not offered those tabs; their URLs show the
  // status tab.
  it.each(['webhook', 'settings', 'notifications'])(
    'sends a person from the %s tab to the status tab',
    async (tab) => {
      renderPage(`/dags/release-notes/${tab}`, true);

      expect(screen.getByTestId('dag-details-content')).toHaveAttribute(
        'data-active-tab',
        'status'
      );
      await waitFor(() => {
        expect(screen.getByTestId('location')).toHaveTextContent(
          /^\/dags\/release-notes$/
        );
      });
    }
  );

  it('keeps the webhook tab outside a person dashboard', () => {
    renderPage('/dags/release-notes/webhook');

    expect(screen.getByTestId('dag-details-content')).toHaveAttribute(
      'data-active-tab',
      'webhook'
    );
  });

  // The hub answers a person the same 404 for another owner's DAG as for
  // one that does not exist.
  it('tells a person only that the job is not found', () => {
    useQueryMock.mockImplementation(
      (path) =>
        ({
          data: undefined,
          error:
            path === '/dags/{fileName}'
              ? { code: 'not_found', message: 'not found' }
              : undefined,
          mutate: vi.fn(),
        }) as never
    );
    renderPage('/dags/job_other', true);

    expect(screen.getByText('Job not found')).toBeInTheDocument();
    expect(screen.queryByTestId('dag-details-content')).not.toBeInTheDocument();
  });

  // A person's dashboard has no workspace selector, so the ordinary
  // dashboard's saved selection must not hide a person's own DAG.
  it.each([
    [true, 'shows'],
    [false, 'hides'],
  ])(
    'with a saved Default selection, person scope %s: %s a workspace DAG',
    (personScope, verdict) => {
      useQueryMock.mockImplementation(
        (path) =>
          ({
            data:
              path === '/dags/{fileName}'
                ? {
                    ...dagData,
                    dag: { ...dagData.dag, labels: ['workspace=ops'] },
                  }
                : undefined,
            mutate: vi.fn(),
          }) as never
      );
      renderPage('/dags/release-notes', personScope, {
        selectedRemoteNode: 'local',
        workspaceSelection: { kind: WorkspaceKind.default },
      } as never);

      const notInWorkspace = screen.queryByText(
        'This DAG is not in the selected workspace.'
      );
      if (verdict === 'shows') {
        expect(screen.getByTestId('dag-details-content')).toBeInTheDocument();
        expect(notInWorkspace).not.toBeInTheDocument();
      } else {
        expect(
          screen.queryByTestId('dag-details-content')
        ).not.toBeInTheDocument();
        expect(notInWorkspace).toBeInTheDocument();
      }
    }
  );
});
