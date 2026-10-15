// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

import { render, screen } from '@testing-library/react';
import React from 'react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AppBarContext } from '@/contexts/AppBarContext';
import { useBoundedDAGRunDetails } from '@/features/dag-runs/hooks/useBoundedDAGRunDetails';
import { PersonScopeContext } from '@/features/txe/personScope';
import DAGRunDetailsPage from '..';

vi.mock('@/features/dag-runs/hooks/useBoundedDAGRunDetails', () => ({
  useBoundedDAGRunDetails: vi.fn(),
}));

vi.mock('@/features/dag-runs/components/dag-run-details', () => ({
  DAGRunDetailsContent: vi.fn(({ fillHeight }) => (
    <div data-fill-height={String(fillHeight)} data-testid="dag-run-content" />
  )),
}));

const useBoundedDAGRunDetailsMock = vi.mocked(useBoundedDAGRunDetails);

const dagRunDetails = {
  name: 'release-notes',
  dagRunId: 'run-1',
  artifactsAvailable: true,
} as never;

function renderPage(personScope = false) {
  render(
    <PersonScopeContext.Provider value={personScope}>
      <MemoryRouter initialEntries={['/dag-runs/release-notes/run-1']}>
        <AppBarContext.Provider
          value={
            {
              selectedRemoteNode: 'local',
            } as never
          }
        >
          <Routes>
            <Route
              path="/dag-runs/:name/:dagRunId"
              element={<DAGRunDetailsPage />}
            />
          </Routes>
        </AppBarContext.Provider>
      </MemoryRouter>
    </PersonScopeContext.Provider>
  );
}

describe('DAGRunDetailsPage', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useBoundedDAGRunDetailsMock.mockReturnValue({
      data: dagRunDetails,
      error: null,
      refresh: vi.fn(),
    } as never);
  });

  it('uses full-height layout for DAG run details content', () => {
    renderPage();

    const content = screen.getByTestId('dag-run-content');
    expect(content).toHaveAttribute('data-fill-height', 'true');
    expect(content.parentElement).toHaveClass('h-full');
    expect(content.parentElement).toHaveClass('min-h-0');
  });

  // A person gets the hub's uniform 404 for a run of another owner's DAG
  // too, so the page must not suggest the run once existed.
  it('tells a person only that the job is not found', () => {
    useBoundedDAGRunDetailsMock.mockReturnValue({
      data: null,
      error: { code: 'not_found', message: 'not found' },
      refresh: vi.fn(),
    } as never);
    renderPage(true);

    expect(screen.getByText('Job not found')).toBeInTheDocument();
    expect(screen.queryByText('DAG Run Not Found')).not.toBeInTheDocument();
    expect(screen.queryByText(/dequeued or removed/)).not.toBeInTheDocument();
  });

  it('keeps the native not-found message outside a person dashboard', () => {
    useBoundedDAGRunDetailsMock.mockReturnValue({
      data: null,
      error: { response: { status: 404 } },
      refresh: vi.fn(),
    } as never);
    renderPage();

    expect(screen.getByText('DAG Run Not Found')).toBeInTheDocument();
    expect(screen.queryByText('Job not found')).not.toBeInTheDocument();
  });
});
