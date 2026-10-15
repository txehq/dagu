// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { render, screen } from '@testing-library/react';
import React from 'react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { SWRConfig } from 'swr';
import { describe, expect, it, vi } from 'vitest';

import TxeJobPage from '@/pages/txe/job';

import type { TxeAccessApi } from '../access';
import type { TxeApi } from '../api';
import { fixtureJob } from '../fixtures';
import { TxeAccessApiContext, TxeApiContext } from '../hooks';
import { isNotFoundAnswer } from '../personScope';

vi.mock('@/contexts/AuthContext', () => ({
  useCanExecute: () => true,
}));

vi.mock('@/hooks/api', () => ({
  useClient: () => ({}),
}));

vi.mock('@/contexts/ConfigContext', () => ({
  useConfig: () => ({ authMode: 'builtin' }),
}));

describe('isNotFoundAnswer', () => {
  it.each([
    [{ code: 'not_found', message: 'not found' }, true],
    [{ response: { status: 404 } }, true],
    [{ code: 'forbidden' }, false],
    [{ response: { status: 500 } }, false],
    [new Error('network'), false],
    [undefined, false],
    ['not_found', false],
  ])('%j is %s', (error, expected) => {
    expect(isNotFoundAnswer(error)).toBe(expected);
  });
});

describe('the job page', () => {
  it("links the job's DAG", async () => {
    const api = {
      getJob: async () => fixtureJob(),
      listProposals: async () => [],
      listDecisions: async () => [],
      listRetryStates: async () => new Map(),
    } as unknown as TxeApi;
    render(
      <SWRConfig value={{ provider: () => new Map(), dedupingInterval: 0 }}>
        <TxeApiContext.Provider value={api}>
          <TxeAccessApiContext.Provider value={{} as TxeAccessApi}>
            <MemoryRouter initialEntries={['/txe/jobs/job_volume_monitor']}>
              <Routes>
                <Route path="/txe/jobs/:jobId" element={<TxeJobPage />} />
              </Routes>
            </MemoryRouter>
          </TxeAccessApiContext.Provider>
        </TxeApiContext.Provider>
      </SWRConfig>
    );

    expect(
      await screen.findByRole('link', { name: 'Open the DAG' })
    ).toHaveAttribute('href', '/dags/job_volume_monitor');
  });
});
