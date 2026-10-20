// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { render, renderHook, screen } from '@testing-library/react';
import React from 'react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { useViews } from '@/hooks/useViews';

import { PersonLayout } from '../components/identity/PersonLayout';
import { PersonScopeContext } from '../personScope';

const useQuery = vi.fn();

vi.mock('@/hooks/api', () => ({
  useClient: () => ({}),
  useQuery: (...args: unknown[]) => useQuery(...args),
}));

vi.mock('@/contexts/ConfigContext', () => ({
  useConfig: () => ({ title: 'Dagu' }),
}));

vi.mock('@/components/UserMenu', () => ({
  UserMenu: () => <span>user menu</span>,
}));

vi.mock('@/components/LanguageSelector', () => ({
  LanguageSelector: () => <span>language</span>,
}));

vi.mock('../identity', () => ({
  useTxeIdentity: () => ({ identity: undefined }),
}));

beforeEach(() => {
  useQuery.mockReset();
  useQuery.mockReturnValue({ data: undefined, isLoading: false });
});

describe("a person's DAG, run and queue lists", () => {
  it('are linked from the person header', () => {
    render(
      <MemoryRouter>
        <PersonLayout>
          <span />
        </PersonLayout>
      </MemoryRouter>
    );

    expect(screen.getByRole('link', { name: 'Workflows' })).toHaveAttribute(
      'href',
      '/dags'
    );
    expect(screen.getByRole('link', { name: 'Executions' })).toHaveAttribute(
      'href',
      '/dag-runs'
    );
    expect(screen.getByRole('link', { name: 'Queues' })).toHaveAttribute(
      'href',
      '/queues'
    );
  });
});

describe('saved views', () => {
  // The hub refuses saved views to a person; asking would fail every list
  // page with an error notice.
  it('are not asked for on a person’s pages', () => {
    const { result } = renderHook(() => useViews(), {
      wrapper: ({ children }) => (
        <PersonScopeContext.Provider value={true}>
          {children}
        </PersonScopeContext.Provider>
      ),
    });

    expect(useQuery).toHaveBeenCalledWith('/views', null);
    expect(result.current.views).toEqual([]);
  });

  it('are asked for on the ordinary dashboard', () => {
    renderHook(() => useViews());

    expect(useQuery).toHaveBeenCalledWith('/views', {
      params: { query: { remoteNode: 'local' } },
    });
  });
});
