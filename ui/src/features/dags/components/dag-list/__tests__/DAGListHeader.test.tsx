// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

import { render, screen } from '@testing-library/react';
import React from 'react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import DAGListHeader from '../DAGListHeader';
import { PersonScopeContext } from '@/features/txe/personScope';

vi.mock('../../common', () => ({
  CreateDAGButton: () => <button type="button">New</button>,
}));

describe('DAGListHeader', () => {
  it('offers a new workflow on the ordinary dashboard', () => {
    render(
      <MemoryRouter>
        <DAGListHeader />
      </MemoryRouter>
    );

    expect(screen.getByRole('button', { name: 'New' })).toBeInTheDocument();
  });

  // The hub refuses a person a new platform DAG.
  it('offers a person no new workflow', () => {
    render(
      <PersonScopeContext.Provider value={true}>
        <MemoryRouter>
          <DAGListHeader />
        </MemoryRouter>
      </PersonScopeContext.Provider>
    );

    expect(screen.queryByRole('button', { name: 'New' })).toBeNull();
  });

  it('labels the definitions list as Workflows', () => {
    render(
      <MemoryRouter>
        <DAGListHeader />
      </MemoryRouter>
    );

    expect(screen.getByRole('heading', { name: /^workflows$/i })).toBeVisible();
    expect(
      screen.queryByRole('heading', { name: /dag definitions/i })
    ).toBeNull();
  });
});
