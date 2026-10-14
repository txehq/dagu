// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { UserAuthProvider, UserRole } from '@/api/v1/schema';
import { UserMenu } from '../UserMenu';

const mocks = vi.hoisted(() => ({
  useAuth: vi.fn(),
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: mocks.useAuth,
}));

vi.mock('@/contexts/ConfigContext', () => ({
  useConfig: () => ({ authMode: 'builtin' }),
}));

function LoginProbe() {
  const location = useLocation();
  return <div data-testid="login-page">{location.search}</div>;
}

function renderMenu(
  authProvider: UserAuthProvider,
  logout: () => Promise<string> = vi.fn(() => Promise.resolve('local')),
  actingFor?: string
) {
  mocks.useAuth.mockReturnValue({
    user: {
      id: 'user-id',
      username: 'test-user',
      role: UserRole.viewer,
      workspaceAccess: { all: true, grants: [] },
      authProvider,
      createdAt: '2026-07-20T00:00:00Z',
      updatedAt: '2026-07-20T00:00:00Z',
    },
    logout,
    isAuthenticated: true,
  });

  render(
    <MemoryRouter initialEntries={['/']}>
      <Routes>
        <Route path="/" element={<UserMenu actingFor={actingFor} />} />
        <Route path="/login" element={<LoginProbe />} />
      </Routes>
    </MemoryRouter>
  );
}

describe('UserMenu', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('does not offer password changes to OIDC users', async () => {
    const user = userEvent.setup();
    renderMenu(UserAuthProvider.oidc);

    await user.click(screen.getByRole('button', { name: 'test-user' }));

    expect(
      screen.queryByRole('menuitem', { name: 'Change Password' })
    ).not.toBeInTheDocument();
    expect(screen.getByRole('menuitem', { name: 'Sign Out' })).toBeVisible();
  });

  it('shows the role of a caller that acts for no owner', async () => {
    const user = userEvent.setup();
    renderMenu(UserAuthProvider.builtin);

    await user.click(screen.getByRole('button', { name: 'test-user' }));

    expect(screen.getByText(UserRole.viewer)).toBeVisible();
    expect(screen.queryByTestId('user-menu-owner')).not.toBeInTheDocument();
  });

  it('shows the owner a person acts for instead of the hub role', async () => {
    const user = userEvent.setup();
    renderMenu(UserAuthProvider.oidc, undefined, 'Ada Lovelace');

    await user.click(screen.getByRole('button', { name: 'test-user' }));

    expect(screen.getByTestId('user-menu-owner')).toHaveTextContent(
      'Acting for Ada Lovelace'
    );
    expect(screen.queryByText(UserRole.viewer)).not.toBeInTheDocument();
  });

  it('does not offer password changes to proxy users', async () => {
    const user = userEvent.setup();
    renderMenu(UserAuthProvider.proxy);

    await user.click(screen.getByRole('button', { name: 'test-user' }));

    expect(
      screen.queryByRole('menuitem', { name: 'Change Password' })
    ).not.toBeInTheDocument();
  });

  it('offers password changes to local users', async () => {
    const user = userEvent.setup();
    renderMenu(UserAuthProvider.builtin);

    await user.click(screen.getByRole('button', { name: 'test-user' }));

    expect(
      screen.getByRole('menuitem', { name: 'Change Password' })
    ).toBeVisible();
  });

  it.each([
    ['local', ''],
    ['ended', ''],
    ['unconfirmed', '?signout=unconfirmed'],
  ])(
    'goes to the login page after a %s sign-out',
    async (result, search) => {
      const user = userEvent.setup();
      const logout = vi.fn(() => Promise.resolve(result));
      renderMenu(UserAuthProvider.oidc, logout);

      await user.click(screen.getByRole('button', { name: 'test-user' }));
      await user.click(screen.getByRole('menuitem', { name: 'Sign Out' }));

      expect(await screen.findByTestId('login-page')).toHaveTextContent(
        search
      );
      expect(screen.getByTestId('login-page').textContent).toBe(search);
      expect(logout).toHaveBeenCalledTimes(1);
    }
  );

  it('stays put and disables Sign Out until the hub has answered', async () => {
    const user = userEvent.setup();
    let answer: (result: string) => void = () => {};
    const logout = vi.fn(
      () =>
        new Promise<string>((resolve) => {
          answer = resolve;
        })
    );
    renderMenu(UserAuthProvider.oidc, logout);

    await user.click(screen.getByRole('button', { name: 'test-user' }));
    await user.click(screen.getByRole('menuitem', { name: 'Sign Out' }));

    expect(screen.queryByTestId('login-page')).not.toBeInTheDocument();
    expect(logout).toHaveBeenCalledTimes(1);

    // Reopen the menu while the request is pending: the item cannot fire again.
    await user.click(screen.getByRole('button', { name: 'test-user' }));
    const item = screen.getByRole('menuitem', { name: 'Sign Out' });
    expect(item).toHaveAttribute('aria-disabled', 'true');
    await user.click(item);
    expect(logout).toHaveBeenCalledTimes(1);

    answer('ended');
    expect(await screen.findByTestId('login-page')).toBeInTheDocument();
  });
});
