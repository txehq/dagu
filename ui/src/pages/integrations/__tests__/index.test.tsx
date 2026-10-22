// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

import { fireEvent, render, screen, within } from '@testing-library/react';
import React from 'react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AppBarContext } from '@/contexts/AppBarContext';
import { PersonScopeContext } from '@/features/txe/personScope';
import type { TxeIdentity } from '@/features/txe/identity';
import IntegrationsPage from '..';
import { MIN_TAG } from '../setupCommands';

const mocks = vi.hoisted(() => ({
  apiURL: { value: '/api/v1' },
  identity: { value: undefined as unknown },
  copyText: vi.fn(),
}));

vi.mock('@/contexts/ConfigContext', () => ({
  useConfig: () => ({ apiURL: mocks.apiURL.value, authMode: 'builtin' }),
}));

vi.mock('@/features/txe/identity', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/features/txe/identity')>()),
  useTxeIdentity: () => ({
    identity: mocks.identity.value,
    isLoading: false,
    error: undefined,
    reload: async () => undefined,
  }),
}));

vi.mock('@/lib/clipboard', () => ({ copyText: mocks.copyText }));

vi.mock('@/hooks/api', () => ({ useClient: () => ({}) }));

function renderPage({ person = false } = {}) {
  const setTitle = vi.fn();
  render(
    <MemoryRouter>
      <PersonScopeContext.Provider value={person}>
        <AppBarContext.Provider value={{ setTitle } as never}>
          <IntegrationsPage />
        </AppBarContext.Provider>
      </PersonScopeContext.Provider>
    </MemoryRouter>
  );
  return { setTitle };
}

function codeBlocks(): string[] {
  return Array.from(document.querySelectorAll('pre code')).map(
    (el) => el.textContent ?? ''
  );
}

function boundPerson(): TxeIdentity {
  return {
    contract: 1,
    principal: { class: 'person', shown: { username: 'ada' } },
    state: 'bound',
    owners: [{ owner_id: 'own_ada', display_name: 'Ada' }],
    scope: { kind: 'owner' },
    platform_admin: false,
    is_person: true,
  } as unknown as TxeIdentity;
}

beforeEach(() => {
  mocks.apiURL.value = '/api/v1';
  mocks.identity.value = undefined;
  mocks.copyText.mockResolvedValue(true);
});

afterEach(() => {
  vi.clearAllMocks();
});

describe('IntegrationsPage', () => {
  it('renders integration links', () => {
    const { setTitle } = renderPage();

    expect(
      screen.getByRole('heading', { name: /integrations/i })
    ).toBeVisible();
    expect(screen.getByRole('link', { name: /webhooks/i })).toHaveAttribute(
      'href',
      '/webhooks'
    );
    expect(
      screen.getByRole('link', { name: /api reference/i })
    ).toHaveAttribute('href', '/api-docs');
    expect(
      screen.getByText('Trigger workflows from external systems.')
    ).toBeVisible();
    expect(
      screen.getByText('Explore authenticated REST API endpoints.')
    ).toBeVisible();
    expect(setTitle).toHaveBeenCalledWith('Integrations');
    // The developer guide follows the links.
    expect(
      screen.getByRole('heading', { name: 'Developer setup' })
    ).toBeVisible();
  });

  // A person's dashboard has no webhook or API reference pages; the person
  // gets the guide alone.
  it('gives a person the developer guide without the links', () => {
    const { setTitle } = renderPage({ person: true });

    expect(
      screen.queryByRole('link', { name: /webhooks/i })
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole('link', { name: /api reference/i })
    ).not.toBeInTheDocument();
    expect(
      screen.getAllByRole('heading', { name: 'Developer setup' })
    ).not.toHaveLength(0);
    expect(setTitle).toHaveBeenCalledWith('Developer setup');
  });
});

describe('DeveloperSetup', () => {
  it('builds the accepted tag with the shipped installer', () => {
    renderPage();

    const blocks = codeBlocks();
    expect(blocks).toContain(
      [
        `git clone --depth 1 --branch ${MIN_TAG} https://github.com/txehq/dagu.git txe-dagu-${MIN_TAG}`,
        `cd txe-dagu-${MIN_TAG}`,
        `txe/developer/install.sh --tag ${MIN_TAG}`,
      ].join('\n')
    );
    expect(blocks).toContain('txe/developer/install.sh --check\ndagu version');
    expect(
      screen.getByText(/dagu version prints 2\.18\.2-txe\.14/)
    ).toBeVisible();
    // Nothing invented: no download link or release asset.
    expect(blocks.join('\n')).not.toMatch(/releases\/download|curl |wget /);
  });

  it("signs in to this page's hub, quoted for the shell", () => {
    renderPage();

    expect(codeBlocks()).toContain(
      `dagu txe login --hub '${window.location.origin}'`
    );
    expect(codeBlocks()).toContain(
      `dagu txe login --hub '${window.location.origin}' --no-browser`
    );
  });

  // --no-browser only skips opening a browser: the sign-in returns to a
  // listener on that machine, reached from elsewhere only by forwarding its
  // port.
  it('explains signing in on a machine without a browser', () => {
    renderPage();

    expect(
      screen.getByText(/--no-browser only stops the CLI opening a browser/)
    ).toBeVisible();
    expect(codeBlocks()).toContain(
      'ssh -L <port>:127.0.0.1:<port> <you>@<that machine>'
    );
  });

  // Behind a base path the CLI must be given the API root, which it keeps.
  it('names the API root behind a base path', () => {
    mocks.apiURL.value = '/dagu/api/v1';
    renderPage();

    expect(codeBlocks()).toContain(
      `dagu txe login --hub '${window.location.origin}/dagu/api/v1'`
    );
  });

  it('warns that the CLI refuses a plain http hub', () => {
    mocks.apiURL.value = 'http://dag.example.com/api/v1';
    renderPage();

    expect(screen.getByText(/The CLI signs in only over https/)).toBeVisible();
  });

  it('shows a placeholder and says why for a malformed tag', () => {
    renderPage();
    const input = screen.getByLabelText('Accepted tag');

    fireEvent.change(input, { target: { value: 'v2.18.2; id' } });

    expect(input).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByText(/A tag looks like/)).toBeVisible();
    expect(codeBlocks().join('\n')).not.toContain('; id');
    expect(codeBlocks().join('\n')).toContain('--tag <accepted tag>');
  });

  it('warns about a tag without machine create', () => {
    renderPage();

    fireEvent.change(screen.getByLabelText('Accepted tag'), {
      target: { value: 'txe-v2.18.2-13' },
    });

    expect(
      screen.getByText(
        `txe-v2.18.2-13 does not have dagu txe machine create. Use ${MIN_TAG} or later.`
      )
    ).toBeVisible();
    expect(codeBlocks().join('\n')).toContain('--tag txe-v2.18.2-13');
  });

  it('copies a command and says so', async () => {
    renderPage();

    fireEvent.click(
      screen.getByRole('button', {
        name: 'Copy: Check who the hub says you are',
      })
    );

    expect(mocks.copyText).toHaveBeenCalledWith('dagu txe whoami');
    expect(await screen.findByText('Copied')).toBeInTheDocument();
  });

  it('says when a copy failed', async () => {
    mocks.copyText.mockResolvedValue(false);
    renderPage();

    fireEvent.click(
      screen.getByRole('button', {
        name: 'Copy: Check who the hub says you are',
      })
    );

    expect(
      await screen.findAllByText('Could not copy. Select the text and copy it.')
    ).not.toHaveLength(0);
  });

  it('says the developer install is not a worker and needs no key', () => {
    renderPage();

    expect(screen.getByText(/It does not install a worker/)).toBeVisible();
    expect(
      screen.getByText(/needs no kubeconfig, API key or copied credential/)
    ).toBeVisible();
    expect(
      screen.getByRole('heading', {
        name: /Install and enrol a worker \(needs an administrator\)/,
      })
    ).toBeVisible();
  });

  // The browser cannot see the machine: it shows nothing as the machine's
  // state, and the one thing it reads is labelled as this browser's.
  it("names this browser's account only as the browser's", () => {
    mocks.identity.value = boundPerson();
    renderPage();

    expect(screen.getByTestId('dev-setup-browser-identity')).toHaveTextContent(
      "This browser's account acts for Ada (own_ada). That is this browser, not your machine"
    );
  });

  it('claims no identity it has not read', () => {
    renderPage();

    expect(
      screen.queryByTestId('dev-setup-browser-identity')
    ).not.toBeInTheDocument();
  });

  it('checks the stages in order, and keeps registering apart', () => {
    renderPage();
    const stages = screen.getByRole('list', { name: 'Check that it works' });

    expect(
      within(stages)
        .getAllByRole('heading', { level: 4 })
        .map((h) => h.textContent?.replace(/^\d+\./, ''))
    ).toEqual([
      'CLI and skill installed',
      'Identity bound',
      'Machine and worker ready',
      'Test job ran and its result reached the hub',
    ]);
    const blocks = codeBlocks();
    const dry = blocks.indexOf(
      'dagu txe register -f job.yaml --session dev-setup-smoke --dry-run'
    );
    const register = blocks.indexOf(
      'dagu txe register -f job.yaml --session dev-setup-smoke'
    );
    expect(dry).toBeGreaterThan(-1);
    expect(register).toBeGreaterThan(dry);
    expect(
      screen.getByText(/This is the one step that changes the hub/)
    ).toBeVisible();
    expect(blocks.indexOf('dagu txe package verify <job id>')).toBeGreaterThan(
      register
    );
    expect(blocks.indexOf('dagu txe inspect <job id>')).toBeGreaterThan(
      register
    );
    expect(screen.getByText(/The job has not run yet/)).toBeVisible();
    expect(
      screen.getByText(/"Recent runs" lists a run with status succeeded/)
    ).toBeVisible();
  });
});
