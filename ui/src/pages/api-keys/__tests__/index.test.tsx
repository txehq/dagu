// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

import { MemoryRouter } from 'react-router-dom';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  APIKeyAllowedSurfaces,
  APIKeyAttributionClass,
  APIKeyLimitSource,
  UserRole,
  type components,
} from '@/api/v1/schema';
import { AppBarContext } from '@/contexts/AppBarContext';
import { ConfigContext, type Config } from '@/contexts/ConfigContext';
import APIKeysPage from '..';
import { APIKeyFormModal } from '../APIKeyFormModal';
import { buildMCPServerURL } from '../mcpSetupPrompt';

vi.mock('@/contexts/AuthContext', () => ({
  TOKEN_KEY: 'daguToken',
  useIsAdmin: () => true,
}));

type APIKey = components['schemas']['APIKey'];

const originalClipboard = Object.getOwnPropertyDescriptor(
  navigator,
  'clipboard'
);

const appBarValue = {
  title: '',
  setTitle: () => undefined,
  remoteNodes: ['local'],
  setRemoteNodes: () => undefined,
  selectedRemoteNode: 'local',
  selectRemoteNode: () => undefined,
  workspaces: [],
};

function makeConfig(licenseOverrides: Partial<Config['license']> = {}): Config {
  return {
    apiURL: '/api/v1',
    basePath: '/',
    title: 'Dagu',
    navbarColor: '',
    tz: 'UTC',
    tzOffsetInSec: 0,
    version: 'test',
    maxDashboardPageLimit: 100,
    remoteNodes: 'local',
    initialWorkspaces: [],
    authMode: 'builtin',
    setupRequired: false,
    oidcEnabled: false,
    oidcButtonLabel: '',
    proxyEnabled: false,
    proxyButtonLabel: '',
    terminalEnabled: false,
    gitSyncEnabled: false,
    updateAvailable: false,
    latestVersion: '',
    upgradeCommand: '',
    restartRequired: false,
    restartCommand: '',
    permissions: {
      writeDags: true,
      runDags: true,
    },
    license: {
      valid: false,
      plan: '',
      expiry: '',
      features: [],
      gracePeriod: false,
      graceEndsAt: '',
      community: true,
      source: '',
      warningCode: '',
      ...licenseOverrides,
    },
    paths: {
      dagsDir: '',
      logDir: '',
      suspendFlagsDir: '',
      adminLogsDir: '',
      baseConfig: '',
      dagRunsDir: '',
      queueDir: '',
      procDir: '',
      serviceRegistryDir: '',
      configFileUsed: '',
      gitSyncDir: '',
      auditLogsDir: '',
    },
  };
}

function makeAPIKey(id: string): APIKey {
  return {
    id,
    name: `api-key-${id}`,
    role: UserRole.viewer,
    workspaceAccess: { all: true, grants: [] },
    allowedSurfaces: [
      APIKeyAllowedSurfaces.rest_api,
      APIKeyAllowedSurfaces.mcp,
    ],
    attributionClass: APIKeyAttributionClass.service_account,
    serviceAccountId: `api_key:${id}`,
    serviceAccountName: `api-key-${id}`,
    keyPrefix: `dagu_${id}`,
    createdAt: '2026-05-22T00:00:00Z',
    updatedAt: '2026-05-22T00:00:00Z',
    createdBy: 'admin',
    lastUsedAt: null,
  };
}

type KeyLimitFields = Pick<
  components['schemas']['APIKeysListResponse'],
  'unlicensedApiKeyLimit' | 'unlicensedApiKeyLimitSource'
>;

function makeAPIKeys(count: number): APIKey[] {
  return Array.from({ length: count }, (_, i) => makeAPIKey(String(i + 1)));
}

/** The key-limit fields of a server that runs the given fork policy limit. */
function forkPolicyLimit(limit: number): KeyLimitFields {
  return {
    unlicensedApiKeyLimit: limit,
    unlicensedApiKeyLimitSource: APIKeyLimitSource.fork_policy,
  };
}

function renderPage({
  license,
  apiKeys,
  keyLimit = {},
}: {
  license?: Partial<Config['license']>;
  apiKeys: APIKey[];
  // Omitted, the response is an older server's, which reports no limit.
  keyLimit?: KeyLimitFields;
}) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: true,
    json: async () => ({ apiKeys, ...keyLimit }),
  });
  vi.stubGlobal('fetch', fetchMock);

  render(
    <ConfigContext.Provider value={makeConfig(license)}>
      <AppBarContext.Provider value={appBarValue}>
        <MemoryRouter>
          <APIKeysPage />
        </MemoryRouter>
      </AppBarContext.Provider>
    </ConfigContext.Provider>
  );

  return { fetchMock };
}

describe('APIKeysPage', () => {
  beforeEach(() => {
    localStorage.setItem('daguToken', 'test-token');
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
  });

  it('warns and disables creation when a community install reaches 2 API keys', async () => {
    renderPage({
      apiKeys: [makeAPIKey('1'), makeAPIKey('2')],
      keyLimit: {
        unlicensedApiKeyLimit: 2,
        unlicensedApiKeyLimitSource: APIKeyLimitSource.community_default,
      },
    });

    expect(
      await screen.findByText(/Community installs can manage up to 2 API keys/i)
    ).toBeVisible();
    expect(
      screen.getByRole('button', { name: /create api key/i })
    ).toBeDisabled();
  });

  it('does not warn licensed installs with more than 2 API keys', async () => {
    renderPage({
      license: {
        valid: true,
        plan: 'pro',
        expiry: '2026-05-22T00:00:00Z',
        features: ['audit', 'rbac'],
        community: false,
        source: 'file',
      },
      apiKeys: [makeAPIKey('1'), makeAPIKey('2'), makeAPIKey('3')],
    });

    await waitFor(() => {
      expect(screen.getAllByText('api-key-3')[0]).toBeVisible();
    });

    expect(
      screen.queryByText(/Community installs can manage up to 2 API keys/i)
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /create api key/i })
    ).toBeEnabled();
  });

  it('names the free plan when it reaches 2 API keys', async () => {
    renderPage({
      license: {
        valid: true,
        plan: 'free',
        features: [],
        community: false,
        source: 'file',
      },
      apiKeys: [makeAPIKey('1'), makeAPIKey('2')],
    });

    expect(
      await screen.findByText('The Free plan supports up to 2 API keys.')
    ).toBeVisible();
    expect(screen.getByText(/Revoke a key to create another/)).toBeVisible();
    expect(
      screen.getByRole('button', { name: /create api key/i })
    ).toBeDisabled();
  });

  // An older server reports no limit and enforced 2 with no license.
  it('applies the community limit of 2 when the server reports no limit', async () => {
    renderPage({ apiKeys: makeAPIKeys(2) });

    expect(
      await screen.findByText(/Community installs can manage up to 2 API keys/i)
    ).toBeVisible();
    expect(
      screen.getByRole('button', { name: /create api key/i })
    ).toBeDisabled();
  });

  it('allows a third key when the server allows 3', async () => {
    renderPage({ apiKeys: makeAPIKeys(2), keyLimit: forkPolicyLimit(3) });

    await waitFor(() => {
      expect(screen.getAllByText('api-key-2')[0]).toBeVisible();
    });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /create api key/i })
    ).toBeEnabled();
  });

  it('refuses a fourth key and names the server limit of 3', async () => {
    renderPage({ apiKeys: makeAPIKeys(3), keyLimit: forkPolicyLimit(3) });

    expect(
      await screen.findByText('This server allows up to 3 API keys.')
    ).toBeVisible();
    expect(screen.queryByText(/Community installs/i)).not.toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /create api key/i })
    ).toBeDisabled();
  });

  it('never refuses when the server reports no limit (0)', async () => {
    renderPage({ apiKeys: makeAPIKeys(12), keyLimit: forkPolicyLimit(0) });

    await waitFor(() => {
      expect(screen.getAllByText('api-key-12')[0]).toBeVisible();
    });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(
      screen.getByRole('button', { name: /create api key/i })
    ).toBeEnabled();
  });

  // The server applies the fork policy limit to the Free plan as well.
  it('follows the server limit on the Free plan', async () => {
    renderPage({
      license: {
        valid: true,
        plan: 'free',
        features: [],
        community: false,
        source: 'file',
      },
      apiKeys: makeAPIKeys(2),
      keyLimit: forkPolicyLimit(3),
    });

    await waitFor(() => {
      expect(screen.getAllByText('api-key-2')[0]).toBeVisible();
    });
    expect(
      screen.getByRole('button', { name: /create api key/i })
    ).toBeEnabled();
  });

  it('warns when an inactive loaded license reaches 2 API keys', async () => {
    renderPage({
      license: {
        valid: false,
        gracePeriod: false,
        community: false,
        plan: 'pro',
        source: 'file',
      },
      apiKeys: [makeAPIKey('1'), makeAPIKey('2')],
    });

    expect(
      await screen.findByText(/Community installs can manage up to 2 API keys/i)
    ).toBeVisible();
  });
});

describe('buildMCPServerURL', () => {
  const origin = window.location.origin;

  it.each([
    ['/', `${origin}/mcp`],
    ['', `${origin}/mcp`],
    [undefined, `${origin}/mcp`],
    ['/dagu', `${origin}/dagu/mcp`],
    ['/dagu/', `${origin}/dagu/mcp`],
  ])('resolves base path %o to %s', (basePath, expected) => {
    expect(buildMCPServerURL(basePath)).toBe(expected);
  });
});

describe('APIKeyFormModal', () => {
  beforeEach(() => {
    localStorage.setItem('daguToken', 'test-token');
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: {
        writeText: vi.fn().mockResolvedValue(undefined),
      },
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    localStorage.clear();
    if (originalClipboard) {
      Object.defineProperty(navigator, 'clipboard', originalClipboard);
    } else {
      Reflect.deleteProperty(navigator, 'clipboard');
    }
  });

  /**
   * Drives the modal through a successful create so the tests can act on the
   * one screen where the plaintext key exists.
   */
  async function createKey({
    mcpSurface,
    remoteNode = 'local',
  }: {
    mcpSurface: boolean;
    remoteNode?: string;
  }) {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ key: 'dagu_test_secret' }),
      })
    );

    render(
      <ConfigContext.Provider value={makeConfig()}>
        <AppBarContext.Provider
          value={{ ...appBarValue, selectedRemoteNode: remoteNode }}
        >
          <APIKeyFormModal
            open
            onClose={() => undefined}
            onSuccess={() => undefined}
          />
        </AppBarContext.Provider>
      </ConfigContext.Provider>
    );

    fireEvent.change(screen.getByLabelText('Name'), {
      target: { value: 'mcp-bot' },
    });
    if (!mcpSurface) {
      fireEvent.click(screen.getByRole('checkbox', { name: 'MCP' }));
    }
    fireEvent.click(screen.getByRole('button', { name: 'Create key' }));
    await screen.findByText('API Key Created');
  }

  it('copies a setup prompt carrying the MCP URL and the new key', async () => {
    await createKey({ mcpSurface: true });

    fireEvent.click(
      screen.getByRole('button', { name: 'Copy MCP setup prompt' })
    );

    await waitFor(() =>
      expect(navigator.clipboard.writeText).toHaveBeenCalledOnce()
    );
    const prompt = vi.mocked(navigator.clipboard.writeText).mock.calls[0]?.[0];
    expect(prompt).toContain(`${window.location.origin}/mcp`);
    expect(prompt).toContain('Authorization: Bearer dagu_test_secret');
  });

  it.each([
    ['the key does not accept the MCP surface', { mcpSurface: false }],
    [
      'the key was created on a remote node',
      { mcpSurface: true, remoteNode: 'worker-1' },
    ],
  ])('omits the setup prompt when %s', async (_label, options) => {
    await createKey(options);

    expect(
      screen.queryByRole('button', { name: 'Copy MCP setup prompt' })
    ).not.toBeInTheDocument();
  });
});
