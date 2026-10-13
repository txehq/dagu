// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

import { act, render, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  AuthProvider,
  OIDC_LOGOUT_TIMEOUT_MS,
  useAuth,
  type LogoutResult,
} from '@/contexts/AuthContext';
import { getAuthToken, setAuthSession } from '@/lib/authSession';

const mocks = vi.hoisted(() => ({
  config: {
    apiURL: '/api/v1',
    basePath: '',
    authMode: 'builtin',
    setupRequired: false,
    oidcSessionEnabled: true,
  } as Record<string, unknown>,
}));

vi.mock('@/contexts/ConfigContext', () => ({
  useConfig: () => mocks.config,
}));

const TOKEN = 'test-token';
const FAR_FUTURE = '2099-01-01T00:00:00Z';

type Auth = ReturnType<typeof useAuth>;

let auth: Auth | null = null;

function Probe() {
  auth = useAuth();
  return null;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

// fetchMock answers /auth/me with a signed-in user and hands every
// oidc-logout request to logoutAnswer.
function installFetch(logoutAnswer: (init?: RequestInit) => Promise<Response>) {
  const fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith('/auth/me')) {
      return Promise.resolve(
        jsonResponse({ user: { id: 'u1', username: 'alice', role: 'admin' } })
      );
    }
    if (url.endsWith('/oidc-logout')) {
      return logoutAnswer(init);
    }
    return Promise.reject(new Error(`unexpected fetch ${url}`));
  });
  vi.stubGlobal('fetch', fetchMock);
  return fetchMock;
}

function logoutCalls(fetchMock: ReturnType<typeof installFetch>) {
  return fetchMock.mock.calls.filter(([input]) =>
    String(input).endsWith('/oidc-logout')
  );
}

async function renderSignedIn() {
  render(
    <AuthProvider>
      <Probe />
    </AuthProvider>
  );
  await waitFor(() => expect(auth?.isAuthenticated).toBe(true));
}

async function signOut(): Promise<LogoutResult> {
  let result: LogoutResult | undefined;
  await act(async () => {
    result = await auth!.logout();
  });
  return result!;
}

describe('AuthProvider logout', () => {
  beforeEach(() => {
    localStorage.clear();
    auth = null;
    mocks.config.basePath = '';
    mocks.config.oidcSessionEnabled = true;
    setAuthSession(TOKEN, FAR_FUTURE, 'login');
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('only clears this browser when OIDC sessions are off', async () => {
    mocks.config.oidcSessionEnabled = false;
    const fetchMock = installFetch(() =>
      Promise.resolve(new Response(null, { status: 204 }))
    );
    await renderSignedIn();

    expect(await signOut()).toBe('local');

    expect(logoutCalls(fetchMock)).toHaveLength(0);
    expect(getAuthToken()).toBeNull();
    expect(auth!.isAuthenticated).toBe(false);

    // Signed in again without a reload, the next sign-out clears again.
    act(() => setAuthSession('second-token', FAR_FUTURE, 'login'));
    await waitFor(() => expect(auth?.isAuthenticated).toBe(true));
    expect(await signOut()).toBe('local');
    expect(getAuthToken()).toBeNull();
    expect(auth!.isAuthenticated).toBe(false);
  });

  it('reports the session ended when the hub answers 204', async () => {
    let tokenDuringRequest: string | null = 'unset';
    const fetchMock = installFetch(() => {
      tokenDuringRequest = getAuthToken();
      return Promise.resolve(new Response(null, { status: 204 }));
    });
    await renderSignedIn();

    expect(await signOut()).toBe('ended');

    const calls = logoutCalls(fetchMock);
    expect(calls).toHaveLength(1);
    const [url, init] = calls[0]!;
    expect(url).toBe('/oidc-logout');
    expect(init?.method).toBe('POST');
    expect(init?.headers).toEqual({ Authorization: `Bearer ${TOKEN}` });
    // The browser is signed out before the hub is asked.
    expect(tokenDuringRequest).toBeNull();
    expect(getAuthToken()).toBeNull();
    expect(auth!.isAuthenticated).toBe(false);
  });

  it.each([401, 405, 500])(
    'reports a %i answer as unconfirmed and still signs this browser out',
    async (status) => {
      installFetch(() => Promise.resolve(new Response(null, { status })));
      await renderSignedIn();

      expect(await signOut()).toBe('unconfirmed');

      expect(getAuthToken()).toBeNull();
      expect(auth!.isAuthenticated).toBe(false);
    }
  );

  it('reports a network failure as unconfirmed and still signs this browser out', async () => {
    installFetch(() => Promise.reject(new TypeError('Failed to fetch')));
    await renderSignedIn();

    expect(await signOut()).toBe('unconfirmed');

    expect(getAuthToken()).toBeNull();
    expect(auth!.isAuthenticated).toBe(false);
  });

  it('bounds the wait for the hub and reports a timed-out request as unconfirmed', async () => {
    // AbortSignal.timeout runs on Node's own timers, out of reach of fake
    // timers, so the test hands out a signal it aborts itself.
    const timeout = new AbortController();
    const timeoutSpy = vi
      .spyOn(AbortSignal, 'timeout')
      .mockReturnValue(timeout.signal);
    let requestSignal: AbortSignal | undefined;
    installFetch(
      (init) =>
        new Promise<Response>((_, reject) => {
          requestSignal = init?.signal ?? undefined;
          requestSignal?.addEventListener('abort', () =>
            reject(requestSignal?.reason)
          );
        })
    );
    await renderSignedIn();

    let result: LogoutResult | undefined;
    let pending: Promise<void> | undefined;
    act(() => {
      pending = auth!.logout().then((r) => {
        result = r;
      });
    });
    expect(timeoutSpy).toHaveBeenCalledWith(OIDC_LOGOUT_TIMEOUT_MS);
    expect(requestSignal).toBe(timeout.signal);
    // Already signed out here, while the hub has not answered: closing the
    // tab now leaves no token behind.
    expect(getAuthToken()).toBeNull();
    expect(auth!.isAuthenticated).toBe(false);

    await act(async () => {
      timeout.abort(new DOMException('timed out', 'TimeoutError'));
      await pending;
    });
    expect(result).toBe('unconfirmed');
    expect(getAuthToken()).toBeNull();
    expect(auth!.isAuthenticated).toBe(false);
  });

  it('asks the hub once when sign-out is pressed again while it is under way', async () => {
    let answer: (response: Response) => void = () => {};
    const fetchMock = installFetch(
      () =>
        new Promise<Response>((resolve) => {
          answer = resolve;
        })
    );
    await renderSignedIn();

    let first: Promise<LogoutResult> | undefined;
    let second: Promise<LogoutResult> | undefined;
    act(() => {
      first = auth!.logout();
      second = auth!.logout();
    });
    expect(second).toBe(first);

    let results: LogoutResult[] = [];
    await act(async () => {
      answer(new Response(null, { status: 204 }));
      results = await Promise.all([first!, second!]);
    });

    expect(results).toEqual(['ended', 'ended']);
    expect(logoutCalls(fetchMock)).toHaveLength(1);
    expect(getAuthToken()).toBeNull();

    // A sign-out after the first one finished has no token left to send.
    expect(await signOut()).toBe('local');
    expect(logoutCalls(fetchMock)).toHaveLength(1);
  });

  it('still clears the browser when the same token is restored during a pending sign-out', async () => {
    let answer: (response: Response) => void = () => {};
    const fetchMock = installFetch(
      () =>
        new Promise<Response>((resolve) => {
          answer = resolve;
        })
    );
    await renderSignedIn();

    let first: Promise<LogoutResult> | undefined;
    act(() => {
      first = auth!.logout();
    });

    // A second sign-in can be issued the very same token.
    act(() => setAuthSession(TOKEN, FAR_FUTURE, 'login'));
    await waitFor(() => expect(auth?.isAuthenticated).toBe(true));

    let second: Promise<LogoutResult> | undefined;
    act(() => {
      second = auth!.logout();
    });
    expect(second).toBe(first);
    expect(getAuthToken()).toBeNull();
    expect(auth!.isAuthenticated).toBe(false);
    expect(logoutCalls(fetchMock)).toHaveLength(1);

    await act(async () => {
      answer(new Response(null, { status: 204 }));
      await first;
    });
    expect(getAuthToken()).toBeNull();
  });

  it('signs out a session signed in while an earlier sign-out is still waiting for the hub', async () => {
    const answers: Array<(response: Response) => void> = [];
    const fetchMock = installFetch(
      () =>
        new Promise<Response>((resolve) => {
          answers.push(resolve);
        })
    );
    await renderSignedIn();

    let first: Promise<LogoutResult> | undefined;
    act(() => {
      first = auth!.logout();
    });
    expect(getAuthToken()).toBeNull();

    // Signed in again before the hub answered the first sign-out.
    act(() => setAuthSession('second-token', FAR_FUTURE, 'login'));
    await waitFor(() => expect(auth?.isAuthenticated).toBe(true));

    let second: Promise<LogoutResult> | undefined;
    act(() => {
      second = auth!.logout();
    });
    expect(second).not.toBe(first);
    expect(getAuthToken()).toBeNull();
    expect(auth!.isAuthenticated).toBe(false);

    const calls = logoutCalls(fetchMock);
    expect(calls.map(([, init]) => init?.headers)).toEqual([
      { Authorization: `Bearer ${TOKEN}` },
      { Authorization: 'Bearer second-token' },
    ]);

    let results: LogoutResult[] = [];
    await act(async () => {
      answers[1]!(new Response(null, { status: 204 }));
      answers[0]!(new Response(null, { status: 500 }));
      results = await Promise.all([first!, second!]);
    });
    expect(results).toEqual(['unconfirmed', 'ended']);
    expect(getAuthToken()).toBeNull();
  });

  it.each([
    ['/dagu', '/dagu/oidc-logout'],
    ['/dagu/', '/dagu/oidc-logout'],
    ['/', '/oidc-logout'],
  ])('posts to the base path %s as %s', async (basePath, expected) => {
    mocks.config.basePath = basePath;
    const fetchMock = installFetch(() =>
      Promise.resolve(new Response(null, { status: 204 }))
    );
    await renderSignedIn();

    await signOut();

    expect(logoutCalls(fetchMock).map(([url]) => url)).toEqual([expected]);
  });
});
