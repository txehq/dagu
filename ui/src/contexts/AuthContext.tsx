// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
  ReactNode,
} from 'react';
import { mutate as globalMutate } from 'swr';
import { AppBarContext } from './AppBarContext';
import { useConfig } from './ConfigContext';
import { components, UserRole } from '@/api/v1/schema';
import { sseManager } from '@/hooks/SSEManager';
import {
  TOKEN_KEY,
  addAuthSessionListener,
  clearAuthSession,
  getAuthToken,
  scheduleAuthSessionExpiry,
  setAuthSession,
} from '@/lib/authSession';
import {
  effectiveWorkspaceRole,
  normalizeAccess,
  roleAtLeast,
  workspaceRoleTarget,
} from '@/lib/workspaceAccess';

export type { UserRole } from '@/api/v1/schema';

type User = components['schemas']['User'];

type SetupResult = {
  token: string;
  expiresAt?: string;
  user: User;
};

// How a sign-out ended at the hub. 'local': only this browser's session was
// cleared, because OIDC sessions are off or there was no token (as before
// sessions existed). 'ended': the hub confirmed the session is over.
// 'unconfirmed': the hub did not confirm it (an error answer, no answer, or
// no answer in time); this browser is signed out either way, but the session
// may live on at the hub until its token expires.
export type LogoutResult = 'local' | 'ended' | 'unconfirmed';

// How long a sign-out waits for the hub before it is reported unconfirmed.
export const OIDC_LOGOUT_TIMEOUT_MS = 5000;

function oidcLogoutURL(basePath: string): string {
  return `${basePath.replace(/\/+$/, '')}/oidc-logout`;
}

type AuthContextType = {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  setupRequired: boolean;
  login: (username: string, password: string) => Promise<void>;
  setup: (username: string, password: string) => Promise<SetupResult>;
  logout: () => Promise<LogoutResult>;
  refreshUser: () => Promise<void>;
  completeSetup: (result: SetupResult) => void;
};

const AuthContext = createContext<AuthContextType | null>(null);

export { TOKEN_KEY };

export function AuthProvider({ children }: { children: ReactNode }) {
  const config = useConfig();
  const [user, setUser] = useState<User | null>(null);
  const [token, setToken] = useState<string | null>(() => getAuthToken());
  const [isLoading, setIsLoading] = useState(true);
  const [setupRequired, setSetupRequired] = useState(config.setupRequired);

  const clearLocalSession = useCallback(() => {
    setToken(null);
    setUser(null);
    sseManager.disposeAll();
    void globalMutate(() => true, undefined, { revalidate: false });
  }, []);

  // The hub sign-out under way, with the token it ends. A repeated or
  // concurrent call for that same session shares it, so the hub is asked
  // once; a session signed in since then is signed out on its own.
  const logoutInFlight = useRef<{
    token: string;
    request: Promise<LogoutResult>;
  } | null>(null);

  const logout = useCallback((): Promise<LogoutResult> => {
    const storedToken = getAuthToken();
    const inFlight = logoutInFlight.current;
    if (inFlight && (!storedToken || storedToken === inFlight.token)) {
      return inFlight.request;
    }
    // This browser is signed out first, whatever the hub answers: a tab
    // closed while the hub is asked must not leave the token behind.
    clearAuthSession('logout');
    clearLocalSession();
    // With OIDC sessions off the route does not exist: no request.
    if (!config.oidcSessionEnabled || !storedToken) {
      return Promise.resolve('local');
    }
    const request = (async (): Promise<LogoutResult> => {
      try {
        const response = await fetch(oidcLogoutURL(config.basePath), {
          method: 'POST',
          headers: { Authorization: `Bearer ${storedToken}` },
          keepalive: true,
          signal: AbortSignal.timeout(OIDC_LOGOUT_TIMEOUT_MS),
        });
        return response.status === 204 ? 'ended' : 'unconfirmed';
      } catch {
        return 'unconfirmed';
      }
    })();
    const entry = { token: storedToken, request };
    logoutInFlight.current = entry;
    void request.finally(() => {
      if (logoutInFlight.current === entry) {
        logoutInFlight.current = null;
      }
    });
    return request;
  }, [clearLocalSession, config.oidcSessionEnabled, config.basePath]);

  const refreshUser = useCallback(async () => {
    const storedToken = getAuthToken();
    if (!storedToken) {
      clearLocalSession();
      setIsLoading(false);
      return;
    }

    try {
      const response = await fetch(`${config.apiURL}/auth/me`, {
        headers: {
          Authorization: `Bearer ${storedToken}`,
        },
      });

      if (response.ok) {
        const data = await response.json();
        setUser(data.user);
        setToken(storedToken);
      } else if (response.status === 401 || response.status === 403) {
        clearAuthSession('unauthorized');
        clearLocalSession();
      } else {
        console.warn(
          'Failed to refresh authenticated user',
          response.status,
          response.statusText
        );
      }
    } catch (error) {
      console.warn('Failed to refresh authenticated user', error);
    } finally {
      setIsLoading(false);
    }
  }, [clearLocalSession, config.apiURL]);

  const login = useCallback(
    async (username: string, password: string) => {
      const response = await fetch(`${config.apiURL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.message || 'Login failed');
      }

      const data = await response.json();
      setAuthSession(data.token, data.expiresAt, 'login');
      setToken(data.token);
      setUser(data.user);
    },
    [config.apiURL]
  );

  const setup = useCallback(
    async (username: string, password: string): Promise<SetupResult> => {
      const response = await fetch(
        `${config.apiURL}/auth/setup?remoteNode=local`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password }),
        }
      );

      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        const err = new Error(data.message || 'Setup failed');
        (err as any).status = response.status;
        throw err;
      }

      const data = await response.json();
      return { token: data.token, expiresAt: data.expiresAt, user: data.user };
    },
    [config.apiURL]
  );

  const completeSetup = useCallback((result: SetupResult) => {
    setAuthSession(result.token, result.expiresAt, 'setup');
    setToken(result.token);
    setUser(result.user);
    setSetupRequired(false);
  }, []);

  useEffect(() => {
    return addAuthSessionListener((change) => {
      if (change.token) {
        setToken(change.token);
        setIsLoading(true);
        void refreshUser();
        return;
      }
      clearLocalSession();
      setIsLoading(false);
    });
  }, [clearLocalSession, refreshUser]);

  useEffect(() => {
    if (!token) {
      return;
    }
    return scheduleAuthSessionExpiry();
  }, [token]);

  useEffect(() => {
    if (config.authMode === 'builtin') {
      refreshUser();
    } else {
      setIsLoading(false);
    }
  }, [config.authMode, refreshUser]);

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user,
        isLoading,
        setupRequired,
        login,
        setup,
        completeSetup,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

export function useIsAdmin(): boolean {
  const { user } = useAuth();
  const config = useConfig();
  if (config.authMode !== 'builtin') return true;
  return user?.role === UserRole.admin;
}

export function useCanWrite(): boolean {
  const { user } = useAuth();
  const config = useConfig();
  const appBarContext = useContext(AppBarContext);
  const workspace = workspaceRoleTarget(appBarContext.workspaceSelection);
  if (config.authMode !== 'builtin') return config.permissions.writeDags;
  if (!user) return false;
  return roleAtLeast(
    effectiveWorkspaceRole(user, workspace),
    UserRole.developer
  );
}

export function useCanWriteForWorkspace(workspace?: string | null): boolean {
  const { user } = useAuth();
  const config = useConfig();
  if (config.authMode !== 'builtin') return config.permissions.writeDags;
  if (!user) return false;
  return roleAtLeast(
    effectiveWorkspaceRole(user, workspace ?? ''),
    UserRole.developer
  );
}

export function useCanAccessGitSync(): boolean {
  const { user } = useAuth();
  const config = useConfig();
  if (config.authMode !== 'builtin') return true;
  return !!user && normalizeAccess(user.workspaceAccess).all;
}

export function useCanWriteGitSync(): boolean {
  const { user } = useAuth();
  const config = useConfig();
  if (config.authMode !== 'builtin') return config.permissions.writeDags;
  return (
    !!user &&
    normalizeAccess(user.workspaceAccess).all &&
    roleAtLeast(user.role, UserRole.developer)
  );
}

export function useCanExecute(): boolean {
  const { user } = useAuth();
  const config = useConfig();
  const appBarContext = useContext(AppBarContext);
  const workspace = workspaceRoleTarget(appBarContext.workspaceSelection);
  if (config.authMode !== 'builtin') return config.permissions.runDags;
  if (!user) return false;
  return roleAtLeast(
    effectiveWorkspaceRole(user, workspace),
    UserRole.operator
  );
}

export function useCanExecuteForWorkspace(workspace?: string | null): boolean {
  const { user } = useAuth();
  const config = useConfig();
  if (config.authMode !== 'builtin') return config.permissions.runDags;
  if (!user) return false;
  return roleAtLeast(
    effectiveWorkspaceRole(user, workspace ?? ''),
    UserRole.operator
  );
}

export function useCanAccessSystemStatus(): boolean {
  const { user } = useAuth();
  const config = useConfig();
  if (config.authMode !== 'builtin') return true;
  if (!user) return false;
  return roleAtLeast(user.role, UserRole.developer);
}

export function useCanManageWebhooks(): boolean {
  const { user } = useAuth();
  const config = useConfig();
  // Webhooks require the builtin auth service (webhook token store).
  if (config.authMode !== 'builtin') return false;
  if (!user) return false;
  return roleAtLeast(user.role, UserRole.developer);
}

export function useCanViewAuditLogs(): boolean {
  const { user } = useAuth();
  const config = useConfig();
  if (config.authMode !== 'builtin') return true;
  if (!user) return false;
  return roleAtLeast(user.role, UserRole.manager);
}

function secretScopeRoleTarget(scope?: string | null): string {
  if (!scope || scope === 'global') return '';
  return scope;
}

export function useCanManageSecrets(scope?: string | null): boolean {
  const { user } = useAuth();
  const config = useConfig();
  const appBarContext = useContext(AppBarContext);
  const workspace =
    scope === undefined
      ? workspaceRoleTarget(appBarContext.workspaceSelection)
      : secretScopeRoleTarget(scope);
  if (config.authMode !== 'builtin') return true;
  if (!user) return false;
  return roleAtLeast(effectiveWorkspaceRole(user, workspace), UserRole.manager);
}

export function useCanManageProfiles(): boolean {
  return useCanManageSecrets('global');
}

export function useCanViewEventLogs(): boolean {
  const { user } = useAuth();
  const config = useConfig();
  if (config.authMode !== 'builtin') return true;
  if (!user) return false;
  return roleAtLeast(user.role, UserRole.manager);
}

export function hasRole(userRole: UserRole, requiredRole: UserRole): boolean {
  return roleAtLeast(userRole, requiredRole);
}
