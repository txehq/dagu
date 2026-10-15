// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import React from 'react';

// PersonScopeContext is true inside the dashboard of a person acting for an
// owner (PersonApp). Shared native pages read it to leave out what the hub
// refuses a person, so a refusal never shows as a failure.
export const PersonScopeContext = React.createContext(false);

export function usePersonScope(): boolean {
  return React.useContext(PersonScopeContext);
}

// The DAG page tabs a person is not offered: the hub refuses a person the
// webhook and the notification settings of a DAG.
export const PERSON_HIDDEN_DAG_TABS: ReadonlySet<string> = new Set([
  'webhook',
  'notifications',
]);

// isNotFoundAnswer is whether a native request failed with the hub's 404.
// The hub gives a person the same 404 for a DAG or run that does not exist
// and for one of another owner, so a page must not tell the two apart.
export function isNotFoundAnswer(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const value = error as { code?: string; response?: { status?: number } };
  return value.code === 'not_found' || value.response?.status === 404;
}
