// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { useSyncExternalStore } from 'react';

// The app shell sits above TxePersonGate and asks the hub for workspaces,
// remote nodes and license status, which the hub refuses a person. The gate
// publishes here whether the signed-in caller is a person, so the shell can
// leave those requests out. It is kept for this tab across reloads, so a
// person's page load does not ask before the identity has been read again,
// and it is cleared on sign-out.
const STORAGE_KEY = 'dagu_txe_person';

function stored(): boolean {
  try {
    return sessionStorage.getItem(STORAGE_KEY) === '1';
  } catch {
    return false;
  }
}

let current = stored();
const listeners = new Set<() => void>();

export function setPersonSignal(person: boolean): void {
  if (person === current) return;
  current = person;
  try {
    if (person) {
      sessionStorage.setItem(STORAGE_KEY, '1');
    } else {
      sessionStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Without storage the signal still holds for this page.
  }
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

// usePersonSignal is whether the signed-in caller is, as far as this tab last
// read, a person signed in through the identity provider.
export function usePersonSignal(): boolean {
  return useSyncExternalStore(subscribe, () => current);
}

// resetPersonSignalForTest reloads the signal from storage.
export function resetPersonSignalForTest(): void {
  current = stored();
}
