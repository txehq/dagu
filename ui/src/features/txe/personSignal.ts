// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { useSyncExternalStore } from 'react';

// The app shell sits above TxePersonGate and asks the hub for workspaces,
// remote nodes and license status, which the hub refuses a person. The gate
// publishes here whether the signed-in caller is a person once it has read
// the identity; until then the signal is unknown (undefined). It is kept for
// this tab across reloads, so a person's page load does not ask before the
// identity has been read again, and it is cleared on sign-out.
const STORAGE_KEY = 'dagu_txe_person';

type Signal = boolean | undefined;

function stored(): Signal {
  try {
    const value = sessionStorage.getItem(STORAGE_KEY);
    return value === '1' ? true : value === '0' ? false : undefined;
  } catch {
    return undefined;
  }
}

let current: Signal = stored();
const listeners = new Set<() => void>();

// setPersonSignal records what the gate read; undefined forgets it.
export function setPersonSignal(person: Signal): void {
  if (person === current) return;
  current = person;
  try {
    if (person === undefined) {
      sessionStorage.removeItem(STORAGE_KEY);
    } else {
      sessionStorage.setItem(STORAGE_KEY, person ? '1' : '0');
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

// usePersonSignal is whether the signed-in caller is, as this tab last read
// it, a person signed in through the identity provider; undefined until the
// gate has read the identity of this session.
export function usePersonSignal(): Signal {
  return useSyncExternalStore(subscribe, () => current);
}

// resetPersonSignalForTest reloads the signal from storage.
export function resetPersonSignalForTest(): void {
  current = stored();
}
