// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { useSyncExternalStore } from 'react';

import { TOKEN_KEY } from '@/lib/authSession';

// The app shell sits above TxePersonGate and asks the hub for workspaces,
// remote nodes and license status, which the hub refuses a person. The gate
// publishes here whether the signed-in caller is a person once it has read
// the identity; until then the signal is unknown (undefined). It is kept for
// this tab across reloads, so a person's page load does not ask before the
// identity has been read again, and it is cleared on sign-out.
const STORAGE_KEY = 'dagu_txe_person';

type Signal = boolean | undefined;

// sessionTag names the signed-in session without keeping its token: a
// 32-bit FNV-1a of the token. A stored signal holds only for the session it
// was read for, so a token another tab put in place is read again.
function sessionTag(): string {
  let token: string | null = null;
  try {
    token = localStorage.getItem(TOKEN_KEY);
  } catch {
    return '';
  }
  if (!token) return '';
  let hash = 0x811c9dc5;
  for (let i = 0; i < token.length; i++) {
    hash ^= token.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16);
}

// personSignalStorageValue is what is stored for person in the current session.
export function personSignalStorageValue(person: boolean): string {
  return `${sessionTag()}:${person ? '1' : '0'}`;
}

function stored(): Signal {
  try {
    const value = sessionStorage.getItem(STORAGE_KEY);
    if (!value) return undefined;
    const [tag, flag] = value.split(':');
    if (!tag || tag !== sessionTag()) return undefined;
    return flag === '1' ? true : flag === '0' ? false : undefined;
  } catch {
    return undefined;
  }
}

let current: Signal = stored();
const listeners = new Set<() => void>();

// setPersonSignal records what the gate read; undefined forgets it. With
// persist false it holds for this page only: a reload asks again.
export function setPersonSignal(
  person: Signal,
  { persist = true }: { persist?: boolean } = {}
): void {
  try {
    if (person === undefined || !persist) {
      sessionStorage.removeItem(STORAGE_KEY);
    } else {
      sessionStorage.setItem(STORAGE_KEY, personSignalStorageValue(person));
    }
  } catch {
    // Without storage the signal still holds for this page.
  }
  if (person === current) return;
  current = person;
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
