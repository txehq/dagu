// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// Browser storage that holds what one signed-in account read or wrote, such
// as run outputs and unsaved drafts, must not outlive that account's session:
// a second account in the same browser profile would read it (TXE-5923).
//
// SESSION_DATA_PREFIXES is the one list of storage key prefixes that hold
// such data. clearSessionData removes every key under them from storage,
// whether or not the code that wrote them has loaded, and runs the resets of
// the in-memory copies registered with registerSessionDataReset.
// src/lib/__tests__/sessionData.test.ts fails a file that uses localStorage
// without being classified as session data, a preference, or auth.

/** Run outputs captured by the editor (outputCache.ts). */
export const OUTPUT_CACHE_PREFIX = 'dagu.output-cache.v1:';
/** Unsaved DAG definitions (draftStorage.ts). */
export const DRAFT_PREFIX = 'dagu:draft:';

/** Open wiki tabs and their unsaved page drafts (WikiPageTabContext), with
 * the key they had before the wiki was renamed. */
export const WIKI_TABS_PREFIXES = ['dagu_wiki_tabs', 'dagu_doc_tabs'] as const;
/** Open DAG tabs, which name the DAGs this account opened (TabContext). */
export const DAG_TABS_PREFIX = 'dagu_dag_tabs';

export const SESSION_DATA_PREFIXES: readonly string[] = [
  OUTPUT_CACHE_PREFIX,
  DRAFT_PREFIX,
  ...WIKI_TABS_PREFIXES,
  DAG_TABS_PREFIX,
];

const resets = new Set<() => void>();

/** Registers the reset of an in-memory copy of session data. */
export function registerSessionDataReset(reset: () => void): () => void {
  resets.add(reset);
  return () => {
    resets.delete(reset);
  };
}

/**
 * Removes every account's session data from this browser. Each failure is
 * silent: storage may be absent or blocked.
 */
export function clearSessionData(
  storage: Storage | null = typeof window === 'undefined'
    ? null
    : window.localStorage
): void {
  try {
    if (storage) {
      const doomed: string[] = [];
      for (let i = 0; i < storage.length; i++) {
        const key = storage.key(i);
        if (key && SESSION_DATA_PREFIXES.some((p) => key.startsWith(p))) {
          doomed.push(key);
        }
      }
      doomed.forEach((key) => storage.removeItem(key));
    }
  } catch {
    // Storage is unavailable; nothing is left to read either.
  }
  resets.forEach((reset) => {
    try {
      reset();
    } catch {
      // A reset that fails leaves only its own copy.
    }
  });
}
