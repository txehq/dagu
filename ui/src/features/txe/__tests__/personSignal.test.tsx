// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import {
  resetPersonSignalForTest,
  setPersonSignal,
  usePersonSignal,
  personSignalStorageValue,
} from '../personSignal';

afterEach(() => {
  setPersonSignal(undefined);
  sessionStorage.clear();
  resetPersonSignalForTest();
});

describe('the person signal', () => {
  it('is unknown until the gate has read the identity, then says which', () => {
    const { result } = renderHook(() => usePersonSignal());
    expect(result.current).toBeUndefined();

    act(() => setPersonSignal(true));
    expect(result.current).toBe(true);
    expect(sessionStorage.getItem('dagu_txe_person')).toBe(
      personSignalStorageValue(true)
    );

    act(() => setPersonSignal(false));
    expect(result.current).toBe(false);
    expect(sessionStorage.getItem('dagu_txe_person')).toBe(
      personSignalStorageValue(false)
    );
  });

  it('is forgotten on sign-out', () => {
    act(() => setPersonSignal(true));
    act(() => setPersonSignal(undefined));

    expect(sessionStorage.getItem('dagu_txe_person')).toBeNull();
    const { result } = renderHook(() => usePersonSignal());
    expect(result.current).toBeUndefined();
  });

  // Another tab may have signed someone else in: a stored signal holds only
  // for the session it was read for.
  it("is not trusted for another session's token", () => {
    localStorage.setItem('dagu_auth_token', 'token-a');
    sessionStorage.setItem('dagu_txe_person', personSignalStorageValue(false));
    localStorage.setItem('dagu_auth_token', 'token-b');
    resetPersonSignalForTest();

    const { result } = renderHook(() => usePersonSignal());
    expect(result.current).toBeUndefined();
    localStorage.removeItem('dagu_auth_token');
  });

  it('can hold for this page only', () => {
    act(() => setPersonSignal(false, { persist: false }));

    const { result } = renderHook(() => usePersonSignal());
    expect(result.current).toBe(false);
    expect(sessionStorage.getItem('dagu_txe_person')).toBeNull();
  });

  // A reload of a person's tab must not ask before the identity is read.
  it('holds across a reload of this tab', () => {
    localStorage.setItem('dagu_auth_token', 'token-a');
    sessionStorage.setItem('dagu_txe_person', personSignalStorageValue(true));
    resetPersonSignalForTest();

    const { result } = renderHook(() => usePersonSignal());
    expect(result.current).toBe(true);
    localStorage.removeItem('dagu_auth_token');
  });
});
