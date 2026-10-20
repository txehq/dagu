// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';

import {
  resetPersonSignalForTest,
  setPersonSignal,
  usePersonSignal,
} from '../personSignal';

afterEach(() => {
  setPersonSignal(false);
  sessionStorage.clear();
  resetPersonSignalForTest();
});

describe('the person signal', () => {
  it('tells the app shell when the caller is a person, and when not', () => {
    const { result } = renderHook(() => usePersonSignal());
    expect(result.current).toBe(false);

    act(() => setPersonSignal(true));
    expect(result.current).toBe(true);
    expect(sessionStorage.getItem('dagu_txe_person')).toBe('1');

    act(() => setPersonSignal(false));
    expect(result.current).toBe(false);
    expect(sessionStorage.getItem('dagu_txe_person')).toBeNull();
  });

  // A reload of a person's tab must not ask before the identity is read.
  it('holds across a reload of this tab', () => {
    sessionStorage.setItem('dagu_txe_person', '1');
    resetPersonSignalForTest();

    const { result } = renderHook(() => usePersonSignal());
    expect(result.current).toBe(true);
  });
});
