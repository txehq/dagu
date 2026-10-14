// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

import { describe, expect, it } from 'vitest';

import { ulid } from '../access';

describe('ulid', () => {
  it('is 26 Crockford base32 characters', () => {
    expect(ulid()).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
  });

  it('starts with the time in milliseconds', () => {
    expect(ulid(0).slice(0, 10)).toBe('0000000000');
    expect(ulid(1).slice(0, 10)).toBe('0000000001');
    expect(ulid(32).slice(0, 10)).toBe('0000000010');
    expect(ulid(2 ** 48 - 1).slice(0, 10)).toBe('7ZZZZZZZZZ');
  });

  it('differs every call', () => {
    expect(ulid(5)).not.toBe(ulid(5));
  });
});
