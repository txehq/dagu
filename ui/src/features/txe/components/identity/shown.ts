// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// ShownIdentity is what the identity provider says about a signed-in account,
// for display only. Nothing in the dashboard matches, filters or decides on
// these values: access comes from the hub, never from a name or an address.
export type ShownIdentity = {
  name?: string;
  username?: string;
  email?: string;
};

// shownName is the label for a signed-in account, or undefined when the
// provider gave none.
export function shownName(
  shown: ShownIdentity | undefined
): string | undefined {
  return [shown?.name, shown?.username, shown?.email]
    .map((value) => value?.trim())
    .find((value) => !!value);
}
