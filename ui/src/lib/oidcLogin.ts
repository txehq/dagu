// Copyright (C) 2026 TXE contributors
// SPDX-License-Identifier: GPL-3.0-or-later

// oidcLoginURL is where a browser starts the identity provider sign-in.
// prompt=login asks the provider to show its sign-in page even when the
// browser is still signed in there, so a person can use another account. It
// is the only prompt the dashboard sends.
export function oidcLoginURL(basePath: string, prompt?: 'login'): string {
  const url = `${basePath.replace(/\/+$/, '')}/oidc-login`;
  return prompt ? `${url}?prompt=${prompt}` : url;
}
