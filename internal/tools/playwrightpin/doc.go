// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

// Package playwrightpin holds the test that keeps one Playwright version in
// this repository (TXE-7866).
//
// ui/pnpm-lock.yaml is the one source. CI's browser tests install their
// Chromium from the Playwright it locks, and Dockerfile.dev reads the same
// lockfile for the Chromium the dev image ships, so both run one Chromium
// build. The test fails when:
//
//   - the lockfile locks no playwright version, or more than one;
//   - the locked version is newer than the dev image's Node.js 18 can run
//     (Playwright 1.61);
//   - ui/package.json names a Playwright spec other than the locked version;
//   - Dockerfile.dev does not read the lockfile;
//   - any other file pins a Playwright version: playwright@<version>,
//     PLAYWRIGHT_VERSION=<version>, a Playwright container image tag, or a
//     Python pin. A reference such as playwright@${PLAYWRIGHT_VERSION} reads
//     the pin and is allowed.
//
// Run it with `go test ./internal/tools/playwrightpin`. CI runs it in the
// cleanup lint job, which has no path filter, so a change to the lockfile, a
// Dockerfile or a workflow alone is checked too.
package playwrightpin
