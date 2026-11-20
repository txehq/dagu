// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

// Package installerapi holds the test that keeps CI's installer tests off
// unauthenticated GitHub API calls (TXE-7871).
//
// Without -Version, scripts/installer.ps1 (and scripts/installer.cmd, which
// runs it) asks api.github.com for the latest release. GitHub limits
// unauthenticated API calls per IP address, and a GitHub-hosted runner shares
// its address with other tenants, so that call failed CI at random with
// "API rate limit exceeded". The installer sends the token in
// DAGU_INSTALLER_GITHUB_TOKEN on that one request, and CI passes the job's
// token there. The test fails when:
//
//   - a workflow step runs installer.ps1 or installer.cmd without
//     DAGU_INSTALLER_GITHUB_TOKEN set to the workflow token, in the step's,
//     the job's or the workflow's env;
//   - a workflow step runs installer.sh, which has no token path;
//   - installer.ps1 stops reading DAGU_INSTALLER_GITHUB_TOKEN, or makes a
//     request to the release API without the headers that carry it.
//
// Run it with `go test ./internal/tools/installerapi`. CI runs it in the
// cleanup lint job, which has no path filter, so a change to a workflow alone
// is checked too.
package installerapi
