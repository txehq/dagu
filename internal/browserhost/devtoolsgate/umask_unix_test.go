// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package devtoolsgate

import "syscall"

// groupWritableUmask makes the tests run as on a host whose umask lets the
// group write (002, common with per-user groups). The gate refuses a
// profile directory others may write, so a test that makes its profile
// with a mode the umask decides fails here on every host, not only on
// those hosts.
func groupWritableUmask() {
	syscall.Umask(0o002)
}
