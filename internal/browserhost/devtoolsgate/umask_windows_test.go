// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package devtoolsgate

// groupWritableUmask does nothing on Windows, which has no umask.
func groupWritableUmask() {}
