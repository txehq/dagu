// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package browser

import "syscall"

// openNoFollow makes an open refuse a symbolic link.
const openNoFollow = syscall.O_NOFOLLOW
