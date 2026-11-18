// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package browser

// openNoFollow is 0 on Windows: an os.Root open does not leave the
// directory, and every file is checked with Lstat first.
const openNoFollow = 0
