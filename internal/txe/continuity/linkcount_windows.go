// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package continuity

import "io/fs"

// linkCount is 1 on Windows, where transitions do not run.
func linkCount(fs.FileInfo) uint64 { return 1 }
