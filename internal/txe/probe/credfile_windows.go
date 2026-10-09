// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package probe

import "io/fs"

// checkOwner is not enforced on Windows, where file permissions are ACLs;
// the path checks still apply.
func checkOwner(string, fs.FileInfo) error { return nil }
