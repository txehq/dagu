// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity

import "context"

// SetScanWorkers sets the scan's read pool for one test and returns what
// restores it (TXE-7023).
func SetScanWorkers(n int) (restore func()) {
	old := scanWorkers
	scanWorkers = n
	return func() { scanWorkers = old }
}

// ForEach runs the scan's bounded pool on its own.
func ForEach(ctx context.Context, n int, fn func(i int) error) error {
	return (&scanner{ctx: ctx}).forEach(n, fn)
}
