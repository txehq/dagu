// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package transportauth

// SetSyncCredentialDir replaces the directory sync of credential writes for
// one test and returns what restores it.
func SetSyncCredentialDir(sync func(string) error) (restore func()) {
	previous := syncCredentialDir
	syncCredentialDir = sync
	return func() { syncCredentialDir = previous }
}
