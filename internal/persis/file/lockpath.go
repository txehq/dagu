// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package file

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/dagucloud/dagu/v2/internal/cmn/dirlock"
)

// IsLockMetadataPath reports whether path is, or lies under, the store's own
// coordination lock metadata: a record lock bucket directory
// (.dagu_record_locks) or a directory lock (dirlock's .dagu_lock, including
// one being released). These names are reserved: no record, artifact or log
// is ever written under them. The rule reads path elements, so a data file
// whose name merely resembles a lock (report.lock, .dagu_lock.txt) is not
// lock metadata.
//
// This is the one place that says what lock metadata is. The store's own
// walks and every scanner that asserts on stored data ask here, so a lock
// the live process holds is never taken for a record, and nothing else is
// passed over.
func IsLockMetadataPath(path string) bool {
	return slices.ContainsFunc(strings.FieldsFunc(filepath.ToSlash(path), func(r rune) bool { return r == '/' }), IsLockMetadataName)
}

// IsLockMetadataName reports whether one path element names lock metadata.
func IsLockMetadataName(name string) bool {
	return name == recordLockDirectoryName || dirlock.IsLockDirectoryName(name)
}
