// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package ir

import (
	"crypto/sha256"
	"encoding/hex"
)

// ExecutionRef is the portable reference of one execution of a run: the
// attempt ID and the first 8 bytes of sha256(attemptID + "\n" + queuedAt) in
// hex. A direct retry starts a new attempt; a queued retry runs the same
// attempt again under a later queue marker, so the attempt ID alone does not
// name an execution. queuedAt is the stored marker byte for byte, empty when
// the run was never queued.
func ExecutionRef(attemptID, queuedAt string) string {
	sum := sha256.Sum256([]byte(attemptID + "\n" + queuedAt))
	return attemptID + "-" + hex.EncodeToString(sum[:8])
}
