// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"time"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewID mints an opaque ID, <prefix>_<ULID>: 48 bits of time and 80 random
// bits. It is the shape every TXE record ID has; nothing is derived from a
// name, path, host or session.
func NewID(prefix string) (string, error) {
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())               //nolint:gosec // wall-clock milliseconds are positive
	binary.BigEndian.PutUint16(b[0:2], uint16(ms>>32)) //nolint:gosec // the time is 48 bits; these are its top 16
	binary.BigEndian.PutUint32(b[2:6], uint32(ms))     //nolint:gosec // the low 32 bits are meant
	if _, err := rand.Read(b[6:]); err != nil {
		return "", fmt.Errorf("mint %s id: %w", prefix, err)
	}
	hi, lo := binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])
	out := make([]byte, 26)
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return prefix + "_" + string(out), nil
}
