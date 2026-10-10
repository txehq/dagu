// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// Prefix names the record kind an opaque ID belongs to.
type Prefix string

// ID prefixes. The first seven match txe/worker/mint-id.sh.
const (
	PrefixOwner     Prefix = "own"
	PrefixProject   Prefix = "prj"
	PrefixMachine   Prefix = "mch"
	PrefixJob       Prefix = "job"
	PrefixClaim     Prefix = "clm"
	PrefixDecision  Prefix = "dec"
	PrefixAction    Prefix = "act"
	PrefixProposal  Prefix = "prp"
	PrefixReview    Prefix = "rev"
	PrefixEvent     Prefix = "evt"
	PrefixException Prefix = "exc"
	PrefixGrant     Prefix = "grt"
	PrefixClosure   Prefix = "cls"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var idPattern = regexp.MustCompile(`^([a-z]{3})_([0-9A-HJKMNP-TV-Z]{26})$`)

// NewID mints a ULID-shaped ID: 48 bits of milliseconds and 80 random bits.
func NewID(p Prefix, now time.Time) (string, error) {
	var b [16]byte
	var ms [8]byte
	binary.BigEndian.PutUint64(ms[:], uint64(now.UnixMilli())) //nolint:gosec // wall-clock milliseconds are positive
	copy(b[0:6], ms[2:8])
	if _, err := rand.Read(b[6:]); err != nil {
		return "", fmt.Errorf("registry: mint %s id: %w", p, err)
	}
	return string(p) + "_" + encode128(b), nil
}

// DerivedID returns a deterministic ID for parts: the first 128 bits of the
// SHA-256 of their canonical JSON array, in the same shape as a minted ID.
// Equal parts always yield the same ID, which makes replays idempotent.
func DerivedID(p Prefix, parts ...any) (string, error) {
	canonical, err := CanonicalJSON(parts)
	if err != nil {
		return "", fmt.Errorf("registry: derive %s id: %w", p, err)
	}
	sum := sha256.Sum256(canonical)
	var b [16]byte
	copy(b[:], sum[:16])
	return string(p) + "_" + encode128(b), nil
}

// ValidateID reports whether id is a well-formed ID with prefix p.
func ValidateID(p Prefix, id string) error {
	m := idPattern.FindStringSubmatch(id)
	if m == nil || m[1] != string(p) {
		return &Error{Code: CodeInvalid, Message: fmt.Sprintf("invalid %s id %q", p, id)}
	}
	return nil
}

// encode128 renders 128 bits as 26 Crockford base32 characters, the ULID text
// form; the first character carries the top 3 bits.
func encode128(b [16]byte) string {
	hi := binary.BigEndian.Uint64(b[:8])
	lo := binary.BigEndian.Uint64(b[8:])
	out := make([]byte, 26)
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out)
}

// CanonicalJSON encodes v with object keys sorted, no insignificant
// whitespace, no HTML escaping and numbers kept as written. It is the only
// canonical form used for digests and derived IDs; callers must not
// canonicalise values themselves.
func CanonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(generic); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("sha256:%x", sum)
}
