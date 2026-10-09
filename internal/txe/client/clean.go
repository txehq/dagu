// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"fmt"
	"strings"
)

// CleanText makes text that came from the registry safe to show. Records are
// written by many sessions, and a title or a reason is free text: printed as
// it is, an escape sequence in it would drive the reader's terminal, and a
// line break would let it pass for output of the command itself. Control
// characters, including the direction overrides that reorder displayed text,
// are replaced by a visible escape. Line breaks and tabs are kept only when
// keepLayout is set, for text the command itself laid out.
func CleanText(s string, keepLayout bool) string {
	clean := true
	for _, r := range s {
		if unsafeRune(r, keepLayout) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case !unsafeRune(r, keepLayout):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String()
}

func unsafeRune(r rune, keepLayout bool) bool {
	switch {
	case r == '\n' || r == '\t':
		return !keepLayout
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0x200e, r == 0x200f, r == 0xfffd:
		return true
	default:
		return false
	}
}
