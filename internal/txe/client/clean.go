// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"fmt"
	"strings"
	"unicode"
)

// CleanText makes text that came from the registry safe to show. Records are
// written by many sessions, and a title or a reason is free text: printed as
// it is, an escape sequence in it would drive the reader's terminal, and a
// line break would let it pass for output of the command itself.
//
// Every character that is not printable is replaced by a visible escape:
// control characters, the format characters that hide or reorder displayed
// text, and the Unicode line and paragraph separators. A backslash is doubled,
// so an escape in the output can only have been written by this function.
// Line breaks and tabs are kept when keepLayout is set, for text the command
// laid out itself.
func CleanText(s string, keepLayout bool) string {
	clean := true
	for _, r := range s {
		if needsEscape(r, keepLayout) {
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
		case r == '\\':
			b.WriteString(`\\`)
		case !needsEscape(r, keepLayout):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x10000:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	return b.String()
}

// needsEscape reports whether r must not be shown as it is. Printable
// characters and the ordinary space are shown; everything else is not, which
// covers the control (Cc), format (Cf), line separator (Zl), paragraph
// separator (Zp), surrogate and unassigned classes without listing them.
func needsEscape(r rune, keepLayout bool) bool {
	switch r {
	case '\\', unicode.ReplacementChar:
		return true
	case '\n', '\t':
		return !keepLayout
	default:
		return !unicode.IsPrint(r)
	}
}
