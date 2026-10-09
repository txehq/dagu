// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCleanText(t *testing.T) {
	tests := []struct {
		name, in, want string
		keepLayout     bool
	}{
		{name: "Plain", in: "Watch the hub volume (v2), 100% of it", want: "Watch the hub volume (v2), 100% of it"},
		{name: "Accented", in: "caf\u00e9 na\u00efve", want: "caf\u00e9 na\u00efve"},
		{name: "EscapeSequence", in: "ok\x1b[2J\x1b[31mFAIL", want: `ok\x1b[2J\x1b[31mFAIL`},
		{name: "LineBreak", in: "title\nRegistration: ready", want: `title\x0aRegistration: ready`},
		{name: "CarriageReturn", in: "real\rfake", want: `real\x0dfake`},
		{name: "C1Control", in: "a\u009b31mb", want: `a\x9b31mb`},
		{name: "Delete", in: "a\x7fb", want: `a\x7fb`},
		{name: "DirectionOverride", in: "safe\u202egnp.exe", want: `safe\u202egnp.exe`},
		{name: "DirectionIsolate", in: "a\u2066b\u2069", want: `a\u2066b\u2069`},
		{name: "ArabicLetterMark", in: "a\u061cb", want: `a\u061cb`},
		{name: "ZeroWidth", in: "pass\u200bword\ufeff", want: `pass\u200bword\ufeff`},
		{name: "LineSeparator", in: "a\u2028b\u2029c", want: `a\u2028b\u2029c`},
		{name: "TagCharacter", in: "a\U000e0041b", want: `a\U000e0041b`},
		{name: "InvalidUTF8", in: "a\xffb", want: `a\ufffdb`},
		{name: "LiteralEscapeText", in: `plain \x1b text`, want: `plain \\x1b text`},
		{name: "BackslashWithControl", in: "C:\\dir\x1b", want: `C:\\dir\x1b`},
		{name: "LayoutKept", in: "line one\n\tline two\x1b[0m", want: "line one\n\tline two" + `\x1b[0m`, keepLayout: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, CleanText(tt.in, tt.keepLayout))
		})
	}
}
