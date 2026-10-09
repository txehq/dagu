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
		{name: "Plain", in: "Watch the hub volume (v2) — état", want: "Watch the hub volume (v2) — état"},
		{name: "EscapeSequence", in: "ok\x1b[2J\x1b[31mFAIL", want: `ok\x1b[2J\x1b[31mFAIL`},
		{name: "LineBreak", in: "title\nRegistration: ready", want: `title\x0aRegistration: ready`},
		{name: "CarriageReturn", in: "real\rfake", want: `real\x0dfake`},
		{name: "C1Control", in: "a\u009b31mb", want: `a\x9b31mb`},
		{name: "Delete", in: "a\x7fb", want: `a\x7fb`},
		{name: "DirectionOverride", in: "safe\u202egnp.exe", want: `safe\u202egnp.exe`},
		{name: "InvalidUTF8", in: "a\xffb", want: `a\ufffdb`},
		{name: "LayoutKept", in: "line one\n\tline two\x1b[0m", want: "line one\n\tline two" + `\x1b[0m`, keepLayout: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, CleanText(tt.in, tt.keepLayout))
		})
	}
}
