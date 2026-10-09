// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeskill

import (
	"fmt"
	"os"
	"runtime"
	"testing"
)

// The TXE job tooling packages, links and runs jobs on a Unix machine: it
// relies on permission bits, symbolic links and POSIX paths. Its tests run
// there only, and say so where they do not.
func TestMain(m *testing.M) {
	if runtime.GOOS == "windows" {
		fmt.Println("skipped: TXE job tooling is built for and tested on Unix machines")
		os.Exit(0)
	}
	os.Exit(m.Run())
}
