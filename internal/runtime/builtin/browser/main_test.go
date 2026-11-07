// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package browser

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/browserhost/devtoolsgate"
)

// TestMain lets the test binary serve as the `dagu browser devtools-gate`
// helper: without a Dagu configuration, the launcher starts the gate from
// this process's own executable. A test run keeps what its browsers learn
// about the executable in testBrowserDir.
func TestMain(m *testing.M) {
	if len(os.Args) >= 3 && os.Args[1] == "browser" && os.Args[2] == "devtools-gate" {
		if err := devtoolsgate.Main(context.Background(), os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "dagu-browser-state-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	testBrowserDir = dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}
