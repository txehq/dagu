// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package writegate_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/browserhost/devtoolsgate"
)

// TestMain lets the test binary serve as the `dagu browser devtools-gate`
// helper the tests' browsers run behind.
func TestMain(m *testing.M) {
	if len(os.Args) >= 3 && os.Args[1] == "browser" && os.Args[2] == "devtools-gate" {
		if err := devtoolsgate.Main(context.Background(), os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
