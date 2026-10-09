// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd_test

import (
	"context"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/test"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	"github.com/stretchr/testify/require"
)

// Registration asks the dagu a job's DAG will call whether it has each
// command the DAG calls. The binary built from this tree is asked here, not a
// stand-in: it has every command a rendered DAG uses, and the same question
// about a command it does not have is answered no although the binary prints
// help and exits zero.
func TestTXEBuiltBinaryHasTheCommandsItsDAGsCall(t *testing.T) {
	binary := test.Setup(t, test.WithBuiltExecutable()).Config.Paths.Executable
	ctx := context.Background()

	require.NoError(t, txeclient.HasTXECommands(ctx, binary, [][]string{
		{"resource", "check"},
		{"artifacts", "begin"},
		{"artifacts", "seal"},
		{"artifacts", "publish"},
	}))

	for _, missing := range [][]string{
		{"resource", "inspect"},
		{"artifacts", "unseal"},
		{"nothing"},
	} {
		err := txeclient.HasTXECommands(ctx, binary, [][]string{missing})
		require.ErrorContains(t, err, "it has no", "%v", missing)
	}
}
