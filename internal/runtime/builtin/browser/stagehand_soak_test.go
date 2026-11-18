// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package browser

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/browserhost"
	"github.com/stretchr/testify/require"
)

// TXE-7832 soak only, removed before the PR is ready: how long the browser
// keeps answering after its process was ended.
func TestSoakStagehandKillLatency(t *testing.T) {
	t.Parallel()

	eng := launchShop(t, &shopModel{})
	handle := eng.Handle()
	process, err := os.FindProcess(handle.BrowserPID)
	require.NoError(t, err)
	killed := time.Now()
	require.NoError(t, process.Kill())
	for time.Since(killed) < time.Minute {
		err := browserhost.Probe(context.Background(), handle.CDPURL)
		var netErr net.Error
		if errors.Is(err, browserhost.ErrUnreachable) || (errors.As(err, &netErr) && netErr.Timeout()) {
			t.Logf("TXE7832-SOAK stagehand-kill stopped after %s", time.Since(killed).Round(time.Millisecond))
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Logf("TXE7832-SOAK stagehand-kill still answering after 1m")
}
