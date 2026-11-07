// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package browserhost

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/cmn/procutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A recorded browser counts as gone only once its process has exited; its
// gate's address going quiet says nothing about a browser that hangs on its
// way out. Without a recorded process the address decides.
func TestRecordedBrowserGone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const address = "http://127.0.0.1:0/TESTTOKEN0000000000000000A"

	self := os.Getpid()
	selfStartedAt, _ := procutil.StartTime(self)
	alive := Record{CDPURL: address, BrowserPID: self, BrowserStartedAt: selfStartedAt}
	assert.False(t, recordedBrowserGone(ctx, alive), "a live browser process is not gone, whatever its address says")

	exited := exec.Command(os.Args[0], "-test.run=^$")
	require.NoError(t, exited.Start())
	pid := exited.Process.Pid
	startedAt, _ := procutil.StartTime(pid)
	require.NoError(t, exited.Wait())
	gone := Record{CDPURL: address, BrowserPID: pid, BrowserStartedAt: startedAt}
	assert.True(t, recordedBrowserGone(ctx, gone), "an exited process is gone even while nothing is known of the address")

	assert.True(t, recordedBrowserGone(ctx, Record{CDPURL: address}), "without a process, an address nothing answers at is gone")
	assert.True(t, recordedBrowserGone(ctx, Record{CDPURL: "http://127.0.0.1:9222"}), "a record from before gates, without a process, cannot be reached and is gone")
}
