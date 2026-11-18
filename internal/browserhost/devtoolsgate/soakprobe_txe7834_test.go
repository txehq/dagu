// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

// TEMPORARY soak probe for TXE-7834; removed before the PR leaves draft.

import (
	"context"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/procutil"
	"github.com/dagucloud/dagu/v2/internal/test/chrometest"
)

// probeRoundsCap is the hard iteration cap on concurrent rounds.
const probeRoundsCap = 10

func TestTXE7834Probe(t *testing.T) {
	if os.Getenv("TXE7834_PROBE") == "" {
		t.Skip("soak probe only")
	}
	chrome := chrometest.Require(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	concurrency, _ := strconv.Atoi(os.Getenv("TXE7834_PROBE_CONCURRENCY"))
	if concurrency <= 0 {
		concurrency = 4
	}
	rounds, _ := strconv.Atoi(os.Getenv("TXE7834_PROBE_ROUNDS"))
	if rounds <= 0 || rounds > probeRoundsCap {
		rounds = probeRoundsCap
	}
	launch := func(round, idx int) {
		profile, err := os.MkdirTemp("", "txe7834-probe-")
		if err != nil {
			t.Errorf("profile: %v", err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		began := time.Now()
		h, err := Start(ctx, self, Config{
			Token:      NewToken(),
			Executable: chrome,
			Args:       ChromeArgs(LaunchOptions{UserDataDir: profile, Headless: true, NoSandbox: true}),
		})
		took := time.Since(began)
		if err != nil {
			t.Logf("PROBE round=%d idx=%d began=%s ms=%d err=%v", round, idx, began.UTC().Format(time.RFC3339Nano), took.Milliseconds(), err)
			return
		}
		t.Logf("PROBE round=%d idx=%d began=%s ms=%d ok", round, idx, began.UTC().Format(time.RFC3339Nano), took.Milliseconds())
		_ = h.Kill()
		for range 300 {
			if !procutil.IsAlive(h.BrowserPID) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		for range 50 {
			if os.RemoveAll(profile) == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	// Round 0: one launch alone, the first Chrome start on this VM when the
	// probe runs first.
	launch(0, 0)
	for round := 1; round <= rounds; round++ {
		var wg sync.WaitGroup
		for idx := range concurrency {
			wg.Add(1)
			go func() {
				defer wg.Done()
				launch(round, idx)
			}()
		}
		wg.Wait()
	}
}
