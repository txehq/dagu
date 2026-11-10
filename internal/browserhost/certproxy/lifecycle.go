// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package certproxy

import (
	"context"
	"errors"
	"net"
	"time"
)

const (
	// browserPollInterval spaces the checks that the browser still runs.
	browserPollInterval = 2 * time.Second
	// defaultGrace is how long the proxy waits for the browser to answer
	// for the first time when Config sets no grace period.
	defaultGrace = 5 * time.Minute
)

// prober asks the browser at cdpURL who it is and returns its identity, as
// browserhost.BrowserID does over the browser's DevTools address. An error
// that timedOut reports is a browser slow to answer; any other error means
// no browser answers there.
type prober func(ctx context.Context, cdpURL string) (string, error)

// watchBrowser returns once the browser at cdpURL is gone, as probe reports
// it: nothing accepts connections there, or something else answers in its
// place, such as another browser or a server that took its port. It also
// returns when no browser answers within grace, or when ctx ends. A browser
// that is slow to answer counts as running.
func watchBrowser(ctx context.Context, cdpURL string, grace, interval time.Duration, probe prober) {
	deadline := time.Now().Add(grace)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var pinned string
	for {
		id, err := probe(ctx, cdpURL)
		switch {
		case ctx.Err() != nil:
			return
		case pinned == "" && err == nil:
			pinned = id
		case pinned == "" && time.Now().After(deadline):
			return
		case pinned != "" && err != nil && !timedOut(err):
			return
		case pinned != "" && err == nil && id != pinned:
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// timedOut reports whether err is a check that ran out of time, which a
// busy browser causes, rather than an answer that no browser is there.
func timedOut(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
