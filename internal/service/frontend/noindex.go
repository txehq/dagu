// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package frontend

import "net/http"

// robotsTagValue asks a crawler that fetches a page not to index it, follow
// its links or keep a cached copy.
const robotsTagValue = "noindex, nofollow, noarchive"

// robotsTxt disallows crawling everything. A compliant crawler then fetches
// nothing; one that ignores robots.txt still meets X-Robots-Tag. Neither keeps
// out a crawler that ignores both, and a URL linked from elsewhere may still be
// listed without its content: this discourages indexing, it is not access
// control.
const robotsTxt = "User-agent: *\nDisallow: /\n"

// noindexMiddleware sets X-Robots-Tag before anything else answers, so that
// every response carries it: pages, static files, API answers, refusals,
// redirects and errors alike.
func noindexMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Robots-Tag", robotsTagValue)
		next.ServeHTTP(w, r)
	})
}

// serveRobotsTxt answers GET /robots.txt at the host's root, where crawlers
// look for it whatever the base path.
func serveRobotsTxt(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(robotsTxt))
}
