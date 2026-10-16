// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rawGet fetches path with no credentials and without following redirects.
func rawGet(t *testing.T, server test.Server, path string) (int, http.Header, string) {
	t.Helper()
	url := fmt.Sprintf("http://%s:%d%s", server.Config.Server.Host, server.Config.Server.Port, path)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(url)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, resp.Header, string(body)
}

func TestNoIndex_On(t *testing.T) {
	t.Parallel()
	server := setupBuiltinAuthServer(t, func(cfg *config.Config) { cfg.Server.NoIndex = true })

	// Every kind of answer carries the header: the page, a static path's 404, a
	// public API answer, a refusal for missing credentials, and a path that
	// matches no API route.
	for path, status := range map[string]int{
		"/":                     http.StatusOK,
		"/assets/favicon.ico":   http.StatusNotFound, // a static path the test build lacks
		"/api/v1/health":        http.StatusOK,
		"/api/v1/dags":          http.StatusUnauthorized,
		"/api/v1/no-such-route": http.StatusUnauthorized,
	} {
		t.Run(path, func(t *testing.T) {
			code, header, _ := rawGet(t, server, path)
			assert.Equal(t, status, code)
			assert.Equal(t, "noindex, nofollow, noarchive", header.Get("X-Robots-Tag"))
		})
	}

	t.Run("the page carries the meta tag", func(t *testing.T) {
		_, _, body := rawGet(t, server, "/")
		assert.Contains(t, body, `<meta name="robots" content="noindex, nofollow, noarchive" />`)
	})

	t.Run("robots.txt disallows everything, without credentials", func(t *testing.T) {
		code, _, body := rawGet(t, server, "/robots.txt")
		assert.Equal(t, http.StatusOK, code)
		assert.Equal(t, "User-agent: *\nDisallow: /\n", body)
	})
}

func TestNoIndex_OffChangesNothing(t *testing.T) {
	t.Parallel()
	server := setupBuiltinAuthServer(t)

	_, header, body := rawGet(t, server, "/")
	assert.Empty(t, header.Get("X-Robots-Tag"))
	assert.NotContains(t, body, `name="robots"`)
	_, _, robots := rawGet(t, server, "/robots.txt")
	assert.NotContains(t, robots, "Disallow")
}
