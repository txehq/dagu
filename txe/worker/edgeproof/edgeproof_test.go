// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dagucloud/dagu/v2/internal/txe/workerchannel"
)

const testToken = "0123456789abcdef0123456789abcdef"

func shortLimits() workerchannel.Limits {
	limits := workerchannel.DefaultLimits()
	limits.PollWait = 300 * time.Millisecond
	return limits
}

func startOrigin(t *testing.T) (*httptest.Server, *bytes.Buffer) {
	t.Helper()
	log := &bytes.Buffer{}
	handler, err := originHandler(originConfig{Token: testToken, Log: log, Limits: shortLimits()})
	require.NoError(t, err)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server, log
}

func run(t *testing.T, url string, names ...string) []Result {
	t.Helper()
	results, err := runChecks(context.Background(), clientConfig{URL: url, Token: testToken, Limits: shortLimits(), Pause: 0.001, Watch: 200 * time.Millisecond}, names)
	require.NoError(t, err)
	return results
}

func TestEveryCheckPassesAgainstTheRealHandler(t *testing.T) {
	server, log := startOrigin(t)
	for _, result := range run(t, server.URL, defaultChecks...) {
		assert.True(t, result.Pass, "%s: %s", result.Check, result.Detail)
		assert.Zero(t, result.HTTP.HTML, result.Check)
	}
	assert.Contains(t, log.String(), "Heartbeat status=200 ")
	assert.Contains(t, log.String(), "StreamArtifacts status=200 ")
	assert.NotContains(t, log.String(), testToken)
	assert.NotContains(t, log.String(), "Bearer")
	assert.NotContains(t, log.String(), strings.TrimPrefix(server.URL, "http://"), "the log holds no address")
}

func TestTheOverLimitRefusalIsTheChannels(t *testing.T) {
	server, _ := startOrigin(t)
	results := run(t, server.URL, "over-limit")
	require.True(t, results[0].Pass, results[0].Detail)
	assert.Equal(t, "ResourceExhausted", results[0].Numbers["code"])
}

func TestAStoppedOriginReadsAsUnavailable(t *testing.T) {
	server, _ := startOrigin(t)
	url := server.URL
	server.Close()
	results := run(t, url, "down")
	assert.True(t, results[0].Pass, results[0].Detail)
}

func TestAnEdgePageIsUnavailableAndNotARefusal(t *testing.T) {
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>bad gateway</html>"))
	}))
	t.Cleanup(edge.Close)
	results := run(t, edge.URL, "down")
	assert.True(t, results[0].Pass, results[0].Detail)
	assert.EqualValues(t, 1, results[0].HTTP.HTML)
}

func TestAChallengeStopsTheRun(t *testing.T) {
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cf-Mitigated", "challenge")
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(edge.Close)
	results, err := runChecks(context.Background(), clientConfig{URL: edge.URL, Token: testToken, Limits: shortLimits()}, []string{"unary", "bytes16"})
	require.Error(t, err)
	require.Len(t, results, 1, "nothing is sent after a challenge")
	assert.False(t, results[0].Pass)
}

func TestTheOriginBindsLoopbackOnly(t *testing.T) {
	err := serveOrigin(context.Background(), originConfig{Listen: "0.0.0.0:0", Token: testToken, Log: &bytes.Buffer{}})
	require.ErrorContains(t, err, "loopback")
}

func TestAWrongTokenIsRefusedByTheChannel(t *testing.T) {
	server, _ := startOrigin(t)
	results, err := runChecks(context.Background(), clientConfig{URL: server.URL, Token: strings.Repeat("x", 32), Limits: shortLimits()}, []string{"unary"})
	require.NoError(t, err)
	assert.False(t, results[0].Pass)
	assert.Contains(t, results[0].Detail, "Unauthenticated")
}

func TestTheRequestBudgetHolds(t *testing.T) {
	calls := 0
	transport := roundTripper(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, http.ErrHandlerTimeout
	})
	w := &wire{next: transport}
	for range maxRequests + 5 {
		request := httptest.NewRequest(http.MethodPost, "http://hub.invalid", nil)
		_, _ = w.RoundTrip(request) //nolint:bodyclose // nothing is returned
	}
	assert.Equal(t, maxRequests, calls)
}

func TestAnErrorIsPrintedWithoutItsAddress(t *testing.T) {
	err := fmt.Errorf("dial tcp 192.0.2.7:443: certificate is valid for hub.example.test: %w", status.Error(codes.Unavailable, "connect failed to 192.0.2.7"))
	assert.Equal(t, "Unavailable", says(err))
	assert.Equal(t, "a poll failed", says(fmt.Errorf("wrapped: %w", finding("a poll failed"))))
}

func TestWhatACallerSendsNeverReachesTheLog(t *testing.T) {
	server, log := startOrigin(t)
	response, err := http.Post(server.URL+"/%0aforged%20line", "text/plain", strings.NewReader("x")) //nolint:noctx // a test's one request
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	assert.Equal(t, http.StatusNotFound, response.StatusCode)
	assert.Contains(t, log.String(), " other status=404 ")
	assert.NotContains(t, log.String(), "forged")
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
