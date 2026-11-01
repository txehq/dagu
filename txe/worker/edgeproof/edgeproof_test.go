// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	neturl "net/url"
	"slices"
	"strings"
	"sync/atomic"
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
	// The load check is compressed here, so its calls overlap far more than
	// they do at its real rate.
	limits.MaxCallsPerMachine = 2000
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
	names := slices.DeleteFunc(slices.Clone(defaultChecks), func(name string) bool { return name == "load" })
	for _, result := range run(t, server.URL, names...) {
		assert.True(t, result.Pass, "%s: %s", result.Check, result.Detail)
		assert.Zero(t, result.HTTP.HTML, result.Check)
	}
	assert.Contains(t, log.String(), "Heartbeat status=200 ")
	assert.Contains(t, log.String(), "StreamArtifacts status=200 ")
	assert.NotContains(t, log.String(), testToken)
	assert.NotContains(t, log.String(), "Bearer")
	assert.NotContains(t, log.String(), strings.TrimPrefix(server.URL, "http://"), "the log holds no address")
}

// The load check at a twentieth of its real wait: its heartbeats each open a
// connection, so any faster measures the test machine's accept queue.
func TestTheLoadCheckHoldsItsPollsBesideItsHeartbeats(t *testing.T) {
	server, _ := startOrigin(t)
	results, err := runChecks(context.Background(), clientConfig{URL: server.URL, Token: testToken, Limits: shortLimits(), Pause: 0.05}, []string{"load"})
	require.NoError(t, err)
	require.True(t, results[0].Pass, "%s: %v", results[0].Detail, results[0].Numbers)
	assert.EqualValues(t, loadPolls+loadSeconds*loadHeartbeats, results[0].HTTP.Requests)
}

func TestTheOverLimitRefusalIsTheChannels(t *testing.T) {
	server, _ := startOrigin(t)
	results := run(t, server.URL, "over-limit")
	require.True(t, results[0].Pass, results[0].Detail)
	assert.Equal(t, "ResourceExhausted", results[0].Numbers["code"])
}

func TestOnlyTheSizeRefusalPassesTheOverLimitCheck(t *testing.T) {
	server, _ := startOrigin(t)
	results, err := runChecks(context.Background(), clientConfig{URL: server.URL, Token: strings.Repeat("x", 32), Limits: shortLimits()}, []string{"over-limit"})
	require.NoError(t, err)
	assert.False(t, results[0].Pass, "a wrong token is refused for another reason")
}

func TestAnOutageIsTimedFromTheCallThatFailed(t *testing.T) {
	server, _ := startOrigin(t)
	var calls atomic.Int64
	transport := roundTripper(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			time.Sleep(300 * time.Millisecond)
			return nil, errors.New("connection stalled")
		}
		return http.DefaultTransport.RoundTrip(r)
	})
	results, err := runChecks(context.Background(), clientConfig{URL: server.URL, Token: testToken, Limits: shortLimits(), Pause: 0.001,
		Watch: 400 * time.Millisecond, Transport: transport}, []string{"reconnect"})
	require.NoError(t, err)
	require.True(t, results[0].Pass, results[0].Detail)
	outage, err := time.ParseDuration(results[0].Numbers["longest_outage"].(string))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, outage, 300*time.Millisecond)
}

func TestAnOutageStillOpenAtTheEndIsCounted(t *testing.T) {
	server, _ := startOrigin(t)
	url := server.URL
	server.Close()
	results, err := runChecks(context.Background(), clientConfig{URL: url, Token: testToken, Limits: shortLimits(), Pause: 0.05,
		Watch: 200 * time.Millisecond}, []string{"reconnect"})
	require.NoError(t, err)
	assert.False(t, results[0].Pass)
	outage, err := time.ParseDuration(results[0].Numbers["longest_outage"].(string))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, outage, 100*time.Millisecond)
}

func TestAnEdgePageDuringARestartIsAnOutageNotAFailure(t *testing.T) {
	server, _ := startOrigin(t)
	var calls atomic.Int64
	transport := roundTripper(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			page := httptest.NewRecorder()
			page.Header().Set("Content-Type", "text/html")
			page.WriteHeader(http.StatusBadGateway)
			return page.Result(), nil //nolint:bodyclose // the channel's client closes it
		}
		return http.DefaultTransport.RoundTrip(r)
	})
	results, err := runChecks(context.Background(), clientConfig{URL: server.URL, Token: testToken, Limits: shortLimits(), Pause: 0.001,
		Watch: 100 * time.Millisecond, Transport: transport}, []string{"reconnect"})
	require.NoError(t, err)
	assert.True(t, results[0].Pass, results[0].Detail)
	assert.EqualValues(t, 1, results[0].HTTP.HTML)
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

// bufferingProxy reads a whole request before it forwards any of it, and may
// read it slowly.
func bufferingProxy(t *testing.T, target string, bytesPerSecond int) *httptest.Server {
	t.Helper()
	address, err := neturl.Parse(target)
	require.NoError(t, err)
	forward := httputil.NewSingleHostReverseProxy(address)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body bytes.Buffer
		buffer := make([]byte, 64<<10)
		for {
			n, err := r.Body.Read(buffer)
			body.Write(buffer[:n])
			if bytesPerSecond > 0 {
				select {
				case <-r.Context().Done():
					return
				case <-time.After(time.Duration(n) * time.Second / time.Duration(bytesPerSecond)):
				}
			}
			if err != nil {
				break
			}
		}
		r.Body, r.ContentLength = io.NopCloser(&body), int64(body.Len())
		forward.ServeHTTP(w, r)
	}))
	t.Cleanup(proxy.Close)
	return proxy
}

func TestABufferedStreamShowsInTheOriginsSpan(t *testing.T) {
	server, log := startOrigin(t)
	direct := run(t, server.URL, "gap25")
	require.True(t, direct[0].Pass, direct[0].Detail)
	assert.GreaterOrEqual(t, direct[0].Numbers["origin_first_to_last_ms"], int64(15))

	held := run(t, bufferingProxy(t, server.URL, 0).URL, "gap25")
	require.True(t, held[0].Pass, held[0].Detail)
	assert.LessOrEqual(t, held[0].Numbers["origin_first_to_last_ms"], int64(5), "the body arrived whole")
	assert.Contains(t, log.String(), "stream complete chunks=2 bytes=2048")
}

func TestASlowUploadReportsItsRateAndSkipsWhatCannotFit(t *testing.T) {
	server, _ := startOrigin(t)
	proxy := bufferingProxy(t, server.URL, 2<<20)
	limits := shortLimits()
	limits.Stream = time.Second
	results, err := runChecks(context.Background(), clientConfig{URL: proxy.URL, Token: testToken, Limits: limits, CheckLimit: 3 * time.Second},
		[]string{"bytes16", "bytes31", "over-limit"})
	require.NoError(t, err)
	require.Len(t, results, 3)
	assert.False(t, results[0].Pass, "16 MiB does not fit a second at this rate")
	assert.NotZero(t, results[0].Numbers["upload_kib_s"])
	assert.Contains(t, results[1].Skipped, "past the 1s stream limit")
	assert.False(t, results[1].Pass)
	assert.Contains(t, results[2].Skipped, "past the 1s stream limit")
}

func TestAStalledEdgeCannotHoldACheckPastItsDeadline(t *testing.T) {
	release := make(chan struct{})
	edge := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(func() { close(release); edge.Close() })
	start := time.Now()
	results, err := runChecks(context.Background(), clientConfig{URL: edge.URL, Token: testToken, Limits: shortLimits(), CheckLimit: 300 * time.Millisecond},
		[]string{"bytes16", "gap25", "unary"})
	require.NoError(t, err)
	require.Len(t, results, 3)
	assert.Less(t, time.Since(start), 5*time.Second)
	for _, result := range results {
		assert.False(t, result.Pass, result.Check)
	}
}

func TestAStopFromOutsideKeepsWhatWasMeasured(t *testing.T) {
	server, _ := startOrigin(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var events []Event
	emit := func(event Event) {
		events = append(events, event)
		if event.Event == "start" && event.Check == "poll" {
			cancel()
		}
	}
	_, err := runChecks(ctx, clientConfig{URL: server.URL, Token: testToken, Limits: shortLimits(), Emit: emit}, []string{"unary", "poll", "bytes16"})
	require.ErrorIs(t, err, context.Canceled)
	require.GreaterOrEqual(t, len(events), 3)
	assert.Equal(t, "start", events[0].Event)
	assert.Equal(t, "result", events[1].Event)
	assert.True(t, events[1].Pass)
}

func TestACutStreamIsLoggedAsCut(t *testing.T) {
	limits := shortLimits()
	limits.Stream = 200 * time.Millisecond
	log := &bytes.Buffer{}
	handler, err := originHandler(originConfig{Token: testToken, Log: log, Limits: limits})
	require.NoError(t, err)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	results, err := runChecks(context.Background(), clientConfig{URL: server.URL, Token: testToken, Limits: limits, CheckLimit: 2 * time.Second}, []string{"gap35"})
	require.NoError(t, err)
	assert.Equal(t, false, results[0].Numbers["survived"])
	assert.Contains(t, log.String(), "stream cut chunks=1 bytes=1024")
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
