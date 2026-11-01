// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/workerchannel"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

const (
	// maxRequests is every request one client run may send. It holds whatever
	// a check is asked: a run that reaches it stops.
	maxRequests = 1500
	// loadPolls and the heartbeats beside them are the load check: as many
	// polls as a hundred workers hold, and a heartbeat rate a hundred workers
	// reach in ten seconds of their own, for half a minute.
	loadPolls      = 100
	loadHeartbeats = 10
	loadSeconds    = 30
	maxWatch       = 10 * time.Minute

	chunkBytes = 1 << 20
)

var defaultChecks = []string{"unary", "refused", "poll", "bytes16", "bytes31", "over-limit", "gap25", "gap35", "hold", "load"}

func allChecks() []string {
	return append(slices.Clone(defaultChecks), "down", "reconnect")
}

type clientConfig struct {
	URL   string
	Token string
	Watch time.Duration
	// Limits are the channel's defaults when zero.
	Limits workerchannel.Limits
	// Pause scales the waits inside a check, for a test. Zero is one.
	Pause float64
	// HTTP stands in for the real transport, for a test.
	Transport http.RoundTripper
}

// Result is one check's outcome and what it measured.
type Result struct {
	Check   string         `json:"check"`
	Pass    bool           `json:"pass"`
	Took    string         `json:"took"`
	Numbers map[string]any `json:"numbers,omitempty"`
	Detail  string         `json:"detail,omitempty"`
	HTTP    wireCounts     `json:"http"`
}

type wireCounts struct {
	Requests int64            `json:"requests"`
	Statuses map[string]int64 `json:"statuses,omitempty"`
	Protos   map[string]int64 `json:"protos,omitempty"`
	// HTML counts answers that came back as a page.
	HTML int64 `json:"html"`
	// Challenges counts answers that say an edge asked for a challenge.
	Challenges int64 `json:"challenges"`
}

// wire counts what crossed, and refuses to send past the cap.
type wire struct {
	next       http.RoundTripper
	mu         sync.Mutex
	counts     wireCounts
	total      atomic.Int64
	challenged atomic.Bool
}

var errBudget = errors.New("the run's request budget is spent")

func (w *wire) RoundTrip(r *http.Request) (*http.Response, error) {
	if w.total.Add(1) > maxRequests {
		return nil, errBudget
	}
	if w.challenged.Load() {
		return nil, errors.New("stopped at a challenge")
	}
	resp, err := w.next.RoundTrip(r)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.counts.Requests++
	if err != nil {
		return resp, err
	}
	bump(&w.counts.Statuses, fmt.Sprint(resp.StatusCode))
	bump(&w.counts.Protos, resp.Proto)
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		w.counts.HTML++
	}
	if resp.Header.Get("Cf-Mitigated") != "" {
		w.counts.Challenges++
		w.challenged.Store(true)
	}
	return resp, nil
}

func bump(m *map[string]int64, key string) {
	if *m == nil {
		*m = map[string]int64{}
	}
	(*m)[key]++
}

// take returns the counts since the last take.
func (w *wire) take() wireCounts {
	w.mu.Lock()
	defer w.mu.Unlock()
	counts := w.counts
	w.counts = wireCounts{}
	return counts
}

const workerID = originMachine + "@edgeproof"

func machineLabels() map[string]string { return map[string]string{txepkg.LabelMachine: originMachine} }

func heartbeat() *coordinatorv1.HeartbeatRequest {
	return &coordinatorv1.HeartbeatRequest{WorkerId: workerID, Labels: machineLabels()}
}

type bearer string

func (b bearer) HTTPAuthorization(context.Context, string) (string, error) {
	return "Bearer " + string(b), nil
}

type client struct {
	cfg  clientConfig
	wire *wire
}

func (c *client) conn(token string, limits workerchannel.Limits) (coordinatorv1.CoordinatorServiceClient, error) {
	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{
		BaseURL:     strings.TrimRight(c.cfg.URL, "/") + path.Join(apiRoot, workerchannel.MountPath),
		Credentials: bearer(token), Limits: limits,
		HTTP: &http.Client{Transport: c.wire},
	})
	if err != nil {
		return nil, err
	}
	return coordinatorv1.NewCoordinatorServiceClient(conn), nil
}

func (c *client) wait(ctx context.Context, d time.Duration) {
	if c.cfg.Pause > 0 {
		d = time.Duration(float64(d) * c.cfg.Pause)
	}
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// finding is a failure in the check's own words. They hold no address.
type finding string

func (f finding) Error() string { return string(f) }

// says prints an error for the results. Transport text can hold an address or a
// certificate's names, so anything not a finding is reduced to its code.
func says(err error) string {
	if err == nil {
		return ""
	}
	if f, ok := errors.AsType[finding](err); ok {
		return string(f)
	}
	return status.Code(err).String()
}

type check func(ctx context.Context, c *client, api coordinatorv1.CoordinatorServiceClient) (map[string]any, error)

func checkFor(name string) (check, bool) {
	checks := map[string]check{
		"unary": checkUnary, "refused": checkRefused, "poll": checkPoll,
		"bytes16": func(ctx context.Context, _ *client, api coordinatorv1.CoordinatorServiceClient) (map[string]any, error) {
			return streamBytes(ctx, api, 16)
		},
		"bytes31": func(ctx context.Context, _ *client, api coordinatorv1.CoordinatorServiceClient) (map[string]any, error) {
			return streamBytes(ctx, api, 31)
		},
		"over-limit": checkOverLimit, "gap25": gapCheck(25 * time.Second), "gap35": gapCheck(35 * time.Second),
		"hold": checkHold, "load": checkLoad, "down": checkDown, "reconnect": checkReconnect,
	}
	found, ok := checks[name]
	return found, ok
}

func runChecks(ctx context.Context, cfg clientConfig, names []string) ([]Result, error) {
	parsed, err := url.Parse(cfg.URL)
	if err != nil || parsed.Host == "" {
		return nil, errors.New("--url is not a URL with a host")
	}
	next := cfg.Transport
	if next == nil {
		next = workerchannel.NewHTTPClient().Transport
	}
	c := &client{cfg: cfg, wire: &wire{next: next}}
	limits := cfg.Limits
	if limits == (workerchannel.Limits{}) {
		limits = workerchannel.DefaultLimits()
	}
	c.cfg.Limits = limits
	api, err := c.conn(cfg.Token, limits)
	if err != nil {
		return nil, err
	}
	var results []Result
	for _, name := range names {
		run, ok := checkFor(name)
		if !ok {
			return results, fmt.Errorf("unknown check %q", name)
		}
		start := time.Now()
		numbers, err := run(ctx, c, api)
		counts := c.wire.take()
		result := Result{Check: name, Pass: err == nil, Took: time.Since(start).Round(time.Millisecond).String(),
			Numbers: numbers, Detail: says(err), HTTP: counts}
		// A stopped origin and a restart are meant to meet an edge's error page.
		if counts.Challenges > 0 || (counts.HTML > 0 && name != "down" && name != "reconnect") {
			result.Pass, result.Detail = false, "an edge answered with a page: "+result.Detail
		}
		results = append(results, result)
		if c.wire.challenged.Load() {
			return results, errors.New("stopped at a challenge")
		}
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
	}
	return results, nil
}

func checkUnary(ctx context.Context, _ *client, api coordinatorv1.CoordinatorServiceClient) (map[string]any, error) {
	_, err := api.Heartbeat(ctx, heartbeat())
	return nil, err
}

// checkRefused sends a wrong token. A refusal must come from the channel, as
// itself: an edge's error reads as Unavailable.
func checkRefused(ctx context.Context, c *client, _ coordinatorv1.CoordinatorServiceClient) (map[string]any, error) {
	wrong := make([]byte, 32)
	_, _ = rand.Read(wrong)
	api, err := c.conn(hex.EncodeToString(wrong), c.cfg.Limits)
	if err != nil {
		return nil, err
	}
	_, err = api.Heartbeat(ctx, heartbeat())
	code := status.Code(err)
	if code != codes.Unauthenticated {
		return map[string]any{"code": code.String()}, finding("a wrong token got " + code.String())
	}
	return map[string]any{"code": code.String()}, nil
}

func polls(ctx context.Context, api coordinatorv1.CoordinatorServiceClient, n int) (map[string]any, error) {
	var wg sync.WaitGroup
	var failed atomic.Int64
	var slowest atomic.Int64
	var mu sync.Mutex
	failures := map[string]int{}
	for range n {
		wg.Go(func() {
			start := time.Now()
			_, err := api.Poll(ctx, &coordinatorv1.PollRequest{WorkerId: workerID, PollerId: "edgeproof", Labels: machineLabels()})
			took := time.Since(start).Milliseconds()
			for {
				current := slowest.Load()
				if took <= current || slowest.CompareAndSwap(current, took) {
					break
				}
			}
			if err != nil {
				failed.Add(1)
				mu.Lock()
				failures[status.Code(err).String()]++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	numbers := map[string]any{"polls": n, "failed": failed.Load(), "slowest_ms": slowest.Load(), "failures": maps.Clone(failures)}
	if failed.Load() > 0 {
		return numbers, finding("a poll failed")
	}
	return numbers, nil
}

func checkPoll(ctx context.Context, _ *client, api coordinatorv1.CoordinatorServiceClient) (map[string]any, error) {
	return polls(ctx, api, loadPolls)
}

type artifactStream = interface {
	Send(*coordinatorv1.ArtifactChunk) error
	CloseAndRecv() (*coordinatorv1.StreamArtifactsResponse, error)
}

func syntheticChunk(digest interface{ Write([]byte) (int, error) }, size int) (*coordinatorv1.ArtifactChunk, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}
	_, _ = digest.Write(data)
	return &coordinatorv1.ArtifactChunk{WorkerId: workerID, RelativePath: "synthetic.bin", Data: data}, nil
}

func finish(stream artifactStream, want []byte, sent uint64) (map[string]any, error) {
	reply, err := stream.CloseAndRecv()
	if err != nil {
		return nil, err
	}
	numbers := map[string]any{"bytes_sent": sent, "bytes_received": reply.BytesWritten, "chunks": reply.ChunksReceived}
	if reply.BytesWritten != sent || reply.Error != hex.EncodeToString(want) {
		return numbers, finding("the origin did not receive the bytes sent")
	}
	return numbers, nil
}

func streamBytes(ctx context.Context, api coordinatorv1.CoordinatorServiceClient, mib int) (map[string]any, error) {
	stream, err := api.StreamArtifacts(ctx)
	if err != nil {
		return nil, err
	}
	digest := sha256.New()
	var sent uint64
	for range mib {
		chunk, err := syntheticChunk(digest, chunkBytes)
		if err != nil {
			return nil, err
		}
		if err := stream.Send(chunk); err != nil {
			_, recvErr := stream.CloseAndRecv()
			return nil, errors.Join(err, recvErr)
		}
		sent += chunkBytes
	}
	return finish(stream, digest.Sum(nil), sent)
}

// checkOverLimit lifts the client's own limit, so that the origin's is what is
// met: a refusal from the channel, not an edge's page.
func checkOverLimit(ctx context.Context, c *client, _ coordinatorv1.CoordinatorServiceClient) (map[string]any, error) {
	wide := c.cfg.Limits
	wide.MaxRequestBytes *= 2
	api, err := c.conn(c.cfg.Token, wide)
	if err != nil {
		return nil, err
	}
	over := int(c.cfg.Limits.MaxRequestBytes/chunkBytes) + 2
	numbers, err := streamBytes(ctx, api, over)
	if err == nil {
		return numbers, finding("the origin took a request over its limit")
	}
	code := status.Code(err)
	numbers = map[string]any{"code": code.String(), "mib_offered": over}
	if code != codes.ResourceExhausted {
		return numbers, finding("over the limit read as " + code.String() + ", not as the channel's size refusal")
	}
	return numbers, nil
}

// gapCheck leaves a stream idle in the middle. It records what happened: the
// design says a stream never idles past 30 s, so a cut at 35 s is a measurement
// and passes.
func gapCheck(gap time.Duration) check {
	return func(ctx context.Context, c *client, api coordinatorv1.CoordinatorServiceClient) (map[string]any, error) {
		stream, err := api.StreamArtifacts(ctx)
		if err != nil {
			return nil, err
		}
		digest := sha256.New()
		chunk, err := syntheticChunk(digest, 1024)
		if err != nil {
			return nil, err
		}
		if err := stream.Send(chunk); err != nil {
			return nil, err
		}
		c.wait(ctx, gap)
		if chunk, err = syntheticChunk(digest, 1024); err != nil {
			return nil, err
		}
		sendErr := stream.Send(chunk)
		numbers, recvErr := finish(stream, digest.Sum(nil), 2048)
		survived := sendErr == nil && recvErr == nil
		if numbers == nil {
			numbers = map[string]any{}
		}
		numbers["gap"], numbers["survived"] = gap.String(), survived
		if !survived {
			numbers["code"] = status.Code(errors.Join(sendErr, recvErr)).String()
		}
		if gap <= 30*time.Second && !survived {
			return numbers, errors.Join(sendErr, recvErr)
		}
		return numbers, nil
	}
}

// checkHold keeps a stream open for what a stream may take, sending a little
// every ten seconds.
func checkHold(ctx context.Context, c *client, api coordinatorv1.CoordinatorServiceClient) (map[string]any, error) {
	stream, err := api.StreamArtifacts(ctx)
	if err != nil {
		return nil, err
	}
	digest := sha256.New()
	const beats = 11
	var sent uint64
	for range beats {
		chunk, err := syntheticChunk(digest, 1024)
		if err != nil {
			return nil, err
		}
		if err := stream.Send(chunk); err != nil {
			return nil, err
		}
		sent += 1024
		c.wait(ctx, 9500*time.Millisecond)
	}
	return finish(stream, digest.Sum(nil), sent)
}

// checkLoad holds a full set of polls beside a modest heartbeat rate.
func checkLoad(ctx context.Context, c *client, api coordinatorv1.CoordinatorServiceClient) (map[string]any, error) {
	var wg sync.WaitGroup
	var pollNumbers map[string]any
	var pollErr error
	wg.Go(func() { pollNumbers, pollErr = polls(ctx, api, loadPolls) })
	var failed atomic.Int64
	var mu sync.Mutex
	failures := map[string]int{}
	sent := 0
	for range loadSeconds {
		for range loadHeartbeats {
			sent++
			wg.Go(func() {
				if _, err := api.Heartbeat(ctx, heartbeat()); err != nil {
					failed.Add(1)
					mu.Lock()
					failures[status.Code(err).String()]++
					mu.Unlock()
				}
			})
		}
		c.wait(ctx, time.Second)
	}
	wg.Wait()
	numbers := map[string]any{"polls": pollNumbers, "heartbeats": sent, "heartbeats_failed": failed.Load(), "heartbeat_failures": failures}
	if pollErr != nil {
		return numbers, pollErr
	}
	if failed.Load() > 0 {
		return numbers, finding("a heartbeat failed")
	}
	return numbers, nil
}

// checkDown is for an origin that was stopped: what the edge answers must read
// as Unavailable, so that a worker retries and does not count a refusal.
func checkDown(ctx context.Context, _ *client, api coordinatorv1.CoordinatorServiceClient) (map[string]any, error) {
	_, err := api.Heartbeat(ctx, heartbeat())
	code := status.Code(err)
	numbers := map[string]any{"code": code.String()}
	if code != codes.Unavailable {
		return numbers, finding("a stopped origin read as " + code.String())
	}
	return numbers, nil
}

// checkReconnect heartbeats once a second while someone restarts what is in
// between, and says how long it could not get through.
func checkReconnect(ctx context.Context, c *client, api coordinatorv1.CoordinatorServiceClient) (map[string]any, error) {
	deadline := time.Now().Add(c.cfg.Watch)
	var failures, beats int64
	var outage, longest time.Duration
	var down time.Time
	codesSeen := map[string]int{}
	for time.Now().Before(deadline) && ctx.Err() == nil {
		beats++
		sent := time.Now()
		_, err := api.Heartbeat(ctx, heartbeat())
		switch {
		case err == nil && !down.IsZero():
			outage = time.Since(down)
			longest = max(longest, outage)
			down = time.Time{}
		case err != nil:
			failures++
			codesSeen[status.Code(err).String()]++
			// An outage starts when the call that failed was sent, however long
			// that call took to fail.
			if down.IsZero() {
				down = sent
			}
		}
		c.wait(ctx, time.Second)
	}
	if !down.IsZero() {
		longest = max(longest, time.Since(down))
	}
	numbers := map[string]any{"beats": beats, "failed": failures, "longest_outage": longest.Round(time.Millisecond).String(), "codes": codesSeen}
	if !down.IsZero() {
		return numbers, finding("still down at the end of the watch")
	}
	for code := range codesSeen {
		if code != codes.Unavailable.String() {
			return numbers, finding("an outage read as " + code)
		}
	}
	return numbers, nil
}
