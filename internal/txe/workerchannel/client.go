// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package workerchannel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
)

// Authorizer gives the Authorization value for a request. *transportauth.PerRPC
// is one.
type Authorizer interface {
	HTTPAuthorization(ctx context.Context, target string) (string, error)
}

var _ Authorizer = (*transportauth.PerRPC)(nil)

// ClientConfig configures a Conn.
type ClientConfig struct {
	// BaseURL is the address the channel is mounted at: https, or http to a
	// loopback address. It holds no user, query or fragment.
	BaseURL string
	// Credentials gives each request its credential.
	Credentials Authorizer
	// Limits are DefaultLimits when zero. A Conn enforces what a hub would
	// refuse, so that a worker hears it before it has sent the bytes.
	Limits Limits
	// HTTP is the client to use; its redirect policy is replaced. Nil builds
	// one with bounded connection setup and dead-connection detection.
	HTTP *http.Client
}

// Conn is a grpc.ClientConnInterface that sends calls to a Handler.
type Conn struct {
	base   string
	auth   Authorizer
	limits Limits
	http   *http.Client
}

var _ grpc.ClientConnInterface = (*Conn)(nil)

// NewConn validates cfg and returns a Conn. It opens nothing.
func NewConn(cfg ClientConfig) (*Conn, error) {
	base, err := checkBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.Credentials == nil {
		return nil, errors.New("workerchannel: a credential is required")
	}
	limits := cfg.Limits
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	client := newHTTPClient()
	if cfg.HTTP != nil {
		copied := *cfg.HTTP
		client = &copied
	}
	// A credential goes to the configured address and nowhere else.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Conn{base: base, auth: cfg.Credentials, limits: limits, http: client}, nil
}

func checkBaseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", errors.New("workerchannel: the base URL is not a URL with a host")
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("workerchannel: the base URL holds a user, a query or a fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !transportauth.IsLoopbackHost(u.Hostname()) {
			return "", errors.New("workerchannel: plain http is for a loopback address only")
		}
	default:
		return "", errors.New("workerchannel: the base URL must be https")
	}
	return strings.TrimRight(raw, "/"), nil
}

func newHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 15 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 2 * time.Minute,
		IdleConnTimeout:       90 * time.Second,
		// An idle connection that stopped answering is closed in bounded
		// time, so a call never waits on one that has silently died.
		HTTP2: &http.HTTP2Config{SendPingTimeout: 15 * time.Second, PingTimeout: 5 * time.Second},
	}
	return &http.Client{Transport: transport}
}

// Close releases idle connections.
func (c *Conn) Close() error {
	c.http.CloseIdleConnections()
	return nil
}

// Invoke implements grpc.ClientConnInterface.
func (c *Conn) Invoke(ctx context.Context, method string, args, reply any, _ ...grpc.CallOption) error {
	request, ok := args.(proto.Message)
	if !ok {
		return status.Error(codes.Internal, "workerchannel: not a protobuf message")
	}
	data, err := proto.Marshal(request)
	if err != nil {
		return status.Error(codes.Internal, "workerchannel: the message cannot be written")
	}
	if int64(len(data)) > c.limits.MaxMessageBytes {
		return status.Error(codes.ResourceExhausted, "workerchannel: the message is too large")
	}
	limit := c.limits.Unary + 5*time.Second
	callCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	req, err := c.newRequest(callCtx, ctx, method, contentTypeMessage, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(data))
	resp, err := c.http.Do(req)
	if err != nil {
		return transportError(ctx, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return c.readResponse(resp, reply)
}

// NewStream implements grpc.ClientConnInterface for client-streaming methods.
// The request starts with the stream and its body is what SendMsg writes.
func (c *Conn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
	if !desc.ClientStreams || desc.ServerStreams {
		return nil, status.Error(codes.Unimplemented, "workerchannel: only client streams are carried")
	}
	streamCtx, cancel := context.WithTimeout(ctx, c.limits.Stream+5*time.Second)
	reader, writer := io.Pipe()
	req, err := c.newRequest(streamCtx, ctx, method, contentTypeFrames, reader)
	if err != nil {
		cancel()
		return nil, err
	}
	stream := &clientStream{
		conn: c, ctx: ctx, callCtx: streamCtx, cancel: cancel, writer: writer,
		done: make(chan struct{}),
	}
	go func() {
		defer close(stream.done)
		stream.resp, stream.err = c.http.Do(req) //nolint:bodyclose // closed by RecvMsg, or by ctx when nobody calls it
		// A response ends the request, read to its end or not.
		_ = reader.CloseWithError(io.ErrClosedPipe)
	}()
	return stream, nil
}

// newRequest builds a request. callerCtx is what the deadline header reports:
// callCtx also holds the channel's own limit, which the hub applies itself.
func (c *Conn) newRequest(callCtx, callerCtx context.Context, method, contentType string, body io.Reader) (*http.Request, error) {
	target := c.base + method
	authorization, err := c.auth.HTTPAuthorization(callCtx, target)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, target, body)
	if err != nil {
		return nil, status.Error(codes.Internal, "workerchannel: the request cannot be built")
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", contentType)
	if left := remaining(callerCtx); left > 0 {
		req.Header.Set(HeaderTimeout, strconv.FormatInt(left.Milliseconds(), 10))
	}
	return req, nil
}

// readResponse believes a response only if it is the channel's own.
func (c *Conn) readResponse(resp *http.Response, reply any) error {
	if resp.Header.Get(HeaderChannel) != ChannelVersion {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBytes))
		return status.Error(codes.Unavailable, fmt.Sprintf("workerchannel: an answer that is not the hub's (HTTP %d)", resp.StatusCode))
	}
	code, err := strconv.Atoi(resp.Header.Get(HeaderCode))
	if err != nil || code < 0 {
		return status.Error(codes.Unavailable, "workerchannel: an answer with no status")
	}
	if codes.Code(code) != codes.OK { // #nosec G115 -- non-negative, and an unknown code is only reported
		text, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
		return status.Error(codes.Code(code), string(text)) // #nosec G115 -- as above
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, c.limits.MaxMessageBytes+1))
	if err != nil {
		return status.Error(codes.Unavailable, "workerchannel: the answer was cut short")
	}
	if int64(len(data)) > c.limits.MaxMessageBytes {
		return status.Error(codes.ResourceExhausted, "workerchannel: the answer is too large")
	}
	return unmarshal(data, reply)
}

// transportError says what became of a call that got no response.
func transportError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return status.FromContextError(ctxErr).Err()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, "workerchannel: the call took too long")
	}
	return status.Error(codes.Unavailable, "workerchannel: the hub cannot be reached")
}

// clientStream is one client stream, written to a request's body.
type clientStream struct {
	conn    *Conn
	ctx     context.Context
	callCtx context.Context
	cancel  context.CancelFunc
	writer  *io.PipeWriter

	mu     sync.Mutex
	sent   int64
	closed bool

	done chan struct{}
	resp *http.Response
	err  error

	received bool
}

func (s *clientStream) Header() (metadata.MD, error) { return nil, nil }
func (s *clientStream) Trailer() metadata.MD         { return nil }
func (s *clientStream) Context() context.Context     { return s.ctx }

// SendMsg writes one frame. As on gRPC, io.EOF says the call has ended and
// RecvMsg holds why.
func (s *clientStream) SendMsg(m any) error {
	message, ok := m.(proto.Message)
	if !ok {
		return status.Error(codes.Internal, "workerchannel: not a protobuf message")
	}
	data, err := proto.Marshal(message)
	if err != nil {
		return status.Error(codes.Internal, "workerchannel: the message cannot be written")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return status.Error(codes.Internal, "workerchannel: the stream is closed")
	}
	size := int64(len(data)) + frameHeaderBytes
	if int64(len(data)) > s.conn.limits.MaxMessageBytes || s.sent+size > s.conn.limits.MaxStreamBytes {
		s.abandon()
		return status.Error(codes.ResourceExhausted, "workerchannel: the stream is over its size limit")
	}
	if err := writeFrame(s.writer, data); err != nil {
		return io.EOF
	}
	s.sent += size
	return nil
}

// abandon cuts the request off, without the end frame.
func (s *clientStream) abandon() {
	s.closed = true
	_ = s.writer.CloseWithError(errors.New("workerchannel: stream abandoned"))
	s.cancel()
}

// CloseSend writes the end frame.
func (s *clientStream) CloseSend() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if err := writeFrameEnd(s.writer); err != nil {
		return nil //nolint:nilerr // the call has ended: RecvMsg holds why
	}
	return s.writer.Close()
}

// RecvMsg waits for the response and reads the stream's one reply.
func (s *clientStream) RecvMsg(m any) error {
	if s.received {
		return io.EOF
	}
	s.received = true
	defer s.cancel()
	select {
	case <-s.done:
	case <-s.callCtx.Done():
		<-s.done
	}
	if s.err != nil {
		return transportError(s.ctx, s.err)
	}
	defer func() { _ = s.resp.Body.Close() }()
	return s.conn.readResponse(s.resp, m)
}
