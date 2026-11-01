// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package workerchannel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
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
	// one with bounded connection setup.
	HTTP *http.Client
}

// Conn is a grpc.ClientConnInterface that sends calls to a Handler.
type Conn struct {
	base    string
	auth    Authorizer
	limits  Limits
	http    *http.Client
	options []connect.ClientOption
	calls   map[string]func(ctx context.Context, args, reply any) error
	streams map[string]func(ctx context.Context) (grpc.ClientStream, error)
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
	c := &Conn{
		base: base, auth: cfg.Credentials, limits: limits, http: client,
		options: []connect.ClientOption{
			connect.WithReadMaxBytes(limits.MaxMessageBytes),
			connect.WithSendMaxBytes(limits.MaxMessageBytes),
			connect.WithAcceptCompression("gzip", nil, nil),
		},
		calls:   make(map[string]func(context.Context, any, any) error),
		streams: make(map[string]func(context.Context) (grpc.ClientStream, error)),
	}
	c.addMethods()
	return c, nil
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
		// A connection to the edge that stopped answering is closed in
		// bounded time. It says nothing about the hub behind the edge: that
		// is what the worker's heartbeat calls are for.
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
	call, ok := c.calls[method]
	if !ok {
		return status.Error(codes.Unimplemented, "workerchannel: this method is not carried")
	}
	return call(ctx, args, reply)
}

// NewStream implements grpc.ClientConnInterface for client-streaming methods.
func (c *Conn) NewStream(ctx context.Context, _ *grpc.StreamDesc, method string, _ ...grpc.CallOption) (grpc.ClientStream, error) {
	open, ok := c.streams[method]
	if !ok {
		return nil, status.Error(codes.Unimplemented, "workerchannel: this method is not carried")
	}
	return open(ctx)
}

func addCall[Req, Res any](c *Conn, procedure string) {
	target := c.base + procedure
	client := connect.NewClient[Req, Res](c.http, target, c.options...)
	c.calls[procedure] = func(ctx context.Context, args, reply any) error {
		authorization, err := c.auth.HTTPAuthorization(ctx, target)
		if err != nil {
			return err
		}
		callCtx, cancel := context.WithTimeout(ctx, c.limits.Unary+5*time.Second)
		defer cancel()
		req := connect.NewRequest(args.(*Req))
		req.Header().Set("Authorization", authorization)
		resp, err := client.CallUnary(callCtx, req)
		if err != nil {
			return callError(ctx, err)
		}
		proto.Reset(reply.(proto.Message))
		proto.Merge(reply.(proto.Message), any(resp.Msg).(proto.Message))
		return nil
	}
}

func addClientStream[Req, Res any](c *Conn, procedure string) {
	target := c.base + procedure
	client := connect.NewClient[Req, Res](c.http, target, c.options...)
	c.streams[procedure] = func(ctx context.Context) (grpc.ClientStream, error) {
		authorization, err := c.auth.HTTPAuthorization(ctx, target)
		if err != nil {
			return nil, err
		}
		callCtx, cancel := context.WithTimeout(ctx, c.limits.Stream+5*time.Second) //nolint:gosec // cancelled by RecvMsg, or by its own timeout
		stream := client.CallClientStream(callCtx)
		stream.RequestHeader().Set("Authorization", authorization)
		return &clientStream[Req, Res]{ctx: ctx, cancel: cancel, stream: stream, limit: c.limits.MaxRequestBytes}, nil
	}
}

// callError says what became of a call. The caller's own context comes first:
// a cancelled call is not a hub that cannot be reached.
func callError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return status.FromContextError(ctxErr).Err()
	}
	return fromConnect(err)
}

// clientStream is the generated client's view of one Connect client stream.
type clientStream[Req, Res any] struct {
	ctx    context.Context
	cancel context.CancelFunc
	stream *connect.ClientStreamForClient[Req, Res]
	limit  int64

	mu       sync.Mutex
	sent     int64
	refused  error
	received bool
}

func (s *clientStream[Req, Res]) Header() (metadata.MD, error) { return nil, nil }
func (s *clientStream[Req, Res]) Trailer() metadata.MD         { return nil }
func (s *clientStream[Req, Res]) Context() context.Context     { return s.ctx }

// SendMsg sends one message. As on gRPC, io.EOF says the call has ended and
// RecvMsg holds why.
func (s *clientStream[Req, Res]) SendMsg(m any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	message := m.(*Req)
	size := int64(proto.Size(any(message).(proto.Message))) + envelopeBytes
	if s.sent+size > s.limit {
		// Cut off: the hub must not read what was sent as a finished stream.
		s.refused = status.Error(codes.ResourceExhausted, "workerchannel: the request is over its size limit")
		s.cancel()
		return s.refused
	}
	if err := s.stream.Send(message); err != nil {
		if errors.Is(err, io.EOF) {
			return io.EOF
		}
		return callError(s.ctx, err)
	}
	s.sent += size
	return nil
}

// envelopeBytes is the Connect envelope around a stream's message.
const envelopeBytes = 5

// CloseSend is part of CloseAndRecv: closing and reading the reply are one
// step of the Connect client.
func (s *clientStream[Req, Res]) CloseSend() error { return nil }

// RecvMsg ends the stream and reads its one reply.
func (s *clientStream[Req, Res]) RecvMsg(m any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.received {
		return io.EOF
	}
	s.received = true
	defer s.cancel()
	if s.refused != nil {
		return s.refused
	}
	resp, err := s.stream.CloseAndReceive()
	if err != nil {
		return callError(s.ctx, err)
	}
	proto.Reset(m.(proto.Message))
	proto.Merge(m.(proto.Message), any(resp.Msg).(proto.Message))
	return nil
}
