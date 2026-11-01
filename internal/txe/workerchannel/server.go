// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package workerchannel

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// Config configures a Handler.
type Config struct {
	// Auth decides every call. It must be a machines-only Server.
	Auth *transportauth.Server
	// Coordinator is the service the calls run on.
	Coordinator coordinatorv1.CoordinatorServiceServer
	// Health answers a machine's health check.
	Health grpc_health_v1.HealthServer
	// Limits are DefaultLimits when zero.
	Limits Limits
}

type unaryMethod struct {
	service any
	handler grpc.MethodHandler
}

type streamMethod struct {
	service any
	handler grpc.StreamHandler
}

// Handler serves coordinator calls. It answers on the path's last two
// segments, the service and the method, so it can be mounted anywhere.
type Handler struct {
	auth   *transportauth.Server
	limits Limits
	unary  map[string]unaryMethod
	stream map[string]streamMethod

	mu    sync.Mutex
	calls map[string]int
}

// NewHandler validates cfg and returns a Handler.
func NewHandler(cfg Config) (*Handler, error) {
	if cfg.Auth == nil || !cfg.Auth.MachinesOnly() {
		return nil, errors.New("workerchannel: a machines-only transportauth server is required")
	}
	if cfg.Coordinator == nil || cfg.Health == nil {
		return nil, errors.New("workerchannel: the coordinator and health services are required")
	}
	limits := cfg.Limits
	if limits == (Limits{}) {
		limits = DefaultLimits()
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	h := &Handler{
		auth:   cfg.Auth,
		limits: limits,
		unary:  make(map[string]unaryMethod),
		stream: make(map[string]streamMethod),
		calls:  make(map[string]int),
	}
	desc := coordinatorv1.CoordinatorService_ServiceDesc
	for _, m := range desc.Methods {
		h.unary["/"+desc.ServiceName+"/"+m.MethodName] = unaryMethod{service: cfg.Coordinator, handler: m.Handler}
	}
	for _, s := range desc.Streams {
		// A server stream has no bounded form here, and no worker method
		// needs one: its one use is refused without a resource authorizer.
		if s.ClientStreams && !s.ServerStreams {
			h.stream["/"+desc.ServiceName+"/"+s.StreamName] = streamMethod{service: cfg.Coordinator, handler: s.Handler}
		}
	}
	health := grpc_health_v1.Health_ServiceDesc
	for _, m := range health.Methods {
		if "/"+health.ServiceName+"/"+m.MethodName == grpc_health_v1.Health_Check_FullMethodName {
			h.unary[grpc_health_v1.Health_Check_FullMethodName] = unaryMethod{service: cfg.Health, handler: m.Handler}
		}
	}
	return h, nil
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(HeaderChannel, ChannelVersion)
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodPost {
		writeError(w, status.Error(codes.Unimplemented, "workerchannel: calls are POST"))
		return
	}
	method, ok := fullMethod(r.URL.Path)
	if !ok {
		writeError(w, status.Error(codes.Unimplemented, "workerchannel: no such method"))
		return
	}
	ctx := metadata.NewIncomingContext(r.Context(),
		metadata.MD{transportauth.AuthorizationHeader: r.Header.Values("Authorization")})
	caller, err := h.auth.Admit(ctx, method)
	if err != nil {
		writeError(w, err)
		return
	}
	release, err := h.enter(caller.Machine.MachineID)
	if err != nil {
		writeError(w, err)
		return
	}
	defer release()

	if m, ok := h.unary[method]; ok {
		h.serveUnary(ctx, w, r, method, m)
		return
	}
	if m, ok := h.stream[method]; ok {
		h.serveStream(ctx, w, r, method, m)
		return
	}
	writeError(w, status.Error(codes.Unimplemented, "workerchannel: this method is not carried"))
}

func (h *Handler) serveUnary(ctx context.Context, w http.ResponseWriter, r *http.Request, method string, m unaryMethod) {
	isPoll := method == coordinatorv1.CoordinatorService_Poll_FullMethodName
	limit := h.limits.Unary
	if isPoll {
		limit = h.limits.PollWait
	}
	callCtx, cancel := context.WithTimeout(ctx, bounded(r, limit))
	defer cancel()

	body := http.MaxBytesReader(w, r.Body, h.limits.MaxMessageBytes)
	decode := func(in any) error {
		data, err := io.ReadAll(body)
		if err != nil {
			return readError(err)
		}
		return unmarshal(data, in)
	}
	out, err := m.handler(m.service, callCtx, decode, h.auth.UnaryInterceptor())
	if isPoll && err != nil && callCtx.Err() != nil && ctx.Err() == nil && status.Code(asStatus(err)) == codes.DeadlineExceeded {
		// The wait is over and no task came: a Poll's ordinary answer.
		out, err = &coordinatorv1.PollResponse{}, nil
	}
	if err != nil {
		writeError(w, err)
		return
	}
	writeMessage(w, out)
}

func (h *Handler) serveStream(ctx context.Context, w http.ResponseWriter, r *http.Request, method string, m streamMethod) {
	limit := bounded(r, h.limits.Stream)
	callCtx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	// The server's own write timeout is for ordinary requests.
	control := http.NewResponseController(w)
	_ = control.SetReadDeadline(time.Now().Add(limit))
	_ = control.SetWriteDeadline(time.Now().Add(limit + time.Second))

	stream := &serverStream{
		ctx:      callCtx,
		body:     bufio.NewReader(http.MaxBytesReader(w, r.Body, h.limits.MaxStreamBytes)),
		maxBytes: h.limits.MaxMessageBytes,
	}
	info := &grpc.StreamServerInfo{FullMethod: method, IsClientStream: true}
	if err := h.auth.StreamInterceptor()(m.service, stream, info, m.handler); err != nil {
		writeError(w, err)
		return
	}
	if stream.reply == nil {
		writeError(w, status.Error(codes.Internal, "workerchannel: the method ended without a reply"))
		return
	}
	writeMessage(w, stream.reply)
}

// enter counts a call of a machine, and refuses it past the limit.
func (h *Handler) enter(machine string) (func(), error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.calls[machine] >= h.limits.MaxCallsPerMachine {
		return nil, status.Error(codes.ResourceExhausted, "workerchannel: this machine has too many calls open")
	}
	h.calls[machine]++
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.calls[machine]--; h.calls[machine] == 0 {
			delete(h.calls, machine)
		}
	}, nil
}

// bounded is limit, or what the caller says is left of its deadline when that
// is shorter.
func bounded(r *http.Request, limit time.Duration) time.Duration {
	ms, err := strconv.ParseInt(r.Header.Get(HeaderTimeout), 10, 64)
	if err != nil || ms <= 0 || ms >= limit.Milliseconds() {
		return limit
	}
	return time.Duration(ms) * time.Millisecond
}

// fullMethod is "/service/method" from the path's last two segments.
func fullMethod(path string) (string, bool) {
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")
	if len(parts) < 2 || parts[len(parts)-1] == "" || parts[len(parts)-2] == "" {
		return "", false
	}
	return "/" + parts[len(parts)-2] + "/" + parts[len(parts)-1], true
}

func unmarshal(data []byte, in any) error {
	message, ok := in.(proto.Message)
	if !ok {
		return status.Error(codes.Internal, "workerchannel: not a protobuf message")
	}
	if err := proto.Unmarshal(data, message); err != nil {
		return status.Error(codes.InvalidArgument, "workerchannel: the message cannot be read")
	}
	return nil
}

func readError(err error) error {
	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		return status.Error(codes.ResourceExhausted, "workerchannel: the request is too large")
	}
	return status.Error(codes.Canceled, "workerchannel: the request ended early")
}

// asStatus keeps a context error's meaning: status.Convert would call it
// Unknown.
func asStatus(err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return status.FromContextError(err).Err()
	default:
		return err
	}
}

func writeMessage(w http.ResponseWriter, out any) {
	message, ok := out.(proto.Message)
	if !ok {
		writeError(w, status.Error(codes.Internal, "workerchannel: not a protobuf message"))
		return
	}
	data, err := proto.Marshal(message)
	if err != nil {
		writeError(w, status.Error(codes.Internal, "workerchannel: the reply cannot be written"))
		return
	}
	w.Header().Set("Content-Type", contentTypeMessage)
	w.Header().Set(HeaderCode, strconv.Itoa(int(codes.OK)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func writeError(w http.ResponseWriter, err error) {
	s := status.Convert(asStatus(err))
	text := s.Message()
	if len(text) > maxErrorBytes {
		text = text[:maxErrorBytes]
	}
	w.Header().Set("Content-Type", contentTypeError)
	w.Header().Set(HeaderCode, strconv.Itoa(int(s.Code())))
	w.WriteHeader(statusOf(s.Code()))
	_, _ = io.WriteString(w, text) //nolint:gosec // text/plain, read by a Conn
}

// serverStream is one client stream, read from a request's body.
type serverStream struct {
	ctx      context.Context
	body     *bufio.Reader
	maxBytes int64
	reply    any
}

func (s *serverStream) SetHeader(metadata.MD) error  { return nil }
func (s *serverStream) SendHeader(metadata.MD) error { return nil }
func (s *serverStream) SetTrailer(metadata.MD)       {}
func (s *serverStream) Context() context.Context     { return s.ctx }

// SendMsg keeps the reply: a client stream has one, sent when the handler
// returns.
func (s *serverStream) SendMsg(m any) error {
	s.reply = m
	return nil
}

// RecvMsg reads the next frame. Only the end frame is io.EOF: a body that
// stops anywhere else is a request that was cut short.
func (s *serverStream) RecvMsg(m any) error {
	if err := s.ctx.Err(); err != nil {
		return status.FromContextError(err).Err()
	}
	var header [frameHeaderBytes]byte
	if _, err := io.ReadFull(s.body, header[:]); err != nil {
		return s.streamError(err)
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == frameEnd {
		return io.EOF
	}
	if int64(size) > s.maxBytes {
		return status.Error(codes.ResourceExhausted, fmt.Sprintf("workerchannel: a message is over %d bytes", s.maxBytes))
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(s.body, data); err != nil {
		return s.streamError(err)
	}
	return unmarshal(data, m)
}

func (s *serverStream) streamError(err error) error {
	if ctxErr := s.ctx.Err(); ctxErr != nil {
		return status.FromContextError(ctxErr).Err()
	}
	return readError(err)
}
