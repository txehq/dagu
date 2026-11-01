// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package workerchannel

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

const (
	contentTypeUnary  = "application/proto"
	contentTypeStream = "application/connect+proto"
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

// Handler serves coordinator calls at /<service>/<method>. Mount it with the
// mount path stripped.
type Handler struct {
	auth    *transportauth.Server
	limits  Limits
	routes  map[string]route
	options []connect.HandlerOption

	mu    sync.Mutex
	calls map[string]int
}

type route struct {
	handler     http.Handler
	contentType string
	limit       time.Duration
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
		routes: make(map[string]route),
		options: []connect.HandlerOption{
			connect.WithReadMaxBytes(limits.MaxMessageBytes),
			connect.WithSendMaxBytes(limits.MaxMessageBytes),
			// Compressed bytes would escape the size limits.
			connect.WithCompression("gzip", nil, nil),
		},
		calls: make(map[string]int),
	}
	h.addMethods(cfg.Coordinator, cfg.Health)
	return h, nil
}

// ServeHTTP implements http.Handler. It admits the caller before anything of
// the body is read, and bounds the request before Connect reads it.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx := incoming(r.Context(), r.Header)
	caller, err := h.auth.Admit(ctx, r.URL.Path)
	if err != nil {
		writeError(w, r, err)
		return
	}
	entry, ok := h.routes[r.URL.Path]
	if !ok {
		writeError(w, r, status.Error(codes.Unimplemented, "workerchannel: this method is not carried"))
		return
	}
	if contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || contentType != entry.contentType || r.Method != http.MethodPost {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	release, err := h.enter(caller.Machine.MachineID)
	if err != nil {
		writeError(w, r, err)
		return
	}
	defer release()

	// A stalled body is released by the read deadline: cancelling a context
	// does not interrupt a read of it.
	control := http.NewResponseController(w)
	_ = control.SetReadDeadline(time.Now().Add(entry.limit))
	_ = control.SetWriteDeadline(time.Now().Add(entry.limit + 5*time.Second))
	r.Body = http.MaxBytesReader(w, r.Body, h.limits.MaxRequestBytes)
	entry.handler.ServeHTTP(w, r)
}

func incoming(ctx context.Context, header http.Header) context.Context {
	return metadata.NewIncomingContext(ctx, metadata.MD{transportauth.AuthorizationHeader: header.Values("Authorization")})
}

func writeError(w http.ResponseWriter, r *http.Request, err error) {
	_ = connect.NewErrorWriter().Write(w, r, toConnect(err))
}

// addUnary carries one unary method. The generated service runs behind the
// same interceptor as on gRPC, which is the only thing that sees the request.
func addUnary[Req, Res any](h *Handler, procedure string, call func(context.Context, *Req) (*Res, error)) {
	limit := h.limits.Unary
	isPoll := procedure == coordinatorv1.CoordinatorService_Poll_FullMethodName
	if isPoll {
		limit = h.limits.PollWait
	}
	info := &grpc.UnaryServerInfo{FullMethod: procedure}
	run := func(ctx context.Context, in any) (any, error) { return call(ctx, in.(*Req)) }
	handler := connect.NewUnaryHandler(procedure, func(ctx context.Context, req *connect.Request[Req]) (*connect.Response[Res], error) {
		callCtx, cancel := context.WithTimeout(incoming(ctx, req.Header()), limit)
		defer cancel()
		out, err := h.auth.UnaryInterceptor()(callCtx, req.Msg, info, run)
		if isPoll && err != nil && callCtx.Err() != nil && ctx.Err() == nil && status.Code(asStatus(err)) == codes.DeadlineExceeded {
			// The wait is over and no task came: a Poll's ordinary answer.
			return connect.NewResponse(new(Res)), nil
		}
		if err != nil {
			return nil, toConnect(err)
		}
		return connect.NewResponse(out.(*Res)), nil
	}, h.options...)
	h.routes[procedure] = route{handler: handler, contentType: contentTypeUnary, limit: limit + time.Second}
}

// addStream carries one client-streaming method through the generated
// descriptor's handler, behind the same interceptor as on gRPC.
func addStream[Req, Res any](h *Handler, procedure string, service any, run grpc.StreamHandler) {
	limit := h.limits.Stream
	info := &grpc.StreamServerInfo{FullMethod: procedure, IsClientStream: true}
	handler := connect.NewClientStreamHandler(procedure, func(ctx context.Context, in *connect.ClientStream[Req]) (*connect.Response[Res], error) {
		callCtx, cancel := context.WithTimeout(incoming(ctx, in.RequestHeader()), limit)
		defer cancel()
		stream := &serverStream{ctx: callCtx, receive: func(m any) error {
			if in.Receive() {
				proto.Merge(m.(proto.Message), any(in.Msg()).(proto.Message))
				return nil
			}
			if err := in.Err(); err != nil {
				return fromRead(err)
			}
			return io.EOF
		}}
		if err := h.auth.StreamInterceptor()(service, stream, info, run); err != nil {
			return nil, toConnect(err)
		}
		reply, ok := stream.reply.(*Res)
		if !ok {
			return nil, toConnect(status.Error(codes.Internal, "workerchannel: the method ended without a reply"))
		}
		return connect.NewResponse(reply), nil
	}, h.options...)
	h.routes[procedure] = route{handler: handler, contentType: contentTypeStream, limit: limit + time.Second}
}

// fromRead keeps what Connect said about a request body as a gRPC status.
func fromRead(err error) error {
	if refusal, ok := errors.AsType[*connect.Error](err); ok {
		return status.Error(codes.Code(refusal.Code()), refusal.Message())
	}
	return status.Error(codes.Canceled, "workerchannel: the request ended early")
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

// serverStream is one client stream, as the generated handler sees it.
type serverStream struct {
	ctx     context.Context
	receive func(any) error
	reply   any
}

func (s *serverStream) SetHeader(metadata.MD) error  { return nil }
func (s *serverStream) SendHeader(metadata.MD) error { return nil }
func (s *serverStream) SetTrailer(metadata.MD)       {}
func (s *serverStream) Context() context.Context     { return s.ctx }
func (s *serverStream) RecvMsg(m any) error          { return s.receive(m) }

// SendMsg keeps the reply: a client stream has one, sent when the handler
// returns.
func (s *serverStream) SendMsg(m any) error {
	s.reply = m
	return nil
}
