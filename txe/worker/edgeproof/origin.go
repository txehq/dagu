// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/health"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	"github.com/dagucloud/dagu/v2/internal/txe/workerchannel"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

const (
	originMachine = "mch_EDGEPROOF"
	originOwner   = "own_EDGEPROOF"
	apiRoot       = "/api/v1"
	originRead    = 5 * time.Second
	originIdle    = 2 * time.Minute
)

type originConfig struct {
	Listen string
	Token  string
	Log    io.Writer
	// Limits are the channel's defaults when zero.
	Limits workerchannel.Limits
	// Ready is told the address, once the origin listens.
	Ready func(addr string)
}

// oneToken accepts one token and names one machine.
type oneToken struct {
	token string
}

func (o oneToken) Verify(_ context.Context, token string) (authn.Principal, error) {
	if subtle.ConstantTimeCompare([]byte(token), []byte(o.token)) != 1 {
		return authn.Principal{}, errors.New("unknown token")
	}
	return authn.Principal{Class: authn.ClassWorker, ClientID: "edgeproof", Expires: time.Now().Add(time.Hour)}, nil
}

func (oneToken) ResolveMachine(context.Context, authn.Principal) (authz.Machine, authz.Reason, error) {
	return authz.Machine{MachineID: originMachine, OwnerID: originOwner, Class: authn.ClassWorker}, "", nil
}

// stubCoordinator answers what the checks call and nothing else. Any other
// method is unimplemented, so the origin can do nothing but echo sizes.
type stubCoordinator struct {
	coordinatorv1.UnimplementedCoordinatorServiceServer
	log *originLog
}

func (*stubCoordinator) Heartbeat(context.Context, *coordinatorv1.HeartbeatRequest) (*coordinatorv1.HeartbeatResponse, error) {
	return &coordinatorv1.HeartbeatResponse{}, nil
}

func (*stubCoordinator) Poll(ctx context.Context, _ *coordinatorv1.PollRequest) (*coordinatorv1.PollResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// StreamArtifacts keeps nothing: it hashes what arrives and says, in the reply's
// free text, the digest and how long passed between the first chunk's arrival
// and the last's. A proxy that holds a body until it ends makes that span nothing,
// however long the sender took. An HTTP status cannot show a stream that was cut,
// because a Connect error travels in the body, so each stream's end is logged.
func (s *stubCoordinator) StreamArtifacts(stream coordinatorv1.CoordinatorService_StreamArtifactsServer) error {
	digest := sha256.New()
	var chunks, written uint64
	var first, last time.Time
	span := func() time.Duration { return last.Sub(first) }
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			s.log.line("stream complete chunks=%d bytes=%d span=%s", chunks, written, span().Round(time.Millisecond))
			return stream.SendAndClose(&coordinatorv1.StreamArtifactsResponse{
				ChunksReceived: chunks, BytesWritten: written,
				Error: fmt.Sprintf("%s %d", hex.EncodeToString(digest.Sum(nil)), span().Milliseconds())})
		}
		if err != nil {
			s.log.line("stream cut chunks=%d bytes=%d span=%s", chunks, written, span().Round(time.Millisecond))
			return err
		}
		last = time.Now()
		if first.IsZero() {
			first = last
		}
		_, _ = digest.Write(chunk.Data)
		chunks++
		written += uint64(len(chunk.Data))
	}
}

// statusRecorder keeps the status for the log line. Unwrap gives the channel's
// per-request deadlines the real connection.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// loggedMethod names a request by the method it called, from a closed set: what
// a caller puts in a path never reaches the log.
func loggedMethod(requestPath string) string {
	for _, method := range []string{"Poll", "Heartbeat", "StreamArtifacts", "Check"} {
		if strings.HasSuffix(requestPath, "/"+method) {
			return method
		}
	}
	return "other"
}

// originLog serializes the log's lines.
type originLog struct {
	mu  sync.Mutex
	out io.Writer
}

func (l *originLog) line(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = fmt.Fprintf(l.out, time.Now().UTC().Format(time.RFC3339)+" "+format+"\n", args...)
}

// logged writes one line per request, of the method's name, the status, and the
// time taken. It is written to hold no header, no address and no token. It also
// bounds the read of every request, a path outside the channel's included; the
// channel sets its own deadline over this one.
func logged(log *originLog, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		_ = http.NewResponseController(w).SetReadDeadline(start.Add(originRead))
		recorder := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		// With no explicit header, net/http sends 200 when the handler returns.
		code := recorder.status
		if code == 0 {
			code = http.StatusOK
		}
		log.line("%s status=%d took=%s", loggedMethod(r.URL.Path), code, time.Since(start).Round(time.Millisecond))
	})
}

func originHandler(cfg originConfig) (http.Handler, error) {
	identity := oneToken{token: cfg.Token}
	auth, err := transportauth.NewServer(transportauth.ServerConfig{
		Mode: authz.ModeEnforce, MachinesOnly: true, Verifier: identity, Machines: identity,
	})
	if err != nil {
		return nil, err
	}
	log := &originLog{out: cfg.Log}
	channel, err := workerchannel.NewHandler(workerchannel.Config{
		Auth: auth, Coordinator: &stubCoordinator{log: log}, Health: health.NewServer(), Limits: cfg.Limits,
	})
	if err != nil {
		return nil, err
	}
	mount := path.Join(apiRoot, workerchannel.MountPath)
	mux := http.NewServeMux()
	mux.Handle(mount+"/", http.StripPrefix(mount, channel))
	return logged(log, mux), nil
}

func serveOrigin(ctx context.Context, cfg originConfig) error {
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return errors.New("the origin binds a loopback address only: what reaches it is a tunnel on this machine")
	}
	handler, err := originHandler(cfg)
	if err != nil {
		return err
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return err
	}
	if cfg.Ready != nil {
		cfg.Ready(listener.Addr().String())
	}
	_, _ = fmt.Fprintln(cfg.Log, "listening on", strings.Split(listener.Addr().String(), ":")[1:])
	// WriteTimeout stays zero: the channel sets each request's own deadline.
	server := &http.Server{Handler: handler, ReadHeaderTimeout: originRead, IdleTimeout: originIdle}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		_ = server.Close()
	}()
	err = server.Serve(listener)
	<-stopped
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
