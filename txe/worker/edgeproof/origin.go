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
}

func (stubCoordinator) Heartbeat(context.Context, *coordinatorv1.HeartbeatRequest) (*coordinatorv1.HeartbeatResponse, error) {
	return &coordinatorv1.HeartbeatResponse{}, nil
}

func (stubCoordinator) Poll(ctx context.Context, _ *coordinatorv1.PollRequest) (*coordinatorv1.PollResponse, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// StreamArtifacts keeps nothing: it hashes what arrives and says the digest,
// in the reply's free text.
func (stubCoordinator) StreamArtifacts(stream coordinatorv1.CoordinatorService_StreamArtifactsServer) error {
	digest := sha256.New()
	var chunks, written uint64
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return stream.SendAndClose(&coordinatorv1.StreamArtifactsResponse{
				ChunksReceived: chunks, BytesWritten: written, Error: hex.EncodeToString(digest.Sum(nil))})
		}
		if err != nil {
			return err
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

func (s *statusRecorder) Write(data []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(data)
}

func (s *statusRecorder) Flush() {
	if s.status == 0 {
		s.status = http.StatusOK
	}
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

// logged writes one line per request, of the method's name, the status, and the
// time taken. It is written to hold no header, no address and no token. It also
// bounds the read of every request, a path outside the channel's included; the
// channel sets its own deadline over this one.
func logged(out io.Writer, next http.Handler) http.Handler {
	var mu sync.Mutex
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		_ = http.NewResponseController(w).SetReadDeadline(start.Add(originRead))
		recorder := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(recorder, r)
		mu.Lock()
		defer mu.Unlock()
		_, _ = fmt.Fprintf(out, "%s %s status=%d took=%s\n", start.UTC().Format(time.RFC3339), loggedMethod(r.URL.Path), recorder.status, time.Since(start).Round(time.Millisecond))
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
	channel, err := workerchannel.NewHandler(workerchannel.Config{
		Auth: auth, Coordinator: stubCoordinator{}, Health: health.NewServer(), Limits: cfg.Limits,
	})
	if err != nil {
		return nil, err
	}
	mount := path.Join(apiRoot, workerchannel.MountPath)
	mux := http.NewServeMux()
	mux.Handle(mount+"/", http.StripPrefix(mount, channel))
	return logged(cfg.Log, mux), nil
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
