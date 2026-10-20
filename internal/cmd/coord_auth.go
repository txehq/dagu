// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/grpc"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// coordinatorAuthOptions returns the gRPC server options that make the
// coordinator authenticate every caller, or none when coordinator.auth is off,
// which leaves the coordinator exactly as it was. Owner authorization in
// enforce needs coordinator.auth in enforce too: the coordinator does not
// start otherwise.
//
// A worker machine is verified with the server's provider token settings
// (txe.authn) and found through its enrolment in the TXE owner store. The
// hub's own processes present the hub key. Anything this cannot set up is an
// error, so a coordinator asked to authenticate never starts without doing so.
//
// advertise is the address the coordinator registers for the hub's processes
// and gives workers as its own. Without TLS a credential is sent only to a
// loopback address, so that address must be one; otherwise every
// authenticated call would fail in the client, observe mode included.
func coordinatorAuthOptions(ctx context.Context, cfg *config.Config, advertise string, opts ...txeauth.Option) ([]grpc.ServerOption, error) {
	// Owner authorization in enforce hands each machine only its own tasks
	// (TXE-4422), and only an authenticating coordinator knows which machine
	// a worker is: without it, a process that claims a machine's label is
	// handed that machine's tasks (TXE-4720).
	if cfg.TXE.Authz.Mode == config.TXEAuthzModeEnforce && cfg.Coordinator.Auth.Mode != config.TXEAuthzModeEnforce {
		return nil, fmt.Errorf("txe.authz.mode is enforce but coordinator.auth.mode is %q: a coordinator that does not authenticate "+
			"workers would hand a machine's tasks to any worker naming that machine; set coordinator.auth.mode to enforce, "+
			"or keep txe.authz.mode at observe until it is", cfg.Coordinator.Auth.Mode)
	}
	if !cfg.Coordinator.Auth.Enabled() {
		return nil, nil
	}
	mode := authz.Mode(cfg.Coordinator.Auth.Mode)
	tls := cfg.Core.Peer.CertFile != "" && cfg.Core.Peer.KeyFile != ""
	if !tls && !transportauth.IsLoopbackHost(advertise) {
		return nil, fmt.Errorf("coordinator.auth.mode is %s without TLS, so credentials are sent only to a loopback address, "+
			"but the coordinator advertises %q: set coordinator.advertise to 127.0.0.1 (workers reach it through a tunnel), "+
			"or configure peer TLS", mode, advertise)
	}
	if cfg.Paths.DataDir == "" {
		return nil, errors.New("coordinator.auth needs the data directory, where the TXE owner store and the hub key live")
	}
	reg, err := registry.NewFileStore(cfg.Paths.DataDir)
	if err != nil {
		return nil, fmt.Errorf("coordinator.auth: open the TXE job registry: %w", err)
	}
	service, err := txeauth.NewService(cfg.TXE, cfg.Paths.DataDir, reg, opts...)
	if err != nil {
		return nil, fmt.Errorf("coordinator.auth: %w", err)
	}
	if !service.AcceptsTokens() {
		return nil, fmt.Errorf("coordinator.auth.mode is %s but txe.authn is not configured: "+
			"name the issuer, audience, jwks_url and each worker machine's client. "+
			"It is read by start-all and server, not by a coordinator started on its own", mode)
	}
	key, err := transportauth.LoadOrCreateHubKey(cfg.CoordinatorHubKeyFile())
	if err != nil {
		return nil, fmt.Errorf("coordinator.auth: %w", err)
	}
	server, err := transportauth.NewServer(transportauth.ServerConfig{
		Mode:     mode,
		Verifier: service,
		Machines: service.Store(),
		HubKey:   key,
		Observe:  logCoordinatorAuthDecision,
	})
	if err != nil {
		return nil, fmt.Errorf("coordinator.auth: %w", err)
	}
	// The provider's keys are refreshed for as long as the process runs, so an
	// issuer that stops answering is noticed while no worker calls.
	go service.Run(ctx)
	logger.Info(ctx, "Coordinator authenticates its callers",
		slog.String("mode", string(mode)),
		slog.String("hub-key-file", cfg.CoordinatorHubKeyFile()))
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(server.UnaryInterceptor()),
		grpc.ChainStreamInterceptor(server.StreamInterceptor()),
	}, nil
}

// logCoordinatorAuthDecision records a refusal, and in observe mode what
// enforce would refuse. Allowed calls are logged at debug: workers poll
// constantly.
func logCoordinatorAuthDecision(ctx context.Context, d transportauth.Decision) {
	attrs := []slog.Attr{
		slog.String("method", d.Method),
		slog.String("mode", string(d.Mode)),
		slog.String("reason", string(d.Reason)),
		slog.String("detail", d.Detail),
		slog.String("caller", string(d.Kind)),
		slog.String("machine", d.MachineID),
		slog.String("owner", d.OwnerID),
	}
	switch {
	case !d.Allowed:
		logger.Warn(ctx, "Coordinator call refused", attrs...)
	case d.WouldDeny:
		logger.Warn(ctx, "Coordinator call would be refused in enforce mode", attrs...)
	default:
		logger.Debug(ctx, "Coordinator call authenticated", attrs...)
	}
}
