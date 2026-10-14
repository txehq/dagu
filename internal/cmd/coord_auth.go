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
// which leaves the coordinator exactly as it was.
//
// A worker machine is verified with the server's provider token settings
// (txe.authn) and found through its enrolment in the TXE owner store. The
// hub's own processes present the hub key. Anything this cannot set up is an
// error, so a coordinator asked to authenticate never starts without doing so.
func coordinatorAuthOptions(ctx context.Context, cfg *config.Config, opts ...txeauth.Option) ([]grpc.ServerOption, error) {
	if !cfg.Coordinator.Auth.Enabled() {
		return nil, nil
	}
	mode := authz.Mode(cfg.Coordinator.Auth.Mode)
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
