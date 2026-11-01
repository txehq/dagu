// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/go-chi/chi/v5"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/service/frontend"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
	"github.com/dagucloud/dagu/v2/internal/txe/workerchannel"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// workerChannelRoutes builds the worker channel on a running coordinator.
func workerChannelRoutes(ctx context.Context, cfg *config.Config, coord *coordinator.Service) (frontend.RouteRegistrar, error) {
	if coord == nil {
		return nil, errors.New("coordinator.worker_channel needs the coordinator in this process")
	}
	handler, err := newWorkerChannel(ctx, cfg, coord.Handler(), coord.Health())
	if err != nil {
		return nil, err
	}
	logger.Info(ctx, "Worker channel is served")
	return func(_ context.Context, r chi.Router, apiV1BasePath string) { handler.Mount(r, apiV1BasePath) }, nil
}

// newWorkerChannel stands apart from coordinator.auth and txe.authz: it always
// authenticates every call, it needs no hub key and creates none, and the
// private gRPC port is unchanged by it.
func newWorkerChannel(
	ctx context.Context,
	cfg *config.Config,
	service coordinatorv1.CoordinatorServiceServer,
	health grpc_health_v1.HealthServer,
	opts ...txeauth.Option,
) (*workerchannel.Handler, error) {
	if cfg.Paths.DataDir == "" {
		return nil, errors.New("coordinator.worker_channel needs the data directory, where the TXE owner store lives")
	}
	reg, err := registry.NewFileStore(cfg.Paths.DataDir)
	if err != nil {
		return nil, fmt.Errorf("coordinator.worker_channel: open the TXE job registry: %w", err)
	}
	identity, err := txeauth.NewService(cfg.TXE, cfg.Paths.DataDir, reg, opts...)
	if err != nil {
		return nil, fmt.Errorf("coordinator.worker_channel: %w", err)
	}
	if !identity.AcceptsTokens() {
		return nil, errors.New("coordinator.worker_channel is enabled but txe.authn is not configured: " +
			"name the issuer, audience, jwks_url and each worker machine's client")
	}
	auth, err := transportauth.NewServer(transportauth.ServerConfig{
		Mode:         authz.ModeEnforce,
		Verifier:     identity,
		Machines:     identity.Store(),
		Observe:      logCoordinatorAuthDecision,
		MachinesOnly: true,
	})
	if err != nil {
		return nil, fmt.Errorf("coordinator.worker_channel: %w", err)
	}
	limits := workerchannel.DefaultLimits()
	if size := cfg.Coordinator.WorkerChannel.MaxRequestBytes; size > 0 {
		limits.MaxRequestBytes = size
		limits.MaxMessageBytes = int(min(int64(limits.MaxMessageBytes), size))
	}
	handler, err := workerchannel.NewHandler(workerchannel.Config{
		Auth: auth, Coordinator: service, Health: health, Limits: limits,
	})
	if err != nil {
		return nil, fmt.Errorf("coordinator.worker_channel: %w", err)
	}
	go identity.Run(ctx)
	return handler, nil
}
