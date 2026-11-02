// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"errors"

	"github.com/go-chi/chi/v5"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/service/frontend"
	"github.com/dagucloud/dagu/v2/internal/txe/channelhub"
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

// newWorkerChannel is the channel start-all serves, with its refusals logged
// as the coordinator's are.
func newWorkerChannel(
	ctx context.Context,
	cfg *config.Config,
	service coordinatorv1.CoordinatorServiceServer,
	health grpc_health_v1.HealthServer,
	opts ...txeauth.Option,
) (*workerchannel.Handler, error) {
	return channelhub.New(ctx, cfg, service, health, logCoordinatorAuthDecision, opts...)
}
