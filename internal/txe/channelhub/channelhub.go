// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package channelhub builds the hub's side of the worker channel from the
// hub's configuration. start-all serves what it builds, and so do the tests
// that put the channel behind the real frontend server.
package channelhub

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
	"github.com/dagucloud/dagu/v2/internal/txe/workerchannel"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// New builds the channel. It stands apart from coordinator.auth and
// txe.authz: it always authenticates every call, it needs no hub key and
// creates none, and the private gRPC port is unchanged by it. observe is told
// each refusal; it may be nil. The identity service it starts runs until ctx
// ends.
func New(
	ctx context.Context,
	cfg *config.Config,
	service coordinatorv1.CoordinatorServiceServer,
	health grpc_health_v1.HealthServer,
	observe func(context.Context, transportauth.Decision),
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
		Observe:      observe,
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
