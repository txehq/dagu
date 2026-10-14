// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package worker

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/runtime/workspacebundle"
	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
)

// NewCoordinatorClient creates a client using the worker's configured coordinators.
//
// A worker presents its machine credential when worker.auth.credential_file
// names one, and nothing otherwise. It never presents the hub's key, whatever
// else the configuration says: a worker that has no credential of its own is
// refused by a coordinator that authenticates, rather than let in as the hub.
func NewCoordinatorClient(ctx context.Context, cfg *config.Config) (coordinator.Client, error) {
	if len(cfg.Worker.Coordinators) == 0 {
		return nil, fmt.Errorf("worker.coordinators is required")
	}

	clientConfig := coordinator.ConfigFromPeer(cfg.Core.Peer)
	clientConfig.WorkspaceBundleDir = workspacebundle.StoreDir(cfg.Paths.DataDir)
	if err := clientConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid coordinator client configuration: %w", err)
	}
	if path := cfg.Worker.Auth.CredentialFile; path != "" {
		source, err := transportauth.NewRefreshingSource(path)
		if err != nil {
			return nil, fmt.Errorf("worker.auth.credential_file: %w", err)
		}
		clientConfig.Credentials = transportauth.NewWorkerCredentials(source)
		logger.Info(ctx, "Presenting the machine credential to the coordinator",
			slog.String("machine", source.MachineID()))
	}
	registry, err := coordinator.NewStaticRegistry(cfg.Worker.Coordinators)
	if err != nil {
		return nil, fmt.Errorf("failed to create static registry: %w", err)
	}
	logger.Info(ctx, "Using static coordinator discovery",
		slog.Any("coordinators", cfg.Worker.Coordinators))
	return coordinator.New(registry, clientConfig), nil
}
