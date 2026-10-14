// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package coordinator

import (
	"fmt"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/serviceregistry"
	"google.golang.org/grpc/credentials"
)

// NewRuntimeDispatcher creates a coordinator-backed dispatcher for runtime DAG execution.
// workspaceBundleDir must be set (typically workspacebundle.StoreDir(dataDir)) so child
// DAGs with file dependencies can pack workspace bundles the same way as top-level
// NewCoordinatorClient / Engine.coordinatorClient.
//
// credentials, when set, is presented on every call, as the caller's own
// coordinator client presents it.
func NewRuntimeDispatcher(
	registry serviceregistry.ServiceRegistry,
	peerConfig config.Peer,
	workspaceBundleDir string,
	credentials credentials.PerRPCCredentials,
) (dispatch.Dispatcher, error) {
	if registry == nil {
		return nil, nil
	}

	cfg := ConfigFromPeer(peerConfig)
	cfg.WorkspaceBundleDir = workspaceBundleDir
	cfg.Credentials = credentials
	if peerConfig.MaxRetries <= 0 {
		cfg.MaxRetries = 50
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate runtime dispatcher config: %w", err)
	}
	return New(registry, cfg), nil
}
