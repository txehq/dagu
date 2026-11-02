// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package worker

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/runtime/workspacebundle"
	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	"github.com/dagucloud/dagu/v2/internal/txe/workerchannel"
)

// NewCoordinatorClient creates a client using the worker's configured coordinators.
//
// A worker presents its machine credential when worker.auth.credential_file
// names one, and nothing otherwise. It never presents the hub's key, whatever
// else the configuration says: a worker that has no credential of its own is
// refused by a coordinator that authenticates, rather than let in as the hub.
//
// With worker.hub_url the worker reaches the hub by the worker channel over
// HTTPS, and a machine credential is required.
func NewCoordinatorClient(ctx context.Context, cfg *config.Config) (coordinator.Client, error) {
	if cfg.Worker.HubURL != "" {
		return newChannelClient(ctx, cfg)
	}
	if len(cfg.Worker.Coordinators) == 0 {
		return nil, fmt.Errorf("worker.coordinators is required")
	}

	clientConfig := coordinator.ConfigFromPeer(cfg.Core.Peer)
	clientConfig.WorkspaceBundleDir = workspacebundle.StoreDir(cfg.Paths.DataDir)
	clientConfig.ArtifactSegmentBytes = cfg.Worker.ArtifactSegmentBytes
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

// channelBaseURL is where the hub serves the channel. As for the CLI's --hub, a
// path names the hub's API root, for a hub with its own base path, and no path
// means the default one.
func channelBaseURL(hub *url.URL) string {
	root := *hub
	root.Path = strings.TrimRight(hub.Path, "/")
	if root.Path == "" {
		root.Path = "/api/v1"
	}
	root.Path += workerchannel.MountPath
	return root.String()
}

// ChannelBaseURL is where a hub at hubURL serves the worker channel, by the
// worker's own rule.
func ChannelBaseURL(hubURL string) (string, error) {
	hub, err := url.Parse(hubURL)
	if err != nil || hub.Host == "" {
		return "", fmt.Errorf("%q is not a hub address", hubURL)
	}
	return channelBaseURL(hub), nil
}

// channelSegmentBytes is the most an artifact stream carries over the channel,
// well below workerchannel's request limit.
const channelSegmentBytes = 16 << 20

// newChannelClient is the coordinator client over the worker channel. The hub
// is the only coordinator, and an owner's advertised address is not dialled:
// every member uses the one connection.
func newChannelClient(ctx context.Context, cfg *config.Config) (coordinator.Client, error) {
	if len(cfg.Worker.Coordinators) != 0 {
		return nil, fmt.Errorf("worker.hub_url and worker.coordinators are two routes to a hub: give one")
	}
	path := cfg.Worker.Auth.CredentialFile
	if path == "" {
		return nil, fmt.Errorf("worker.hub_url needs worker.auth.credential_file: the channel admits only enrolled machines")
	}
	hub, err := url.Parse(cfg.Worker.HubURL)
	if err != nil {
		return nil, fmt.Errorf("worker.hub_url is not a URL")
	}
	source, err := transportauth.NewRefreshingSource(path)
	if err != nil {
		return nil, fmt.Errorf("worker.auth.credential_file: %w", err)
	}
	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{
		BaseURL:     channelBaseURL(hub),
		Credentials: transportauth.NewWorkerCredentials(source),
	})
	if err != nil {
		return nil, fmt.Errorf("worker.hub_url: %w", err)
	}

	clientConfig := coordinator.ConfigFromPeer(cfg.Core.Peer)
	clientConfig.WorkspaceBundleDir = workspacebundle.StoreDir(cfg.Paths.DataDir)
	clientConfig.Connect = func() coordinator.Connection { return conn }
	clientConfig.ArtifactSegmentBytes = channelSegmentBytes
	if size := cfg.Worker.ArtifactSegmentBytes; size > 0 {
		clientConfig.ArtifactSegmentBytes = size
	}
	// Half leaves the rest for what is still in buffers on the way to the hub.
	clientConfig.ArtifactStreamTime = workerchannel.DefaultLimits().Stream / 2
	if err := clientConfig.Validate(); err != nil {
		return nil, fmt.Errorf("invalid coordinator client configuration: %w", err)
	}
	port := hub.Port()
	if port == "" {
		port = "443"
	}
	registry, err := coordinator.NewStaticRegistry([]string{net.JoinHostPort(hub.Hostname(), port)})
	if err != nil {
		return nil, fmt.Errorf("failed to create static registry: %w", err)
	}
	logger.Info(ctx, "Reaching the hub by the worker channel",
		slog.String("hub", hub.Host), slog.String("machine", source.MachineID()))
	return coordinator.New(registry, clientConfig), nil
}
