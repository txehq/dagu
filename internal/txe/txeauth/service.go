// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeauth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// keyRefreshInterval is how often the provider's keys are fetched again in
// the background. The key set needs at least one try every half of its
// maximum age for its bound on stale keys to hold on an idle server; once a
// minute is well inside that.
const keyRefreshInterval = time.Minute

// Service is the server's TXE authentication and authorization: the mode,
// the owner store, and the provider token verifier when one is configured.
type Service struct {
	mode     authz.Mode
	store    *authz.Store
	registry Registry
	verifier *authn.Verifier
	keys     *authn.RemoteKeySet
}

// Option configures a Service, for tests.
type Option func(*options)

type options struct {
	keys  authn.KeySource
	clock func() time.Time
}

// WithKeySource replaces the provider's published key set.
func WithKeySource(keys authn.KeySource) Option {
	return func(o *options) { o.keys = keys }
}

// WithClock overrides the clock of the verifier and the owner store.
func WithClock(now func() time.Time) Option {
	return func(o *options) { o.clock = now }
}

// NewService builds the service from the server's configuration. The owner
// store lives beside the registry under dataDir.
func NewService(cfg config.TXEConfig, dataDir string, reg *registry.Store, opts ...Option) (*Service, error) {
	if reg == nil {
		return nil, errors.New("txeauth: the TXE registry is required")
	}
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	mode, err := authz.ParseMode(cfg.Authz.Mode)
	if err != nil {
		return nil, err
	}
	registryView := NewRegistry(reg)
	var storeOpts []authz.Option
	if o.clock != nil {
		storeOpts = append(storeOpts, authz.WithClock(o.clock))
	}
	store, err := authz.NewFileStore(dataDir, registryView, storeOpts...)
	if err != nil {
		return nil, err
	}
	s := &Service{mode: mode, store: store, registry: registryView}
	if !cfg.Authn.Enabled() {
		return s, nil
	}

	keys := o.keys
	if keys == nil {
		remote, err := authn.NewRemoteKeySet(authn.RemoteKeySetConfig{URL: cfg.Authn.JWKSURL, Now: o.clock})
		if err != nil {
			return nil, fmt.Errorf("txeauth: %s: %w", "txe.authn.jwks_url", err)
		}
		s.keys, keys = remote, remote
	}
	clients := make(map[string]authn.Class, len(cfg.Authn.Clients))
	for _, c := range cfg.Authn.Clients {
		clients[c.ID] = authn.Class(c.Class)
	}
	s.verifier, err = authn.NewVerifier(authn.Config{
		Issuer:      cfg.Authn.Issuer,
		Audience:    cfg.Authn.Audience,
		Clients:     clients,
		MaxLifetime: cfg.Authn.MaxLifetime,
		// Shared by the hub and the coordinator, which verify with this
		// service.
		IssuedAtSkew: cfg.Authn.IssuedAtSkew,
		Keys:         keys,
		Now:          o.clock,
	})
	if err != nil {
		return nil, err
	}
	return s, nil
}

// Mode is the authorization mode for credentials accepted before owners were
// enforced. Callers that authenticated through the identity provider are
// always held to their owner, whatever it says.
func (s *Service) Mode() authz.Mode { return s.mode }

// Store is the owner store: bindings, shares and enrolments.
func (s *Service) Store() *authz.Store { return s.store }

// Registry is the owner lookups.
func (s *Service) Registry() Registry { return s.registry }

// AcceptsTokens reports whether provider access tokens are verified.
func (s *Service) AcceptsTokens() bool { return s.verifier != nil }

// Verify verifies a provider access token. It must only be called when
// AcceptsTokens is true.
func (s *Service) Verify(ctx context.Context, token string) (authn.Principal, error) {
	if s.verifier == nil {
		return authn.Principal{}, errors.New("txeauth: provider tokens are not accepted")
	}
	return s.verifier.Verify(ctx, token)
}

// Run keeps the provider's keys fresh until ctx ends, so that an issuer that
// stops answering is noticed even while no token arrives. It returns at once
// when no remote key set is in use.
func (s *Service) Run(ctx context.Context) {
	if s.keys == nil {
		return
	}
	refresh := func() {
		if err := s.keys.Refresh(ctx); err != nil && ctx.Err() == nil {
			slog.Default().Warn("txe: the identity provider's keys could not be fetched", slog.String("error", err.Error()))
		}
	}
	refresh()
	ticker := time.NewTicker(keyRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}

// Scope resolves a caller to what it may act as. The platform administrator
// is its own scope; one signed in through the identity provider whose
// identity is bound is also its owner's person (authz.ResolvePlatformAdmin). A person or a token is resolved through its binding or
// enrolment. A legacy caller, and a request nothing authenticated, act for
// nobody. An error means the owner store could not be read.
func (s *Service) Scope(ctx context.Context, c Caller) (authz.Scope, error) {
	switch c.Kind {
	case KindPlatformAdmin:
		if c.Principal.Issuer == "" {
			return authz.PlatformAdmin(c.Username), nil
		}
		return s.store.ResolvePlatformAdmin(ctx, c.Username, c.Principal.Identity)
	case KindPerson, KindToken:
		return s.store.Resolve(ctx, c.Principal)
	case KindLegacy, KindNone:
		return authz.Scope{}, nil
	default:
		return authz.Scope{}, nil
	}
}
