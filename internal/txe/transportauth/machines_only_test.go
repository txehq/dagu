// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package transportauth_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
)

type refuseAll struct{}

func (refuseAll) Verify(context.Context, string) (authn.Principal, error) {
	return authn.Principal{}, errors.New("no token is accepted")
}

func (refuseAll) ResolveMachine(context.Context, authn.Principal) (authz.Machine, authz.Reason, error) {
	return authz.Machine{}, "", errors.New("no enrolment")
}

func TestMachinesOnlyServerIsEnforcingAndHoldsNoHubKey(t *testing.T) {
	cfg := transportauth.ServerConfig{Mode: authz.ModeEnforce, Verifier: refuseAll{}, Machines: refuseAll{}, MachinesOnly: true}
	server, err := transportauth.NewServer(cfg)
	require.NoError(t, err)
	assert.True(t, server.MachinesOnly())

	observe := cfg
	observe.Mode = authz.ModeObserve
	_, err = transportauth.NewServer(observe)
	require.Error(t, err)

	withKey := cfg
	withKey.HubKey = testHubKey
	_, err = transportauth.NewServer(withKey)
	require.Error(t, err)
}

func TestMachinesOnlyServerAsksACredentialOnPublicMethodsAndRefusesTheHubKey(t *testing.T) {
	server, err := transportauth.NewServer(transportauth.ServerConfig{
		Mode: authz.ModeEnforce, Verifier: refuseAll{}, Machines: refuseAll{}, MachinesOnly: true,
	})
	require.NoError(t, err)

	_, err = server.Admit(context.Background(), grpc_health_v1.Health_Check_FullMethodName)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	ctx := metadata.NewIncomingContext(context.Background(),
		metadata.Pairs(transportauth.AuthorizationHeader, transportauth.HubScheme+" "+string(testHubKey)))
	_, err = server.Admit(ctx, grpc_health_v1.Health_Check_FullMethodName)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.Contains(t, err.Error(), "not accepted here")
}

func TestHTTPAuthorizationGoesOnlyOverTLSOrToLoopback(t *testing.T) {
	credentials := transportauth.NewWorkerCredentials(staticToken("tok"))
	for _, target := range []string{"https://hub.example/x", "http://127.0.0.1:1/x"} {
		value, err := credentials.HTTPAuthorization(context.Background(), target)
		require.NoError(t, err, target)
		assert.Equal(t, "Bearer tok", value)
	}
	for _, target := range []string{"http://hub.example/x", "http://127.0.0.1@hub.example/x"} {
		_, err := credentials.HTTPAuthorization(context.Background(), target)
		assert.Equal(t, codes.Unauthenticated, status.Code(err), target)
	}
}

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }
