// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"testing"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/runtime"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// passwordOffAPI is an API whose auth service is never reached: every route
// below must refuse before it is asked anything.
func passwordOffAPI(t *testing.T) *API {
	t.Helper()
	cfg := &config.Config{}
	cfg.Server.Auth.Mode = config.AuthModeBuiltin
	cfg.Server.Auth.Builtin.PasswordDisabled = true
	return New(nil, nil, nil, nil, runtime.Manager{}, cfg, nil, nil, prometheus.NewRegistry(), nil,
		WithAuthService(struct{ AuthService }{}))
}

func TestPasswordDisabled_EveryPasswordRouteIsRefused(t *testing.T) {
	a := passwordOffAPI(t)
	admin := auth.WithUser(context.Background(), &auth.User{ID: "u1", Username: "admin", Role: auth.RoleAdmin})

	login, err := a.Login(context.Background(), apigen.LoginRequestObject{Body: &apigen.LoginJSONRequestBody{Username: "admin", Password: "pw"}})
	require.NoError(t, err)
	assert.IsType(t, apigen.Login401JSONResponse{}, login)
	assert.Equal(t, passwordDisabledMessage, login.(apigen.Login401JSONResponse).Message)

	setup, err := a.Setup(context.Background(), apigen.SetupRequestObject{Body: &apigen.SetupJSONRequestBody{Username: "admin", Password: "pw"}})
	require.NoError(t, err)
	assert.IsType(t, apigen.Setup403JSONResponse{}, setup)

	change, err := a.ChangePassword(admin, apigen.ChangePasswordRequestObject{Body: &apigen.ChangePasswordJSONRequestBody{CurrentPassword: "a", NewPassword: "b"}})
	require.NoError(t, err)
	assert.IsType(t, apigen.ChangePassword403JSONResponse{}, change)

	create, err := a.CreateUser(admin, apigen.CreateUserRequestObject{Body: &apigen.CreateUserJSONRequestBody{Username: "bob", Password: "pw", Role: apigen.UserRoleViewer}})
	require.NoError(t, err)
	assert.IsType(t, apigen.CreateUser403JSONResponse{}, create)

	reset, err := a.ResetUserPassword(admin, apigen.ResetUserPasswordRequestObject{UserId: "u2", Body: &apigen.ResetUserPasswordJSONRequestBody{NewPassword: "pw"}})
	require.NoError(t, err)
	assert.IsType(t, apigen.ResetUserPassword403JSONResponse{}, reset)
}
