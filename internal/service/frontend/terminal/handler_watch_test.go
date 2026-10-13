// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package terminal_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
	persiststore "github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	authservice "github.com/dagucloud/dagu/v2/internal/service/auth"
	frontendauth "github.com/dagucloud/dagu/v2/internal/service/frontend/auth"
	terminalpkg "github.com/dagucloud/dagu/v2/internal/service/frontend/terminal"
	"github.com/dagucloud/dagu/v2/internal/service/oidcsession"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixedWindow struct{ err error }

func (f fixedWindow) Window(context.Context, string) (oidcsession.Window, error) {
	return oidcsession.Window{}, f.err
}

// A terminal whose session stopped letting its user in between the token
// being checked and the terminal being set up is refused before anything is
// set up for it: no slot is taken, the connection is not upgraded, and no
// shell is started.
func TestTerminal_SessionOverBeforeTheTerminalIsSetUp(t *testing.T) {
	t.Parallel()
	store, err := persiststore.NewUserStore(testutil.NewMemoryBackend().Collection("users"))
	require.NoError(t, err)
	secret, err := authmodel.NewTokenSecretFromString("test-secret-key-for-jwt-signing")
	require.NoError(t, err)
	user := authmodel.NewUser("alice", "", authmodel.RoleAdmin)
	user.AuthProvider = authmodel.AuthProviderOIDC
	require.NoError(t, store.Create(context.Background(), user))

	for name, tt := range map[string]struct {
		window     error
		status     int
		retryAfter string
	}{
		"SessionEnded":    {oidcsession.ErrSessionEnded, http.StatusUnauthorized, ""},
		"StoreUnreadable": {errors.New("disk unavailable"), http.StatusServiceUnavailable, "5"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			svc := authservice.New(store, authservice.Config{TokenSecret: secret, TokenTTL: time.Hour, BcryptCost: 4})
			// The check of the token itself passes.
			svc.SetSessionChecker(fixedSession{})
			token, err := svc.GenerateSessionToken(user, "0123456789abcdef0123456789abcdef", time.Now().Add(time.Hour))
			require.NoError(t, err)
			// One slot: a refusal that had taken it would be seen below.
			manager := terminalpkg.NewManager(context.Background(), 1)
			handler := terminalpkg.NewHandler(svc, nil, nil, manager, "/bin/sh")
			handler.SetSessionWatch(frontendauth.NewSessionWatch(svc, fixedWindow{err: tt.window}, nil))

			for range 3 {
				// A recorder cannot be upgraded to a WebSocket: an attempt
				// would answer otherwise than the refusal does.
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/terminal/ws?token="+token.Token, nil))

				assert.Equal(t, tt.status, recorder.Code)
				assert.Equal(t, tt.retryAfter, recorder.Header().Get("Retry-After"))
			}
		})
	}
}
