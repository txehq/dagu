// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package terminal_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
	persiststore "github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	authservice "github.com/dagucloud/dagu/v2/internal/service/auth"
	terminalpkg "github.com/dagucloud/dagu/v2/internal/service/frontend/terminal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixedSession struct{ err error }

func (f fixedSession) CheckSession(context.Context, string, *authmodel.User) error { return f.err }

// Opening a terminal with a token whose session cannot be confirmed is told
// the provider is unavailable, not that the token is bad. A session that has
// ended is told to sign in.
func TestTerminal_SessionAnswersAtConnect(t *testing.T) {
	t.Parallel()
	store, err := persiststore.NewUserStore(testutil.NewMemoryBackend().Collection("users"))
	require.NoError(t, err)
	secret, err := authmodel.NewTokenSecretFromString("test-secret-key-for-jwt-signing")
	require.NoError(t, err)
	user := authmodel.NewUser("alice", "", authmodel.RoleAdmin)
	user.AuthProvider = authmodel.AuthProviderOIDC
	require.NoError(t, store.Create(context.Background(), user))

	for name, tt := range map[string]struct {
		session    error
		status     int
		retryAfter string
	}{
		"ProviderUnavailable": {authservice.ErrSessionCheckUnavailable, http.StatusServiceUnavailable, "5"},
		"SessionEnded":        {authservice.ErrInvalidToken, http.StatusUnauthorized, ""},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			svc := authservice.New(store, authservice.Config{TokenSecret: secret, TokenTTL: time.Hour, BcryptCost: 4})
			svc.SetSessionChecker(fixedSession{err: tt.session})
			token, err := svc.GenerateSessionToken(user, "0123456789abcdef0123456789abcdef", time.Now().Add(time.Hour))
			require.NoError(t, err)
			handler := terminalpkg.NewHandler(svc, nil, nil, nil, "")

			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/terminal/ws?token="+token.Token, nil))

			assert.Equal(t, tt.status, recorder.Code)
			assert.Equal(t, tt.retryAfter, recorder.Header().Get("Retry-After"))
		})
	}
}
