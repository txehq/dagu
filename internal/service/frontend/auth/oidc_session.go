// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/persis"
	authservice "github.com/dagucloud/dagu/v2/internal/service/auth"
	"github.com/dagucloud/dagu/v2/internal/service/oidcsession"
)

// NewOIDCSessionManager builds the session manager for the OIDC provider the
// browser sign-in uses. It is called only when auth.oidc.session is
// configured.
func NewOIDCSessionManager(session config.AuthOIDCSession, oidcCfg *BuiltinOIDCConfig, col persis.Collection, enc oidcsession.Encryptor) (*oidcsession.Manager, error) {
	if oidcCfg == nil || oidcCfg.OAuth2Config == nil || oidcCfg.Provider == nil || oidcCfg.Verifier == nil {
		return nil, errors.New("OIDC sessions need the OIDC sign-in to be configured")
	}
	var endpoints struct {
		Revocation string `json:"revocation_endpoint"`
	}
	// A provider without a revocation endpoint is not an error: sign-out
	// still ends the hub's session, which is what lets nobody in.
	_ = oidcCfg.Provider.Claims(&endpoints)

	provider, err := oidcsession.NewHTTPProvider(oidcsession.HTTPProviderConfig{
		TokenURL:      oidcCfg.OAuth2Config.Endpoint.TokenURL,
		RevocationURL: endpoints.Revocation,
		ClientID:      oidcCfg.OAuth2Config.ClientID,
		ClientSecret:  oidcCfg.OAuth2Config.ClientSecret,
	})
	if err != nil {
		return nil, err
	}
	verifier := oidcCfg.Verifier
	checkID := func(ctx context.Context, rawIDToken string) (string, string, error) {
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err != nil {
			return "", "", err
		}
		return idToken.Issuer, idToken.Subject, nil
	}
	return oidcsession.NewManager(oidcsession.Config{
		RevalidateAfter: session.RevalidateAfter,
		RevalidateLimit: session.RevalidateLimit,
	}, col, enc, provider, checkID)
}

// OIDCSessionChecker adapts a session manager to the auth service, which asks
// it for every token that carries a session.
type OIDCSessionChecker struct {
	Manager *oidcsession.Manager
}

var _ authservice.SessionChecker = OIDCSessionChecker{}

// CheckSession implements authservice.SessionChecker.
func (c OIDCSessionChecker) CheckSession(ctx context.Context, sessionID string, user *authmodel.User) error {
	err := c.Manager.Check(ctx, sessionID, oidcSessionIdentity(user))
	switch {
	case err == nil:
		return nil
	case errors.Is(err, oidcsession.ErrSessionEnded):
		return authservice.ErrInvalidToken
	case errors.Is(err, oidcsession.ErrProviderUnavailable):
		return authservice.ErrIdentityProviderUnavailable
	default:
		// The session could not be read. That is not an answer about the
		// user, and it is not a reason to let them in.
		return err
	}
}

func oidcSessionIdentity(user *authmodel.User) oidcsession.Identity {
	return oidcsession.Identity{UserID: user.ID, Issuer: user.OIDCIssuer, Subject: user.OIDCSubject}
}

// BuiltinOIDCLogoutHandler ends the OIDC session of the hub token it is sent
// and revokes its refresh token at the provider.
//
// It takes a POST with the hub token in the Authorization header and nothing
// else. The token is not accepted from a cookie or the query string, so a
// page on another site cannot make a signed-in browser sign out, and the
// token does not end up in a log. A token with no session, and a session
// that has already ended, are answered the same as a session that was ended:
// there is nothing left to sign out of.
func BuiltinOIDCLogoutHandler(cfg *BuiltinOIDCConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "Sign-out takes a POST", http.StatusMethodNotAllowed)
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if token == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
			requireBearerAuth(w, "restricted")
			return
		}
		claims, err := cfg.AuthService.ValidateToken(token)
		if err != nil {
			requireBearerAuth(w, "restricted")
			return
		}
		if cfg.Sessions != nil && claims.SessionID != "" {
			if err := cfg.Sessions.End(r.Context(), claims.SessionID, "signed out"); err != nil {
				logger.Error(r.Context(), "Failed to end OIDC session at sign-out", tag.Error(err))
				http.Error(w, "The session could not be ended", http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
