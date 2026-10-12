// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	oidc "github.com/coreos/go-oidc"
	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/persis"
	authservice "github.com/dagucloud/dagu/v2/internal/service/auth"
	"github.com/dagucloud/dagu/v2/internal/service/oidcsession"
	"golang.org/x/oauth2"
)

// NewOIDCSessionManager builds the session manager for the OIDC provider the
// browser sign-in uses. It is called only when auth.oidc.session is
// configured.
func NewOIDCSessionManager(session config.AuthOIDCSession, oidcCfg *BuiltinOIDCConfig, col persis.Collection, enc oidcsession.Encryptor) (*oidcsession.Manager, error) {
	if oidcCfg == nil || oidcCfg.OAuth2Config == nil || oidcCfg.Provider == nil || oidcCfg.Verifier == nil {
		return nil, errors.New("OIDC sessions need the OIDC sign-in to be configured")
	}
	var endpoints struct {
		Revocation  string   `json:"revocation_endpoint"`
		AuthMethods []string `json:"token_endpoint_auth_methods_supported"`
	}
	// A provider without a revocation endpoint is not an error: sign-out
	// still ends the hub's session, which is what lets nobody in.
	_ = oidcCfg.Provider.Claims(&endpoints)

	provider, err := oidcsession.NewHTTPProvider(oidcsession.HTTPProviderConfig{
		TokenURL:      oidcCfg.OAuth2Config.Endpoint.TokenURL,
		RevocationURL: endpoints.Revocation,
		ClientID:      oidcCfg.OAuth2Config.ClientID,
		ClientSecret:  oidcCfg.OAuth2Config.ClientSecret,
		ClientAuth:    oidcClientAuth(oidcCfg.OAuth2Config.Endpoint.AuthStyle, endpoints.AuthMethods),
	})
	if err != nil {
		return nil, err
	}
	return oidcsession.NewManager(oidcsession.Config{
		RevalidateAfter: session.RevalidateAfter,
		RevalidateLimit: session.RevalidateLimit,
	}, col, enc, provider, newIDTokenChecker(oidcCfg.Verifier))
}

// newIDTokenChecker checks a renewed ID token with the verifier the sign-in
// uses.
//
// The verifier reports a token it rejects and signing keys it could not fetch
// in the same way. So a token that at least is one, and says whom it is for,
// is reported as not verifiable: the session is then neither confirmed nor
// ended on that token. If it names another identity the session ends,
// verified or not.
func newIDTokenChecker(verifier *oidc.IDTokenVerifier) oidcsession.IDTokenChecker {
	return func(ctx context.Context, rawIDToken string) (string, string, error) {
		idToken, err := verifier.Verify(ctx, rawIDToken)
		if err == nil {
			return idToken.Issuer, idToken.Subject, nil
		}
		issuer, subject, ok := unverifiedIDTokenIdentity(rawIDToken)
		if !ok {
			return "", "", err
		}
		return issuer, subject, oidcsession.ErrIDTokenUnverifiable
	}
}

// oidcClientAuth is the way the refresh sends the client secret: the way the
// sign-in's code exchange is configured to, and otherwise what the provider's
// discovery document settles. A provider that lists the form and not the
// header takes the form. Anything else is found out as the exchange finds it
// out: the header first, then the form. A provider may list the header and
// still refuse it for this client, so the list alone does not settle it.
func oidcClientAuth(style oauth2.AuthStyle, supported []string) oidcsession.ClientAuth {
	switch style {
	case oauth2.AuthStyleInParams:
		return oidcsession.ClientAuthForm
	case oauth2.AuthStyleInHeader:
		return oidcsession.ClientAuthHeader
	case oauth2.AuthStyleAutoDetect:
	}
	if slices.Contains(supported, "client_secret_post") && !slices.Contains(supported, "client_secret_basic") {
		return oidcsession.ClientAuthForm
	}
	return oidcsession.ClientAuthDetect
}

// unverifiedIDTokenIdentity reads the issuer and subject a JWT names, without
// verifying it. What it returns is a claim, never a fact.
func unverifiedIDTokenIdentity(rawIDToken string) (issuer, subject string, ok bool) {
	parts := strings.Split(rawIDToken, ".")
	if len(parts) != 3 {
		return "", "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", false
	}
	var claims struct {
		Issuer  string `json:"iss"`
		Subject string `json:"sub"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.Issuer == "" || claims.Subject == "" {
		return "", "", false
	}
	return claims.Issuer, claims.Subject, true
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
	default:
		// The identity provider could not be asked, or the session could not
		// be read. Neither is an answer about the user: they are not let in,
		// and they are not signed out.
		if !errors.Is(err, oidcsession.ErrProviderUnavailable) {
			logger.Error(ctx, "OIDC session could not be checked", tag.Error(err))
		}
		return authservice.ErrSessionCheckUnavailable
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
			// A sign-out that has arrived is carried out even if the browser
			// has gone away meanwhile.
			if err := cfg.Sessions.End(context.WithoutCancel(r.Context()), claims.SessionID, "signed out"); err != nil {
				logger.Error(r.Context(), "Failed to end OIDC session at sign-out", tag.Error(err))
				http.Error(w, "The session could not be ended", http.StatusInternalServerError)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
