// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	authmodel "github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/backoff"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/cmn/stringutil"
	"github.com/dagucloud/dagu/v2/internal/license"
	authservice "github.com/dagucloud/dagu/v2/internal/service/auth"
	"github.com/dagucloud/dagu/v2/internal/service/oidcprovision"
	"github.com/dagucloud/dagu/v2/internal/service/oidcsession"
	"golang.org/x/oauth2"
)

// Tunable constants for OIDC auth behaviour.
const (
	oidcProviderInitTimeout     = 10 * time.Second
	oidcProviderMaxRetries      = 10                     // max retries for OIDC provider init (network issues)
	oidcProviderInitialInterval = 500 * time.Millisecond // initial backoff interval
	oidcProviderMaxInterval     = 5 * time.Second        // maximum backoff interval
	stateCookieExpiry           = 120                    // seconds for transient state/nonce/originalURL cookies
)

// Cookie names centralised to avoid copy-paste strings.
const (
	cookieState       = "state"
	cookieNonce       = "nonce"
	cookieOriginalURL = "originalURL"
	// cookiePKCEVerifier holds the PKCE code verifier between the sign-in
	// redirect and the callback. It is set only when PKCE is enabled.
	cookiePKCEVerifier = "pkce_verifier"
)

// A PKCE code verifier is 43 to 128 characters (RFC 7636, section 4.1).
const (
	minPKCEVerifierLength = 43
	maxPKCEVerifierLength = 128
)

var oidcProviderFactory = func(ctx context.Context, issuer string) (*oidc.Provider, error) {
	return oidc.NewProvider(ctx, issuer)
}

// oidcProviderParams holds the common parameters for OIDC provider initialization.
type oidcProviderParams struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	ClientURL    string
	Scopes       []string
}

// oidcProviderResult holds the initialized OIDC components.
type oidcProviderResult struct {
	Provider     *oidc.Provider
	Verifier     *oidc.IDTokenVerifier
	OAuth2Config *oauth2.Config
}

// initOIDCProviderCore initializes the common OIDC provider components.
// The passed context is used for the OIDC provider initialization and retry loop,
// allowing the initialization to be cancelled (e.g., on SIGINT/SIGTERM).
func initOIDCProviderCore(ctx context.Context, params oidcProviderParams) (*oidcProviderResult, error) {
	// Basic input validation
	if params.Issuer == "" {
		return nil, errors.New("failed to init OIDC provider: issuer is empty")
	}
	if params.ClientID == "" {
		return nil, errors.New("failed to init OIDC provider: client id is empty")
	}
	if params.ClientURL == "" {
		return nil, errors.New("failed to init OIDC provider: client url is empty")
	}

	// Create HTTP client with explicit transport settings to avoid race conditions
	// with gopsutil resource monitoring during startup (both use net/http dial).
	// Force IPv4 to avoid "bad file descriptor" errors on macOS with IPv6.
	dialer := &net.Dialer{
		Timeout:   oidcProviderInitTimeout,
		KeepAlive: 30 * time.Second,
	}
	httpClient := &http.Client{
		Timeout: oidcProviderInitTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp4", addr)
			},
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   oidcProviderInitTimeout,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
	oidcCtx := oidc.ClientContext(ctx, httpClient)

	// Create retry policy with exponential backoff for transient network errors
	policy := backoff.NewExponentialBackoffPolicy(oidcProviderInitialInterval)
	policy.MaxInterval = oidcProviderMaxInterval
	policy.MaxRetries = oidcProviderMaxRetries

	var provider *oidc.Provider
	err := backoff.Retry(oidcCtx, func(retryCtx context.Context) error {
		var providerErr error
		provider, providerErr = oidcProviderFactory(retryCtx, params.Issuer)
		if providerErr != nil {
			// Check for permanent errors that shouldn't be retried
			// (e.g., invalid URL format, unsupported scheme)
			errStr := providerErr.Error()
			if strings.Contains(errStr, "unsupported protocol scheme") ||
				strings.Contains(errStr, "invalid URI") ||
				strings.Contains(errStr, "invalid URL") {
				slog.Error("OIDC provider init failed with permanent error",
					tag.Error(providerErr),
					slog.String("issuer", params.Issuer))
				return backoff.PermanentError(providerErr)
			}

			slog.Warn("OIDC provider init failed, will retry",
				tag.Error(providerErr),
				slog.String("issuer", params.Issuer))
			return providerErr
		}
		return nil
	}, policy, nil)

	if err != nil {
		return nil, fmt.Errorf("failed to init OIDC provider: %w", err)
	}
	if provider == nil {
		return nil, errors.New("failed to init OIDC provider: provider is nil")
	}

	oidcConfig := &oidc.Config{
		ClientID: params.ClientID,
	}
	verifier := provider.Verifier(oidcConfig)
	endpoint := provider.Endpoint()

	oauth2Config := &oauth2.Config{
		ClientID:     params.ClientID,
		ClientSecret: params.ClientSecret,
		Endpoint:     endpoint,
		RedirectURL:  fmt.Sprintf("%s/oidc-callback", strings.TrimSuffix(params.ClientURL, "/")),
		Scopes:       params.Scopes,
	}

	return &oidcProviderResult{
		Provider:     provider,
		Verifier:     verifier,
		OAuth2Config: oauth2Config,
	}, nil
}

func setCookie(w http.ResponseWriter, _ *http.Request, name, value string, expire int) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   expire,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

func clearCookie(w http.ResponseWriter, r *http.Request, name string) {
	setCookie(w, r, name, "", -1)
}

// clearOIDCStateCookies removes all OIDC-related state cookies.
func clearOIDCStateCookies(w http.ResponseWriter, r *http.Request) {
	clearCookie(w, r, cookieState)
	clearCookie(w, r, cookieNonce)
	clearCookie(w, r, cookieOriginalURL)
}

// validPKCEVerifier reports whether a verifier is one RFC 7636 allows: 43 to
// 128 of the unreserved characters.
func validPKCEVerifier(verifier string) bool {
	if len(verifier) < minPKCEVerifierLength || len(verifier) > maxPKCEVerifierLength {
		return false
	}
	for _, c := range []byte(verifier) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' || c == '.' || c == '_' || c == '~':
		default:
			return false
		}
	}
	return true
}

// tokenExchangeFailure describes a failed code exchange for the log without
// any text the provider chose. The exchange carries the PKCE verifier, and a
// provider's error description or body can repeat what it was sent.
func tokenExchangeFailure(err error) []slog.Attr {
	var retrieveErr *oauth2.RetrieveError
	if !errors.As(err, &retrieveErr) {
		return []slog.Attr{slog.String("failure", "no usable response from the token endpoint")}
	}
	attrs := []slog.Attr{slog.String("failure", "the token endpoint refused the exchange")}
	if retrieveErr.Response != nil {
		attrs = append(attrs, slog.Int("status", retrieveErr.Response.StatusCode))
	}
	// Only the error codes RFC 6749 defines are repeated; anything else the
	// provider put there is not.
	switch retrieveErr.ErrorCode {
	case "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope":
		attrs = append(attrs, slog.String("oauth_error", retrieveErr.ErrorCode))
	case "":
	default:
		attrs = append(attrs, slog.String("oauth_error", "other"))
	}
	return attrs
}

// BuiltinOIDCConfig holds configuration for OIDC under builtin auth mode.
type BuiltinOIDCConfig struct {
	Provider       *oidc.Provider
	Verifier       *oidc.IDTokenVerifier
	OAuth2Config   *oauth2.Config
	Provision      *oidcprovision.Service
	AuthService    *authservice.Service
	LicenseChecker license.Checker
	// InitialSetupComplete reports whether builtin administrator bootstrap has completed.
	InitialSetupComplete func(context.Context) (bool, error)
	LoginBasePath        string // Base path for login page redirect
	// PKCE makes the sign-in send an S256 code challenge and the callback
	// send its verifier (RFC 7636). Off by default.
	PKCE bool
	// Sessions keeps a session per signed-in user and revalidates it at the
	// provider. Nil, the default, means the hub token alone decides, as
	// before.
	Sessions *oidcsession.Manager
}

// InitBuiltinOIDCConfig initializes OIDC for builtin auth mode.
func InitBuiltinOIDCConfig(ctx context.Context, cfg config.AuthOIDC, authSvc *authservice.Service, provisionSvc *oidcprovision.Service, basePath string) (*BuiltinOIDCConfig, error) {
	result, err := initOIDCProviderCore(ctx, oidcProviderParams{
		Issuer:       cfg.Issuer,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		ClientURL:    cfg.ClientURL,
		Scopes:       cfg.Scopes,
	})
	if err != nil {
		return nil, err
	}

	loginBasePath := basePath
	if loginBasePath == "" {
		loginBasePath = "/"
	}
	if !strings.HasPrefix(loginBasePath, "/") {
		loginBasePath = "/" + loginBasePath
	}

	return &BuiltinOIDCConfig{
		Provider:     result.Provider,
		Verifier:     result.Verifier,
		OAuth2Config: result.OAuth2Config,
		Provision:    provisionSvc,
		AuthService:  authSvc,
		InitialSetupComplete: func(ctx context.Context) (bool, error) {
			count, err := authSvc.CountUsers(ctx)
			if err != nil {
				return false, err
			}
			return count > 0, nil
		},
		LoginBasePath: loginBasePath,
		PKCE:          cfg.PKCE,
	}, nil
}

// BuiltinOIDCLoginHandler returns a handler that initiates the OIDC login flow.
func BuiltinOIDCLoginHandler(cfg *BuiltinOIDCConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !allowOIDCAfterInitialSetup(w, r, cfg) {
			return
		}

		if cfg.LicenseChecker != nil && !cfg.LicenseChecker.IsFeatureEnabled(license.FeatureSSO) {
			redirectWithError(w, r, cfg.LoginBasePath, "SSO requires an active Dagu license")
			return
		}

		// A sign-in may ask the provider to show its sign-in page even
		// when the browser already has a session there, so a person can
		// switch accounts. Only the two prompts that do that are passed on.
		// The value sent is always one of these constants, never the
		// request's own text.
		var prompt string
		switch r.URL.Query().Get("prompt") {
		case "":
		case "login":
			prompt = "login"
		case "select_account":
			prompt = "select_account"
		default:
			redirectWithError(w, r, cfg.LoginBasePath, "unsupported sign-in prompt")
			return
		}

		state := stringutil.RandomString(16)
		nonce := stringutil.RandomString(16)

		setCookie(w, r, cookieState, state, stateCookieExpiry)
		setCookie(w, r, cookieNonce, nonce, stateCookieExpiry)
		setCookie(w, r, cookieOriginalURL, cfg.LoginBasePath, stateCookieExpiry)

		authOptions := []oauth2.AuthCodeOption{oidc.Nonce(nonce)}
		if cfg.PKCE {
			// The verifier stays in this browser; only its S256 digest goes
			// to the provider with the sign-in request.
			verifier := oauth2.GenerateVerifier()
			setCookie(w, r, cookiePKCEVerifier, verifier, stateCookieExpiry)
			authOptions = append(authOptions, oauth2.S256ChallengeOption(verifier))
		}
		if prompt != "" {
			authOptions = append(authOptions, oauth2.SetAuthURLParam("prompt", prompt))
		}

		http.Redirect(w, r, cfg.OAuth2Config.AuthCodeURL(state, authOptions...), http.StatusFound)
	}
}

// BuiltinOIDCCallbackHandler returns a handler that processes the OIDC callback.
// It uses the provisioning service to create/lookup users and generates JWT tokens.
func BuiltinOIDCCallbackHandler(cfg *BuiltinOIDCConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// With PKCE on, take this browser's verifier and clear its cookie
		// now, before anything is written, so that every way out of the
		// callback clears it. With PKCE off the response is as it always was.
		var pkceVerifier string
		if cfg.PKCE {
			if verifierCookie, err := r.Cookie(cookiePKCEVerifier); err == nil {
				pkceVerifier = verifierCookie.Value
			}
			clearCookie(w, r, cookiePKCEVerifier)
		}

		if !allowOIDCAfterInitialSetup(w, r, cfg) {
			return
		}

		if cfg.LicenseChecker != nil && !cfg.LicenseChecker.IsFeatureEnabled(license.FeatureSSO) {
			redirectWithError(w, r, cfg.LoginBasePath, "SSO requires an active Dagu license")
			return
		}

		// Verify state
		stateCookie, err := r.Cookie(cookieState)
		if err != nil {
			redirectWithError(w, r, cfg.LoginBasePath, "Authentication failed: state not found")
			return
		}
		if r.URL.Query().Get("state") != stateCookie.Value {
			redirectWithError(w, r, cfg.LoginBasePath, "Authentication failed: state mismatch")
			return
		}

		// Check for error from OIDC provider
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			errDesc := r.URL.Query().Get("error_description")
			if errDesc == "" {
				errDesc = errParam
			}
			redirectWithError(w, r, cfg.LoginBasePath, "Authentication failed: "+errDesc)
			return
		}

		// With PKCE the exchange must carry the verifier this browser was
		// given at sign-in. Without it the callback is refused here, before
		// the code is sent anywhere.
		var exchangeOptions []oauth2.AuthCodeOption
		if cfg.PKCE {
			if !validPKCEVerifier(pkceVerifier) {
				redirectWithError(w, r, cfg.LoginBasePath, "Authentication failed: PKCE verifier not found")
				return
			}
			exchangeOptions = append(exchangeOptions, oauth2.VerifierOption(pkceVerifier))
		}

		// Exchange code for token
		oauth2Token, err := cfg.OAuth2Config.Exchange(ctx, r.URL.Query().Get("code"), exchangeOptions...)
		if err != nil {
			if cfg.PKCE {
				logger.Error(ctx, "OIDC token exchange failed", tokenExchangeFailure(err)...)
			} else {
				logger.Error(ctx, "OIDC token exchange failed", tag.Error(err))
			}
			redirectWithError(w, r, cfg.LoginBasePath, "Authentication failed: could not exchange token")
			return
		}

		// Get raw ID token
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			redirectWithError(w, r, cfg.LoginBasePath, "Authentication failed: no ID token")
			return
		}

		// Verify ID token
		idToken, err := cfg.Verifier.Verify(ctx, rawIDToken)
		if err != nil {
			logger.Error(ctx, "OIDC token verification failed", tag.Error(err))
			redirectWithError(w, r, cfg.LoginBasePath, "Authentication failed: invalid token")
			return
		}

		// Verify nonce
		nonceCookie, err := r.Cookie(cookieNonce)
		if err != nil {
			redirectWithError(w, r, cfg.LoginBasePath, "Authentication failed: nonce not found")
			return
		}
		if idToken.Nonce != nonceCookie.Value {
			redirectWithError(w, r, cfg.LoginBasePath, "Authentication failed: nonce mismatch")
			return
		}

		// Extract typed claims
		var claims oidcprovision.OIDCClaims
		if err := idToken.Claims(&claims); err != nil {
			logger.Error(ctx, "Failed to extract OIDC claims", tag.Error(err))
			redirectWithError(w, r, cfg.LoginBasePath, "Authentication failed: could not read user info")
			return
		}

		// Extract raw claims for role mapping
		var rawClaims map[string]any
		if err := idToken.Claims(&rawClaims); err != nil {
			logger.Error(ctx, "Failed to extract raw OIDC claims", tag.Error(err))
			redirectWithError(w, r, cfg.LoginBasePath, "Authentication failed: could not read user info")
			return
		}
		claims.RawClaims = rawClaims

		// Get userinfo for email (may not be in ID token)
		userInfo, err := cfg.Provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
		if err != nil {
			logger.Warn(ctx, "Failed to get userinfo, using ID token claims", tag.Error(err))
			// Continue with ID token claims if userinfo fails
		} else {
			// Prefer userinfo email
			if userInfo.Email != "" {
				claims.Email = userInfo.Email
			}
			// Merge userinfo claims into raw claims for role mapping
			var userInfoClaims map[string]any
			if err := userInfo.Claims(&userInfoClaims); err == nil {
				for k, v := range userInfoClaims {
					if _, exists := claims.RawClaims[k]; !exists {
						claims.RawClaims[k] = v
					}
				}
			}
		}

		// Process login (create/lookup user)
		user, isNewUser, err := cfg.Provision.ProcessLogin(ctx, claims)
		if err != nil {
			logger.Warn(ctx, "OIDC provisioning failed",
				slog.String("email_domain", stringutil.ExtractEmailDomain(claims.Email)),
				slog.String("subject", claims.Subject),
				tag.Error(err))
			redirectWithError(w, r, cfg.LoginBasePath, err.Error())
			return
		}

		// Generate JWT token
		tokenResult, err := issueHubToken(ctx, cfg, user, oauth2Token.RefreshToken)
		if err != nil {
			logger.Error(ctx, "Failed to generate JWT token", tag.Error(err))
			redirectWithError(w, r, cfg.LoginBasePath, "Authentication failed: could not create session")
			return
		}

		// Clear OIDC cookies
		clearOIDCStateCookies(w, r)

		// Redirect to login page with token in the URL hash fragment.
		// Hash fragments are never sent to the server, so the JWT does not appear
		// in server access logs, reverse-proxy logs, or Referer headers.
		redirectURL := strings.TrimSuffix(cfg.LoginBasePath, "/") + "/login"
		if isNewUser {
			redirectURL += "?welcome=true"
		}
		redirectURL += "#token=" + url.QueryEscape(tokenResult.Token)
		http.Redirect(w, r, redirectURL, http.StatusFound)
	}
}

// issueHubToken issues the hub token for a user who has just signed in. With
// sessions on, it first starts the session the token will be tied to, from
// the provider's refresh token; if the provider gave none, the sign-in fails,
// because such a session could never be revalidated.
func issueHubToken(ctx context.Context, cfg *BuiltinOIDCConfig, user *authmodel.User, refreshToken string) (*authservice.TokenResult, error) {
	if cfg.Sessions == nil {
		return cfg.AuthService.GenerateToken(user)
	}
	expiresAt := time.Now().Add(cfg.AuthService.TokenTTL())
	session, err := cfg.Sessions.Create(ctx, oidcSessionIdentity(user), refreshToken, expiresAt)
	if err != nil {
		return nil, err
	}
	tokenResult, err := cfg.AuthService.GenerateSessionToken(user, session.ID, expiresAt)
	if err != nil {
		// A session nobody holds a token for is ended, not left behind.
		_ = cfg.Sessions.End(ctx, session.ID, "the hub token could not be issued", expiresAt)
		return nil, err
	}
	return tokenResult, nil
}

func allowOIDCAfterInitialSetup(w http.ResponseWriter, r *http.Request, cfg *BuiltinOIDCConfig) bool {
	if cfg.InitialSetupComplete == nil {
		logger.Error(r.Context(), "Initial setup check is not configured for OIDC login")
	} else {
		complete, err := cfg.InitialSetupComplete(r.Context())
		if err != nil {
			logger.Error(r.Context(), "Failed to check initial setup before OIDC login", tag.Error(err))
		} else if complete {
			return true
		}
	}

	clearOIDCStateCookies(w, r)
	setupURL := strings.TrimSuffix(cfg.LoginBasePath, "/") + "/setup"
	http.Redirect(w, r, setupURL, http.StatusFound)
	return false
}

// redirectWithError redirects to the login page with an error message.
func redirectWithError(w http.ResponseWriter, r *http.Request, basePath, errMsg string) {
	clearOIDCStateCookies(w, r)

	redirectURL := strings.TrimSuffix(basePath, "/") + "/login?error=" + url.QueryEscape(errMsg)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}
