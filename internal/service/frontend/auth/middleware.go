// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	authservice "github.com/dagucloud/dagu/v2/internal/service/auth"
	"github.com/dagucloud/dagu/v2/internal/service/frontend/api/pathutil"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// rawRemoteAddrKey is the context key for the unmodified remote address.
type rawRemoteAddrKey struct{}

// PreserveRawRemoteAddr stores r.RemoteAddr in the request context before any
// later middleware can overwrite it. It must be registered first in the
// middleware chain so that LoginRateLimitMiddleware can derive the rate-limit
// key from the true TCP source address rather than an attacker-controlled
// forwarded header.
func PreserveRawRemoteAddr(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), rawRemoteAddrKey{}, r.RemoteAddr)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Options configures the authentication middleware.
type Options struct {
	Realm            string
	BasicAuthEnabled bool
	Creds            map[string]string
	PublicPaths      []string
	// PublicPathPrefixes are path prefixes that bypass authentication.
	// Any path starting with one of these prefixes will be allowed without auth.
	PublicPathPrefixes []string
	// JWTValidator validates JWT tokens for builtin auth mode.
	// When set, JWT Bearer tokens are accepted as an authentication method.
	JWTValidator TokenValidator
	// APIKeyValidator validates API keys with roles.
	// When set, API keys with the "dagu_" prefix are accepted as an authentication method.
	APIKeyValidator APIKeyValidator
	// RequiredAPIKeySurface, when set, requires API keys to include this surface.
	RequiredAPIKeySurface auth.APIKeySurface
	// ProviderTokens, when set, accepts an identity provider access token as
	// a bearer credential. Such a request carries no hub user, role or
	// workspace access: only its verified principal.
	ProviderTokens ProviderTokenVerifier
	// ProviderTokenRoute says which requests may be made with a provider
	// token. Any other request that carries one is refused with 403, so a
	// route that has not been made owner-aware never sees such a caller.
	// Nil admits none.
	ProviderTokenRoute func(r *http.Request) bool
	// OnDenied is called when the middleware rejects a request after auth evaluation.
	OnDenied func(r *http.Request, reason string, apiKey *auth.APIKey)
	// AuthRequired indicates whether authentication is required.
	// When false (e.g., auth mode "none"), credentials are validated if provided
	// but unauthenticated requests are allowed through.
	AuthRequired bool
}

// Authenticates reports whether a route with these options has anything to
// authenticate a request with. When it has not, Middleware lets every request
// through, whatever AuthRequired says. A handler behind the middleware that
// has to know whether its callers were authenticated asks this, so that it
// and the middleware cannot disagree.
func (o Options) Authenticates() bool {
	return o.BasicAuthEnabled || o.JWTValidator != nil || o.APIKeyValidator != nil || o.ProviderTokens != nil
}

// ProviderTokenVerifier verifies an identity provider access token.
type ProviderTokenVerifier interface {
	Verify(ctx context.Context, token string) (authn.Principal, error)
}

const (
	// DenialReasonProviderTokenRoute is a provider token on a route that
	// does not accept one.
	DenialReasonProviderTokenRoute = "provider_token_route"
	// DenialReasonProviderUnavailable is a provider token that could not be
	// verified because the provider's keys could not be fetched.
	DenialReasonProviderUnavailable = "provider_unavailable"
	DenialReasonAPIKeySurfaceDenied = "api_key_surface_denied"
	DenialReasonAuthFailed          = "auth_failed"
	DenialReasonMissingCredentials  = "missing_credentials"
)

// QueryTokenMiddleware converts a "token" query parameter into an Authorization
// Bearer header. This bridges browser APIs that cannot set custom headers
// (EventSource, WebSocket) with the standard auth middleware.
// If an Authorization header is already present, the query parameter is ignored.
func QueryTokenMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				next.ServeHTTP(w, r)
				return
			}

			token := r.URL.Query().Get("token")
			if token != "" {
				r2 := r.Clone(r.Context())
				r2.Header.Set("Authorization", "Bearer "+token)
				next.ServeHTTP(w, r2)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ClientIPMiddleware creates an HTTP middleware that adds the client IP to the request context.
// This should be applied before authentication middleware to ensure IP is available for audit logging.
func ClientIPMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := auth.WithClientIP(r.Context(), GetClientIP(r))
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Middleware creates an HTTP middleware for authentication.
// It supports multiple authentication methods simultaneously:
// - JWT Bearer tokens (if JWTValidator is set)
// - API keys with "dagu_" prefix (if APIKeyValidator is set)
// - HTTP Basic Auth (if BasicAuthEnabled)
// All configured methods work at the same time.
func Middleware(opts Options) func(next http.Handler) http.Handler {
	publicPaths := make(map[string]struct{}, len(opts.PublicPaths))
	for _, p := range opts.PublicPaths {
		publicPaths[pathutil.NormalizePath(p)] = struct{}{}
	}

	// Process public path prefixes - ensure they have leading slash but preserve trailing slash
	// The trailing slash is important for prefixes: "/api/v1/webhooks/" should only match
	// paths like "/api/v1/webhooks/foo", not "/api/v1/webhooks" itself
	publicPrefixes := make([]string, 0, len(opts.PublicPathPrefixes))
	for _, p := range opts.PublicPathPrefixes {
		if p == "" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		publicPrefixes = append(publicPrefixes, p)
	}

	jwtEnabled := opts.JWTValidator != nil
	apiKeyEnabled := opts.APIKeyValidator != nil
	providerEnabled := opts.ProviderTokens != nil
	anyAuthEnabled := opts.Authenticates()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			normalizedPath := pathutil.NormalizePath(r.URL.Path)

			// Allow unauthenticated access to explicitly configured public paths.
			if _, ok := publicPaths[normalizedPath]; ok {
				next.ServeHTTP(w, r)
				return
			}

			// Allow unauthenticated access to paths matching public prefixes.
			for _, prefix := range publicPrefixes {
				if strings.HasPrefix(normalizedPath, prefix) {
					next.ServeHTTP(w, r)
					return
				}
			}

			// If no auth is enabled, skip authentication
			if !anyAuthEnabled {
				next.ServeHTTP(w, r)
				return
			}

			// Extract bearer token once for both JWT and API key checks
			var bearerToken string
			if jwtEnabled || apiKeyEnabled || providerEnabled {
				bearerToken = extractBearerToken(r)
			}
			denialReason := DenialReasonMissingCredentials
			if bearerToken != "" {
				denialReason = DenialReasonAuthFailed
			}

			// Try JWT token authentication if enabled (for builtin auth mode)
			if jwtEnabled && bearerToken != "" {
				user, err := opts.JWTValidator.GetUserFromToken(r.Context(), bearerToken)
				if err == nil {
					ctx := auth.WithUser(r.Context(), user)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				if errors.Is(err, authservice.ErrSessionCheckUnavailable) {
					// The token is not known to be bad. Answering 401 would
					// sign the user out for an outage of the provider or of
					// the session store.
					WriteSessionCheckUnavailable(w)
					return
				}
				// JWT validation failed, continue to try other methods
			}

			// Try API key authentication if enabled
			// API keys have the "dagu_" prefix and have their own role assignment
			if apiKeyEnabled && bearerToken != "" && strings.HasPrefix(bearerToken, "dagu_") {
				apiKey, err := opts.APIKeyValidator.ValidateAPIKey(r.Context(), bearerToken)
				if err == nil {
					apiKey = auth.NormalizeAPIKeyMetadata(apiKey)
					if opts.RequiredAPIKeySurface != "" && !auth.HasAPIKeySurface(apiKey.AllowedSurfaces, opts.RequiredAPIKeySurface) {
						callDenied(opts, r, DenialReasonAPIKeySurfaceDenied, apiKey)
						http.Error(w, "API key is not allowed for this surface", http.StatusForbidden)
						return
					}
					syntheticUser := &auth.User{
						ID:              "apikey:" + apiKey.ID,
						Username:        "apikey:" + apiKey.Name,
						Role:            apiKey.Role,
						WorkspaceAccess: auth.CloneWorkspaceAccess(apiKey.WorkspaceAccess),
					}
					ctx := auth.WithAPIKey(auth.WithUser(r.Context(), syntheticUser), apiKey)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				// API key validation failed, continue to try other methods
			}

			// Try an identity provider access token if enabled. It is tried
			// last among bearer credentials, so a hub token or an API key is
			// never sent to it.
			if providerEnabled && bearerToken != "" && !strings.HasPrefix(bearerToken, "dagu_") {
				principal, err := opts.ProviderTokens.Verify(r.Context(), bearerToken)
				if err != nil {
					// The refusal's category only: never the token, its
					// claims or the identity it names. A key the issuer no
					// longer publishes is told apart from one it never did
					// (TXE-4347), for unknown_key only: it means nothing for
					// any other reason.
					reason := authn.ReasonOf(err)
					attrs := []slog.Attr{slog.String("reason", string(reason))}
					if reason == authn.ReasonUnknownKey {
						attrs = append(attrs, slog.Bool("retired_key_of_issuer", authn.UnpublishedKeyOfIssuer(err)))
					}
					logger.Debug(r.Context(), "Provider token refused", attrs...)
				}
				switch {
				case err == nil:
					if opts.ProviderTokenRoute == nil || !opts.ProviderTokenRoute(r) {
						callDenied(opts, r, DenialReasonProviderTokenRoute, nil)
						writeProviderTokenRouteRefused(w)
						return
					}
					next.ServeHTTP(w, r.WithContext(txeauth.WithToken(r.Context(), principal)))
					return
				case authn.ProviderUnavailable(err):
					// The token was not judged. Answering 401 would tell the
					// caller to sign in again for an outage of the provider.
					callDenied(opts, r, DenialReasonProviderUnavailable, nil)
					writeProviderUnavailable(w)
					return
				case providerMeantToken(err):
					// A token the provider issued and this server refuses:
					// expired, too long-lived, for another audience or
					// client. The caller has to obtain a new one.
					callDenied(opts, r, DenialReasonAuthFailed, nil)
					requireBearerAuthInvalidToken(w, opts.Realm)
					return
				}
				// Not a provider token at all; fall through.
			}

			// Try Basic Auth if enabled
			if opts.BasicAuthEnabled {
				if user, pass, ok := r.BasicAuth(); ok {
					// Credentials were provided - must validate
					if checkBasicAuth(user, pass, opts.Creds) {
						basicUser := &auth.User{
							ID:              user,
							Username:        user,
							Role:            auth.RoleAdmin,
							WorkspaceAccess: auth.AllWorkspaceAccess(),
						}
						ctx := auth.WithUser(r.Context(), basicUser)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
					// Invalid credentials - always reject
					callDenied(opts, r, DenialReasonAuthFailed, nil)
					requireBasicAuth(w, opts.Realm)
					return
				}
			}

			// No credentials provided
			// If auth is not required (e.g., mode "none"), allow the request through
			if !opts.AuthRequired {
				next.ServeHTTP(w, r)
				return
			}

			// Auth is required - send appropriate challenge
			if opts.BasicAuthEnabled {
				callDenied(opts, r, denialReason, nil)
				requireBasicAuth(w, opts.Realm)
				return
			}

			callDenied(opts, r, denialReason, nil)
			requireBearerAuth(w, opts.Realm)
		})
	}
}

// sessionCheckRetryAfterSeconds is how soon a client is told to try again
// when its session could not be confirmed.
const sessionCheckRetryAfterSeconds = "5"

// WriteSessionCheckUnavailable answers a request whose OIDC session could
// not be confirmed, because the identity provider did not answer or the
// session could not be read: 503 with a Retry-After, and never a 401.
func WriteSessionCheckUnavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", sessionCheckRetryAfterSeconds)
	http.Error(w, "The session could not be confirmed with the identity provider. Try again shortly.", http.StatusServiceUnavailable)
}

func callDenied(opts Options, r *http.Request, reason string, apiKey *auth.APIKey) {
	if opts.OnDenied != nil {
		opts.OnDenied(r, reason, apiKey)
	}
}

// checkBasicAuth validates the username and password.
func checkBasicAuth(user, pass string, validCreds map[string]string) bool {
	credPass, credUserOk := validCreds[user]
	if !credUserOk {
		return false
	}

	// Use constant time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(pass), []byte(credPass)) == 1
}

// requireBasicAuth sends a 401 response with Basic auth challenge.
func requireBasicAuth(w http.ResponseWriter, realm string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
	w.WriteHeader(http.StatusUnauthorized)
}

// providerMeantToken reports whether a refused token was one the identity
// provider issued: a signed token of the configured issuer, refused for what
// it says, or one naming the configured issuer on a key the issuer no longer
// publishes, so that the caller renews it. A token that is not one at all, or
// names another issuer, is left to the other methods.
func providerMeantToken(err error) bool {
	switch authn.ReasonOf(err) {
	case authn.ReasonUnknownKey:
		return authn.UnpublishedKeyOfIssuer(err)
	case authn.ReasonMalformed, authn.ReasonIssuer, authn.ReasonAlgorithm:
		return false
	case authn.ReasonSignature, authn.ReasonTokenType, authn.ReasonAudience, authn.ReasonClient, authn.ReasonSubject,
		authn.ReasonTimes, authn.ReasonLifetime, authn.ReasonNotYetValid, authn.ReasonExpired:
		return true
	case authn.ReasonKeysUnavailable:
		// Handled before this is asked.
		return false
	default:
		return false
	}
}

// providerUnavailableRetryAfterSeconds is how soon a client is told to try
// again when the provider's keys could not be fetched.
const providerUnavailableRetryAfterSeconds = "30"

func writeProviderUnavailable(w http.ResponseWriter) {
	w.Header().Set("Retry-After", providerUnavailableRetryAfterSeconds)
	writeJSONError(w, http.StatusServiceUnavailable, "service_unavailable", "provider_unavailable",
		"The identity provider did not answer, so the token could not be verified. Try again shortly.")
}

func writeProviderTokenRouteRefused(w http.ResponseWriter) {
	writeJSONError(w, http.StatusForbidden, "forbidden", "forbidden",
		"This route does not accept an identity provider token.")
}

// requireBearerAuthInvalidToken sends a 401 that tells the caller its token
// was refused and a new one is needed.
func requireBearerAuthInvalidToken(w http.ResponseWriter, realm string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s", error="invalid_token"`, realm))
	writeJSONError(w, http.StatusUnauthorized, "unauthorized", "invalid_token", "The token was refused. Sign in again.")
}

// writeJSONError writes the API's error shape, with the reason in
// details.code.
func writeJSONError(w http.ResponseWriter, status int, code, detail, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": code, "message": message, "details": map[string]string{"code": detail}})
}

// requireBearerAuth sends a 401 response with Bearer auth challenge.
func requireBearerAuth(w http.ResponseWriter, realm string) {
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s"`, realm))
	w.WriteHeader(http.StatusUnauthorized)
}

// GetClientIP extracts the client IP address from the request.
// It checks X-Forwarded-For and X-Real-IP headers for proxied requests.
// Port suffixes (e.g. from HAProxy source-port annotation) are stripped so
// that all connections from the same client IP share one rate-limit bucket.
func GetClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		raw := xff
		if before, _, ok := strings.Cut(xff, ","); ok {
			raw = before
		}
		return stripPort(strings.TrimSpace(raw))
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return stripPort(strings.TrimSpace(xri))
	}

	// Fall back to RemoteAddr - use net.SplitHostPort for proper IPv6 handling
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// Return as-is if parsing fails (e.g., no port present)
		return r.RemoteAddr
	}
	return host
}

// stripPort removes a trailing ":port" from an IP string.
// It handles bare IPv4 ("1.2.3.4:1234"), bracketed IPv6 ("[::1]:1234"),
// and plain addresses without a port.
func stripPort(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr // no port present; return unchanged
	}
	return host
}
