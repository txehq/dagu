// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package transportauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// TokenSource gives the credential a caller presents on its next call.
type TokenSource interface {
	// Token returns a credential that is valid now. It returns ErrRevoked
	// when the provider has refused the machine for good, and
	// ErrProviderUnavailable when it could not be asked and no unexpired
	// credential is held.
	Token(ctx context.Context) (string, error)
}

// StaticHubKey is the hub's own key as a TokenSource.
type StaticHubKey []byte

// Token implements TokenSource.
func (k StaticHubKey) Token(context.Context) (string, error) { return string(k), nil }

// String hides the key.
func (k StaticHubKey) String() string { return "transportauth.StaticHubKey{redacted}" }

// GoString hides the key.
func (k StaticHubKey) GoString() string { return k.String() }

// Format prints String for every verb, so no verb prints the key.
func (k StaticHubKey) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, k.String()) }

// LogValue keeps the key out of structured logs.
func (k StaticHubKey) LogValue() slog.Value { return slog.StringValue(k.String()) }

// PerRPC sends a TokenSource's credential on every call. It implements
// credentials.PerRPCCredentials.
type PerRPC struct {
	source TokenSource
	scheme string
}

// Format prints the scheme and nothing of the credential, for every verb.
func (p PerRPC) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "transportauth.PerRPC{scheme %s}", p.scheme)
}

// NewWorkerCredentials sends a worker machine's provider access token.
func NewWorkerCredentials(source TokenSource) *PerRPC {
	return &PerRPC{source: source, scheme: BearerScheme}
}

// NewHubCredentials sends the hub's own key.
func NewHubCredentials(key []byte) *PerRPC {
	return &PerRPC{source: StaticHubKey(append([]byte(nil), key...)), scheme: HubScheme}
}

// GetRequestMetadata implements credentials.PerRPCCredentials.
//
// On a connection without transport security the credential is sent only to
// a loopback address, which is how a worker reaches the hub through its
// port-forward tunnel. Anywhere else it is refused before anything is sent.
func (p *PerRPC) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	if !secureConnection(ctx) && !allLoopback(uri) {
		return nil, status.Error(codes.Unauthenticated,
			"transportauth: a credential is sent without transport security only to a loopback address")
	}
	token, err := p.source.Token(ctx)
	switch {
	case err == nil:
	case errors.Is(err, ErrRevoked):
		return nil, status.Error(codes.Unauthenticated, err.Error())
	case errors.Is(err, ErrProviderUnavailable):
		return nil, status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return nil, status.FromContextError(err).Err()
	default:
		return nil, status.Error(codes.Unauthenticated, err.Error())
	}
	return map[string]string{AuthorizationHeader: p.scheme + " " + token}, nil
}

// RequireTransportSecurity implements credentials.PerRPCCredentials. It is
// false so that a worker can use its loopback tunnel; GetRequestMetadata
// refuses every other connection that has no transport security.
func (p *PerRPC) RequireTransportSecurity() bool { return false }

func secureConnection(ctx context.Context) bool {
	info, ok := credentials.RequestInfoFromContext(ctx)
	if !ok || info.AuthInfo == nil {
		return false
	}
	carrier, ok := info.AuthInfo.(interface {
		GetCommonAuthInfo() credentials.CommonAuthInfo
	})
	return ok && carrier.GetCommonAuthInfo().SecurityLevel == credentials.PrivacyAndIntegrity
}

// allLoopback reports whether every uri names a loopback host. No uri at all
// is not loopback.
func allLoopback(uris []string) bool {
	if len(uris) == 0 {
		return false
	}
	for _, raw := range uris {
		if !isLoopback(raw) {
			return false
		}
	}
	return true
}

// IsLoopbackHost reports whether an address, a host, or a URL names this
// machine's loopback interface: a loopback IP or "localhost". A host name that
// merely resolves to loopback does not count.
func IsLoopbackHost(raw string) bool { return isLoopback(raw) }

func isLoopback(raw string) bool {
	host := raw
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		host = parsed.Hostname()
	} else if h, _, err := net.SplitHostPort(raw); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
