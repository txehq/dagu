// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"net/http"

	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// TxePlatformAdminSession makes a person the configuration names in
// txe.authz.platform_admins the installation's administrator for this request
// only. It runs after authentication, so a revoked or expired session never
// reaches it.
//
// The match is the account's stored issuer and subject against the list,
// exactly. A provider token (the command line) and an API key are never
// matched, whoever they belong to. The elevation lives in this request's
// context alone: the account keeps the role it was provisioned with in the
// user store, nothing is written, and the next request is decided again from
// the configuration.
func (a *API) TxePlatformAdminSession(next http.Handler) http.Handler {
	if a == nil || len(a.txePlatformAdmins) == 0 {
		return next
	}
	listed := make(map[authn.Identity]bool, len(a.txePlatformAdmins))
	for _, p := range a.txePlatformAdmins {
		listed[authn.Identity{Issuer: p.Issuer, Subject: p.Subject}] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if _, token := txeauth.Token(ctx); token {
			next.ServeHTTP(w, r)
			return
		}
		if _, apiKey := auth.APIKeyFromContext(ctx); apiKey {
			next.ServeHTTP(w, r)
			return
		}
		user, ok := auth.UserFromContext(ctx)
		if !ok || user == nil || user.AuthProvider != auth.AuthProviderOIDC || user.OIDCIssuer == "" || user.OIDCSubject == "" {
			next.ServeHTTP(w, r)
			return
		}
		id := authn.Identity{Issuer: user.OIDCIssuer, Subject: user.OIDCSubject}
		if !listed[id] {
			next.ServeHTTP(w, r)
			return
		}
		// A copy: the user the store returned is never changed.
		admin := *user
		admin.Role = auth.RoleAdmin
		admin.WorkspaceAccess = auth.AllWorkspaceAccess()
		ctx = txeauth.WithPlatformAdminSession(auth.WithUser(ctx, &admin), id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// WithTxePlatformAdmins sets the people TxePlatformAdminSession makes the
// administrator, in place of the configuration's txe.authz.platform_admins.
func WithTxePlatformAdmins(admins []config.TXEPlatformAdmin) APIOption {
	return func(a *API) { a.txePlatformAdmins = admins }
}
