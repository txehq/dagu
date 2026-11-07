// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package spec

import "context"

type schemaReferencesRefusedKey struct{}

// WithoutSchemaReferences marks ctx so that a spec loaded under it leaves
// every params.schema reference unread, as SkipSchemaValidation does: no
// file is read and no URL is fetched for it. Resolving a reference reads the
// loading process's host, so the hub marks the context of every request whose
// caller may not read the hub's own files; every load in that request, by
// any path, then reads none (TXE-5923).
func WithoutSchemaReferences(ctx context.Context) context.Context {
	return context.WithValue(ctx, schemaReferencesRefusedKey{}, true)
}

// schemaReferencesRefused reports whether ctx was marked by
// WithoutSchemaReferences.
func schemaReferencesRefused(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	refused, _ := ctx.Value(schemaReferencesRefusedKey{}).(bool)
	return refused
}
