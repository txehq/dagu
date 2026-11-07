// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package remotenode

import (
	"context"
	"errors"
	"net/http"
)

// SelectorParam is the query parameter that sends a request to a remote node.
const SelectorParam = "remoteNode"

var (
	// ErrAmbiguousSelection refuses a request that names a remote node more
	// than once: the local decision and the proxy must read the same one.
	ErrAmbiguousSelection = errors.New("the remote node is named more than once")
	// ErrUseNotAuthorized refuses to send a remote node's credential for a
	// request the local decision did not allow (TXE-5923).
	ErrUseNotAuthorized = errors.New("a remote node's credential is sent only after the local decision allows the request")
)

// Selected reads which node a request is for. It is the one reading the
// local decision and every proxy share. Absent, empty or "local" is this
// server; any other single value is a remote node; more than one value is
// refused.
func Selected(r *http.Request) (name string, remote bool, err error) {
	values, ok := r.URL.Query()[SelectorParam]
	if !ok {
		return "", false, nil
	}
	if len(values) > 1 {
		return "", false, ErrAmbiguousSelection
	}
	switch values[0] {
	case "", "local":
		return "", false, nil
	default:
		return values[0], true, nil
	}
}

type useAuthorizedKey struct{}

// WithUseAuthorized marks ctx as allowed by the local decision to use a
// remote node's credential. Only that decision calls it.
func WithUseAuthorized(ctx context.Context) context.Context {
	return context.WithValue(ctx, useAuthorizedKey{}, true)
}

// UseAuthorized reports whether the local decision allowed ctx to use a
// remote node's credential.
func UseAuthorized(ctx context.Context) bool {
	ok, _ := ctx.Value(useAuthorizedKey{}).(bool)
	return ok
}
