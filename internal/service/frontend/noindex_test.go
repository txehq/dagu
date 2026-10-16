// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package frontend

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoindexMiddleware_TagsEveryResponse(t *testing.T) {
	handlers := map[string]http.HandlerFunc{
		"ok":       func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) },
		"error":    func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "boom", http.StatusInternalServerError) },
		"refusal":  func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) },
		"redirect": func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/login", http.StatusFound) },
	}
	for name, h := range handlers {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			noindexMiddleware(h).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
			assert.Equal(t, "noindex, nofollow, noarchive", rec.Result().Header.Get("X-Robots-Tag"))
		})
	}
}

func TestServeRobotsTxt(t *testing.T) {
	rec := httptest.NewRecorder()
	serveRobotsTxt(rec, httptest.NewRequest(http.MethodGet, "/robots.txt", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/plain; charset=utf-8", rec.Header().Get("Content-Type"))
	assert.Equal(t, "User-agent: *\nDisallow: /\n", rec.Body.String())
}
