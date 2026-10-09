// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	"github.com/dagucloud/dagu/v2/internal/txe/review"
)

// The reviewer hands the transport a path with its query attached; the hub
// client takes them apart, and a refusal comes back with the registry's own
// code so the reviewer can act on it.
func TestTXEReviewTransport(t *testing.T) {
	var gotPath, gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		if r.URL.Path == "/api/v1/txe/jobs/job_A/claims" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": "conflict", "message": "held by another reviewer", "details": map[string]any{"code": "claim_held"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jobs": []any{}})
	}))
	t.Cleanup(srv.Close)
	transport := txeReviewTransport{client: txeclient.New(srv.URL+"/api/v1", "dagu_test", srv.Client())}

	var out struct {
		Jobs []any `json:"jobs"`
	}
	require.NoError(t, transport.Do(context.Background(), http.MethodGet, "/txe/jobs?machine=mch_A&review_due_before=2026-10-09T00%3A00%3A00Z", nil, &out))
	assert.Equal(t, "/api/v1/txe/jobs", gotPath)
	assert.Contains(t, gotQuery, "machine=mch_A")
	assert.Contains(t, gotQuery, "review_due_before=2026-10-09T00%3A00%3A00Z")

	err := transport.Do(context.Background(), http.MethodPost, "/txe/jobs/job_A/claims", map[string]string{"kind": "review"}, nil)
	var refused *review.TransportError
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, http.StatusConflict, refused.Status)
	assert.Equal(t, "claim_held", refused.Code)
}

func TestTXEReviewCommandIsRegistered(t *testing.T) {
	names := map[string]bool{}
	for _, sub := range TXE().Commands() {
		names[sub.Name()] = true
	}
	require.True(t, names["review"])
	steps := map[string]bool{}
	for _, sub := range txeReviewCommand().Commands() {
		steps[sub.Name()] = true
	}
	assert.Equal(t, map[string]bool{"prepare": true, "apply": true, "execute": true, "render": true}, steps)
}
