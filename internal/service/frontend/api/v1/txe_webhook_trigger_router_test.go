// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// Under enforce a webhook trigger of a DAG named as an owner's is answered
// before any token is checked, exactly as a webhook that does not exist is:
// whatever the request presents, it gets the same answer as an ownerless
// DAG with no webhook, so nothing tells whether that DAG or a webhook of it
// exists, and no token of it is marked used (TXE-4762). A job's DAG that does
// not exist answers the same.
func TestTxeWebhookTriggerOfAnOwnersDAGIsRefusedBeforeItsToken(t *testing.T) {
	h := newSuspendHub(t)
	owned := h.reviewerA
	h.server.CreateDAGFile(t, h.server.Config.Paths.DAGsDir, "plain", []byte("steps:\n  - name: s\n    run: echo s\n"))

	trigger := func(name, bearer string) (int, string) {
		t.Helper()
		req := h.server.Client().Post("/api/v1/webhooks/"+name, map[string]any{})
		if bearer != "" {
			req = req.WithBearerToken(bearer)
		}
		resp := req.Send(t)
		return resp.Response.StatusCode(), resp.Body
	}
	for _, bearer := range []string{"wrong-token", ""} {
		plainStatus, plainBody := trigger("plain", bearer)
		require.Equal(t, http.StatusUnauthorized, plainStatus, "an ownerless DAG with no webhook")
		for _, name := range []string{owned, "job_01M4ZZZZZZZZZZZZZZZZZZZZZZ"} {
			status, body := trigger(name, bearer)
			require.Equal(t, plainStatus, status, name)
			require.JSONEq(t, plainBody, body, name)
		}
	}
}
