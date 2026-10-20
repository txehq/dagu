// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// Under enforce a webhook trigger of an owner's DAG is answered as a webhook
// that does not exist before any token is checked, so a wrong token and none
// get the same 404 as any other request, never the webhook check's 401, and
// nothing of the webhook is read or marked used (TXE-4762). An ownerless
// DAG is still authenticated first.
func TestTxeWebhookTriggerOfAnOwnersDAGIsRefusedBeforeItsToken(t *testing.T) {
	h := newSuspendHub(t)
	owned := h.reviewerA
	h.server.CreateDAGFile(t, h.server.Config.Paths.DAGsDir, "plain", []byte("steps:\n  - name: s\n    run: echo s\n"))

	trigger := func(name, bearer string) int {
		t.Helper()
		req := h.server.Client().Post("/api/v1/webhooks/"+name, map[string]any{})
		if bearer != "" {
			req = req.WithBearerToken(bearer)
		}
		return req.Send(t).Response.StatusCode()
	}
	require.Equal(t, http.StatusNotFound, trigger(owned, "wrong-token"), "a wrong token")
	require.Equal(t, http.StatusNotFound, trigger(owned, ""), "no token")
	require.Equal(t, http.StatusUnauthorized, trigger("plain", "wrong-token"), "an ownerless DAG is authenticated first")
}
