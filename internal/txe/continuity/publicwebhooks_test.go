// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/persis"
	persisfile "github.com/dagucloud/dagu/v2/internal/persis/file"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/publicwebhook"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
)

const testWebhookID = "0b6e1c39-5c55-4c9e-9a51-3d3f39f0e2a1"

// publicWebhookHome returns a fixture with the public webhook store written
// by its own writer: the relay status and one webhook's full delivery log.
func publicWebhookHome(t *testing.T) (dataDir string, scanIt func() *continuity.Inventory) {
	t.Helper()
	l, _ := build(t)
	backend := persisfile.NewBackend(backendPaths(l.DataDir))
	st := store.NewPublicWebhookStore(backend.Collection(persis.CollectionPublicWebhooks))
	ctx := context.Background()
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, st.SetStatus(ctx, publicwebhook.Status{Holding: true, URL: "https://relay.example/h/", MaxHooks: 5,
		LeftOut: []string{"dag-x"}, Error: "not connected", UpdatedAt: at}))
	for i := range publicwebhook.LogSize + 3 {
		require.NoError(t, st.AddDelivery(ctx, testWebhookID, publicwebhook.Delivery{ID: "d" + strings.Repeat("x", i), Received: at,
			Size: 10, Event: "push", Outcome: publicwebhook.OutcomeStarted, RunID: "run"}))
	}
	require.NoError(t, st.AddMissed(ctx, testWebhookID, 2, 1, at))
	return l.DataDir, func() *continuity.Inventory { return scan(t, l) }
}

func blockingIDs(inv *continuity.Inventory) map[string]string {
	out := map[string]string{}
	for _, i := range continuity.Blocking(continuity.Validate(inv, continuity.Policy{})) {
		out[i.ID] = i.Code
	}
	return out
}

// What the store writes is classified: the status and each log are retained
// and may change, and nothing blocks.
func TestPublicWebhookStoreIsClassified(t *testing.T) {
	t.Parallel()
	_, scanIt := publicWebhookHome(t)
	inv := scanIt()
	assert.Empty(t, blockingIDs(inv))
	policies := map[string]string{}
	for _, f := range inv.Files {
		if f.Root == "hub-data" && strings.HasPrefix(f.Path, "public-webhooks/") {
			policies[f.Path] = f.Policy
		}
	}
	assert.Equal(t, map[string]string{
		"public-webhooks/status.json":                    continuity.PolicyMutable,
		"public-webhooks/log/" + testWebhookID + ".json": continuity.PolicyMutable,
	}, policies)
}

// Anything in the store its writer would not have written blocks, named, and
// is not inventoried.
func TestPublicWebhookStoreRefusesWhatItsWriterDoesNotWrite(t *testing.T) {
	t.Parallel()
	logPath := "public-webhooks/log/" + testWebhookID + ".json"
	for name, tc := range map[string]struct {
		path, data string
		blocked    string
	}{
		"status with a field the store does not write": {"public-webhooks/status.json", `{"connected":false,"token":"x","updatedAt":"2026-10-01T00:00:00Z"}`, "public-webhooks/status.json"},
		"status that is not JSON":                      {"public-webhooks/status.json", `{`, "public-webhooks/status.json"},
		"log with an unknown outcome":                  {logPath, `{"deliveries":[{"id":"d1","received":"2026-10-01T00:00:00Z","size":1,"outcome":"queued"}],"missed":{"expired":0,"refused":0}}`, logPath},
		"log entry with no ID":                         {logPath, `{"deliveries":[{"id":"","received":"2026-10-01T00:00:00Z","size":1,"outcome":"started"}],"missed":{"expired":0,"refused":0}}`, logPath},
		"log with a delivery body":                     {logPath, `{"deliveries":[{"id":"d1","received":"2026-10-01T00:00:00Z","size":1,"outcome":"started","body":"secret"}],"missed":{"expired":0,"refused":0}}`, logPath},
		"log with negative missed counts":              {logPath, `{"missed":{"expired":-1,"refused":0}}`, logPath},
		"log longer than its writer keeps":             {logPath, `{"deliveries":[` + strings.TrimSuffix(strings.Repeat(`{"id":"d","received":"2026-10-01T00:00:00Z","size":1,"outcome":"started"},`, publicwebhook.LogSize+1), ",") + `],"missed":{"expired":0,"refused":0}}`, logPath},
		"log named by something but a webhook ID":      {"public-webhooks/log/my-dag.json", `{"missed":{"expired":0,"refused":0}}`, "hub-data/public-webhooks/log/my-dag.json"},
		"another file in the store":                    {"public-webhooks/hooks.json", `{}`, "hub-data/public-webhooks/hooks.json"},
		"a directory beside the logs":                  {"public-webhooks/bodies/b1.json", `{}`, "hub-data/public-webhooks/bodies"},
		// Arbitrary JSON in the other collections added after F blocks too.
		"a dummy claim":                        {"webhook-dag-claims/my-dag.json", `{"value":"x"}`, "hub-data/webhook-dag-claims/my-dag.json"},
		"a claim naming no webhook":            {"webhook-dag-claims/my-dag.json", `{"webhookId":"w1"}`, "hub-data/webhook-dag-claims/my-dag.json"},
		"a claim under no DAG name":            {"webhook-dag-claims/a b.json", `{"webhookId":"` + testWebhookID + `"}`, "hub-data/webhook-dag-claims/a b.json"},
		"a dummy watch record":                 {"watch_state/watch.json", `{"value":"x"}`, "hub-data/watch_state/watch.json"},
		"a watch record of an unread version":  {"watch_state/watch.json", `{"version":3}`, "hub-data/watch_state/watch.json"},
		"a watch ledger with an unknown field": {"watch_state/watch.json", `{"version":2,"dags":{"d":{"path":"/in","secret":"x"}}}`, "hub-data/watch_state/watch.json"},
		"another watch record":                 {"watch_state/other.json", `{"version":2}`, "hub-data/watch_state/other.json"},
		"a dummy pin record":                   {"dag-pins/pins.json", `{"value":"x"}`, "hub-data/dag-pins/pins.json"},
		"a pin that is not a DAG name":         {"dag-pins/pins.json", `{"fileNames":["../x"]}`, "hub-data/dag-pins/pins.json"},
		"another pin record":                   {"dag-pins/user-1.json", `{"fileNames":[]}`, "hub-data/dag-pins/user-1.json"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dataDir, scanIt := publicWebhookHome(t)
			p := filepath.Join(dataDir, filepath.FromSlash(tc.path))
			require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
			require.NoError(t, os.WriteFile(p, []byte(tc.data), 0o600))
			inv := scanIt()
			blocked := blockingIDs(inv)
			want := tc.blocked
			if !strings.HasPrefix(want, "hub-data/") {
				want = "hub-data/" + want
			}
			assert.Contains(t, blocked, want, "blocking: %v", blocked)
			for _, f := range inv.Files {
				assert.NotEqual(t, strings.TrimPrefix(want, "hub-data/"), f.Path, "a refused file is not inventoried")
			}
			// A refusal never quotes the file's values.
			for _, i := range inv.Issues {
				assert.NotContains(t, i.Detail, `"x"`)
				assert.NotContains(t, i.Detail, "secret")
				assert.NotContains(t, i.Detail, "queued")
			}
		})
	}
}

// The scan inventories the collections added after F as digest, size and
// mode only, and a refusal never quotes what a file holds: a stored value,
// in a file that is accepted or in one that is refused, in a field it knows
// or in one it does not, never reaches the inventory (TXE-7830).
func TestScanEmitsNoStoredValue(t *testing.T) {
	t.Parallel()
	const marker = "stored-value-marker-0f1e2d3c"
	accepted := map[string]string{
		"public-webhooks/status.json":                    `{"connected":false,"url":"https://relay.example/` + marker + `","leftOut":["` + marker + `"],"error":"` + marker + `","updatedAt":"2026-10-01T00:00:00Z"}`,
		"public-webhooks/log/" + testWebhookID + ".json": `{"deliveries":[{"id":"` + marker + `","received":"2026-10-01T00:00:00Z","size":1,"event":"` + marker + `","outcome":"failed","runId":"` + marker + `","error":"` + marker + `"}],"missed":{"expired":0,"refused":0}}`,
		"watch_state/watch.json":                         `{"version":2,"dags":{"` + marker + `":{"path":"/in/` + marker + `","files":{"` + marker + `":{"size":1,"modTime":"2026-10-01T00:00:00Z"}}}}}`,
		"dag-pins/pins.json":                             `{"fileNames":["` + marker + `"]}`,
		"webhook-dag-claims/d.json":                      `{"webhookId":"` + testWebhookID + `"}`,
	}
	refused := map[string]string{
		"public-webhooks/status.json":                    `{"` + marker + `":"` + marker + `"}`,
		"public-webhooks/log/" + testWebhookID + ".json": `{"deliveries":[{"id":"d","received":"2026-10-01T00:00:00Z","size":"` + marker + `","outcome":"` + marker + `"}]}`,
		"watch_state/watch.json":                         `{"version":"` + marker + `"}`,
		"dag-pins/pins.json":                             `{"fileNames":["` + marker + `/x"]}`,
		"webhook-dag-claims/d.json":                      `{"webhookId":"` + marker + `"}`,
	}
	for name, files := range map[string]map[string]string{"accepted": accepted, "refused": refused} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			l, _ := build(t)
			for rel, data := range files {
				p := filepath.Join(l.DataDir, filepath.FromSlash(rel))
				require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
				require.NoError(t, os.WriteFile(p, []byte(data), 0o600))
			}
			inv := scan(t, l)
			blocked := blockingIDs(inv)
			for rel := range files {
				if name == "accepted" {
					assert.NotContains(t, blocked, "hub-data/"+rel)
				} else {
					assert.Contains(t, blocked, "hub-data/"+rel)
				}
			}
			out, err := json.Marshal(inv)
			require.NoError(t, err)
			assert.NotContains(t, string(out), marker, "the inventory holds a stored value")
		})
	}
}
