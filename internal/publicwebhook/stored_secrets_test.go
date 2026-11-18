// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package publicwebhook_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cloudrelay"
	"github.com/dagucloud/dagu/v2/internal/license"
	persisfile "github.com/dagucloud/dagu/v2/internal/persis/file"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/publicwebhook"
	"github.com/dagucloud/dagu/v2/internal/webhooksig"
)

// TXE-7830: the continuity scanner reads the public webhook store as
// holding no secret. This drives the service itself, through a relay, into
// the file collection a hub keeps it in, with every kind of delivery the log
// records, and reads back every byte the store wrote: no URL token, sender
// signing secret, header value or body is there, and each file decodes
// strictly as the status or a log.
func TestStoredStatusAndLogsHoldNoSecret(t *testing.T) {
	const (
		tokenSigned  = "token-signed-never-stored-0123456789"
		tokenPlain   = "token-plain-never-stored-9876543210"
		senderSecret = "sender-secret-never-stored-abcdef"
		headerSecret = "header-value-never-stored-ghijkl"
		bodySecret   = "body-value-never-stored-mnopqr"
	)
	dir := filepath.Join(t.TempDir(), "public-webhooks")
	h := newHarness(t, 1000)
	h.log = store.NewPublicWebhookStore(persisfile.NewCollection(dir, persisfile.WithIndentedJSON()))
	h.svc = publicwebhook.New(publicwebhook.Config{
		Credentials: func() (license.CloudCredentials, bool) {
			return license.CloudCredentials{CloudURL: h.cloud.srv.URL, LicenseID: "lic", ServerID: "srv", HeartbeatSecret: "heartbeat-never-stored"}, true
		},
		Webhooks:       h.webhooks,
		Store:          h.log,
		Runs:           h.runs,
		HTTPClient:     h.cloud.srv.Client(),
		Hello:          cloudrelay.Hello{Name: "etl-prod-1", Version: "2.20.0"},
		MaxPayloadSize: testMaxPayloadSize,
	})
	h.svc.SetTimingForTest(20*time.Millisecond, 10*time.Millisecond, time.Hour)

	now := time.Now()
	signed := h.addWebhook(t, "signed", &auth.WebhookPublic{Token: tokenSigned, Sender: "github", SenderSecret: senderSecret, CreatedAt: now})
	plain := h.addWebhook(t, "plain", &auth.WebhookPublic{Token: tokenPlain, Events: []string{"push"}, CreatedAt: now.Add(time.Second)})
	// The service runs until the store is read: stopped first, so nothing
	// writes while every file is read back.
	ctx, stop := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		h.svc.Run(ctx)
	}()
	t.Cleanup(func() { stop(); <-stopped })
	ws := h.cloud.relay(t)
	hooks := ws.next(t, "hooks")
	ws.write(t, map[string]any{"t": "hooked", "id": hooks["id"], "url": "https://hooks.example/obj"})

	body := `{"secret":"` + bodySecret + `"}`
	sig, err := webhooksig.Sign(webhooksig.GitHub, senderSecret, []byte(body), time.Now())
	require.NoError(t, err)
	header := func(event string, extra map[string]string) map[string]string {
		m := map[string]string{"X-Github-Event": event, "Authorization": "Bearer " + headerSecret}
		maps.Copy(m, extra)
		return m
	}
	for _, d := range []struct {
		id, hook string
		header   map[string]string
		outcome  string
	}{
		{"started", hookOf(signed), header("push", map[string]string{"X-Hub-Signature-256": sig.Get("X-Hub-Signature-256")}), "started"},
		{"rejected", hookOf(signed), header("push", map[string]string{"X-Hub-Signature-256": "sha256=" + headerSecret}), "ignored"},
		{"skipped", hookOf(plain), header("issues", nil), "ignored"},
		{"plain", hookOf(plain), header("push", nil), "started"},
	} {
		ws.write(t, deliveryFrame(d.id, d.hook, d.header, body))
		assert.Equal(t, d.outcome, ws.next(t, "delivered")["outcome"], d.id)
	}
	ws.write(t, map[string]any{"t": "missed", "hooks": []map[string]any{{"hook": hookOf(plain), "expired": 1, "refused": 0}}})
	require.Eventually(t, func() bool {
		l, err := h.log.Log(t.Context(), plain.ID)
		return err == nil && l.Missed.Expired == 1 && len(l.Deliveries) == 2
	}, 5*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return h.status(t).URL == "https://hooks.example/obj" }, 5*time.Second, 10*time.Millisecond)
	stop()
	<-stopped

	logs := map[string]bool{}
	require.NoError(t, filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".dagu_record_locks" {
			return filepath.SkipDir
		}
		if !d.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(p) //nolint:gosec // a test path
		require.NoError(t, err)
		rel, err := filepath.Rel(dir, p)
		require.NoError(t, err)
		for _, secret := range []string{tokenSigned, tokenPlain, senderSecret, headerSecret, bodySecret, "heartbeat-never-stored"} {
			assert.False(t, bytes.Contains(data, []byte(secret)), "%s holds a secret", rel)
		}
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		switch filepath.ToSlash(rel) {
		case "status.json":
			var st publicwebhook.Status
			assert.NoError(t, dec.Decode(&st), rel)
		default:
			var l publicwebhook.Log
			assert.NoError(t, dec.Decode(&l), rel)
			logs[filepath.ToSlash(rel)] = true
		}
		return nil
	}))
	assert.Equal(t, map[string]bool{"log/" + signed.ID + ".json": true, "log/" + plain.ID + ".json": true}, logs)
}
