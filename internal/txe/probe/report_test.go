// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
)

// The registry adapter speaks the hub's resource-event API: POST
// /txe/resource-events with the report, and GET with complete=false and the
// reporter's machine to list what is not yet applied, page by page.
func TestClientRegistryWire(t *testing.T) {
	var posted map[string]any
	pages := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/txe/resource-events":
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				t.Error(err)
			}
			_, _ = w.Write([]byte(`{"event_id":"evt_01JTXE0000000000000000000A","complete":true,"observation":"absent",
				"target":{"kind":"kubernetes.configmap","stable_id":{"cluster_uid":"c1","uid":"u1"}},
				"dispositions":[{"job_id":"job_01JTXE00000000000000000AAA","match":"identity","outcome":"retired"}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/txe/resource-events":
			q := r.URL.Query()
			if q.Get("complete") != "false" || q.Get("reporter_machine_id") != mch || q.Get("limit") != "200" {
				t.Errorf("query = %v", q)
			}
			pages++
			if q.Get("after") == "" {
				_, _ = w.Write([]byte(`{"events":[{"event_id":"evt_1","target":{"kind":"linear.issue","stable_id":{"id":"x"}},"observation":"unknown","complete":false,"dispositions":[]}],"next_cursor":"c2"}`))
				return
			}
			if q.Get("after") != "c2" {
				t.Errorf("after = %q", q.Get("after"))
			}
			_, _ = w.Write([]byte(`{"events":[]}`))
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	reg := ClientRegistry{Client: txeclient.New(srv.URL+"/api/v1", "test-key", srv.Client())}

	ev := Event{EventID: "evt_01JTXE0000000000000000000A", Observation: Absent, Authoritative: true,
		Target:     Target{Kind: "kubernetes.configmap", Environment: "dev", DisplayName: "ns/cm", StableID: map[string]string{"cluster_uid": "c1", "uid": "u1"}},
		Evidence:   []string{"GET configmaps/ns/cm: 404"},
		ObservedAt: time.Date(2026, 10, 10, 3, 0, 0, 0, time.UTC),
		Actor:      &txeclient.Actor{Kind: ActorKindReconciler, ID: "txe-probe", MachineID: mch}}
	rec, err := reg.RecordEvent(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}
	if rec.EventID != ev.EventID || !rec.Complete || len(rec.Dispositions) != 1 || rec.Dispositions[0].Outcome != "retired" {
		t.Fatalf("recorded = %+v", rec)
	}
	for key, want := range map[string]any{"event_id": ev.EventID, "observation": "absent", "authoritative": true} {
		if posted[key] != want {
			t.Errorf("posted %s = %v, want %v", key, posted[key], want)
		}
	}
	if actor, _ := posted["actor"].(map[string]any); actor["kind"] != ActorKindReconciler || actor["machine_id"] != mch {
		t.Errorf("posted actor = %v", posted["actor"])
	}
	if target, _ := posted["target"].(map[string]any); target["display_name"] != "ns/cm" {
		t.Errorf("posted target = %v", posted["target"])
	}

	events, next, err := reg.IncompleteEvents(context.Background(), mch, "", 200)
	if err != nil || len(events) != 1 || next != "c2" || events[0].Observation != Unknown {
		t.Fatalf("first page = %+v %q %v", events, next, err)
	}
	if events, next, err = reg.IncompleteEvents(context.Background(), mch, next, 200); err != nil || len(events) != 0 || next != "" {
		t.Fatalf("second page = %+v %q %v", events, next, err)
	}
	if pages != 2 {
		t.Fatalf("pages = %d", pages)
	}
}
