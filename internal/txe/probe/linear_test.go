// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const linearKey = "lin_api_test_0000"

func linearTarget(id string) Target {
	return Target{Kind: KindLinearIssue, StableID: map[string]string{KeyLinearIssueID: id}}
}

// fakeLinear answers as Linear's GraphQL API would, and fails the test if a
// request carries the wrong key or anything but the read query.
func fakeLinear(t *testing.T, status int, body string) Linear {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != linearKey {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		var req struct {
			Query string `json:"query"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if strings.Contains(req.Query, "mutation") {
			t.Errorf("probe sent a mutation: %s", req.Query)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return Linear{Endpoint: srv.URL, HTTP: srv.Client()}
}

var linearCreds = credMap{LinearCredential: {Value: linearKey}}

func TestLinearPresent(t *testing.T) {
	l := fakeLinear(t, 200, `{"data":{"issue":{"id":"uuid-1","identifier":"TXE-1","archivedAt":null}}}`)
	if r := l.Probe(context.Background(), linearTarget("uuid-1"), linearCreds); r.Outcome != Present {
		t.Fatalf("result = %+v, want present", r)
	}
}

func TestLinearArchivedIsNotDeleted(t *testing.T) {
	l := fakeLinear(t, 200, `{"data":{"issue":{"id":"uuid-1","identifier":"TXE-1","archivedAt":"2026-10-01T00:00:00Z"}}}`)
	r := l.Probe(context.Background(), linearTarget("uuid-1"), linearCreds)
	if r.Outcome != Present || !strings.Contains(r.Detail, "archived") {
		t.Fatalf("result = %+v, want present and archived", r)
	}
}

// A null or not-found answer, including one for a synthetic id, is never
// absence: it is unknown and not authoritative.
func TestLinearNotFoundIsUnknownNotAbsent(t *testing.T) {
	for name, body := range map[string]string{
		"null issue":       `{"data":{"issue":null}}`,
		"entity not found": `{"data":null,"errors":[{"message":"Entity not found: Issue","extensions":{"code":"INVALID_INPUT","type":"invalid input"}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			l := fakeLinear(t, 200, body)
			r := l.Probe(context.Background(), linearTarget("00000000-0000-0000-0000-000000000000"), linearCreds)
			if r.Outcome != Unknown || r.Authoritative {
				t.Fatalf("result = %+v, want unknown", r)
			}
		})
	}
}

func TestLinearRefusedKeyIsAuthDenied(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
	}{
		"http 401":  {401, `{"errors":[{"message":"Authentication required"}]}`},
		"http 403":  {403, `{}`},
		"graphql":   {200, `{"data":null,"errors":[{"message":"Authentication required, not authenticated","extensions":{"code":"AUTHENTICATION_ERROR"}}]}`},
		"forbidden": {200, `{"data":null,"errors":[{"message":"Forbidden","extensions":{"code":"FORBIDDEN"}}]}`},
	} {
		t.Run(name, func(t *testing.T) {
			l := fakeLinear(t, tc.status, tc.body)
			if r := l.Probe(context.Background(), linearTarget("uuid-1"), linearCreds); r.Outcome != AuthDenied {
				t.Fatalf("result = %+v, want auth_denied", r)
			}
		})
	}
}

func TestLinearOutageIsUnreachable(t *testing.T) {
	l := fakeLinear(t, 503, `upstream unavailable`)
	if r := l.Probe(context.Background(), linearTarget("uuid-1"), linearCreds); r.Outcome != Unreachable {
		t.Fatalf("result = %+v, want unreachable", r)
	}
	down := Linear{Endpoint: "http://127.0.0.1:1"}
	if r := down.Probe(context.Background(), linearTarget("uuid-1"), linearCreds); r.Outcome != Unreachable || strings.Contains(r.Detail, linearKey) {
		t.Fatalf("result = %+v, want unreachable without the key", r)
	}
}

func TestLinearTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	// Cleanups run last-in first-out: the handler is released before the
	// server waits for it.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	l := Linear{Endpoint: srv.URL, HTTP: srv.Client()}
	if r := l.Probe(ctx, linearTarget("uuid-1"), linearCreds); r.Outcome != Timeout {
		t.Fatalf("result = %+v, want timeout", r)
	}
}

func TestLinearKeyFromFileAndMissingKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "linear-key")
	if err := os.WriteFile(path, []byte(linearKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := fakeLinear(t, 200, `{"data":{"issue":{"id":"uuid-1","identifier":"TXE-1"}}}`)
	if r := l.Probe(context.Background(), linearTarget("uuid-1"), credMap{LinearCredential: {Path: path}}); r.Outcome != Present {
		t.Fatalf("file key: %+v, want present", r)
	}
	if r := l.Probe(context.Background(), linearTarget("uuid-1"), credMap{}); r.Outcome != AuthDenied {
		t.Fatalf("no key: %+v, want auth_denied", r)
	}
	if r := l.Probe(context.Background(), linearTarget(""), linearCreds); r.Outcome != Unknown {
		t.Fatalf("no id: %+v, want unknown", r)
	}
}
