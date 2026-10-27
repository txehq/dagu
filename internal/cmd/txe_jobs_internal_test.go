// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/cliauth/cliauthtest"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
)

// A change made by the hub or by a worker's own check has no session. It is
// named by what the registry recorded instead of being left blank.
func TestTXEActorName(t *testing.T) {
	assert.Equal(t, "cc2-s855054", txeActorName(txeclient.Actor{Kind: "cli", ID: "admin", Session: "cc2-s855054"}))
	assert.Equal(t, "reconciler registry", txeActorName(txeclient.Actor{Kind: "reconciler", ID: "registry"}))
	assert.Equal(t, "cli", txeActorName(txeclient.Actor{Kind: "cli"}))
	assert.Equal(t, "admin", txeActorName(txeclient.Actor{ID: "admin"}))
	assert.Equal(t, "(not recorded)", txeActorName(txeclient.Actor{}))
}

// An error is printed on one line with everything unprintable escaped,
// because it may quote what another session stored. Two errors are laid out
// over several lines by this program or by the YAML reader, and keep their
// line breaks; anything else in them that is not printable is still escaped.
func TestTXEShownErrorKeepsTheLayoutOfASpecError(t *testing.T) {
	reader := errors.New("[3:1] unknown field \"titel\"\n   2 | job_key: abc\n>  3 | titel: \x1b[31mtypo\n       ^")
	shown := (&txeShownError{err: fmt.Errorf("register: %w", &txeclient.SpecSyntaxError{Path: "job.yaml", Err: reader})}).Error()
	assert.Equal(t, "register: parse job spec job.yaml: [3:1] unknown field \"titel\"\n   2 | job_key: abc\n>  3 | titel: \\x1b[31mtypo\n       ^", shown)

	fromHub := (&txeShownError{err: errors.New("the hub said: first\nsecond")}).Error()
	assert.Equal(t, `the hub said: first\x0asecond`, fromHub)
}

// Inspect asks for the job's newest runs from the epoch on. Asked for no
// start, the hub lists only runs since its local midnight, so a job that has
// not run today showed none.
func TestTXEInspectListsRunsFromBeforeMidnight(t *testing.T) {
	f := newTXEAuthFixture(t)
	const job = "job_01K7A5ZQ8M3N4P5R6S7T8V9W0J"
	var queries []url.Values
	f.hub.Handle = func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/v1/txe/jobs/" + job:
			cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"job_id": job, "version": 1})
		case "/api/v1/txe/jobs/" + job + "/versions/1":
			cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"title": "a job"})
		case "/api/v1/dag-runs/" + job:
			queries = append(queries, r.URL.Query())
			cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"dagRuns": []any{
				map[string]any{"dagRunId": "run-yesterday", "statusLabel": "succeeded", "startedAt": "2026-10-19T23:00:00Z"},
			}})
		default:
			return false
		}
		return true
	}

	out := f.json("inspect", job)
	runs, ok := out["runs"].([]any)
	require.True(t, ok, "runs: %v", out["runs"])
	require.Len(t, runs, 1)
	assert.Equal(t, "run-yesterday", runs[0].(map[string]any)["run_id"])
	require.Len(t, queries, 1)
	assert.Equal(t, "0", queries[0].Get("fromDate"))
	assert.Equal(t, "5", queries[0].Get("limit"))

	// --runs bounds what is asked for, up to the hub's most; none asks nothing.
	f.json("inspect", job, "--runs", "900")
	assert.Equal(t, "500", queries[1].Get("limit"))
	f.json("inspect", job, "--runs", "0")
	assert.Len(t, queries, 2)
}

// The registry keeps decided and finished proposals and resolved exceptions in
// the job record. Inspect counts only what is still open, and says a job whose
// registration is not ready cannot run, whatever its availability.
func TestTXEInspectCountsOnlyWhatIsOpen(t *testing.T) {
	f := newTXEAuthFixture(t)
	const job = "job_01K7A5ZQ8M3N4P5R6S7T8V9W0J"
	record := map[string]any{
		"job_id": job, "version": 2, "machine_id": "mch_01K7A5ZQ8M3N4P5R6S7T8V9W0K",
		"registration": map[string]any{"state": "ready", "job_key": "k"},
		"availability": map[string]any{"state": "ready"},
		"proposals": map[string]any{
			"prp_open":     map[string]any{"state": "open"},
			"prp_snoozed":  map[string]any{"state": "snoozed"},
			"prp_decided":  map[string]any{"state": "decided"},
			"prp_executed": map[string]any{"state": "executed"},
			"prp_rejected": map[string]any{"state": "rejected"},
			"prp_super":    map[string]any{"state": "superseded"},
			"prp_closed":   map[string]any{"state": "closed"},
			"prp_unknown":  map[string]any{"state": "some-later-state"},
		},
		"exceptions": map[string]any{
			"exc_resolved": map[string]any{"kind": "target_auth_denied", "resolved_at": "2026-10-12T09:30:12Z"},
			"exc_open":     map[string]any{"kind": "machine_unavailable"},
		},
	}
	f.hub.Handle = func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/v1/txe/jobs/" + job:
			cliauthtest.WriteJSON(w, http.StatusOK, record)
		case "/api/v1/txe/jobs/" + job + "/versions/2":
			cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"title": "a job"})
		default:
			return false
		}
		return true
	}

	out, err := f.run("inspect", job, "--runs", "0")
	require.NoError(t, err)
	assert.Contains(t, out, "Open:          3 proposal(s) waiting for a decision, 1 unresolved exception(s)\n")
	assert.NotContains(t, out, "Not runnable")

	// Only a resolved exception, as on job_01M4QP81VY08CJY8Q120WVKCEY: nothing is open.
	record["proposals"] = nil
	record["exceptions"] = map[string]any{"exc_resolved": map[string]any{"kind": "target_auth_denied", "resolved_at": "2026-10-12T09:30:12Z"}}
	out, err = f.run("inspect", job, "--runs", "0")
	require.NoError(t, err)
	assert.Contains(t, out, "Open:          0 proposal(s) waiting for a decision, 0 unresolved exception(s)\n")

	// Version 2 saved and not ready: the hub runs none of its ticks.
	record["registration"] = map[string]any{"state": "incomplete", "job_key": "k", "request_id": "req_01M4QQYWB60735V0287GA71339"}
	out, err = f.run("inspect", job, "--runs", "0")
	require.NoError(t, err)
	assert.Contains(t, out, "Registration:  incomplete\nAvailability:  ready\n"+
		"Not runnable:  registration incomplete; finish it on machine mch_01K7A5ZQ8M3N4P5R6S7T8V9W0K with: dagu txe resume req_01M4QQYWB60735V0287GA71339\n")

	// No request id, or one the CLI did not mint: no command to paste.
	for _, requestID := range []string{"", "req_x; rm -rf ~", "$(touch /tmp/x)", "req_01M4QQYWB60735V0287GA7133 x"} {
		record["registration"] = map[string]any{"state": "incomplete", "job_key": "k", "request_id": requestID}
		out, err = f.run("inspect", job, "--runs", "0")
		require.NoError(t, err)
		assert.Contains(t, out, "Not runnable:  registration incomplete\n", requestID)
		assert.NotContains(t, out, "dagu txe resume", requestID)
	}
}
