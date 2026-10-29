// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/cliauth/cliauthtest"
	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
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

// txeTestDigest is a package digest made of one repeated hex digit.
func txeTestDigest(digit string) string { return "sha256:" + strings.Repeat(digit, 64) }

// A package is used when a ready event names its digest, whichever version
// the event was for: two versions may share one package. Only directories no
// ready event names are listed, each with the unfinished requests that
// registered it.
func TestTXENeverReadyOf(t *testing.T) {
	const job = "job_01K7A5ZQ8M3N4P5R6S7T8V9W0J"
	ready, superseded, shared, current := txeTestDigest("1"), txeTestDigest("2"), txeTestDigest("3"), txeTestDigest("4")
	held := []txepkg.HeldPackage{
		{Dir: "/p/" + job + "/leftover"},
		{Dir: "/p/" + job + "/sha256-1", Digest: ready},
		{Dir: "/p/" + job + "/sha256-2", Digest: superseded},
		{Dir: "/p/" + job + "/sha256-3", Digest: shared},
		{Dir: "/p/" + job + "/sha256-4", Digest: current},
	}
	events := []txeclient.Event{
		{Kind: txeclient.EventReady, Evidence: []string{ready, "dag-hash-1"}},
		// Version 4 was superseded; version 5 became ready with the same package.
		{Kind: txeclient.EventReady, Evidence: []string{shared, "dag-hash-5"}},
		// Another kind of event naming a digest does not make it used.
		{Kind: "registered", Evidence: []string{superseded}},
	}
	entries := []txepkg.Entry{
		{RequestID: "req_super", JobID: job, Version: 2, Step: txepkg.StepSuperseded, PackageDigest: superseded, SupersededBy: 3},
		{RequestID: "req_shared", JobID: job, Version: 4, Step: txepkg.StepSuperseded, PackageDigest: shared, SupersededBy: 5},
		{RequestID: "req_other_job", JobID: "job_other", Version: 1, Step: txepkg.StepCommitted, PackageDigest: superseded},
		// A refused request built the same package; it never placed it.
		{RequestID: "req_refused", JobID: job, Version: 3, Step: txepkg.StepRejected, PackageDigest: superseded},
		{RequestID: "req_current", JobID: job, Version: 6, Step: txepkg.StepCommitted, PackageDigest: current},
	}
	got := txeNeverReadyOf(&txeclient.Job{JobID: job, PackageDigest: current}, held, events, entries)
	assert.Equal(t, []txeNeverReady{
		{Dir: "/p/" + job + "/leftover"},
		{Dir: "/p/" + job + "/sha256-2", Digest: superseded, Requests: []txeNeverReadyRequest{
			{RequestID: "req_super", Version: 2, Step: txepkg.StepSuperseded, SupersededBy: 3},
		}},
		{Dir: "/p/" + job + "/sha256-4", Digest: current, Current: true, Requests: []txeNeverReadyRequest{
			{RequestID: "req_current", Version: 6, Step: txepkg.StepCommitted},
		}},
	}, got)

	assert.Empty(t, txeNeverReadyOf(&txeclient.Job{JobID: job}, nil, events, entries), "nothing held")
}

// Inspect names the job's package directories no version was ever marked
// ready with, as on job_01M4QQYWB60735V0287GA71338, whose version 4 was
// replaced before it became ready. It reads the job's history only when this
// machine holds a directory for the job, and a history it cannot read leaves
// the answer unknown without failing the command.
func TestTXEInspectNamesPackagesNoReadyVersionUsed(t *testing.T) {
	f := newTXEAuthFixture(t)
	const job = "job_01M4QQYWB60735V0287GA71338"
	v3, v4, v5 := txeTestDigest("3"), txeTestDigest("4"), txeTestDigest("5")
	record := map[string]any{
		"job_id": job, "version": 5, "package_digest": v5,
		"registration": map[string]any{"state": "ready", "job_key": "k"},
	}
	events := []any{
		map[string]any{"event_id": "evt_5", "kind": "ready", "evidence": []string{v5, "dag-5"}},
		map[string]any{"event_id": "evt_3", "kind": "ready", "evidence": []string{v3, "dag-3"}},
	}
	eventCalls, eventStatus := 0, http.StatusOK
	f.hub.Handle = func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.Path {
		case "/api/v1/txe/jobs/" + job:
			cliauthtest.WriteJSON(w, http.StatusOK, record)
		case "/api/v1/txe/jobs/" + job + "/versions/5":
			cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"title": "a job"})
		case "/api/v1/txe/jobs/" + job + "/events":
			eventCalls++
			cliauthtest.WriteJSON(w, eventStatus, map[string]any{"events": events})
		default:
			return false
		}
		return true
	}

	// No directory for the job on this machine: the hub is not asked.
	out, err := f.run("inspect", job, "--runs", "0")
	require.NoError(t, err)
	assert.NotContains(t, out, "Never ready")
	assert.Zero(t, eventCalls)

	home := txepkg.Home{Root: f.home}
	jobDir := filepath.Join(home.PackagesDir(), job)
	for _, digest := range []string{v3, v4, v5} {
		name, err := txepkg.DigestDirName(digest)
		require.NoError(t, err)
		require.NoError(t, os.MkdirAll(filepath.Join(jobDir, name), 0o700))
	}
	_, err = txepkg.NewJournal(home).Begin(txepkg.Entry{RequestID: "req_01M4QZS6Z1HXHJFE9D82QHR2E3", JobID: job, Version: 4,
		Step: txepkg.StepSuperseded, PackageDigest: v4, SupersededBy: 5})
	require.NoError(t, err)
	v4Dir := filepath.Join(jobDir, "sha256-"+strings.Repeat("4", 64))
	// Text output escapes what it prints, a Windows path's backslashes included.
	v4Shown := txeclient.CleanText(v4Dir, false)

	out, err = f.run("inspect", job, "--runs", "0")
	require.NoError(t, err)
	assert.Contains(t, out, "Never ready:   1 package directory on this machine that no version of this job was ever marked ready with;\n"+
		"               kept as a record, and nothing removes them\n"+
		"  "+v4Shown+"\n"+
		"      the job does not use it\n"+
		"      version 4, request req_01M4QZS6Z1HXHJFE9D82QHR2E3, superseded by version 5\n")
	assert.NotContains(t, out, strings.Repeat("3", 64), "version 3 was ready once: its package is not listed")

	answer := f.json("inspect", job, "--runs", "0")
	local := answer["local"].(map[string]any)
	require.Len(t, local["never_ready"], 1)
	assert.Equal(t, v4Dir, local["never_ready"].([]any)[0].(map[string]any)["dir"])

	// Version 6 is saved and not ready yet; its package is in place.
	v6 := txeTestDigest("6")
	record["version"], record["package_digest"] = 6, v6
	record["registration"] = map[string]any{"state": "incomplete", "job_key": "k"}
	require.NoError(t, os.Mkdir(filepath.Join(jobDir, "sha256-"+strings.Repeat("6", 64)), 0o700))
	f.hub.Handle = func(next func(http.ResponseWriter, *http.Request) bool) func(http.ResponseWriter, *http.Request) bool {
		return func(w http.ResponseWriter, r *http.Request) bool {
			if r.URL.Path == "/api/v1/txe/jobs/"+job+"/versions/6" {
				cliauthtest.WriteJSON(w, http.StatusOK, map[string]any{"title": "a job"})
				return true
			}
			return next(w, r)
		}
	}(f.hub.Handle)
	out, err = f.run("inspect", job, "--runs", "0")
	require.NoError(t, err)
	assert.Contains(t, out, "Never ready:   2 package directories")
	assert.Contains(t, out, "      the current version's package; registration is incomplete, and finishing it uses this package\n")

	// The history cannot be read: nothing is called unused, and inspect still answers.
	eventStatus = http.StatusInternalServerError
	out, err = f.run("inspect", job, "--runs", "0")
	require.NoError(t, err)
	assert.Contains(t, out, "Never ready:   unknown: the history of "+job+", needed to tell which of the 4 entries of its package directory were used, could not be read: ")
	assert.NotContains(t, out, v4Shown)
}
