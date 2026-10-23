// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const txeLifecycleSpec = `schema: 1
job_key: %s
title: Read back one purge
purpose: Read back that one purge happened, then stop; the owner completes or retires the job when its purpose is met or gone.
project:
  key: txe.local/lifecycle
  name: lifecycle
targets:
  - kind: example.purge
    environment: test
    stable_id: {id: purge-0001}
schedule:
  cron: "0 3 * * *"
  timezone: UTC
  timeout_sec: 60
package:
  include: [run.sh]
  entrypoint: [./run.sh]
expected_outcome:
  success_criteria: ["The read-back says the purge happened."]
lifetime:
  expires_at: "2027-01-31T00:00:00Z"
review_policy:
  cadence: "0 9 * * *"
  brief: Nothing to act on.
`

// A job's owner ends it with the built CLI, against a hub with the real
// registry: complete when its purpose is met, retire when it is no longer
// wanted. The change records why, the evidence and the session; the job runs
// no more, and its history is kept. A job already ended cannot be ended again,
// and the CLI refuses a change that would say nothing about why.
func TestTXECompleteAndRetire(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("job packages are shell scripts run by a Unix worker")
	}
	server := test.SetupServer(t)
	baseURL := fmt.Sprintf("http://%s:%d/api/v1", server.Config.Server.Host, server.Config.Server.Port)
	userDir := t.TempDir()
	cli := &txeCLI{t: t, binary: server.Config.Paths.Executable, home: txeDurableHome(t, userDir), userDir: userDir}
	identity := fmt.Sprintf(`{"schema":1,"machine_id":%q,"owner_id":%q,"display_name":"test-mac"}`, txeITMachine, txeITOwner)
	require.NoError(t, os.WriteFile(filepath.Join(cli.home, "machine.json"), []byte(identity), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(cli.home, "bin"), 0o700))
	require.NoError(t, os.Symlink(cli.binary, filepath.Join(cli.home, "bin", "dagu")))
	_, err := cli.run("installer", "context", "add", "txe", "--server="+baseURL, "--api-key="+txeITKey,
		"--dagu-home="+filepath.Join(cli.home, "client"))
	require.NoError(t, err)
	actor := map[string]any{"kind": "cli", "id": "installer"}
	txePost(t, baseURL, "/txe/owners", map[string]any{"owner_id": txeITOwner, "display_name": "Ada", "actor": actor})
	txePost(t, baseURL, "/txe/machines", map[string]any{"machine_id": txeITMachine, "owner_id": txeITOwner, "display_name": "test-mac", "actor": actor})

	register := func(key string) string {
		t.Helper()
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "run.sh"), []byte("#!/bin/sh\necho ok\n"), 0o755)) //nolint:gosec // test script
		spec := filepath.Join(dir, "job.yaml")
		require.NoError(t, os.WriteFile(spec, fmt.Appendf(nil, txeLifecycleSpec, key), 0o644)) //nolint:gosec // test file
		out, err := cli.run("cc2-s000003", "txe", "register", "-f", spec)
		require.NoError(t, err, out)
		found, err := cli.json("cc2-s000003", "txe", "list", "--job-key", key)
		require.NoError(t, err)
		jobs := txeJobs(t, found)
		require.Len(t, jobs, 1)
		return jobs[0].(map[string]any)["job_id"].(string)
	}
	job := func(jobID string) map[string]any {
		t.Helper()
		answer, err := cli.json("cc2-s000003", "txe", "inspect", jobID)
		require.NoError(t, err)
		return answer["job"].(map[string]any)
	}
	versions := func(jobID string) int {
		t.Helper()
		return len(job(jobID)["version_refs"].([]any))
	}

	// Complete: the purpose is met.
	done := register("purge-readback-a")
	before := versions(done)
	out, err := cli.run("cc2-s000004", "txe", "complete", done,
		"--detail", "The read-back found the purge done; nothing more to read.",
		"--evidence", "run 034jzSFyTVbTPHUbWCRlkN", "--evidence", "TXE-4839")
	require.NoError(t, err, out)
	assert.Contains(t, out, done+" is completed.")
	assert.Contains(t, out, "Reason:       completed")
	assert.Contains(t, out, "Evidence:     run 034jzSFyTVbTPHUbWCRlkN")
	assert.Contains(t, out, "By:           cc2-s000004")
	assert.Contains(t, out, "No new or queued run will start.")
	completed := job(done)
	assert.Equal(t, "completed", completed["lifecycle"])
	retirement := completed["retirement"].(map[string]any)
	assert.Equal(t, "completed", retirement["reason"])
	assert.Equal(t, "The read-back found the purge done; nothing more to read.", retirement["detail"])
	assert.Equal(t, []any{"run 034jzSFyTVbTPHUbWCRlkN", "TXE-4839"}, retirement["evidence"])
	by := retirement["actor"].(map[string]any)
	assert.Equal(t, "cli", by["kind"])
	assert.Equal(t, "cc2-s000004", by["session"])
	assert.Equal(t, txeITMachine, by["machine_id"])
	assert.Equal(t, before, versions(done), "versions are kept")
	text, err := cli.run("cc2-s000004", "txe", "inspect", done)
	require.NoError(t, err)
	assert.Contains(t, text, "Lifecycle:     completed")

	// A completed job cannot be completed or retired again.
	out, err = cli.run("cc2-s000004", "txe", "complete", done, "--detail", "again")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot complete a completed job")
	_, err = cli.run("cc2-s000004", "txe", "retire", done, "--detail", "again")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot retire a completed job")
	assert.Equal(t, "completed", job(done)["lifecycle"], out)

	// Retire: no longer wanted, with a run already going cancelled.
	gone := register("purge-readback-b")
	answer, err := cli.json("cc2-s000004", "txe", "retire", gone, "--reason", "replaced",
		"--detail", "purge-readback-a covers this purge.", "--active-runs", "cancel")
	require.NoError(t, err)
	assert.Equal(t, "retired", answer["job"].(map[string]any)["lifecycle"])
	retired := job(gone)
	assert.Equal(t, "retired", retired["lifecycle"])
	retirement = retired["retirement"].(map[string]any)
	assert.Equal(t, "replaced", retirement["reason"])
	assert.Equal(t, "cancel", retirement["active_run_policy"])

	// The CLI refuses what would say nothing, or the wrong thing, before
	// asking the hub.
	other := register("purge-readback-c")
	for args, want := range map[string]string{
		"complete|" + other + "|--detail| ":                    "--detail is required",
		"retire|" + other + "|--detail|x|--reason|completed":   `use "dagu txe complete"`,
		"retire|" + other + "|--detail|x|--reason|expired":     "the registry retires a job itself",
		"retire|" + other + "|--detail|x|--reason|gone":        `--reason "gone"`,
		"complete|" + other + "|--detail|x|--active-runs|kill": `--active-runs "kill"`,
	} {
		_, err := cli.run("cc2-s000004", append([]string{"txe"}, strings.Split(args, "|")...)...)
		require.Error(t, err, args)
		assert.Contains(t, err.Error(), want, args)
	}
	_, err = cli.run("", "txe", "complete", other, "--detail", "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pass --session or set TXE_SESSION")
	assert.Equal(t, "active", job(other)["lifecycle"], "nothing was changed")
}
