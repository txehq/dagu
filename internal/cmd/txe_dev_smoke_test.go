// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The smoke test the Integrations page's developer guide gives
// (txe/developer/smoke, TXE-4938) goes through the built CLI the way the guide
// says: a dry run that registers nothing, the registration, inspect and
// package verify, against a hub with the real registry. Its script runs as
// the worker would start it, and the lifetime the page writes is the one the
// registry keeps, so the job retires itself.
func TestTXEDeveloperSmokeJob(t *testing.T) {
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

	// The files as the page writes them: the stamp and the lifetime filled in.
	now := time.Now().UTC()
	stamp := now.Format("20060102150405") + "-0a1b2c"
	expires := now.Truncate(time.Minute).Add(15 * time.Minute).Format(time.RFC3339)
	template, err := os.ReadFile(filepath.Join("..", "..", "txe", "developer", "smoke", "job.yaml"))
	require.NoError(t, err)
	script, err := os.ReadFile(filepath.Join("..", "..", "txe", "developer", "smoke", "run.sh"))
	require.NoError(t, err)
	spec := strings.NewReplacer("{{STAMP}}", stamp, "{{EXPIRES_AT}}", expires).Replace(string(template))
	require.NotContains(t, spec, "{{")
	dir := filepath.Join(t.TempDir(), "txe-dev-setup-smoke")
	require.NoError(t, os.MkdirAll(dir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "job.yaml"), []byte(spec), 0o644)) //nolint:gosec // test file
	require.NoError(t, os.WriteFile(filepath.Join(dir, "run.sh"), script, 0o755))         //nolint:gosec // test script
	jobYAML := filepath.Join(dir, "job.yaml")
	session := "dev-setup-smoke"

	_, err = cli.run(session, "txe", "skill", "install")
	require.NoError(t, err)
	doctor, err := cli.run(session, "txe", "doctor")
	require.NoError(t, err, doctor)
	assert.Contains(t, doctor, "machine on hub")
	assert.NotContains(t, doctor, "FAIL")

	plan, err := cli.run(session, "txe", "register", "-f", jobYAML, "--dry-run")
	require.NoError(t, err)
	assert.Contains(t, plan, "The spec is complete. Nothing was registered.")
	assert.Contains(t, plan, "run.sh")
	listed, err := cli.json(session, "txe", "list", "--job-key", "dev-setup-smoke-"+stamp)
	require.NoError(t, err)
	assert.Empty(t, txeJobs(t, listed), "a dry run registered nothing")

	registered, err := cli.run(session, "txe", "register", "-f", jobYAML)
	require.NoError(t, err)
	assert.Contains(t, registered, "version 1. The hub has marked it ready.")
	found, err := cli.json(session, "txe", "list", "--job-key", "dev-setup-smoke-"+stamp)
	require.NoError(t, err)
	jobs := txeJobs(t, found)
	require.Len(t, jobs, 1)
	jobID := jobs[0].(map[string]any)["job_id"].(string)
	assert.Contains(t, registered, "Registered "+jobID)

	inspected, err := cli.json(session, "txe", "inspect", jobID)
	require.NoError(t, err)
	job := inspected["job"].(map[string]any)
	assert.Equal(t, "ready", job["registration"].(map[string]any)["state"])
	assert.Equal(t, expires, job["expires_at"], "the registry keeps the lifetime the page wrote")
	text, err := cli.run(session, "txe", "inspect", jobID)
	require.NoError(t, err)
	assert.Contains(t, text, jobID)

	verified, err := cli.run(session, "txe", "package", "verify", jobID)
	require.NoError(t, err)
	assert.Contains(t, verified, "the package is intact and the hub has marked the job ready.")

	// A second registration of the same files is refused, so following the
	// guide twice with one stamp cannot make a second job.
	_, err = cli.run(session, "txe", "register", "-f", jobYAML)
	require.Error(t, err)

	// The script as the worker starts it: an empty run output directory and
	// little else in the environment.
	out := t.TempDir()
	run := exec.Command(filepath.Join(dir, "run.sh")) //nolint:gosec // the test's own script
	run.Dir = dir
	run.Env = []string{"PATH=/usr/bin:/bin", "TXE_RUN_OUTPUT_DIR=" + out}
	printed, err := run.Output()
	require.NoError(t, err)
	result, err := os.ReadFile(filepath.Join(out, "result.json"))
	require.NoError(t, err)
	assert.Equal(t, string(printed), string(result))
	assert.Regexp(t, `^\{"ok":true,"observed_at":"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"\}\n$`, string(result))
}
