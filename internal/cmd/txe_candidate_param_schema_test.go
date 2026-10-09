// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd_test

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/test"
)

const txeParamSchemaSpec = `schema: 1
job_key: %s
title: Reopen a ticket when a snapshot is missing
purpose: Exercise the registry's real registration endpoint with a permitted action that bounds its parameters.
project:
  key: github.com/txehq/txe
  name: txehq/txe
targets:
  - kind: fixture.directory
    environment: test
    stable_id: {id: exports-0001}
schedule:
  cron: "0 2 1 1 *"
  timezone: Australia/Perth
  timeout_sec: 300
package:
  include: [collect.sh, reopen.sh]
  entrypoint: [./collect.sh]
credential_refs:
  - name: LINEAR_API_KEY
    kind: file
    locator: %s
expected_outcome:
  success_criteria: ["A snapshot exists."]
lifetime:
  expires_at: "2027-01-31T00:00:00Z"
review_policy:
  cadence: "0 9 * * *"
  max_attempts: 2
  brief: Check that the snapshot exists.
  permitted_actions:
    - name: reopen-ticket
      command: ./reopen.sh "$TXE_PARAM_REASON" 2>&1
      idempotency: keyed
      timeout_sec: 60
      max_attempts: 3
%s    - name: recount
      command: ./recount.sh
      timeout_sec: 30
`

const txeAdmittedSchema = `      param_schema:
        type: object
        properties:
          reason: {type: string, maxLength: 200, pattern: "^[a-z <&]+$"}
        required: [reason]
        additionalProperties: false
`

// The client's gate against a real registry that does not say it enforces
// parameter schemas (it lists no capabilities in its installation record).
//
// Registering a spec that declares a param_schema, or planning it, is
// refused before anything is sent, and the registry holds no job. The same
// job without the schema registers.
//
// What this registry does with a schema it is sent, measured before the gate
// existed, is in the history of this file and under
// 2026-10-10-param-schema-candidate in the evidence directory.
func TestTXECandidateParamSchemaGate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("job packages are shell scripts run by a Unix worker")
	}
	if testing.Short() {
		t.Skip("starts a real hub process")
	}

	apiPort, coordPort := findPort(t), findPort(t)
	hubHelper := test.SetupCommand(t, test.WithBuiltExecutable(), test.WithCoordinatorEnabled(), txeBuiltinAuth(txeRandom(t)))
	binary := hubHelper.Config.Paths.Executable
	hub := &txeHub{t: t, base: "http://127.0.0.1:" + apiPort + "/api/v1"}
	txeStartProcess(t, "hub", binary, hubHelper.Config.Core.BaseEnv.AsSlice(),
		"start-all", "--config", hubHelper.Config.Paths.ConfigFileUsed, "--host=127.0.0.1", "--port="+apiPort,
		"--coordinator.host=127.0.0.1", "--coordinator.advertise=127.0.0.1", "--coordinator.port="+coordPort,
		"--peer.insecure=true")
	hub.waitUp()
	who := txeBootstrapAuth(t, hub)
	hub.bearer = who.cli

	home := txeDurableHome(t)
	cli := &txeCLI{t: t, binary: binary, home: home, userDir: t.TempDir()}
	identity := fmt.Sprintf(`{"schema":1,"machine_id":%q,"owner_id":%q,"display_name":"candidate-mac"}`, txeITMachine, txeITOwner)
	require.NoError(t, os.WriteFile(filepath.Join(home, "machine.json"), []byte(identity), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "bin"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(home, "bin", "dagu"), fmt.Appendf(nil, "#!/bin/sh\nexec %q \"$@\"\n", binary), 0o700)) //nolint:gosec // a test script
	credential := filepath.Join(home, "linear-token")
	require.NoError(t, os.WriteFile(credential, []byte("txe-sentinel-credential-9f8e7d\n"), 0o600))

	_, err := cli.run("installer", "context", "add", "txe", "--server="+hub.base, "--api-key="+who.cli, "--dagu-home="+filepath.Join(home, "client"))
	require.NoError(t, err)
	actor := map[string]any{"kind": "cli", "id": "installer"}
	code, _, raw := hub.callAs(who.admin, http.MethodPost, "/txe/owners", map[string]any{"owner_id": txeITOwner, "display_name": "Connor Wang", "actor": actor})
	require.Less(t, code, 300, raw)
	code, _, raw = hub.callAs(who.admin, http.MethodPost, "/txe/machines", map[string]any{"machine_id": txeITMachine, "owner_id": txeITOwner, "display_name": "candidate-mac", "actor": actor})
	require.Less(t, code, 300, raw)

	worktree := filepath.Join(t.TempDir(), "worktree")
	require.NoError(t, os.MkdirAll(worktree, 0o755))
	for _, name := range []string{"collect.sh", "reopen.sh"} {
		require.NoError(t, os.WriteFile(filepath.Join(worktree, name), []byte("#!/bin/sh\nexit 0\n"), 0o755)) //nolint:gosec // a test script
	}
	specPath := filepath.Join(worktree, "job.yaml")
	writeSpec := func(key, schema string) {
		require.NoError(t, os.WriteFile(specPath, fmt.Appendf(nil, txeParamSchemaSpec, key, credential, schema), 0o644)) //nolint:gosec // test file
	}

	code, installation, raw := hub.call(http.MethodGet, "/txe/installation", nil)
	require.Equal(t, http.StatusOK, code, raw)
	txeKeep(t, "raw/registry-installation.json", []byte(raw))
	require.NotContains(t, installation, "capabilities", "this registry lists capabilities; the gate's refusal cannot be shown against it")

	writeSpec("bounded-action", txeAdmittedSchema)
	for name, args := range map[string][]string{
		"register": {"txe", "register", "-f", specPath, "--json"},
		"dry-run":  {"txe", "register", "-f", specPath, "--dry-run", "--json"},
	} {
		out, err := cli.run("cc2-s000001", args...)
		require.Error(t, err, "%v was not refused: %s", args, out)
		txeKeep(t, "raw/refused-"+name+".txt", []byte(out+"\n"+err.Error()+"\n"))
		assert.Contains(t, out+err.Error(), "does not say it checks action parameters")
		assert.Contains(t, out+err.Error(), "reopen-ticket")
	}
	code, _, raw = hub.call(http.MethodGet, "/txe/jobs", nil)
	require.Equal(t, http.StatusOK, code, raw)
	txeKeep(t, "raw/registry-jobs-after-refusal.json", []byte(raw))
	assert.NotContains(t, raw, "bounded-action")
	pending, _ := filepath.Glob(filepath.Join(home, "receipts", "pending", "*.json"))
	assert.Empty(t, pending, "a refused registration left a journal entry")

	writeSpec("unbounded-action", "")
	registered, err := cli.json("cc2-s000001", "txe", "register", "-f", specPath)
	require.NoError(t, err, "register: %v", registered)
	code, _, raw = hub.call(http.MethodGet, "/txe/jobs", nil)
	require.Equal(t, http.StatusOK, code, raw)
	txeKeep(t, "raw/registry-jobs-after-unbounded.json", []byte(raw))
	assert.Contains(t, raw, "unbounded-action")
	assert.NotContains(t, raw, "txe-sentinel-credential")
}
