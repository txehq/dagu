// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd_test

import (
	"encoding/json"
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
      param_schema:
%s
    - name: recount
      command: ./recount.sh
      timeout_sec: 30
`

const txeAdmittedSchema = `        type: object
        properties:
          reason: {type: string, maxLength: 200, pattern: "^[a-z <&]+$"}
        required: [reason]
        additionalProperties: false`

// A schema that promises a restriction nothing checks: format.
const txeRefusedSchema = `        type: object
        properties:
          contact: {type: string, format: email}`

// A permitted action's param_schema, declared in a job spec, against the
// registry's real registration endpoint with authentication on.
//
// It shows three things: the registry stores the schema the spec declared;
// the version the registry answers equals the request filed on the machine
// in every field that says what a job's commands are; and a schema the
// registry does not admit is refused and leaves no job.
func TestTXECandidateParamSchema(t *testing.T) {
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

	// 1. The registry stores the schema the spec declared.
	writeSpec("bounded-action", txeAdmittedSchema)
	registered, err := cli.json("cc2-s000001", "txe", "register", "-f", specPath)
	require.NoError(t, err, "register: %v", registered)
	receipt, _ := registered["receipt"].(map[string]any)
	jobID, _ := receipt["job_id"].(string)
	requestID, _ := receipt["request_id"].(string)
	require.NotEmpty(t, jobID, "no receipt: %v", registered)
	require.NotEmpty(t, requestID, "no request id: %v", registered)

	code, version, raw := hub.call(http.MethodGet, "/txe/jobs/"+jobID+"/versions/1", nil)
	require.Equal(t, http.StatusOK, code, raw)
	txeKeep(t, "raw/registry-version-1.json", []byte(raw))
	policy, _ := version["review_policy"].(map[string]any)
	actions, _ := policy["permitted_actions"].([]any)
	require.Len(t, actions, 2, raw)
	bounded, _ := actions[0].(map[string]any)
	unbounded, _ := actions[1].(map[string]any)
	assert.Equal(t, map[string]any{
		"type": "object",
		"properties": map[string]any{
			"reason": map[string]any{"type": "string", "maxLength": float64(200), "pattern": "^[a-z <&]+$"},
		},
		"required":             []any{"reason"},
		"additionalProperties": false,
	}, bounded["param_schema"], "the registry's version 1")
	assert.NotContains(t, unbounded, "param_schema")

	// 2. The request filed on the machine equals the registry's version in
	// every field that says what the job's commands are.
	filedPath := filepath.Join(home, "receipts", jobID, "requests", requestID+".json")
	filedRaw, err := os.ReadFile(filedPath) //nolint:gosec // test directory
	require.NoError(t, err)
	txeKeep(t, "raw/filed-request.json", filedRaw)
	var filed struct {
		Request struct {
			Version map[string]any `json:"version"`
		} `json:"request"`
	}
	require.NoError(t, json.Unmarshal(filedRaw, &filed))
	sentPackage, _ := filed.Request.Version["package"].(map[string]any)
	gotPackage, _ := version["package"].(map[string]any)
	for _, field := range []string{"digest", "path", "working_dir", "entrypoint", "credential_refs"} {
		require.Contains(t, sentPackage, field)
		assert.Equal(t, sentPackage[field], gotPackage[field], "package.%s", field)
	}
	sentPolicy, _ := filed.Request.Version["review_policy"].(map[string]any)
	assert.Equal(t, float64(2), sentPolicy["max_attempts"])
	assert.Equal(t, sentPolicy["max_attempts"], policy["max_attempts"], "review_policy.max_attempts")
	assert.Equal(t, sentPolicy["permitted_actions"], policy["permitted_actions"], "review_policy.permitted_actions")
	// The registry adds nothing to an action and drops nothing from it.
	assert.Equal(t, map[string]any{
		"name": "reopen-ticket", "command": `./reopen.sh "$TXE_PARAM_REASON" 2>&1`, "idempotency": "keyed",
		"timeout_sec": float64(60), "max_attempts": float64(3), "routine": false, "param_schema": bounded["param_schema"],
	}, bounded)
	assert.Equal(t, map[string]any{"name": "recount", "command": "./recount.sh", "timeout_sec": float64(30), "routine": false}, unbounded)

	// 3. A schema that promises a restriction nothing checks. A registry
	// that admits schemas refuses it and keeps no job; one that only stores
	// them accepts it. Which this registry does is recorded either way, and
	// asserted only when TXE_REGISTRY_ADMITS_SCHEMAS says it must refuse.
	writeSpec("refused-action", txeRefusedSchema)
	out, err := cli.run("cc2-s000001", "txe", "register", "-f", specPath, "--json")
	outcome := "ACCEPTED: this registry stored a param_schema that uses format\n"
	if err != nil {
		outcome = "REFUSED: " + err.Error() + "\n"
	}
	t.Log(outcome)
	txeKeep(t, "raw/format-schema-registration.txt", []byte(outcome+out))
	code, _, raw = hub.call(http.MethodGet, "/txe/jobs", nil)
	require.Equal(t, http.StatusOK, code, raw)
	txeKeep(t, "raw/registry-jobs-after-format-schema.json", []byte(raw))
	assert.Contains(t, raw, "bounded-action")
	if os.Getenv("TXE_REGISTRY_ADMITS_SCHEMAS") == "1" {
		require.Error(t, err, "a schema with format was registered: %s", out)
		assert.Contains(t, out+err.Error(), "param_schema")
		assert.NotContains(t, raw, "refused-action")
	}
	for _, kept := range [][]byte{[]byte(raw), filedRaw} {
		assert.NotContains(t, string(kept), "txe-sentinel-credential")
	}
}
