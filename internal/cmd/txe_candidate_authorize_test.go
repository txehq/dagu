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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

const txeAuthorizeSpec = `schema: 1
job_key: %s
title: Restart the exporter when its snapshot is missing
purpose: Exercise a permitted action's parameter schema from the job spec to the registry's grant.
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
  include: [collect.sh, restart.sh]
  entrypoint: [./collect.sh]
expected_outcome:
  success_criteria: ["A snapshot exists."]
lifetime:
  expires_at: "2027-01-31T00:00:00Z"
review_policy:
  cadence: "0 9 * * *"
  brief: Check that the snapshot exists.
  permitted_actions:
    - name: restart
      command: ./restart.sh
      routine: true
      timeout_sec: 60
      param_schema:
%s
`

const txeAuthorizeSchema = `        type: object
        properties:
          mode: {type: string, enum: [soft, hard]}
        required: [mode]
        additionalProperties: false`

// A schema that promises a restriction nothing checks: format.
const txeInadmissibleSchema = `        type: object
        properties:
          contact: {type: string, format: email}`

// A permitted action's parameter schema, from a job spec to the registry's
// grant, on a real hub with authentication on.
//
// The registry is one that says it enforces schemas. The job is registered
// through the CLI, so the schema the registry holds is the one the CLI read
// from the spec. A review claim is taken over HTTP and routine attempts of
// the action are requested with parameters the schema refuses and with
// parameters it admits. The refused ones get no grant and leave no action;
// the admitted one is granted.
//
// It does not run the action's command: that is the reviewer's side.
func TestTXECandidateParamSchemaAtAuthorize(t *testing.T) {
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

	access := &strings.Builder{}
	note := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		t.Log(line)
		access.WriteString(line + "\n")
	}
	defer func() { txeKeep(t, "access.txt", []byte(access.String())) }()

	home := txeDurableHome(t)
	cli := &txeCLI{t: t, binary: binary, home: home, userDir: t.TempDir()}
	identity := fmt.Sprintf(`{"schema":1,"machine_id":%q,"owner_id":%q,"display_name":"candidate-mac"}`, txeITMachine, txeITOwner)
	require.NoError(t, os.WriteFile(filepath.Join(home, "machine.json"), []byte(identity), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "bin"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(home, "bin", "dagu"), fmt.Appendf(nil, "#!/bin/sh\nexec %q \"$@\"\n", binary), 0o700)) //nolint:gosec // a test script

	_, err := cli.run("installer", "context", "add", "txe", "--server="+hub.base, "--api-key="+who.cli, "--dagu-home="+filepath.Join(home, "client"))
	require.NoError(t, err)
	actor := map[string]any{"kind": "cli", "id": "installer"}
	code, _, raw := hub.callAs(who.admin, http.MethodPost, "/txe/owners", map[string]any{"owner_id": txeITOwner, "display_name": "Connor Wang", "actor": actor})
	require.Less(t, code, 300, raw)
	code, _, raw = hub.callAs(who.admin, http.MethodPost, "/txe/machines", map[string]any{"machine_id": txeITMachine, "owner_id": txeITOwner, "display_name": "candidate-mac", "actor": actor})
	require.Less(t, code, 300, raw)

	// The registry says it enforces parameter schemas.
	code, installation, raw := hub.call(http.MethodGet, "/txe/installation", nil)
	require.Equal(t, http.StatusOK, code, raw)
	txeKeep(t, "raw/01-installation.json", []byte(raw))
	require.Contains(t, installation["capabilities"], "param_schema", raw)

	worktree := filepath.Join(t.TempDir(), "worktree")
	require.NoError(t, os.MkdirAll(worktree, 0o755))
	for _, name := range []string{"collect.sh", "restart.sh"} {
		require.NoError(t, os.WriteFile(filepath.Join(worktree, name), []byte("#!/bin/sh\nexit 0\n"), 0o755)) //nolint:gosec // a test script
	}
	specPath := filepath.Join(worktree, "job.yaml")
	writeSpec := func(key, schema string) {
		require.NoError(t, os.WriteFile(specPath, fmt.Appendf(nil, txeAuthorizeSpec, key, schema), 0o644)) //nolint:gosec // test file
	}

	// A schema the registry cannot enforce exactly is refused by the
	// registry, in its own words, and leaves no job.
	writeSpec("inadmissible-schema", txeInadmissibleSchema)
	out, err := cli.run("cc2-s000001", "txe", "register", "-f", specPath, "--json")
	require.Error(t, err, "a schema that uses format was registered: %s", out)
	txeKeep(t, "raw/02-inadmissible-schema-registration.txt", []byte(out+"\n"+err.Error()+"\n"))
	assert.Contains(t, out+err.Error(), "param_schema")
	assert.Contains(t, out+err.Error(), "format")
	code, _, raw = hub.call(http.MethodGet, "/txe/jobs", nil)
	require.Equal(t, http.StatusOK, code, raw)
	assert.NotContains(t, raw, "inadmissible-schema")

	// The job, registered through the CLI.
	writeSpec("bounded-restart", txeAuthorizeSchema)
	registered, err := cli.json("cc2-s000001", "txe", "register", "-f", specPath)
	require.NoError(t, err, "register: %v", registered)
	receipt, _ := registered["receipt"].(map[string]any)
	jobID, _ := receipt["job_id"].(string)
	digest, _ := receipt["package_digest"].(string)
	require.NotEmpty(t, jobID, "no receipt: %v", registered)
	require.NotEmpty(t, digest, "no package digest: %v", registered)
	code, version, raw := hub.call(http.MethodGet, "/txe/jobs/"+jobID+"/versions/1", nil)
	require.Equal(t, http.StatusOK, code, raw)
	txeKeep(t, "raw/03-registry-version-1.json", []byte(raw))
	policy, _ := version["review_policy"].(map[string]any)
	actions, _ := policy["permitted_actions"].([]any)
	require.Len(t, actions, 1, raw)
	action, _ := actions[0].(map[string]any)
	assert.Equal(t, map[string]any{
		"type":                 "object",
		"properties":           map[string]any{"mode": map[string]any{"type": "string", "enum": []any{"soft", "hard"}}},
		"required":             []any{"mode"},
		"additionalProperties": false,
	}, action["param_schema"])

	// A review claim, as a reviewer on the job's machine takes one.
	reviewer := map[string]any{"kind": "reviewer", "id": "candidate-reviewer"}
	claimBody := map[string]any{"kind": "review", "ttl_sec": 600, "reviewer": map[string]any{"machine_id": txeITMachine}, "actor": reviewer}
	bearer := who.cli
	code, claim, raw := hub.callAs(bearer, http.MethodPost, "/txe/jobs/"+jobID+"/claims", claimBody)
	note("CLI key, POST /txe/jobs/<job>/claims: HTTP %d", code)
	if code == http.StatusForbidden {
		bearer = who.admin
		code, claim, raw = hub.callAs(bearer, http.MethodPost, "/txe/jobs/"+jobID+"/claims", claimBody)
		note("admin session, POST /txe/jobs/<job>/claims: HTTP %d", code)
	}
	require.Equal(t, http.StatusOK, code, raw)
	txeKeep(t, "raw/04-claim.json", []byte(raw))
	claimID, _ := claim["claim_id"].(string)
	fence, _ := claim["fence"].(float64)
	require.NotEmpty(t, claimID, raw)
	review, err := registry.ReviewID(jobID, 0)
	require.NoError(t, err)

	authorize := func(params string) (int, string) {
		actionID, err := registry.RoutineActionID(review, registry.ActionSpec{Name: "restart", Params: json.RawMessage(params)})
		require.NoError(t, err)
		body := json.RawMessage(fmt.Sprintf(`{"action_id":%q,"job_version":1,"package_digest":%q,"routine":{"review_id":%q,"claim_id":%q,"fence":%d,"spec":{"name":"restart","params":%s}},"actor":{"kind":"reviewer","id":"candidate-reviewer"}}`,
			actionID, digest, review, claimID, int64(fence), params))
		code, _, raw := hub.callAs(bearer, http.MethodPost, "/txe/jobs/"+jobID+"/effect-grants", body)
		return code, raw
	}
	recorded := func(name string) string {
		code, _, raw := hub.callAs(bearer, http.MethodGet, "/txe/jobs/"+jobID+"/actions", nil)
		require.Equal(t, http.StatusOK, code, raw)
		txeKeep(t, name, []byte(raw))
		return raw
	}

	// Parameters the schema refuses: no grant, and no action is recorded.
	refused := []struct{ name, params string }{
		{"value-outside-enum", `{"mode":"medium"}`},
		{"undeclared-parameter", `{"mode":"soft","force":true}`},
		{"required-parameter-missing", `{}`},
		{"parameter-given-twice", `{"mode":"soft","mode":"hard"}`},
		{"wrong-type", `{"mode":1}`},
	}
	for i, tc := range refused {
		code, raw := authorize(tc.params)
		txeKeep(t, fmt.Sprintf("raw/05-%d-refused-%s.json", i+1, tc.name), []byte(raw))
		note("authorize restart with %s: HTTP %d", tc.params, code)
		assert.Equal(t, http.StatusBadRequest, code, "%s: %s", tc.params, raw)
		assert.NotContains(t, raw, `"grant`, tc.params)
	}
	after := recorded("raw/06-actions-after-refusals.json")
	assert.NotContains(t, after, "restart", "a refused attempt left an action")
	code, _, raw = hub.callAs(bearer, http.MethodGet, "/txe/jobs/"+jobID, nil)
	require.Equal(t, http.StatusOK, code, raw)
	txeKeep(t, "raw/07-job-after-refusals.json", []byte(raw))
	assert.NotContains(t, raw, `"grant`)

	// Parameters the schema admits: granted, and the action is recorded.
	code, raw = authorize(`{"mode":"hard"}`)
	txeKeep(t, "raw/08-granted.json", []byte(raw))
	note(`authorize restart with {"mode":"hard"}: HTTP %d`, code)
	require.Less(t, code, 300, raw)
	after = recorded("raw/09-actions-after-grant.json")
	assert.Contains(t, after, "restart")
	assert.Contains(t, after, `"mode":"hard"`)
}
