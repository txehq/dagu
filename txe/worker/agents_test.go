// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package worker_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
)

const (
	agentsMachine = "mch_01J0000000000000000000000A"
	agentsOwner   = "own_01J0000000000000000000000B"
	// agentsSecret stands in for a refresh token; it must never be printed.
	agentsSecret = "synthetic-refresh-token-must-not-be-printed"
)

func agentsScript(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the worker scripts run on the macOS worker only")
	}
	script, err := filepath.Abs("agents.py")
	require.NoError(t, err)
	return script
}

func python(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	py, lookErr := exec.LookPath("python3")
	require.NoError(t, lookErr)
	cmd := exec.Command(py, append([]string{"-I"}, args...)...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	err = cmd.Run()
	return out.String(), errOut.String(), err
}

// agentsOut writes the agents into a fresh directory whose every path has a
// space, and returns the worker agent as JSON (plistlib reads the plist).
func agentsOut(t *testing.T, credential string) (dir string, worker map[string]any) {
	t.Helper()
	script := agentsScript(t)
	base := filepath.Join(t.TempDir(), "Application Support")
	dir = filepath.Join(base, "Launch Agents")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	home := filepath.Join(base, "txe dagu")
	_, stderr, err := python(t, script, "write", dir, home, "/opt/kube ctl/kubectl", agentsMachine, agentsOwner,
		"/usr/bin:/bin", "com.txe.dagu.tunnel", "com.txe.dagu.worker", "dagu", "svc/dagu", "18080", "50055", credential)
	require.NoError(t, err, stderr)
	dump, stderr, err := python(t, "-c", `import json, plistlib, sys; print(json.dumps(plistlib.load(open(sys.argv[1], "rb"))))`,
		filepath.Join(dir, "com.txe.dagu.worker.plist"))
	require.NoError(t, err, stderr)
	require.NoError(t, json.Unmarshal([]byte(dump), &worker))
	return dir, worker
}

// Without a credential the worker agent is exactly what an install without
// one has always written: no credential setting at all.
func TestAgentsWithoutACredential(t *testing.T) {
	dir, worker := agentsOut(t, "")
	home := filepath.Join(filepath.Dir(dir), "txe dagu")
	assert.Equal(t, map[string]any{"DAGU_HOME": home + "/worker-home", "PATH": "/usr/bin:/bin"}, worker["EnvironmentVariables"])
	assert.Equal(t, []any{home + "/bin/dagu", "worker", "--worker.id", agentsMachine,
		"--worker.labels", "txe.machine=" + agentsMachine + ",txe.owner=" + agentsOwner,
		"--worker.coordinators", "127.0.0.1:50055"}, worker["ProgramArguments"])
	stdout, _, err := python(t, agentsScript(t), "credential", filepath.Join(dir, "com.txe.dagu.worker.plist"))
	require.NoError(t, err)
	assert.Empty(t, stdout)
	tunnel, err := os.ReadFile(filepath.Join(dir, "com.txe.dagu.tunnel.plist"))
	require.NoError(t, err)
	assert.Contains(t, string(tunnel), "<string>/opt/kube ctl/kubectl</string>")
}

// With a credential the worker agent passes its path, spaces and all, as one
// environment value, and nothing of its contents.
func TestAgentsPassTheCredentialPath(t *testing.T) {
	credential := "/Users/some one/Library/Application Support/txe dagu/worker credential.json"
	dir, worker := agentsOut(t, credential)
	env := worker["EnvironmentVariables"].(map[string]any)
	assert.Equal(t, credential, env["DAGU_WORKER_AUTH_CREDENTIAL_FILE"])
	assert.Len(t, env, 3)
	for _, arg := range worker["ProgramArguments"].([]any) {
		assert.NotContains(t, arg, "credential", "the path is not an argument")
	}
	stdout, _, err := python(t, agentsScript(t), "credential", filepath.Join(dir, "com.txe.dagu.worker.plist"))
	require.NoError(t, err)
	assert.Equal(t, credential+"\n", stdout)
}

// credentialFixture writes a synthetic worker credential into a private
// directory whose path has a space, and returns its path.
func credentialFixture(t *testing.T, edit func(map[string]any)) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "txe dagu")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	c := map[string]any{
		"schema": 1, "issuer": "https://idp.example/realms/r", "token_endpoint": "https://idp.example/realms/r/token",
		"client_id": "dagu-worker-x", "class": "worker", "machine_id": agentsMachine, "refresh_token": agentsSecret,
	}
	if edit != nil {
		edit(c)
	}
	raw, err := json.Marshal(c)
	require.NoError(t, err)
	path := filepath.Join(dir, "worker-credential.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

func TestCheckCredential(t *testing.T) {
	script := agentsScript(t)
	good := credentialFixture(t, nil)
	stdout, stderr, err := python(t, script, "check-credential", good, agentsMachine)
	require.NoError(t, err, stderr)
	assert.Equal(t, "credential "+good+" (machine "+agentsMachine+", client dagu-worker-x)\n", stdout)

	loopback := credentialFixture(t, func(c map[string]any) { c["token_endpoint"] = "http://127.0.0.1:8080/realms/r/token" })
	_, stderr, err = python(t, script, "check-credential", loopback, agentsMachine)
	require.NoError(t, err, stderr)

	refused := map[string]struct {
		path func(t *testing.T) string
		why  string
	}{
		"relative":      {func(*testing.T) string { return "worker-credential.json" }, "not an absolute path"},
		"missing":       {func(t *testing.T) string { return filepath.Join(t.TempDir(), "none.json") }, "run `dagu txe enrol` first"},
		"other machine": {func(t *testing.T) string { return good }, "is for machine " + agentsMachine},
		"group readable": {func(t *testing.T) string {
			p := credentialFixture(t, nil)
			require.NoError(t, os.Chmod(p, 0o640))
			return p
		}, "mode 0o640"},
		"symlink": {func(t *testing.T) string {
			link := filepath.Join(filepath.Dir(good), "link.json")
			require.NoError(t, os.Symlink(good, link))
			return link
		}, "is a symlink"},
		"directory": {func(t *testing.T) string { return filepath.Dir(good) }, "not a regular file"},
		"open directory": {func(t *testing.T) string {
			p := credentialFixture(t, nil)
			require.NoError(t, os.Chmod(filepath.Dir(p), 0o777))
			t.Cleanup(func() { _ = os.Chmod(filepath.Dir(p), 0o700) })
			return p
		}, "writable by no one else"},
		"reviewer": {func(t *testing.T) string {
			return credentialFixture(t, func(c map[string]any) { c["class"] = "reviewer" })
		}, "not a worker's"},
		"extra field": {func(t *testing.T) string {
			return credentialFixture(t, func(c map[string]any) { c["access_token"] = "x" })
		}, "unexpected ['access_token']"},
		"missing field": {func(t *testing.T) string {
			return credentialFixture(t, func(c map[string]any) { delete(c, "refresh_token") })
		}, "missing ['refresh_token']"},
		"empty token": {func(t *testing.T) string {
			return credentialFixture(t, func(c map[string]any) { c["refresh_token"] = "" })
		}, "refresh_token is missing"},
		"schema": {func(t *testing.T) string { return credentialFixture(t, func(c map[string]any) { c["schema"] = 2 }) }, "schema 2"},
		"plain http": {func(t *testing.T) string {
			return credentialFixture(t, func(c map[string]any) { c["token_endpoint"] = "http://idp.example/token" })
		}, "must use https"},
		"not json": {func(t *testing.T) string {
			p := credentialFixture(t, nil)
			require.NoError(t, os.WriteFile(p, []byte("{"+agentsSecret), 0o600))
			return p
		}, "not a readable JSON"},
	}
	for name, tc := range refused {
		t.Run(name, func(t *testing.T) {
			machine := agentsMachine
			if name == "other machine" {
				machine = "mch_01J0000000000000000000000C"
			}
			stdout, stderr, err := python(t, script, "check-credential", tc.path(t), machine)
			require.Error(t, err)
			assert.Empty(t, stdout)
			assert.Contains(t, stderr, tc.why)
			assert.NotContains(t, stdout+stderr, agentsSecret, "no token is printed")
		})
	}
}

// worker_credential in lib.sh: an explicit file, enrol's default when it
// exists, or nothing; a bad file fails the install with the reason.
func TestWorkerCredentialChoice(t *testing.T) {
	agentsScript(t)
	lib, err := filepath.Abs("lib.sh")
	require.NoError(t, err)
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	run := func(home, given, path string) (string, string, error) {
		cmd := exec.Command(bash, "-c", `set -euo pipefail; . "$1"; worker_credential "$2" "$3" "$4"`, "bash", lib, given, path, agentsMachine)
		cmd.Env = []string{"HOME=" + t.TempDir(), "TXE_DAGU_HOME=" + home, "PATH=/usr/bin:/bin"}
		var out, errOut bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errOut
		err := cmd.Run()
		return out.String(), errOut.String(), err
	}

	empty := filepath.Join(t.TempDir(), "txe home")
	require.NoError(t, os.MkdirAll(empty, 0o700))
	stdout, stderr, err := run(empty, "0", "")
	require.NoError(t, err, stderr)
	assert.Empty(t, stdout, "no credential: nothing changes")

	enrolled := credentialFixture(t, nil)
	stdout, stderr, err = run(filepath.Dir(enrolled), "0", "")
	require.NoError(t, err, stderr)
	assert.Equal(t, enrolled+"\n", stdout, "enrol's default is used")

	custom := credentialFixture(t, nil)
	stdout, stderr, err = run(empty, "1", custom)
	require.NoError(t, err, stderr)
	assert.Equal(t, custom+"\n", stdout, "an explicit file wins")

	_, stderr, err = run(empty, "1", filepath.Join(empty, "missing.json"))
	require.Error(t, err, "an explicit file that is not there is refused, not skipped")
	assert.Contains(t, stderr, "does not exist")

	bad := credentialFixture(t, nil)
	require.NoError(t, os.Chmod(bad, 0o644))
	_, stderr, err = run(filepath.Dir(bad), "0", "")
	require.Error(t, err, "a bad default is refused, not skipped")
	assert.Contains(t, stderr, "0600")
	assert.False(t, strings.Contains(stderr, agentsSecret))
}

// The install's check never accepts a credential the worker's own loader
// (transportauth) refuses: such a worker would fail at start and launchd
// would restart it forever. Python may be stricter, never looser.
func TestCheckCredentialAgreesWithTheWorker(t *testing.T) {
	script := agentsScript(t)
	cases := map[string]func(map[string]any){
		"good":                func(map[string]any) {},
		"loopback http":       func(c map[string]any) { c["token_endpoint"] = "http://127.0.0.1:8080/realms/r/token" },
		"loopback v6":         func(c map[string]any) { c["token_endpoint"] = "http://[::1]:8080/token" },
		"localhost":           func(c map[string]any) { c["token_endpoint"] = "http://localhost:8080/token" },
		"LOCALHOST":           func(c map[string]any) { c["token_endpoint"] = "http://LOCALHOST:8080/token" },
		"no host":             func(c map[string]any) { c["token_endpoint"] = "https:///token" },
		"user info":           func(c map[string]any) { c["token_endpoint"] = "https://user:pass@idp.example/token" },
		"fragment":            func(c map[string]any) { c["token_endpoint"] = "https://idp.example/token#f" },
		"bad port":            func(c map[string]any) { c["token_endpoint"] = "https://idp.example:99999x/token" },
		"relative":            func(c map[string]any) { c["token_endpoint"] = "/token" },
		"plain http":          func(c map[string]any) { c["token_endpoint"] = "http://idp.example/token" },
		"schema float":        func(c map[string]any) { c["schema"] = 1.0 },
		"schema string":       func(c map[string]any) { c["schema"] = "1" },
		"schema 2":            func(c map[string]any) { c["schema"] = 2 },
		"class":               func(c map[string]any) { c["class"] = "reviewer" },
		"spaced issuer":       func(c map[string]any) { c["issuer"] = " https://idp.example/realms/r" },
		"numeric client":      func(c map[string]any) { c["client_id"] = 7 },
		"extra field":         func(c map[string]any) { c["extra"] = "x" },
		"missing field":       func(c map[string]any) { delete(c, "issuer") },
		"empty refresh token": func(c map[string]any) { c["refresh_token"] = "" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			path := credentialFixture(t, edit)
			if name == "schema float" {
				// encoding/json writes 1.0 as 1; write the JSON text by hand.
				raw, err := os.ReadFile(path)
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(path, bytes.Replace(raw, []byte(`"schema":1`), []byte(`"schema":1.0`), 1), 0o600))
			}
			_, pyErr, err := python(t, script, "check-credential", path, agentsMachine)
			pyAccepts := err == nil
			_, goErr := transportauth.ReadMachineCredential(path)
			if pyAccepts {
				assert.NoError(t, goErr, "the install accepts what the worker refuses")
			}
			if goErr != nil {
				assert.False(t, pyAccepts, "worker refuses (%v); install accepted", goErr)
			}
			assert.NotContains(t, pyErr, agentsSecret)
		})
	}
}
