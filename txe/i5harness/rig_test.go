// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package i5harness_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func rig(t *testing.T, args ...string) (string, int) {
	t.Helper()
	return rigEnv(t, nil, args...)
}

func rigEnv(t *testing.T, env []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{"rig.sh"}, args...)...)
	cmd.Env = append(append(os.Environ(), "I5_PYTHON="+python(t)), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exit *exec.ExitError
		require.ErrorAs(t, err, &exit, string(out))
		return string(out), exit.ExitCode()
	}
	return string(out), 0
}

type fakeRig struct {
	root, manifest, hub, worker, reviewer, profile, claudeDir, repo string
}

// newFakeRig pins three stand-in binaries in a manifest written by pin.py. Only
// init and the step guards run against it: nothing is started.
func newFakeRig(t *testing.T) fakeRig {
	t.Helper()
	dir := shortDir(t)
	f := fakeRig{root: filepath.Join(dir, "rig"), profile: filepath.Join(dir, "profile"), claudeDir: filepath.Join(dir, "claude-bin")}
	repo, err := filepath.Abs("../..")
	require.NoError(t, err)
	f.repo = repo
	require.NoError(t, os.MkdirAll(f.profile, 0o700))
	write(t, filepath.Join(f.claudeDir, "claude"), "#!/bin/sh\nexit 0\n")
	require.NoError(t, os.Chmod(filepath.Join(f.claudeDir, "claude"), 0o755))
	var records []string
	for _, role := range []string{"H", "W/C", "R"} {
		name := strings.ReplaceAll(role, "/", "")
		bin := write(t, filepath.Join(dir, "bin", "dagu-"+name), "#!/bin/sh\necho "+name+"\n")
		rec, _ := json.Marshal(map[string]string{"role": role, "path": bin, "sha256": sha(t, bin)})
		records = append(records, write(t, filepath.Join(dir, "records", name+".json"), string(rec)))
		switch role {
		case "H":
			f.hub = bin
		case "W/C":
			f.worker = bin
		default:
			f.reviewer = bin
		}
	}
	f.manifest = filepath.Join(dir, "manifest.json")
	args := []string{"manifest", "--out", f.manifest, "--harness-dir", "."}
	for _, r := range records {
		args = append(args, "--record", r)
	}
	out, code := tool(t, "pin.py", args...)
	require.Equal(t, 0, code, out)
	return f
}

func (f fakeRig) init(t *testing.T, override ...string) (string, int) {
	t.Helper()
	opts := map[string]string{"--rig": f.root, "--manifest": f.manifest, "--hub-bin": f.hub, "--worker-bin": f.worker,
		"--reviewer-bin": f.reviewer, "--profile": f.profile, "--claude-bin-dir": f.claudeDir, "--repo": f.repo}
	for i := 0; i+1 < len(override); i += 2 {
		opts[override[i]] = override[i+1]
	}
	args := []string{"init"}
	for k, v := range opts {
		args = append(args, k, v)
	}
	return rig(t, args...)
}

func TestRigInitRendersAPreflightedRigAndStartsNothing(t *testing.T) {
	f := newFakeRig(t)
	out, code := f.init(t)
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, "PREFLIGHT OK: config binds [::1]:28255, advertises 127.0.0.1:28255")

	cfg, err := os.ReadFile(filepath.Join(f.root, "hub", "config.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(cfg), "host: \"[::1]\"\n  advertise: 127.0.0.1\n  port: 28255")
	info, err := os.Stat(filepath.Join(f.root, "hub", "config.yaml"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "the config holds the synthetic admin password")
	job, err := os.ReadFile(filepath.Join(f.root, "job", "job.yaml"))
	require.NoError(t, err)
	assert.Contains(t, string(job), `I5_CONTROL_DIR: "`+f.root+`/control"`)
	link, err := os.Readlink(filepath.Join(f.root, "machine-home", "bin", "dagu"))
	require.NoError(t, err)
	assert.Equal(t, f.worker, link, "the machine CLI is the pinned W/C binary")
	for _, pid := range []string{"hub.pid", "relay.pid", "worker.pid"} {
		assert.NoFileExists(t, filepath.Join(f.root, "control", pid), "init starts no process")
	}

	out, code = f.init(t)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, out, "exists and is not empty")
}

func TestRigInitRefusesSharedPathsAndUnpinnedBinaries(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)
	f := newFakeRig(t)
	for name, tc := range map[string]struct {
		override []string
		want     string
	}{
		"the shared installation": {[]string{"--rig", filepath.Join(home, ".local/share/txe-dagu/rig")}, "that is the shared installation"},
		"the live reviewer":       {[]string{"--profile", filepath.Join(home, ".claude5")}, "live reviewer's profile"},
		"an unpinned binary":      {[]string{"--reviewer-bin", "/bin/sh"}, "is not a binary the manifest pins"},
		"no claude":               {[]string{"--claude-bin-dir", t.TempDir()}, "no claude in"},
	} {
		out, code := f.init(t, tc.override...)
		assert.NotEqual(t, 0, code, name)
		assert.Contains(t, out, tc.want, name)
		assert.NoDirExists(t, f.root, "%s: nothing is created", name)
	}
}

// The steps run in order, each at most once, and the decision needs the
// reference of the message that authorised it: the harness never decides on
// its own (root ruling: no auto-approval as if by Connor).
func TestRigStepGuards(t *testing.T) {
	f := newFakeRig(t)
	out, code := f.init(t)
	require.Equal(t, 0, code, out)

	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"loss before up":       {[]string{"loss", "--rig", f.root}, "step up has not completed"},
		"tick before eligible": {[]string{"review-tick", "--rig", f.root}, "step eligibility has not completed"},
		"second tick early":    {[]string{"review-tick", "--rig", f.root, "--post-decision"}, "step decided has not completed"},
		"decide unauthorised":  {[]string{"decide", "--rig", f.root, "--proposal", "prp_1", "--verdict", "retry"}, "--authority"},
		"decide before a tick": {[]string{"decide", "--rig", f.root, "--proposal", "prp_1", "--verdict", "retry", "--authority", "msg_x"}, "step tick1 has not completed"},
	} {
		out, code := rig(t, tc.args...)
		assert.NotEqual(t, 0, code, name)
		assert.Contains(t, out, tc.want, name)
	}

	require.NoError(t, os.WriteFile(f.worker, []byte("#!/bin/sh\necho swapped\n"), 0o755))
	out, code = rig(t, "loss", "--rig", f.root)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, out, "no longer match", "a binary changed after pinning stops every step")
}

// What the harness must never contain, checked on its own text.
func TestRigNeverTouchesTheSharedInstallation(t *testing.T) {
	src, err := os.ReadFile("rig.sh")
	require.NoError(t, err)
	text := string(src)
	for _, banned := range []string{"launchctl", "pkill", "pgrep", "kill -9", "18080", "50055", "com.txe.dagu", "kubectl", "docker"} {
		assert.NotContains(t, text, banned)
	}
	shared := regexp.MustCompile(`\.local/share/txe-dagu[^-]`)
	for line := range strings.SplitSeq(text, "\n") {
		if shared.MatchString(line) {
			assert.Contains(t, line, "that is the shared installation", "the only mention of the shared home is the refusal")
		}
	}
	for _, f := range []string{"fixture-job.yaml.tmpl", "fixture-run.sh"} {
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		body := strings.ToLower(string(b))
		// D5: the fixture states what it does and steers no recovery choice.
		for _, word := range []string{"retry", "republish", "re-run", "rerun"} {
			assert.NotContains(t, body, word, f)
		}
	}
}

// T2 puts TXE-7514's change in the reviewer binary only. The install renders
// the agent's prompt into the reviewer DAG from the installing binary, so the
// install must be the reviewer binary's, and the review steps must call it.
func TestRigInstallsTheReviewerWithTheReviewerBinary(t *testing.T) {
	src, err := os.ReadFile("rig.sh")
	require.NoError(t, err)
	var install []string
	for line := range strings.SplitSeq(string(src), "\n") {
		if strings.Contains(line, "txe review install") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			install = append(install, line)
		}
	}
	require.Len(t, install, 1)
	assert.Contains(t, install[0], "reviewer_cli txe review install")
	assert.Contains(t, string(src), `--review-command "$REVIEWER_BIN txe review"`)
	assert.Regexp(t, regexp.MustCompile(`reviewer_cli\(\) \{\n[^}]*"\$REVIEWER_BIN" "\$@"`), string(src))
}

func TestFixtureRunWaitsForItsGoMarker(t *testing.T) {
	dir := t.TempDir()
	control, out1, out2 := filepath.Join(dir, "control"), filepath.Join(dir, "out1"), filepath.Join(dir, "out2")
	for _, d := range []string{control, out1, out2} {
		require.NoError(t, os.MkdirAll(d, 0o755))
	}
	run := func(id, out, wait string) (string, error) {
		cmd := exec.Command("bash", "fixture-run.sh")
		cmd.Env = append(os.Environ(), "I5_CONTROL_DIR="+control, "DAG_RUN_ID="+id, "TXE_RUN_OUTPUT_DIR="+out, "I5_GO_WAIT_SEC="+wait)
		b, err := cmd.CombinedOutput()
		return string(b), err
	}
	write(t, filepath.Join(control, "go-r1"), "x")
	got, err := run("r1", out1, "5")
	require.NoError(t, err, got)
	var res map[string]any
	raw, err := os.ReadFile(filepath.Join(out1, "result.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &res))
	assert.Equal(t, "r1", res["run_id"])
	assert.EqualValues(t, 1, res["ordinal"])
	assert.Nil(t, res["previous_result_sha256"])
	assert.FileExists(t, filepath.Join(control, "started-r1"))

	got, err = run("r2", out2, "1")
	require.Error(t, err, "without a go marker the run ends without a result")
	assert.Contains(t, got, "no go marker for r2")
	assert.NoFileExists(t, filepath.Join(out2, "result.json"))
	counter, err := os.ReadFile(filepath.Join(control, "counter"))
	require.NoError(t, err)
	assert.Equal(t, "2\n", string(counter), "each execution counts itself once")
}

// The runbook calls ./rig.sh and the tools directly, so each must keep its
// executable bit in the repository.
func TestEntryPointsAreExecutable(t *testing.T) {
	for _, f := range []string{"rig.sh", "relay.py", "preflight.py", "procs.py", "pin.py", "check_seal.py", "check_proof.py", "actions.py", "fixture-run.sh"} {
		info, err := os.Stat(f)
		require.NoError(t, err)
		assert.NotZero(t, info.Mode().Perm()&0o111, "%s is not executable", f)
	}
	out, err := exec.Command("./rig.sh").CombinedOutput()
	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit, string(out))
	assert.Equal(t, 2, exit.ExitCode())
	assert.Contains(t, string(out), "rig.sh init", "with no step, ./rig.sh prints its usage")
}
