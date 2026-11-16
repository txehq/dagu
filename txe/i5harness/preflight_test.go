// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package i5harness_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func write(t *testing.T, path, body string) string {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
	return path
}

const goodConfig = `host: 127.0.0.1
port: 28980
auth:
  mode: builtin
  builtin:
    initial_admin:
      username: synth-owner
coordinator:
  host: "[::1]"
  advertise: 127.0.0.1
  port: 28255
`

// The rendered hub config must bind the coordinator where the relay is not and
// register the relay's address. Each broken variant is one way the cut would
// silently stop proving anything.
func TestPreflightConfig(t *testing.T) {
	check := func(body string) (string, int) {
		f := write(t, filepath.Join(t.TempDir(), "config.yaml"), body)
		return tool(t, "preflight.py", "config", "--hub-config", f, "--relay-coord", "127.0.0.1:28255", "--relay-front", "127.0.0.1:28981")
	}
	out, code := check(goodConfig)
	require.Equal(t, 0, code, out)

	for name, tc := range map[string]struct{ from, to, want string }{
		"bound where the relay is":   {`host: "[::1]"`, `host: 127.0.0.1`, "must bind [::1]"},
		"advertises another host":    {`advertise: 127.0.0.1`, `advertise: localhost`, "must be the relay host"},
		"report 25's split ports":    {`port: 28255`, `port: 28055`, "must equal the relay's coordinator port"},
		"live coordinator port":      {`port: 28255`, `port: 50055`, "shared-installation port"},
		"live frontend port":         {`port: 28980`, `port: 18080`, "shared-installation port"},
		"frontend on the relay port": {`port: 28980`, `port: 28981`, "the relay must sit in front of it"},
		"frontend off loopback":      {`host: 127.0.0.1`, `host: 0.0.0.0`, "must be 127.0.0.1"},
	} {
		out, code := check(strings.Replace(goodConfig, tc.from, tc.to, 1))
		assert.Equal(t, 2, code, "%s: %s", name, out)
		assert.Contains(t, out, tc.want, name)
	}
}

const goodHubLog = `time=2026-11-17T01:00:00.000Z level=INFO msg="Coordinator initialization" bind-address=[::1] advertise-address=127.0.0.1 port=28255 instance-id=h@28255
time=2026-11-17T01:00:00.010Z level=INFO msg="Starting service registry" service=scheduler service-id=s host=h port=8090 status=inactive
time=2026-11-17T01:00:00.020Z level=INFO msg="Starting service registry" service=coordinator service-id=h@28255 host=127.0.0.1 port=28255 status=active
`

func TestPreflightHubLog(t *testing.T) {
	check := func(body string) (string, int) {
		f := write(t, filepath.Join(t.TempDir(), "hub.log"), body)
		return tool(t, "preflight.py", "hub-log", "--log", f, "--relay-coord", "127.0.0.1:28255")
	}
	out, code := check(goodHubLog)
	require.Equal(t, 0, code, out)

	for name, tc := range map[string]struct{ from, to, want string }{
		"bound on IPv4":         {"bind-address=[::1]", "bind-address=127.0.0.1", "not '[::1]'"},
		"advertises a hostname": {"advertise-address=127.0.0.1", "advertise-address=cwang.lan", "not the relay host"},
		"registered elsewhere":  {"host=127.0.0.1 port=28255 status=active", "host=127.0.0.1 port=38055 status=active", "not the relay"},
		"no init line":          {`msg="Coordinator initialization"`, `msg="something else"`, "no 'Coordinator initialization'"},
		"no registry line":      {"service=coordinator", "service=other", "no coordinator 'Starting service registry'"},
	} {
		out, code := check(strings.Replace(goodHubLog, tc.from, tc.to, 1))
		assert.Equal(t, 2, code, "%s: %s", name, out)
		assert.Contains(t, out, tc.want, name)
	}
}

// The registry file is what workers actually read: a registration anywhere but
// the relay sends owner calls (RunHeartbeat, ReportStatus) around the cut.
func TestPreflightRegistry(t *testing.T) {
	dir := t.TempDir()
	out, code := tool(t, "preflight.py", "registry", "--dir", dir, "--relay-coord", "127.0.0.1:28255")
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "no coordinator registration")

	write(t, filepath.Join(dir, "a.json"), `{"id":"h@28255","host":"127.0.0.1","port":28255,"pid":1,"status":0}`)
	out, code = tool(t, "preflight.py", "registry", "--dir", dir, "--relay-coord", "127.0.0.1:28255")
	require.Equal(t, 0, code, out)

	write(t, filepath.Join(dir, "b.json"), `{"id":"h@28055","host":"127.0.0.1","port":28055,"pid":2,"status":0}`)
	out, code = tool(t, "preflight.py", "registry", "--dir", dir, "--relay-coord", "127.0.0.1:28255")
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "b.json registers 127.0.0.1:28055")

	write(t, filepath.Join(dir, "b.json"), `not json`)
	out, code = tool(t, "preflight.py", "registry", "--dir", dir, "--relay-coord", "127.0.0.1:28255")
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "unreadable")
}

func TestPreflightConnections(t *testing.T) {
	lsof := func(body string) string { return write(t, filepath.Join(t.TempDir(), "lsof.txt"), body) }
	allow := "127.0.0.1:28255,127.0.0.1:28981"
	good := lsof("p123\nf7\nn127.0.0.1:50001->127.0.0.1:28255\nf8\nn127.0.0.1:50002->127.0.0.1:28981\n")
	out, code := tool(t, "preflight.py", "conns", "--pid", "123", "--allow", allow, "--require", "127.0.0.1:28255", "--lsof-output", good)
	require.Equal(t, 0, code, out)

	live := lsof("p123\nf7\nn127.0.0.1:50001->127.0.0.1:28255\nf9\nn127.0.0.1:50003->127.0.0.1:50055\n")
	out, code = tool(t, "preflight.py", "conns", "--pid", "123", "--allow", allow, "--require", "127.0.0.1:28255", "--lsof-output", live)
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "connected to 127.0.0.1:50055")

	bypass := lsof("p123\nf7\nn[::1]:50001->[::1]:28255\n")
	out, code = tool(t, "preflight.py", "conns", "--pid", "123", "--allow", allow, "--require", "127.0.0.1:28255", "--lsof-output", bypass)
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "[::1]:28255", "a direct connection to the coordinator bypasses the relay")
	assert.Contains(t, out, "no connection to 127.0.0.1:28255")
}

func TestPreflightLogsAndPorts(t *testing.T) {
	dir := t.TempDir()
	clean := write(t, filepath.Join(dir, "clean.log"), "coordinator=127.0.0.1:28255 port=150055 id=180800\n")
	out, code := tool(t, "preflight.py", "logs", clean)
	require.Equal(t, 0, code, out)
	dirty := write(t, filepath.Join(dir, "dirty.log"), "ok\nAckTaskClaim owner=127.0.0.1:50055 rejected\n")
	out, code = tool(t, "preflight.py", "logs", clean, dirty)
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "dirty.log:2 mentions port 50055")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	busy := ln.Addr().(*net.TCPAddr).Port
	out, code = tool(t, "preflight.py", "ports", "--free", strconv.Itoa(busy))
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "in use")
	out, code = tool(t, "preflight.py", "ports", "--free", "50055")
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "shared-installation port")
	out, code = tool(t, "preflight.py", "ports", "--free", strconv.Itoa(freePort(t)))
	assert.Equal(t, 0, code, out)
}

func sha(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestPreflightPins(t *testing.T) {
	dir := t.TempDir()
	bin := write(t, filepath.Join(dir, "dagu"), "binary bytes")
	manifest := func(m map[string]any) string {
		b, _ := json.Marshal(m)
		return write(t, filepath.Join(t.TempDir(), "manifest.json"), string(b))
	}
	good := manifest(map[string]any{"binaries": map[string]any{"W/C": map[string]string{"path": bin, "sha256": sha(t, bin)}}})
	out, code := tool(t, "preflight.py", "pins", "--manifest", good)
	require.Equal(t, 0, code, out)

	require.NoError(t, os.WriteFile(bin, []byte("swapped"), 0o644))
	out, code = tool(t, "preflight.py", "pins", "--manifest", good)
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "does not hash")

	out, code = tool(t, "preflight.py", "pins", "--manifest", manifest(map[string]any{}))
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "pins nothing")
}

// A run directory as `artifacts begin` and `seal` leave it.
func sealedRun(t *testing.T) (seals, runDir string) {
	t.Helper()
	runDir = t.TempDir()
	body := `{"run_id":"r1","ordinal":1}` + "\n"
	write(t, filepath.Join(runDir, "executions", "a1-e1", "result.json"), body)
	require.NoError(t, os.MkdirAll(filepath.Join(runDir, "attempts"), 0o755))
	s := sha256.Sum256([]byte(body))
	seals = write(t, filepath.Join(runDir, "seals.json"), `{"schema":1,"begun":[{"attempt_id":"a1"}],"seals":[{"attempt_id":"a1","execution":"a1-e1","files":[{"path":"result.json","sha256":"sha256:`+hex.EncodeToString(s[:])+`","bytes":28}]}]}`)
	return seals, runDir
}

func TestCheckSeal(t *testing.T) {
	seals, run := sealedRun(t)
	out, code := tool(t, "check_seal.py", seals, run)
	require.Equal(t, 0, code, out)
	assert.Contains(t, out, `"execution": "a1-e1"`)

	require.NoError(t, os.WriteFile(filepath.Join(run, "executions", "a1-e1", "result.json"), []byte("changed"), 0o644))
	out, code = tool(t, "check_seal.py", seals, run)
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "DIFF")

	seals, run = sealedRun(t)
	require.NoError(t, os.MkdirAll(filepath.Join(run, "attempts", "a2"), 0o755))
	out, code = tool(t, "check_seal.py", seals, run)
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "attempts/ holds")
}

func TestPinCopyInstalledIsReadOnlyAndHashChecked(t *testing.T) {
	dir := t.TempDir()
	src := write(t, filepath.Join(dir, "installed", "dagu-2.18.2-txe.18"), "installed bytes")
	require.NoError(t, os.Chmod(src, 0o555))
	info, err := os.Stat(src)
	require.NoError(t, err)
	want := sha(t, src)

	dest, rec := filepath.Join(dir, "rig", "bin", "dagu-wc"), filepath.Join(dir, "wc.json")
	out, code := tool(t, "pin.py", "copy-installed", "--src", src, "--dest", dest, "--expect-sha", strings.Repeat("0", 64), "--record", rec)
	assert.NotEqual(t, 0, code, out)
	assert.NoFileExists(t, dest, "a hash mismatch copies nothing")

	out, code = tool(t, "pin.py", "copy-installed", "--src", src, "--dest", dest, "--expect-sha", want, "--record", rec)
	require.Equal(t, 0, code, out)
	assert.Equal(t, want, sha(t, dest))
	after, err := os.Stat(src)
	require.NoError(t, err)
	assert.Equal(t, info.ModTime(), after.ModTime(), "the installed file is not written")
	assert.Equal(t, info.Mode(), after.Mode())
	var r map[string]any
	raw, _ := os.ReadFile(rec)
	require.NoError(t, json.Unmarshal(raw, &r))
	assert.Equal(t, want, r["sha256"])
	assert.Equal(t, want, r["receipt_sha256"])

	out, code = tool(t, "pin.py", "copy-installed", "--src", src, "--dest", dest, "--expect-sha", want, "--record", rec)
	assert.NotEqual(t, 0, code, "the harness bin is written once: %s", out)
}

// gitRepo is a tiny Go module: cmd imports internal/txe/review and other.
type miniRepo struct{ dir, base, reviewOnly, outside string }

func gitRepo(t *testing.T) miniRepo {
	t.Helper()
	dir := t.TempDir()
	git := func(args ...string) string {
		cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return strings.TrimSpace(string(out))
	}
	git("init", "-q")
	write(t, filepath.Join(dir, "go.mod"), "module example.com/m\n\ngo 1.22\n")
	write(t, filepath.Join(dir, "cmd", "main.go"), "package main\n\nimport (\n\t\"example.com/m/internal/txe/review\"\n\t\"example.com/m/other\"\n)\n\nvar version = \"dev\"\n\nfunc main() { println(review.Name(), other.Name(), version) }\n")
	write(t, filepath.Join(dir, "internal", "txe", "review", "review.go"), "package review\n\nfunc Name() string { return \"review\" }\n")
	write(t, filepath.Join(dir, "other", "other.go"), "package other\n\nfunc Name() string { return \"other\" }\n")
	git("add", "-A")
	git("commit", "-qm", "base")
	base := git("rev-parse", "HEAD")
	write(t, filepath.Join(dir, "internal", "txe", "review", "review.go"), "package review\n\nfunc Name() string { return \"review+A\" }\n")
	write(t, filepath.Join(dir, "internal", "txe", "review", "review_test.go"), "package review\n")
	git("commit", "-qam", "A: review only")
	git("add", "-A")
	git("commit", "-qm", "A: review test", "--allow-empty")
	reviewOnly := git("rev-parse", "HEAD~1")
	write(t, filepath.Join(dir, "other", "other.go"), "package other\n\nfunc Name() string { return \"other+A\" }\n")
	git("commit", "-qam", "A: touches other")
	outside := git("rev-parse", "HEAD")
	return miniRepo{dir, base, reviewOnly, outside}
}

// The closure report never widens the tuple by itself: it lists what changed
// and flags anything outside the reviewer package for assessment (root, D2).
func TestPinClosureFlagsChangesOutsideTheReviewer(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH")
	}
	g := gitRepo(t)
	repo, base, reviewOnly, outside := g.dir, g.base, g.reviewOnly, g.outside
	report := func(picks ...string) map[string]any {
		work, rec := t.TempDir(), filepath.Join(t.TempDir(), "closure.json")
		args := []string{"closure", "--repo", repo, "--base", base, "--workdir", filepath.Join(work, "w"), "--record", rec}
		for _, p := range picks {
			args = append(args, "--pick", p)
		}
		out, code := tool(t, "pin.py", args...)
		require.Equal(t, 0, code, out)
		var m map[string]any
		raw, _ := os.ReadFile(rec)
		require.NoError(t, json.Unmarshal(raw, &m))
		return m
	}
	m := report(reviewOnly)
	assert.Equal(t, false, m["assessment_required"])
	assert.Empty(t, m["outside_reviewer_package"])

	m = report(reviewOnly, outside)
	assert.Equal(t, true, m["assessment_required"])
	assert.Equal(t, []any{"other/other.go"}, m["outside_reviewer_package"])
	rows := map[string]map[string]any{}
	for _, r := range m["changed"].([]any) {
		row := r.(map[string]any)
		rows[row["file"].(string)] = row
	}
	assert.Equal(t, true, rows["internal/txe/review/review.go"]["in_reviewer_closure"])
	assert.Equal(t, "example.com/m/internal/txe/review", rows["internal/txe/review/review.go"]["package"])
	assert.Equal(t, false, rows["other/other.go"]["in_reviewer_closure"])
	assert.Equal(t, true, rows["other/other.go"]["in_binary"])
}

func TestPinBuildRecordsSourceAndBinary(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH")
	}
	g := gitRepo(t)
	repo, base, reviewOnly := g.dir, g.base, g.reviewOnly
	work, rec := t.TempDir(), filepath.Join(t.TempDir(), "r.json")
	out := filepath.Join(work, "dagu-r")
	o, code := tool(t, "pin.py", "build", "--repo", repo, "--base", base, "--pick", reviewOnly, "--version", "2.18.2-txe.18+a",
		"--workdir", filepath.Join(work, "w"), "--out", out, "--record", rec)
	require.Equal(t, 0, code, o)
	run, err := exec.Command(out).CombinedOutput()
	require.NoError(t, err)
	assert.Equal(t, "review+A other 2.18.2-txe.18+a\n", string(run), "the pick is applied and the version stamped")
	var r map[string]any
	raw, _ := os.ReadFile(rec)
	require.NoError(t, json.Unmarshal(raw, &r))
	assert.Equal(t, base, r["base_commit"])
	assert.Equal(t, []any{reviewOnly}, r["picks"])
	assert.Equal(t, sha(t, out), r["sha256"])
	assert.Regexp(t, regexp.MustCompile(`^[0-9a-f]{64}$`), r["source_tree_sha256"])
	assert.Contains(t, r["build_info"], "example.com/m")
}
