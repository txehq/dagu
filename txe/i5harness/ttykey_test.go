// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package i5harness_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	daguOnce sync.Once
	daguPath string
	daguErr  string
)

// realDagu builds this tree's dagu once for the package, the way
// internal/cmd's tests build one, so the harness's helpers are tested against
// the CLI's real prompt and the real reviewer renderer.
func realDagu(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("builds dagu")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go is not on PATH")
	}
	daguOnce.Do(func() {
		dir, err := os.MkdirTemp("", "i5dagu")
		if err != nil {
			daguErr = err.Error()
			return
		}
		root, _ := filepath.Abs(filepath.Join("..", ".."))
		daguPath = filepath.Join(dir, "dagu")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		//nolint:gosec // the repository's own command, into the test's directory
		cmd := exec.CommandContext(ctx, "go", "build", "-o", daguPath, "./cmd")
		cmd.Dir = root
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Run(); err != nil {
			daguErr = out.String()
		}
	})
	require.Empty(t, daguErr, "build dagu")
	return daguPath
}

// syntheticKey is a fresh key in the CLI's accepted form, written to a 0600
// JSON file as the harness keeps apikey.json.
func syntheticKey(t *testing.T, dir string) (key, file string) {
	t.Helper()
	b := make([]byte, 20)
	_, err := rand.Read(b)
	require.NoError(t, err)
	key = "dagu_" + hex.EncodeToString(b)
	file = filepath.Join(dir, "apikey.json")
	raw, _ := json.Marshal(map[string]string{"key": key})
	require.NoError(t, os.WriteFile(file, raw, 0o600))
	return key, file
}

func ttykey(t *testing.T, keyFile, log string, extra []string, command ...string) (map[string]any, int) {
	t.Helper()
	args := append([]string{"--key-json", keyFile, "--field", "key", "--log", log}, extra...)
	args = append(append(args, "--"), command...)
	out, code := tool(t, "ttykey.py", args...)
	var st map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(out)), &st), out)
	return st, code
}

func assertNoKeyUnder(t *testing.T, key string, paths ...string) {
	t.Helper()
	for _, root := range paths {
		_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			b, _ := os.ReadFile(p)
			assert.NotContains(t, string(b), key, "the key in plain text at %s", p)
			return nil
		})
	}
}

// The real `dagu context add`, on its real prompt, through ttykey's pty: the
// context is stored encrypted, nothing on disk or in the log holds the key in
// plain text, and the stored key is the exact key (the CLI sends it back as
// its bearer token to a server the test owns).
func TestTTYKeyFeedsTheRealContextAddPrompt(t *testing.T) {
	dagu := realDagu(t)
	dir := shortDir(t)
	key, keyFile := syntheticKey(t, dir)
	home, client, log := filepath.Join(dir, "home"), filepath.Join(dir, "client"), filepath.Join(dir, "ctx.log")
	require.NoError(t, os.MkdirAll(home, 0o700))

	var mu sync.Mutex
	var bearer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		bearer = r.Header.Get("Authorization")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user":{"id":"u","username":"rig","role":"admin"}}`))
	}))
	defer srv.Close()

	env := []string{"/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "HOME=" + home, dagu}
	st, code := ttykey(t, keyFile, log, nil, append(env, "context", "add", "rig", "--server="+srv.URL+"/api/v1", "--dagu-home="+client)...)
	require.Equal(t, 0, code, st)
	assert.Equal(t, true, st["ok"])

	stored, err := os.ReadFile(filepath.Join(client, "data", "contexts", "rig.json"))
	require.NoError(t, err)
	assert.Contains(t, string(stored), `"api_key_enc"`, "the CLI stored the key encrypted")
	assertNoKeyUnder(t, key, client, home, log)
	logged, _ := os.ReadFile(log)
	assert.Contains(t, string(logged), "API key: ")

	//nolint:gosec // the test's own binary and arguments
	test := exec.Command(dagu, "context", "test", "rig", "--dagu-home="+client)
	test.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home}
	_, _ = test.CombinedOutput()
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "Bearer "+key, bearer, "the decrypted context key is the key ttykey entered")
}

// standIn writes a Python stand-in for the CLI. Its behaviour is chosen by
// its first argument; it records its argv and pid, and the sha256 of any line it read.
func standIn(t *testing.T, dir string) (script, record string) {
	t.Helper()
	script, record = filepath.Join(dir, "standin.py"), filepath.Join(dir, "standin.json")
	write(t, script, `import hashlib, json, os, sys, termios, time
mode, record = sys.argv[1], sys.argv[2]
rec = {"argv": sys.argv, "pid": os.getpid()}
def save():
    json.dump(rec, open(record, "w"))
save()
if not os.isatty(0):
    sys.stderr.write("stdin is not a terminal\n"); sys.exit(9)
if mode == "garbage":
    sys.stderr.write("something unexpected\n"); sys.stderr.flush(); time.sleep(5)
if mode == "silent":
    time.sleep(30)
if mode == "eof":
    sys.exit(0)
if mode == "warn":
    sys.stderr.write('time=2026-11-16T00:00:00Z level=WARN msg="No auth.mode configured"\n')
attrs = termios.tcgetattr(0)
if mode == "echo-on":
    attrs[3] |= termios.ECHO
    termios.tcsetattr(0, termios.TCSANOW, attrs)
sys.stderr.write("API key: "); sys.stderr.flush()
if mode != "echo-on":
    attrs[3] &= ~termios.ECHO
    termios.tcsetattr(0, termios.TCSANOW, attrs)
line = sys.stdin.readline().rstrip("\n")
rec["read_sha256"] = hashlib.sha256(line.encode()).hexdigest()
rec["echo_off_while_reading"] = not (termios.tcgetattr(0)[3] & termios.ECHO)
save()
if mode == "write-back":
    os.write(0, line.encode())
if mode == "print-key":
    print("your key is", line)
if mode == "hang":
    time.sleep(60)
print("context added")
`)
	return script, record
}

func readRecord(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	return m
}

func TestTTYKeyDeliversTheKeyOnlyThroughThePrompt(t *testing.T) {
	dir := t.TempDir()
	key, keyFile := syntheticKey(t, dir)
	for _, mode := range []string{"plain", "warn"} {
		t.Run(mode, func(t *testing.T) {
			script, record := standIn(t, t.TempDir())
			log := filepath.Join(t.TempDir(), "log")
			st, code := ttykey(t, keyFile, log, nil, python(t), "-I", script, mode, record)
			require.Equal(t, 0, code, st)
			rec := readRecord(t, record)
			assert.Equal(t, sha256Hex(key), rec["read_sha256"], "the stand-in read exactly the key")
			assert.Equal(t, true, rec["echo_off_while_reading"])
			assert.NotContains(t, strings.Join(toStrings(rec["argv"]), " "), key, "the key is not in argv")
			assertNoKeyUnder(t, key, log)
		})
	}
}

// Every refusal writes nothing to the pty: the stand-in never reads a key.
func TestTTYKeyRefusesWithoutWritingTheKey(t *testing.T) {
	dir := t.TempDir()
	key, keyFile := syntheticKey(t, dir)
	for mode, tc := range map[string]struct {
		extra []string
		want  string
	}{
		"garbage": {nil, "unexpected output before the key prompt"},
		"silent":  {[]string{"--prompt-timeout", "1"}, "no key prompt within 1"},
		"eof":     {nil, "ended before its key prompt"},
		"echo-on": {nil, "echo is on at the pty"},
	} {
		t.Run(mode, func(t *testing.T) {
			script, record := standIn(t, t.TempDir())
			log := filepath.Join(t.TempDir(), "log")
			st, code := ttykey(t, keyFile, log, tc.extra, python(t), "-I", script, mode, record)
			assert.Equal(t, 2, code, st)
			assert.Equal(t, false, st["ok"])
			assert.Contains(t, st["reason"], tc.want)
			assert.Nil(t, readRecord(t, record)["read_sha256"], "no key was entered")
			assertProcessGone(t, readRecord(t, record))
			assertNoKeyUnder(t, key, log)
		})
	}
}

// A child that reads the key and then leaks it, or never exits, fails the run;
// the log never holds the key and the child's group is stopped.
func TestTTYKeyFailsWhenTheKeyLeaksOrTheChildHangs(t *testing.T) {
	dir := t.TempDir()
	key, keyFile := syntheticKey(t, dir)
	for mode, tc := range map[string]struct {
		extra []string
		want  string
	}{
		"write-back": {nil, "came back on the pty"},
		"print-key":  {nil, "output contained the key"},
		"hang":       {[]string{"--exit-timeout", "1"}, "did not exit within 1"},
	} {
		t.Run(mode, func(t *testing.T) {
			script, record := standIn(t, t.TempDir())
			log := filepath.Join(t.TempDir(), "log")
			st, code := ttykey(t, keyFile, log, tc.extra, python(t), "-I", script, mode, record)
			assert.Equal(t, 2, code, st)
			assert.Contains(t, st["reason"], tc.want)
			assertNoKeyUnder(t, key, log)
			assertProcessGone(t, readRecord(t, record))
		})
	}
}

func TestTTYKeyRefusesABadKeyFile(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"missing field": `{"other":"x"}`, "empty": `{"key":""}`, "line break": `{"key":"dagu_a\nb"}`, "not json": `nope`,
	} {
		f := write(t, filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".json"), body)
		st, code := ttykey(t, f, filepath.Join(dir, "log"), nil, "/bin/true")
		assert.Equal(t, 2, code, name)
		assert.Equal(t, false, st["ok"], name)
	}
}

// The stand-in itself refuses a non-terminal stdin, as the real CLI's prompt
// path needs one: piping the key would not reach it.
func TestStandInRefusesANonTerminalStdin(t *testing.T) {
	script, record := standIn(t, t.TempDir())
	//nolint:gosec // the test's own stand-in
	cmd := exec.Command(python(t), "-I", script, "plain", record)
	cmd.Stdin = strings.NewReader("dagu_piped\n")
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	require.ErrorAs(t, err, &exit, string(out))
	assert.Equal(t, 9, exit.ExitCode())
}

func assertProcessGone(t *testing.T, rec map[string]any) {
	t.Helper()
	if rec == nil {
		return
	}
	pid := int(rec["pid"].(float64))
	assert.Eventually(t, func() bool { return syscall.Kill(pid, 0) != nil }, 5*time.Second, 50*time.Millisecond,
		"the stand-in %s is still running", strconv.Itoa(pid))
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
