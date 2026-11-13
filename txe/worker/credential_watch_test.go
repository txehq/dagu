// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package worker_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// watchNow is the clock the watch runs at in these tests.
const watchNow = 1794000000

// watchSecret stands in for a webhook URL's secret path; it must never be printed.
const watchSecret = "hooks/synthetic-webhook-secret-must-not-be-printed"

func watchScript(t *testing.T) string {
	t.Helper()
	agentsScript(t)
	script, err := filepath.Abs("credential-watch.py")
	require.NoError(t, err)
	return script
}

// jwtWith is an unsigned JWT carrying claims; the watch reads only exp.
func jwtWith(t *testing.T, claims map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(claims)
	require.NoError(t, err)
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString(raw) + ".sig"
}

// watchHome is a TXE home with machine.json, a tunnel kubeconfig holding kubeconfig (none when
// empty) and the named *-credential.json files, each holding refresh_token.
func watchHome(t *testing.T, kubeconfig string, credentials map[string]string) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "txe dagu")
	require.NoError(t, os.MkdirAll(filepath.Join(home, "tunnel"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(home, "machine.json"), []byte(`{"machine_id":"`+agentsMachine+`"}`), 0o600))
	if kubeconfig != "" {
		require.NoError(t, os.WriteFile(filepath.Join(home, "tunnel", "kubeconfig"), []byte(kubeconfig), 0o600))
	}
	for name, token := range credentials {
		raw, err := json.Marshal(map[string]any{"refresh_token": token})
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(home, name), raw, 0o600))
	}
	return home
}

func kubeconfigWith(lines ...string) string {
	return "apiVersion: v1\nusers:\n- name: dagu-tunnel\n  user:\n" + strings.Join(lines, "\n") + "\n"
}

// certExpiring is a PEM client certificate whose notAfter is at.
func certExpiring(t *testing.T, at time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dagu-tunnel"},
		NotBefore: at.Add(-24 * time.Hour), NotAfter: at}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

type watchRun struct {
	stdout, stderr string
	err            error
}

// runWatch runs credential-watch.py at watchNow+offset with extra environment (the CA file for
// the test webhook) and args.
func runWatch(t *testing.T, env []string, offset int, args ...string) watchRun {
	t.Helper()
	py, err := exec.LookPath("python3")
	require.NoError(t, err)
	cmd := exec.Command(py, append([]string{"-I", watchScript(t), "--now", fmt.Sprint(watchNow + offset)}, args...)...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	cmd.Env = append([]string{"PATH=/usr/bin:/bin"}, env...)
	err = cmd.Run()
	return watchRun{out.String(), errOut.String(), err}
}

// Credentials with no expiry (the tunnel Secret's token, offline refresh tokens) never page;
// a near expiry warns and a past one pages, from the kubeconfig and from any *-credential.json,
// a file no list here names included.
func TestCredentialWatchFindsEachExpiry(t *testing.T) {
	soon := time.Unix(watchNow, 0).Add(72 * time.Hour)
	quiet := watchHome(t, kubeconfigWith("    token: "+jwtWith(t, map[string]any{"sub": "x"})),
		map[string]string{"worker-credential.json": jwtWith(t, map[string]any{"typ": "Offline", "exp": 0})})
	r := runWatch(t, nil, 0, "--home", quiet, "--dry-run")
	require.NoError(t, r.err, r.stderr)
	assert.Contains(t, r.stdout, "tunnel/kubeconfig token")
	assert.Contains(t, r.stdout, "worker-credential.json refresh token")
	assert.Contains(t, r.stdout, "no expiry")
	assert.NotContains(t, r.stdout, "would post")

	cert := base64.StdEncoding.EncodeToString(certExpiring(t, soon))
	loud := watchHome(t, kubeconfigWith("    token: "+jwtWith(t, map[string]any{"exp": watchNow - 60}),
		"    client-certificate-data: "+cert),
		map[string]string{"builder-credential.json": jwtWith(t, map[string]any{"exp": soon.Unix()})})
	r = runWatch(t, nil, 0, "--home", loud, "--dry-run")
	require.NoError(t, r.err, r.stderr)
	assert.Regexp(t, `would post: \[dagu-credential-watch\] \[FIRING\] `+agentsMachine+`: tunnel/kubeconfig token EXPIRED at `, r.stdout)
	assert.Regexp(t, `tunnel/kubeconfig client certificate expires at \S+ \(in 3\.0 days\)`, r.stdout)
	assert.Regexp(t, `builder-credential.json refresh token expires at \S+ \(in 3\.0 days\)`, r.stdout)
}

// The worker's credential given by --credential-file is watched wherever it is and whatever its
// name, and a file the scan already reads is not reported twice.
func TestCredentialWatchReadsTheWorkersCredentialFile(t *testing.T) {
	home := watchHome(t, "", map[string]string{"worker-credential.json": jwtWith(t, map[string]any{"typ": "Offline"})})
	outside := filepath.Join(t.TempDir(), "custom.json")
	raw, err := json.Marshal(map[string]any{"refresh_token": jwtWith(t, map[string]any{"exp": watchNow - 60})})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(outside, raw, 0o600))
	r := runWatch(t, nil, 0, "--home", home, "--dry-run",
		"--credential-file", outside, "--credential-file", filepath.Join(home, "worker-credential.json"))
	require.NoError(t, r.err, r.stderr)
	assert.Contains(t, r.stdout, "would post: [dagu-credential-watch] [FIRING] "+agentsMachine+": "+outside+" refresh token EXPIRED")
	assert.Equal(t, 1, strings.Count(r.stdout, "worker-credential.json refresh token"), "read once")
}

// tunnel-credential.sh writes the kubeconfig as JSON: its token, client certificate and exec
// plugin are read as they are from YAML, so a healthy kit-made tunnel does not page and an
// expiring one does.
func TestCredentialWatchReadsTheKitsJSONKubeconfig(t *testing.T) {
	kubeconfig := func(user map[string]any) string {
		raw, err := json.Marshal(map[string]any{"apiVersion": "v1", "kind": "Config",
			"clusters": []any{map[string]any{"name": "c", "cluster": map[string]any{"server": "https://k.example"}}},
			"users":    []any{map[string]any{"name": "dagu-tunnel", "user": user}},
			"contexts": []any{map[string]any{"name": "t", "context": map[string]any{"cluster": "c", "user": "dagu-tunnel"}}}})
		require.NoError(t, err)
		return string(raw)
	}
	healthy := watchHome(t, kubeconfig(map[string]any{"token": jwtWith(t, map[string]any{"exp": watchNow + 90*86400})}), nil)
	r := runWatch(t, nil, 0, "--home", healthy, "--dry-run")
	require.NoError(t, r.err, r.stderr)
	assert.Regexp(t, `tunnel/kubeconfig token\s+jwt\s+expires `, r.stdout)
	assert.NotContains(t, r.stdout, "would post")

	cert := base64.StdEncoding.EncodeToString(certExpiring(t, time.Unix(watchNow, 0).Add(72*time.Hour)))
	loud := watchHome(t, kubeconfig(map[string]any{"token": jwtWith(t, map[string]any{"exp": watchNow - 60}),
		"client-certificate-data": cert, "exec": map[string]any{"command": "kubelogin"}}), nil)
	r = runWatch(t, nil, 0, "--home", loud, "--dry-run")
	require.NoError(t, r.err, r.stderr)
	assert.Contains(t, r.stdout, "tunnel/kubeconfig token EXPIRED")
	assert.Regexp(t, `tunnel/kubeconfig client certificate expires at \S+ \(in 3\.0 days\)`, r.stdout)
	assert.Contains(t, r.stdout, "tunnel/kubeconfig exec: expiry unknown")
}

// A credential this cannot read the expiry of pages: it cannot be seen otherwise. An opaque token
// is shown as of unknown lifetime, never as "no expiry", and does not page (TXE-7226).
func TestCredentialWatchPagesWhatItCannotRead(t *testing.T) {
	home := watchHome(t, kubeconfigWith("    exec:", "      command: kubelogin"), map[string]string{
		"bad-exp-credential.json": jwtWith(t, map[string]any{"exp": "tomorrow"}),
		"opaque-credential.json":  "an-opaque-refresh-token"})
	require.NoError(t, os.WriteFile(filepath.Join(home, "broken-credential.json"), []byte("not json"), 0o600))
	r := runWatch(t, nil, 0, "--home", home, "--dry-run")
	require.NoError(t, r.err, r.stderr)
	assert.Contains(t, r.stdout, "would post: [dagu-credential-watch] [FIRING] "+agentsMachine+": tunnel/kubeconfig exec: expiry unknown")
	assert.Contains(t, r.stdout, "broken-credential.json: unreadable or has no refresh_token")
	assert.Contains(t, r.stdout, "bad-exp-credential.json refresh token: expiry unknown")
	assert.Regexp(t, `opaque-credential.json refresh token\s+opaque\s+lifetime unknown`, r.stdout)
	assert.NotContains(t, r.stdout, "opaque-credential.json refresh token: ")
}

// webhook is a TLS Mattermost stand-in; refuse makes it answer 403.
type webhook struct {
	mu     sync.Mutex
	posts  []string
	agents []string
	refuse bool
}

func (w *webhook) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.refuse || r.URL.Path != "/"+watchSecret {
		rw.WriteHeader(http.StatusForbidden)
		return
	}
	var msg struct{ Text string }
	_ = json.Unmarshal(body, &msg)
	w.posts = append(w.posts, msg.Text)
	w.agents = append(w.agents, r.UserAgent())
}

func (w *webhook) take() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	p := w.posts
	w.posts = nil
	return p
}

// startWebhook serves w over TLS and returns the webhook file and the environment that makes
// python trust the test server.
func startWebhook(t *testing.T, w *webhook) (file string, env []string) {
	t.Helper()
	srv := httptest.NewTLSServer(w)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600))
	file = filepath.Join(dir, "webhook.url")
	require.NoError(t, os.WriteFile(file, []byte(srv.URL+"/"+watchSecret+"\n"), 0o600))
	return file, []string{"SSL_CERT_FILE=" + ca}
}

// A finding is posted once, again only after an hour, and resolved once when it clears; a post
// that is not delivered is not recorded, so the next run tries it again. The URL is never printed.
func TestCredentialWatchDeliversRepeatsAndResolves(t *testing.T) {
	w := &webhook{}
	hook, env := startWebhook(t, w)
	home := watchHome(t, kubeconfigWith("    token: "+jwtWith(t, map[string]any{"exp": watchNow - 60})), nil)
	state := filepath.Join(t.TempDir(), "state", "state.json")
	run := func(offset int) watchRun {
		r := runWatch(t, env, offset, "--home", home, "--webhook-file", hook, "--state", state)
		assert.NotContains(t, r.stdout+r.stderr, watchSecret, "the webhook URL is never printed")
		return r
	}

	w.refuse = true
	r := run(0)
	require.Error(t, r.err)
	assert.Contains(t, r.stderr, "could not deliver (webhook answered 403)")
	assert.NoFileExists(t, state, "nothing undelivered is recorded")

	w.refuse = false
	require.NoError(t, run(60).err)
	posts := w.take()
	require.Len(t, posts, 1)
	assert.Contains(t, posts[0], "[FIRING] "+agentsMachine+": tunnel/kubeconfig token EXPIRED")
	assert.Equal(t, []string{"txe-dagu-credential-watch/1 (TXE-7226)"}, w.agents, "urllib's default agent is refused by the CDN")

	require.NoError(t, run(120).err)
	assert.Empty(t, w.take(), "not again within the hour")
	require.NoError(t, run(60+3600).err)
	assert.Len(t, w.take(), 1, "again after the hour")

	fresh := jwtWith(t, map[string]any{"exp": watchNow + 90*86400})
	require.NoError(t, os.WriteFile(filepath.Join(home, "tunnel", "kubeconfig"), []byte(kubeconfigWith("    token: "+fresh)), 0o600))
	require.NoError(t, run(7300).err)
	posts = w.take()
	require.Len(t, posts, 1)
	assert.Contains(t, posts[0], "[RESOLVED] "+agentsMachine+": tunnel/kubeconfig token (was: ")
	require.NoError(t, run(7400).err)
	assert.Empty(t, w.take(), "resolved once")
}

func TestCredentialWatchRefusesAWebhookThatIsNotHTTPS(t *testing.T) {
	home := watchHome(t, kubeconfigWith("    token: "+jwtWith(t, map[string]any{"exp": watchNow - 60})), nil)
	hook := filepath.Join(t.TempDir(), "webhook.url")
	require.NoError(t, os.WriteFile(hook, []byte("http://chat.example/"+watchSecret), 0o600))
	state := filepath.Join(t.TempDir(), "state.json")
	r := runWatch(t, nil, 0, "--home", home, "--webhook-file", hook, "--state", state)
	require.Error(t, r.err)
	assert.Contains(t, r.stderr, "does not hold an https URL")
	assert.NotContains(t, r.stderr, watchSecret)
	assert.NoFileExists(t, state)
}

// watchOut writes the watch's macOS agent and Linux units for one home and webhook file.
func watchOut(t *testing.T, home, hook, cred string) (agent map[string]any, service, timer unitFile) {
	t.Helper()
	script := agentsScript(t)
	units, err := filepath.Abs("units.py")
	require.NoError(t, err)
	agents := filepath.Join(t.TempDir(), "Launch Agents")
	require.NoError(t, os.MkdirAll(agents, 0o700))
	_, stderr, err := python(t, script, "write-watch", agents, home, unitsPython, "com.txe.dagu-credential-watch", hook, cred)
	require.NoError(t, err, stderr)
	dump, stderr, err := python(t, "-c", `import json, plistlib, sys; print(json.dumps(plistlib.load(open(sys.argv[1], "rb"))))`,
		filepath.Join(agents, "com.txe.dagu-credential-watch.plist"))
	require.NoError(t, err, stderr)
	require.NoError(t, json.Unmarshal([]byte(dump), &agent))
	dir := filepath.Join(t.TempDir(), "user")
	_, stderr, err = python(t, units, "write-watch", dir, home, unitsPython,
		"txe-dagu-credential-watch.service", "txe-dagu-credential-watch.timer", hook, cred)
	require.NoError(t, err, stderr)
	service = readUnit(t, filepath.Join(dir, "txe-dagu-credential-watch.service"))
	data, err := os.ReadFile(filepath.Join(dir, "txe-dagu-credential-watch.timer"))
	require.NoError(t, err)
	timer = unitFile{text: string(data), settings: map[string]string{}}
	for line := range strings.SplitSeq(timer.text, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			timer.settings[k] = v
		}
	}
	return agent, service, timer
}

// The watch runs the same command on both platforms, under the log wrapper, at load and hourly;
// it is never kept alive, and it gets the webhook file's path, never its URL.
func TestWatchAgentAndUnitsRunTheSameCommand(t *testing.T) {
	home := "/Users/some one/txe 100% $HOME"
	hook := "/Users/some one/hooks/alert webhook.url"
	cred := "/Users/some one/elsewhere/custom 5%.json"
	agent, service, timer := watchOut(t, home, hook, cred)
	want := []any{unitsPython, "-I", home + "/bin/logpipe.py", "--path", home + "/logs/credential-watch.log",
		"--max-bytes", "1048576", "--backups", "3", "--chunk-bytes", "65536", "--",
		unitsPython, "-I", home + "/bin/credential-watch.py", "--home", home,
		"--webhook-file", hook, "--state", home + "/credential-watch/state.json", "--credential-file", cred}
	assert.Equal(t, want, agent["ProgramArguments"])
	assert.Equal(t, true, agent["RunAtLoad"])
	assert.InDelta(t, 3600, agent["StartInterval"], 0)
	assert.Nil(t, agent["KeepAlive"], "each run checks and exits")
	assert.Equal(t, home+"/logs/credential-watch.launchd.log", agent["StandardOutPath"])

	var argv []any
	for _, a := range service.argv {
		argv = append(argv, a)
	}
	assert.Equal(t, want, argv, "the Linux service runs the macOS agent's command")
	assert.Equal(t, "oneshot", service.settings["Type"])
	assert.Equal(t, "journal", service.settings["StandardOutput"])
	assert.NotContains(t, service.text, "[Install]", "only the timer starts it")
	assert.Equal(t, "60", timer.settings["OnActiveSec"], "as RunAtLoad")
	assert.Equal(t, "3600", timer.settings["OnUnitActiveSec"], "as StartInterval")
	assert.Equal(t, "txe-dagu-credential-watch.service", timer.settings["Unit"])
	assert.Equal(t, "timers.target", timer.settings["WantedBy"])
}

// The agent's command, as written, runs: the wrapper accepts its limits, the watch reads the home
// and the log gets its table. The Linux service runs the same command (above).
func TestWatchCommandRuns(t *testing.T) {
	script := agentsScript(t)
	py, err := exec.LookPath("python3")
	require.NoError(t, err)
	home := watchHome(t, kubeconfigWith("    token: "+jwtWith(t, map[string]any{"sub": "x"})), nil)
	require.NoError(t, os.MkdirAll(filepath.Join(home, "bin"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(home, "logs"), 0o700))
	for _, name := range []string{"logpipe.py", "credential-watch.py"} {
		data, err := os.ReadFile(name)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(home, "bin", name), data, 0o600))
	}
	hook := filepath.Join(t.TempDir(), "webhook.url")
	require.NoError(t, os.WriteFile(hook, []byte("https://chat.invalid/"+watchSecret), 0o600))
	agents := t.TempDir()
	_, stderr, err := python(t, script, "write-watch", agents, home, py, "com.txe.dagu-credential-watch", hook)
	require.NoError(t, err, stderr)
	argv := agentArguments(t, filepath.Join(agents, "com.txe.dagu-credential-watch.plist"))
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	log, err := os.ReadFile(filepath.Join(home, "logs", "credential-watch.log"))
	require.NoError(t, err)
	assert.Contains(t, string(log), "tunnel/kubeconfig token")
	assert.Contains(t, string(log), "no expiry")
	assert.NotContains(t, string(log)+string(out), watchSecret)
}

func TestWatchRefusesARelativePath(t *testing.T) {
	script := agentsScript(t)
	units, err := filepath.Abs("units.py")
	require.NoError(t, err)
	for _, args := range [][]string{
		{"relative/txe", unitsPython, "/abs/webhook.url"},
		{"/abs/txe", "python3", "/abs/webhook.url"},
		{"/abs/txe", unitsPython, "webhook.url"},
	} {
		_, stderr, err := python(t, script, "write-watch", t.TempDir(), args[0], args[1], "com.txe.dagu-credential-watch", args[2])
		require.Error(t, err, args)
		assert.Contains(t, stderr, "must be an absolute path")
		_, stderr, err = python(t, units, "write-watch", t.TempDir(), args[0], args[1], "w.service", "w.timer", args[2])
		require.Error(t, err, args)
		assert.Contains(t, stderr, "must be an absolute path")
	}
}

// An install keeps the webhook the installed watch passes, the hand-installed agent of
// TXE-7226 included, so replacing that agent needs no flag.
func TestWatchWebhookReadsBack(t *testing.T) {
	script := agentsScript(t)
	units, err := filepath.Abs("units.py")
	require.NoError(t, err)
	hook := "/Users/some one/hooks/alert 100% $X \"q\" \\ webhook.url"
	dir := t.TempDir()
	hand := filepath.Join(dir, "hand.plist")
	_, stderr, err := python(t, "-c", `import plistlib, sys
plistlib.dump({"Label": "com.txe.dagu-credential-watch", "ProgramArguments": ["/opt/homebrew/bin/python3", "-I",
  "/Users/x/.local/share/dagu-credential-watch/machine-watch.py", "credentials", "--home", "/Users/x/.local/share/txe-dagu",
  "--webhook-file", sys.argv[2], "--state", "/Users/x/.local/state/dagu-credential-watch/state.json", "--warn-days", "7"]},
  open(sys.argv[1], "wb"))`, hand, hook)
	require.NoError(t, err, stderr)
	out, stderr, err := python(t, script, "watch-webhook", hand)
	require.NoError(t, err, stderr)
	assert.Equal(t, hook+"\n", out)

	agent, _, _ := watchOut(t, "/home/dev/txe", hook, "")
	require.Equal(t, hook, agent["ProgramArguments"].([]any)[slices.Index(agent["ProgramArguments"].([]any), any("--webhook-file"))+1])
	udir := filepath.Join(t.TempDir(), "user")
	_, stderr, err = python(t, units, "write-watch", udir, "/home/dev/txe", unitsPython, "w.service", "w.timer", hook)
	require.NoError(t, err, stderr)
	out, stderr, err = python(t, units, "watch-webhook", filepath.Join(udir, "w.service"))
	require.NoError(t, err, stderr)
	assert.Equal(t, hook+"\n", out, "the path reads back exactly from ExecStart=")

	for _, read := range [][]string{{script, "watch-webhook", filepath.Join(dir, "absent.plist")}, {units, "watch-webhook", filepath.Join(dir, "absent")}} {
		out, stderr, err = python(t, read...)
		require.NoError(t, err, stderr)
		assert.Empty(t, out)
	}
}

// libList prints one of lib.sh's arrays, one element a line.
func libList(t *testing.T, name string) []string {
	t.Helper()
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	cmd := exec.Command(bash, "-c", `. ./lib.sh; eval 'printf "%s\n" "${'"$1"'[@]}"'`, "bash", name)
	cmd.Env = []string{"HOME=/nonexistent", "PATH=/usr/bin:/bin"}
	out, err := cmd.Output()
	require.NoError(t, err)
	return strings.Fields(string(out))
}

// Every agent and unit lib.sh names is in the set the scripts start, stop and remove, and those
// scripts use the set rather than their own list: a new unit cannot be installed and then
// forgotten by stop.sh or uninstall-systemd.sh, nor left out of an install.
func TestTheKitsUnitSetIsComplete(t *testing.T) {
	agentsScript(t)
	lib, err := os.ReadFile("lib.sh")
	require.NoError(t, err)
	labels, units := libList(t, "TXE_DAGU_LABELS"), libList(t, "TXE_DAGU_UNITS")
	declared := regexp.MustCompile(`(?m)^(TXE_DAGU_\w+_(LABEL|UNIT|SERVICE|TIMER))="([^"]+)"$`).FindAllStringSubmatch(string(lib), -1)
	require.GreaterOrEqual(t, len(declared), 7)
	for _, d := range declared {
		if d[2] == "LABEL" {
			assert.Contains(t, labels, d[3], "%s is in TXE_DAGU_LABELS", d[1])
		} else {
			assert.Contains(t, units, d[3], "%s is in TXE_DAGU_UNITS", d[1])
		}
	}
	assert.Contains(t, labels, "com.txe.dagu-credential-watch", "every machine runs the credential watch")
	assert.Contains(t, units, "txe-dagu-credential-watch.timer")
	assert.Contains(t, units, "txe-dagu-credential-watch.service")

	for script, set := range map[string]string{"install.sh": "TXE_DAGU_LABELS", "stop.sh": "TXE_DAGU_LABELS", "uninstall-systemd.sh": "TXE_DAGU_UNITS"} {
		data, err := os.ReadFile(script)
		require.NoError(t, err)
		assert.Contains(t, string(data), "${"+set+"[", "%s uses lib.sh's set", script)
	}
	// install-systemd.sh starts the worker units as a list and the watch's timer and service by name.
	data, err := os.ReadFile("install-systemd.sh")
	require.NoError(t, err)
	for _, name := range []string{"TXE_DAGU_TUNNEL_UNIT", "TXE_DAGU_WORKER_UNIT", "TXE_DAGU_WATCH_TIMER", "TXE_DAGU_WATCH_SERVICE"} {
		assert.Contains(t, string(data), "$"+name, "install-systemd.sh starts %s", name)
	}
}

// stubTool writes an executable shell script into dir.
func stubTool(t *testing.T, dir, name, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o700)) //nolint:gosec // a test's stub
}

// installHome prepares what a full install with stand-in tools needs: a built binary for the tag,
// machine.json, a tunnel kubeconfig and a webhook file, and returns the TXE home and tools dir.
func installHome(t *testing.T, home string) (txe, tools, hook string) {
	t.Helper()
	txe = filepath.Join(home, "txe")
	version := "2.18.2-txe.19"
	require.NoError(t, os.MkdirAll(filepath.Join(txe, "bin"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(txe, "tunnel"), 0o700))
	stubTool(t, filepath.Join(txe, "bin"), "dagu-"+version, "echo "+version+"\n")
	require.NoError(t, os.WriteFile(filepath.Join(txe, "machine.json"),
		[]byte(`{"machine_id":"`+agentsMachine+`","owner_id":"`+agentsOwner+`"}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(txe, "tunnel", "kubeconfig"), []byte(kubeconfigWith("    token: x")), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(txe, "tunnel", "kubeconfig.expires"),
		[]byte(fmt.Sprint(time.Now().Add(30*24*time.Hour).Unix())), 0o600))
	hook = filepath.Join(home, "alert webhook.url")
	require.NoError(t, os.WriteFile(hook, []byte("https://chat.example/"+watchSecret+"\n"), 0o600))
	tools = t.TempDir()
	stubTool(t, tools, "go", "")
	stubTool(t, tools, "kubectl", "")
	stubTool(t, tools, "curl", "echo 200\n")
	return txe, tools, hook
}

// A full macOS install, with launchd stood in for, writes and loads the watch's agent beside the
// worker and tunnel, keeps the hand-installed agent's webhook, and is refused with no webhook.
func TestInstallLoadsTheCredentialWatch(t *testing.T) {
	agentsScript(t)
	install, err := filepath.Abs("install.sh")
	require.NoError(t, err)
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	home := t.TempDir()
	txe, tools, hook := installHome(t, home)
	loaded := filepath.Join(home, "loaded")
	require.NoError(t, os.MkdirAll(loaded, 0o700))
	// launchctl: bootstrap marks a label loaded, bootout unmarks it, print answers from the mark.
	stubTool(t, tools, "launchctl", `echo "$*" >> "`+home+`/launchctl.log"
case "$1" in
  bootstrap) touch "`+loaded+`/$(basename "$3" .plist)" ;;
  bootout) l="`+loaded+`/${2##*/}"; [ -e "$l" ] || exit 3; rm -f "$l" ;;
  print) [ -e "`+loaded+`/${2##*/}" ] || exit 113; printf '\tstate = running\n\tlast exit code = 0\n' ;;
esac
`)
	agents := filepath.Join(home, "Library", "LaunchAgents")
	run := func(args ...string) (string, error) {
		cmd := exec.Command(bash, append([]string{install, "--tag", "txe-v2.18.2-19"}, args...)...)
		cmd.Env = []string{"HOME=" + home, "TXE_DAGU_HOME=" + txe, "TXE_DAGU_LINK_DIR=" + filepath.Join(home, "bin"),
			"PATH=" + tools + ":/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	out, err := run()
	require.Error(t, err)
	assert.Contains(t, out, "the credential watch has no webhook")
	assert.NoFileExists(t, filepath.Join(agents, "com.txe.dagu.worker.plist"), "nothing was written")

	loose := filepath.Join(home, "loose.url")
	require.NoError(t, os.WriteFile(loose, []byte("https://chat.example/x"), 0o644)) //nolint:gosec // the mode under test
	out, err = run("--alert-webhook-file", loose)
	require.Error(t, err)
	assert.Contains(t, out, "it must be readable by its owner only")

	// What TXE-7226 hand-installed: same label, its own script and webhook.
	require.NoError(t, os.MkdirAll(agents, 0o700))
	_, stderr, err := python(t, "-c", `import plistlib, sys
plistlib.dump({"Label": "com.txe.dagu-credential-watch", "ProgramArguments": ["/usr/bin/python3", "-I", "/x/machine-watch.py",
  "credentials", "--webhook-file", sys.argv[2]], "StartInterval": 3600}, open(sys.argv[1], "wb"))`,
		filepath.Join(agents, "com.txe.dagu-credential-watch.plist"), hook)
	require.NoError(t, err, stderr)
	require.NoError(t, os.WriteFile(filepath.Join(loaded, "com.txe.dagu-credential-watch"), nil, 0o600))

	out, err = run()
	require.NoError(t, err, out)
	assert.Contains(t, out, "alert webhook "+hook)
	assert.Contains(t, out, "com.txe.dagu-credential-watch loaded, last exit 0")
	assert.NotContains(t, out, watchSecret, "the URL is never printed")
	for _, label := range []string{"com.txe.dagu.tunnel", "com.txe.dagu.worker", "com.txe.dagu-credential-watch"} {
		assert.FileExists(t, filepath.Join(loaded, label), "%s is loaded", label)
	}
	args := agentArguments(t, filepath.Join(agents, "com.txe.dagu-credential-watch.plist"))
	assert.Equal(t, txe+"/bin/credential-watch.py", args[slices.Index(args, "--")+3], "the kit's script replaced the hand-installed one")
	assert.Equal(t, hook, args[slices.Index(args, "--webhook-file")+1])
	installed, err := os.ReadFile(filepath.Join(txe, "bin", "credential-watch.py"))
	require.NoError(t, err)
	source, err := os.ReadFile("credential-watch.py")
	require.NoError(t, err)
	assert.Equal(t, source, installed)
	log, err := os.ReadFile(filepath.Join(home, "launchctl.log"))
	require.NoError(t, err)
	assert.Contains(t, string(log), "bootout gui/", "the hand-installed agent was booted out before the kit's was loaded")

	// stop.sh stops every agent the install loaded.
	stop, err := filepath.Abs("stop.sh")
	require.NoError(t, err)
	cmd := exec.Command(bash, stop)
	cmd.Env = []string{"HOME=" + home, "TXE_DAGU_HOME=" + txe, "PATH=" + tools + ":/usr/bin:/bin"}
	stopped, err := cmd.CombinedOutput()
	require.NoError(t, err, string(stopped))
	assert.Equal(t, "stopped com.txe.dagu-credential-watch\nstopped com.txe.dagu.worker\nstopped com.txe.dagu.tunnel\n", string(stopped))
}

// A full Linux install, with systemd stood in for, writes the watch's timer and service, enables
// and starts the timer, runs the watch once and fails when that run fails; uninstall removes them.
func TestInstallSystemdRunsTheCredentialWatch(t *testing.T) {
	agentsScript(t)
	install, err := filepath.Abs("install-systemd.sh")
	require.NoError(t, err)
	bash, err := exec.LookPath("bash")
	require.NoError(t, err)
	home := t.TempDir()
	txe, tools, hook := installHome(t, home)
	unitsDir := filepath.Join(home, "units")
	stubTool(t, tools, "uname", "echo Linux\n")
	// systemctl: every unit is active and never restarts; starting the watch's service fails when
	// the file "watch-fails" exists.
	stubTool(t, tools, "systemctl", `echo "$*" >> "`+home+`/systemctl.log"
case "$*" in
  *NRestarts*) echo 0 ;;
  *is-active*) echo active ;;
  *"start txe-dagu-credential-watch.service"*) [ ! -e "`+home+`/watch-fails" ] ;;
esac
`)
	run := func(args ...string) (string, error) {
		cmd := exec.Command(bash, append([]string{install, "--tag", "txe-v2.18.2-19"}, args...)...)
		cmd.Env = []string{"HOME=" + home, "TXE_DAGU_HOME=" + txe, "TXE_DAGU_UNITS_DIR=" + unitsDir,
			"TXE_DAGU_LINK_DIR=" + filepath.Join(home, "bin"), "TXE_DAGU_ACTIVE_WAIT=1", "TXE_DAGU_ACTIVE_SETTLE=0",
			"PATH=" + tools + ":/usr/bin:/bin"}
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	out, err := run()
	require.Error(t, err)
	assert.Contains(t, out, "the credential watch has no webhook")
	assert.NoFileExists(t, filepath.Join(unitsDir, "txe-dagu-worker.service"), "nothing was written")

	out, err = run("--alert-webhook-file", hook)
	require.NoError(t, err, out)
	assert.Contains(t, out, "txe-dagu-credential-watch.timer active")
	assert.NotContains(t, out, watchSecret)
	for _, unit := range []string{"txe-dagu-tunnel.service", "txe-dagu-worker.service",
		"txe-dagu-credential-watch.service", "txe-dagu-credential-watch.timer"} {
		assert.FileExists(t, filepath.Join(unitsDir, unit))
	}
	log, err := os.ReadFile(filepath.Join(home, "systemctl.log"))
	require.NoError(t, err)
	assert.Contains(t, string(log), "--user enable txe-dagu-credential-watch.timer\n")
	assert.Contains(t, string(log), "--user restart txe-dagu-credential-watch.timer\n")
	assert.Contains(t, string(log), "--user start txe-dagu-credential-watch.service\n")

	// A second install needs no flag: it keeps the webhook the installed service passes.
	require.NoError(t, os.WriteFile(filepath.Join(home, "watch-fails"), nil, 0o600))
	out, err = run()
	require.Error(t, err)
	assert.Contains(t, out, "the credential watch's first run failed")
	require.NoError(t, os.Remove(filepath.Join(home, "watch-fails")))
	out, err = run()
	require.NoError(t, err, out)
	assert.Contains(t, out, "alert webhook "+hook)

	uninstall, err := filepath.Abs("uninstall-systemd.sh")
	require.NoError(t, err)
	// The uninstall's systemctl: every unit stops.
	stubTool(t, tools, "systemctl", "case \"$*\" in *is-active*) echo inactive; exit 3;; esac\nexit 0\n")
	cmd := exec.Command(bash, uninstall)
	cmd.Env = []string{"HOME=" + home, "TXE_DAGU_HOME=" + txe, "TXE_DAGU_UNITS_DIR=" + unitsDir, "PATH=" + tools + ":/usr/bin:/bin"}
	removed, err := cmd.CombinedOutput()
	require.NoError(t, err, string(removed))
	entries, err := os.ReadDir(unitsDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "every unit the install wrote was removed")
}
