// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package machineauth_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/dagucloud/dagu/v2/internal/cmn/cmdutil"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/workerchannel"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// The rig: real dagu processes (a hub started with start-all, workers, the CLI)
// in directories owned by the test, on ephemeral loopback ports, against the
// in-process issuer. Every process gets a minimal environment of its own — its
// HOME, DAGU_HOME and TXE home are under the test's directory, never the
// user's — and is stopped with its process group when the test ends.

type build struct {
	name, path, sha256 string
}

type machineHome struct {
	name   string // A or B
	person string // alice or bob
	owner  string
	id     string
	root   string // <rig>/machines/<name>
}

func (m *machineHome) txe() string  { return filepath.Join(m.root, "txe") }
func (m *machineHome) home() string { return filepath.Join(m.root, "home") }
func (m *machineHome) dagu() string { return filepath.Join(m.root, "dagu") }
func (m *machineHome) credential(class string) string {
	return filepath.Join(m.txe(), class+"-credential.json")
}

type proc struct {
	name string
	cmd  *exec.Cmd
	log  string
	done chan struct{}
	err  error
}

type rig struct {
	t             *testing.T
	dir           string
	issuer        *issuer
	adminPassword string
	browserSecret string
	machines      map[string]*machineHome
	hubPort       int
	coordPort     int
	hub           *proc
	hubBuild      build
	edge          *httptest.Server
	caFile        string
	tokens        map[string]string // admin, alice, bob: hub session tokens
	procs         []*proc
	mu            sync.Mutex
	logMark       int64
	http          *http.Client
}

const (
	cliClient     = "dagu-cli-rig"
	browserClient = "dagu-hub-browser"
	rigPath       = "/usr/local/bin:/usr/bin:/bin"
)

func randomSecret(t *testing.T) string {
	t.Helper()
	var b [24]byte
	_, err := rand.Read(b[:])
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func mintID(t *testing.T, prefix registry.Prefix) string {
	t.Helper()
	id, err := registry.NewID(prefix, time.Now())
	require.NoError(t, err)
	return id
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// newRig makes the directories, mints two owners and two machines, and starts
// the issuer that knows their clients.
func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, dir: t.TempDir(), machines: map[string]*machineHome{}, tokens: map[string]string{},
		adminPassword: randomSecret(t), browserSecret: randomSecret(t),
		http: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	for _, m := range []struct{ name, person string }{{"A", "alice"}, {"B", "bob"}} {
		h := &machineHome{name: m.name, person: m.person, owner: mintID(t, registry.PrefixOwner), id: mintID(t, registry.PrefixMachine),
			root: filepath.Join(r.dir, "machines", m.name)}
		for _, d := range []string{h.txe(), h.home(), h.dagu()} {
			require.NoError(t, os.MkdirAll(d, 0o700))
		}
		r.machines[m.name] = h
	}
	clients := map[string]string{cliClient: "cli"}
	for _, m := range r.machines {
		clients["dagu-worker-"+m.id] = "worker"
		clients["dagu-reviewer-"+m.id] = "reviewer"
	}
	r.issuer = newIssuer(t, clients, browserClient, r.browserSecret)
	r.hubPort, r.coordPort = freePort(t), freePort(t)
	require.NoError(t, os.MkdirAll(filepath.Join(r.dir, "hub", "dags"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(r.dir, "hub", "home"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(r.dir, "logs"), 0o700))
	t.Cleanup(r.stopAll)
	return r
}

func (r *rig) hubURL() string  { return fmt.Sprintf("http://127.0.0.1:%d", r.hubPort) }
func (r *rig) apiURL() string  { return r.hubURL() + "/api/v1" }
func (r *rig) coord() string   { return fmt.Sprintf("127.0.0.1:%d", r.coordPort) }
func (r *rig) A() *machineHome { return r.machines["A"] }
func (r *rig) B() *machineHome { return r.machines["B"] }

func (r *rig) workerClient(m *machineHome) string { return "dagu-worker-" + m.id }

// hubConfig is the hub's configuration: builtin person auth with the browser
// SSO at the issuer, the fork's licence policy for SSO, the coordinator in
// enforce advertising loopback, the worker channel on, and txe.authn naming the
// issuer, the CLI client and one worker and one reviewer client per machine.
func (r *rig) hubConfig() string {
	var clients strings.Builder
	fmt.Fprintf(&clients, "      - id: %s\n        class: cli\n", cliClient)
	for _, name := range []string{"A", "B"} {
		m := r.machines[name]
		fmt.Fprintf(&clients, "      - id: dagu-worker-%s\n        class: worker\n      - id: dagu-reviewer-%s\n        class: reviewer\n", m.id, m.id)
	}
	return fmt.Sprintf(`host: 127.0.0.1
port: %d
auth:
  mode: builtin
  builtin:
    initial_admin:
      username: rig-admin
  oidc:
    client_id: %s
    client_url: %s
    issuer: %s
    scopes: [openid, profile, email]
    auto_signup: true
    allowed_domains: [rig.test]
    pkce: true
license:
  fork_policy:
    features: [sso]
coordinator:
  host: 127.0.0.1
  advertise: 127.0.0.1
  port: %d
  auth:
    mode: enforce
  worker_channel:
    enabled: true
txe:
  authn:
    issuer: %s
    audience: dagu-hub
    jwks_url: %s/jwks
    cli_client: %s
    clients:
%s  authz:
    mode: enforce
`, r.hubPort, browserClient, r.hubURL(), r.issuer.url(), r.coordPort, r.issuer.url(), r.issuer.url(), cliClient, clients.String())
}

// start runs one process detached in its own group, output to a log file.
func (r *rig) start(name string, env []string, path string, args ...string) *proc {
	r.t.Helper()
	logPath := filepath.Join(r.dir, "logs", name+".log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	require.NoError(r.t, err)
	cmd := exec.Command(path, args...)
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = f, f
	cmdutil.SetupCommand(cmd)
	require.NoError(r.t, cmd.Start(), "start %s", name)
	p := &proc{name: name, cmd: cmd, log: logPath, done: make(chan struct{})}
	go func() {
		p.err = cmd.Wait()
		_ = f.Close()
		close(p.done)
	}()
	r.mu.Lock()
	r.procs = append(r.procs, p)
	r.mu.Unlock()
	return p
}

func (r *rig) stop(p *proc, wait time.Duration) {
	if p == nil {
		return
	}
	select {
	case <-p.done:
		return
	default:
	}
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGCONT)
	_ = cmdutil.TerminateProcessGroup(p.cmd, cmdutil.GracefulTermination(syscall.SIGTERM))
	select {
	case <-p.done:
	case <-time.After(wait):
		_ = cmdutil.TerminateProcessGroup(p.cmd, cmdutil.ForceTermination())
		<-p.done
	}
}

func (r *rig) stopAll() {
	r.mu.Lock()
	procs := append([]*proc{}, r.procs...)
	r.mu.Unlock()
	for _, proc := range slices.Backward(procs) {
		r.stop(proc, 10*time.Second)
	}
	if r.edge != nil {
		r.edge.Close()
	}
}

func (r *rig) exited(p *proc) bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (r *rig) logTail(p *proc, n int) string {
	raw, err := os.ReadFile(p.log)
	if err != nil {
		return err.Error()
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// ── the hub ───────────────────────────────────────────────────────────────────

// startHub starts b as the hub (start-all) over the rig's store and waits for
// its health. Secrets reach it by environment only.
func (r *rig) startHub(b build) {
	r.t.Helper()
	configPath := filepath.Join(r.dir, "hub", "config.yaml")
	require.NoError(r.t, os.WriteFile(configPath, []byte(r.hubConfig()), 0o600))
	env := []string{"PATH=" + rigPath, "HOME=" + filepath.Join(r.dir, "hub", "home"), "DAGU_HOME=" + filepath.Join(r.dir, "hub"),
		"DAGU_AUTH_BUILTIN_INITIAL_ADMIN_PASSWORD=" + r.adminPassword, "DAGU_AUTH_OIDC_CLIENT_SECRET=" + r.browserSecret}
	r.hub = r.start("hub-"+b.name, env, b.path, "start-all", "--config", configPath, "--dagu-home", filepath.Join(r.dir, "hub"))
	r.hubBuild = b
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if r.exited(r.hub) {
			r.t.Fatalf("hub %s exited: %v\n%s", b.name, r.hub.err, r.logTail(r.hub, 30))
		}
		code, _ := r.api(http.MethodGet, "/health", "", nil)
		if code == http.StatusOK {
			r.markLog()
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	r.t.Fatalf("hub %s not healthy in 60 s\n%s", b.name, r.logTail(r.hub, 30))
}

// hubVersion is what the hub reports about itself.
func (r *rig) hubVersion() string {
	_, body := r.api(http.MethodGet, "/health", "", nil)
	var v struct {
		Version string `json:"version"`
	}
	_ = json.Unmarshal(body, &v)
	return v.Version
}

// hubLine says what the hub logged when it started authenticating.
func (r *rig) hubSaysEnforce() bool {
	raw, err := os.ReadFile(r.hub.log)
	return err == nil && strings.Contains(string(raw), `msg="Coordinator authenticates its callers" mode=enforce`)
}

// markLog remembers where the hub's log ends now; the counts below read from
// there. Before a hub runs there is nothing to mark.
func (r *rig) markLog() {
	if r.hub == nil {
		r.logMark = 0
		return
	}
	info, err := os.Stat(r.hub.log)
	if err == nil {
		r.logMark = info.Size()
	}
}

var reasonRE = regexp.MustCompile(`msg="Coordinator call refused".* reason=([a-z_]+)`)

// refusalsSinceMark counts the hub's refusals by reason since the last mark. A
// log that cannot be read fails the test: zero refusals must mean none.
func (r *rig) refusalsSinceMark() map[string]int {
	counts := map[string]int{}
	if r.hub == nil {
		return counts
	}
	for _, line := range linesOfLog(r.t, r.hub.log, r.logMark) {
		if m := reasonRE.FindStringSubmatch(line); m != nil {
			counts[m[1]]++
		}
	}
	return counts
}

// hubLinesSinceMark returns the hub's log lines since the mark that contain all
// of the given fragments.
func (r *rig) hubLinesSinceMark(fragments ...string) []string {
	if r.hub == nil {
		return nil
	}
	return linesWith(linesOfLog(r.t, r.hub.log, r.logMark), fragments...)
}

// linesOfLog reads a log file from offset; it fails the test when it cannot.
func linesOfLog(t *testing.T, path string, offset int64) []string {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err, "read the log %s", filepath.Base(path))
	defer func() { _ = f.Close() }()
	_, err = f.Seek(offset, io.SeekStart)
	require.NoError(t, err)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	require.NoError(t, sc.Err(), "read the log %s", filepath.Base(path))
	return lines
}

// linesWith keeps the lines holding every fragment.
func linesWith(lines []string, fragments ...string) []string {
	var out []string
	for _, line := range lines {
		keep := true
		for _, fr := range fragments {
			if !strings.Contains(line, fr) {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, line)
		}
	}
	return out
}

// logTimeRE finds a line's timestamp in either of the formats the processes
// write: text (time=2026-…Z) and JSON ("time":"2026-…Z").
var logTimeRE = regexp.MustCompile(`(?:^time=|"time":")(\d{4}-\d{2}-\d{2}T[0-9:.]+(?:Z|[+-]\d{2}:\d{2}))`)

// firstTime returns the timestamp of the first line holding every fragment.
func firstTime(lines []string, fragments ...string) (time.Time, bool) {
	for _, line := range linesWith(lines, fragments...) {
		if m := logTimeRE.FindStringSubmatch(line); m != nil {
			if ts, err := time.Parse(time.RFC3339Nano, m[1]); err == nil {
				return ts, true
			}
		}
	}
	return time.Time{}, false
}

// urlRE finds URLs in text that is about to be shown.
var urlRE = regexp.MustCompile(`https?://[^\s"']+`)

// redactText keeps each URL's host and path only, so no query (a code, a
// state, a challenge) reaches a test log.
func redactText(s string) string {
	return urlRE.ReplaceAllStringFunc(s, redactURL)
}

// redactErr is err with its URLs redacted, for a message.
func redactErr(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s", redactText(err.Error()))
}

// workerLastHeartbeat reports when the hub last heard worker id, and whether
// the hub lists it at all.
func (r *rig) workerLastHeartbeat(id string) (string, bool) {
	code, raw := r.api(http.MethodGet, "/workers", r.tokens["admin"], nil)
	require.Equal(r.t, http.StatusOK, code, "list workers")
	var out struct {
		Workers []struct {
			ID            string `json:"id"`
			LastHeartbeat string `json:"lastHeartbeatAt"`
		} `json:"workers"`
	}
	require.NoError(r.t, json.Unmarshal(raw, &out))
	for _, w := range out.Workers {
		if w.ID == id {
			return w.LastHeartbeat, true
		}
	}
	return "", false
}

// ── REST ─────────────────────────────────────────────────────────────────────

// api makes one call to the hub's API as token (empty for none).
func (r *rig) api(method, path, token string, body any) (int, []byte) {
	r.t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(r.t, err)
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, r.apiURL()+path, reader)
	require.NoError(r.t, err)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return 0, []byte(err.Error())
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw
}

func (r *rig) apiOK(method, path, token string, body any) map[string]any {
	r.t.Helper()
	code, raw := r.api(method, path, token, body)
	require.Truef(r.t, code >= 200 && code < 300, "%s %s: HTTP %d %s", method, path, code, truncate(string(raw), 300))
	var out map[string]any
	if len(raw) > 0 {
		require.NoError(r.t, json.Unmarshal(raw, &out), "%s %s", method, path)
	}
	return out
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func (r *rig) adminLogin() {
	r.t.Helper()
	out := r.apiOK(http.MethodPost, "/auth/login", "", map[string]string{"username": "rig-admin", "password": r.adminPassword})
	token, _ := out["token"].(string)
	require.NotEmpty(r.t, token)
	r.tokens["admin"] = token
}

// ── the browser ──────────────────────────────────────────────────────────────

// browser is the person's browser as a loopback client with its own cookie
// store per host, so the hub's state, nonce and PKCE cookies come back to it on
// plain http (a browser treats a loopback origin as secure). It follows
// redirects by hand and never logs a URL.
type browser struct {
	client  *http.Client
	cookies map[string]map[string]string
}

func newBrowser() *browser {
	return &browser{client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		cookies: map[string]map[string]string{}}
}

func (b *browser) get(rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	for name, value := range b.cookies[req.URL.Host] {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, err
	}
	for _, c := range resp.Cookies() {
		store := b.cookies[req.URL.Host]
		if store == nil {
			store = map[string]string{}
			b.cookies[req.URL.Host] = store
		}
		if c.MaxAge < 0 || c.Value == "" {
			delete(store, c.Name)
		} else {
			store[c.Name] = c.Value
		}
	}
	return resp, nil
}

func withLoginHint(rawURL, person string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set("login_hint", person)
	u.RawQuery = q.Encode()
	return u.String()
}

// hubSignIn signs person in through the hub's browser SSO and returns the hub
// token the callback hands back in the URL fragment.
func (r *rig) hubSignIn(person string) string {
	r.t.Helper()
	b := newBrowser()
	next := r.hubURL() + "/oidc-login"
	for range 8 {
		resp, err := b.get(next)
		require.NoError(r.t, redactErr(err))
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		location := resp.Header.Get("Location")
		if resp.StatusCode/100 != 3 || location == "" {
			r.t.Fatalf("browser sign-in of %s stopped at HTTP %d (%s)", person, resp.StatusCode, redactURL(next))
		}
		loc, err := resp.Location()
		require.NoError(r.t, redactErr(err))
		if strings.HasPrefix(loc.Fragment, "token=") {
			token, _ := strings.CutPrefix(loc.Fragment, "token=")
			token, _, _ = strings.Cut(token, "&")
			token, err = url.QueryUnescape(token)
			require.NoError(r.t, err)
			require.NotEmpty(r.t, token)
			r.tokens[person] = token
			return token
		}
		if e := loc.Query().Get("error"); e != "" {
			r.t.Fatalf("browser sign-in of %s refused by the hub: %s", person, e)
		}
		if strings.HasSuffix(loc.Path, "/auth") && loc.Query().Get("login_hint") == "" {
			next = withLoginHint(loc.String(), person)
		} else {
			next = loc.String()
		}
	}
	r.t.Fatalf("browser sign-in of %s: too many redirects", person)
	return ""
}

// redactURL keeps a URL's host and path for a message, never its query.
func redactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "<url>"
	}
	return u.Host + u.Path
}

// ── the CLI ──────────────────────────────────────────────────────────────────

func (r *rig) cliEnv(m *machineHome) []string {
	return []string{"PATH=" + rigPath, "HOME=" + m.home(), "TXE_DAGU_HOME=" + m.txe(), "DAGU_HOME=" + m.dagu(), "TXE_SESSION=machineauth-matrix"}
}

// cliTimeout bounds one CLI command.
const cliTimeout = 120 * time.Second

// cliCommand makes a bounded CLI command of the current hub build as machine
// m's person, in its own process group, which the test's cleanup ends if the
// command is still running then.
func (r *rig) cliCommand(m *machineHome, args ...string) (*exec.Cmd, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), cliTimeout)
	cmd := exec.CommandContext(ctx, r.hubBuild.path, args...)
	cmd.Env = r.cliEnv(m)
	cmdutil.SetupCommand(cmd)
	cmd.Cancel = func() error { return cmdutil.TerminateProcessGroup(cmd, cmdutil.ForceTermination()) }
	cmd.WaitDelay = 5 * time.Second
	r.t.Cleanup(func() {
		cancel()
		if cmd.Process != nil && cmd.ProcessState == nil {
			_ = cmdutil.TerminateProcessGroup(cmd, cmdutil.ForceTermination())
		}
	})
	return cmd, cancel
}

// cli runs a CLI command and returns its stdout; it fails the test on a
// non-zero exit, showing stderr with its URLs redacted.
func (r *rig) cli(m *machineHome, args ...string) []byte {
	r.t.Helper()
	cmd, cancel := r.cliCommand(m, args...)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	require.NoError(r.t, cmd.Run(), "dagu %s: %s", strings.Join(args, " "), truncate(redactText(stderr.String()), 400))
	return stdout.Bytes()
}

var signInURLRE = regexp.MustCompile(`https?://127\.0\.0\.1:\d+/auth\?\S+`)

// lockedText is a string builder two goroutines share.
type lockedText struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *lockedText) write(s string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.b.WriteString(s)
}

func (l *lockedText) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// cliSignIn runs a CLI command that signs the person in (txe login, txe
// enrol) with --no-browser: it reads the sign-in address the CLI prints, opens
// it as person and follows the issuer's redirect to the CLI's loopback
// listener, then returns the CLI's stdout. Its diagnostics never show a URL's
// query.
func (r *rig) cliSignIn(m *machineHome, person string, args ...string) []byte {
	r.t.Helper()
	cmd, cancel := r.cliCommand(m, append(args, "--no-browser")...)
	defer cancel()
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	stderr, err := cmd.StderrPipe()
	require.NoError(r.t, err)
	require.NoError(r.t, cmd.Start())
	found := make(chan string, 1)
	var errText lockedText
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := sc.Text()
			errText.write(redactText(line) + "\n")
			if u := signInURLRE.FindString(line); u != "" {
				select {
				case found <- u:
				default:
				}
			}
		}
	}()
	done := make(chan error, 1)
	go func() {
		<-scanned
		done <- cmd.Wait()
	}()
	what := "dagu " + strings.Join(args, " ")
	select {
	case u := <-found:
		b := newBrowser()
		resp, err := b.get(withLoginHint(u, person))
		require.NoError(r.t, redactErr(err))
		_ = resp.Body.Close()
		require.Equal(r.t, http.StatusFound, resp.StatusCode, "the issuer did not approve the sign-in")
		loc, err := resp.Location()
		require.NoError(r.t, redactErr(err))
		resp, err = b.get(loc.String())
		require.NoError(r.t, redactErr(err))
		_ = resp.Body.Close()
		require.Equal(r.t, http.StatusOK, resp.StatusCode, "the CLI's listener did not take the callback")
	case err := <-done:
		r.t.Fatalf("%s ended before printing a sign-in address: %v\n%s", what, err, truncate(errText.String(), 600))
	case <-time.After(40 * time.Second):
		cancel()
		<-done
		r.t.Fatalf("%s printed no sign-in address in 40 s", what)
	}
	select {
	case err := <-done:
		require.NoError(r.t, err, "%s: %s", what, truncate(errText.String(), 600))
	case <-time.After(60 * time.Second):
		cancel()
		<-done
		r.t.Fatalf("%s did not finish after the sign-in", what)
	}
	return stdout.Bytes()
}

// lastJSON parses the last JSON document in CLI output.
func lastJSON(t *testing.T, out []byte) map[string]any {
	t.Helper()
	text := string(out)
	start := strings.LastIndex(text, "\n{")
	if start < 0 {
		start = strings.Index(text, "{") - 1
	}
	require.GreaterOrEqual(t, start, -1, "no JSON in CLI output")
	var doc map[string]any
	require.NoError(t, json.Unmarshal([]byte(text[start+1:]), &doc), "CLI output: %s", truncate(redactText(text), 300))
	return doc
}

// ── workers ──────────────────────────────────────────────────────────────────

type workerOptions struct {
	id, label  string // default: the machine's id
	noCred     bool
	credential string // another credential file
	maxRuns    int
}

// startWorker starts b as a worker of machine m over route: native (the
// coordinator address), channel (the hub URL) or tls (the hub through the TLS
// edge, trusting its CA by SSL_CERT_FILE).
func (r *rig) startWorker(name string, b build, m *machineHome, route string, o workerOptions) *proc {
	r.t.Helper()
	id, label := m.id, m.id
	if o.id != "" {
		id = o.id
	}
	if o.label != "" {
		label = o.label
	}
	home := filepath.Join(m.root, "worker", name)
	require.NoError(r.t, os.MkdirAll(filepath.Join(home, "dagu"), 0o700))
	env := []string{"PATH=" + rigPath, "HOME=" + home, "TXE_DAGU_HOME=" + m.txe(), "DAGU_HOME=" + filepath.Join(home, "dagu")}
	if !o.noCred {
		cred := m.credential("worker")
		if o.credential != "" {
			cred = o.credential
		}
		env = append(env, "DAGU_WORKER_AUTH_CREDENTIAL_FILE="+cred)
	}
	args := []string{"worker", "--worker.id", id, "--worker.labels", "txe.machine=" + label, "--worker.health-port=0"}
	if o.maxRuns > 0 {
		args = append(args, "--worker.max-active-runs", fmt.Sprint(o.maxRuns))
	}
	switch route {
	case "native":
		args = append(args, "--worker.coordinators", r.coord())
	case "channel":
		args = append(args, "--worker.hub-url", r.hubURL())
	case "tls":
		r.startEdge()
		args = append(args, "--worker.hub-url", r.edge.URL)
		env = append(env, "SSL_CERT_FILE="+r.caFile)
	default:
		r.t.Fatalf("route %q", route)
	}
	return r.start("worker-"+name, env, b.path, args...)
}

// startEdge puts a TLS reverse proxy in front of the hub, the shape of an edge:
// HTTPS to the worker, HTTP/1.1 to the origin. Its certificate is written out
// as the CA the worker trusts.
func (r *rig) startEdge() {
	r.t.Helper()
	if r.edge != nil {
		return
	}
	origin, err := url.Parse(r.hubURL())
	require.NoError(r.t, err)
	proxy := httputil.NewSingleHostReverseProxy(origin)
	proxy.FlushInterval = -1
	proxy.ErrorLog = log.New(io.Discard, "", 0) // a worker's cancelled stream is not a finding
	r.edge = httptest.NewTLSServer(proxy)
	r.caFile = filepath.Join(r.dir, "edge-ca.pem")
	require.NoError(r.t, os.WriteFile(r.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.edge.Certificate().Raw}), 0o600))
}

// workerHealthy waits until the hub lists worker id as healthy.
func (r *rig) workerHealthy(id string, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		code, raw := r.api(http.MethodGet, "/workers", r.tokens["admin"], nil)
		if code == http.StatusOK {
			var out struct {
				Workers []struct {
					ID     string `json:"id"`
					Health string `json:"healthStatus"`
				} `json:"workers"`
			}
			if json.Unmarshal(raw, &out) == nil {
				for _, w := range out.Workers {
					if w.ID == id && w.Health == "healthy" {
						return true
					}
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func (r *rig) freeze(p *proc) { _ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGSTOP) }
func (r *rig) thaw(p *proc)   { _ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGCONT) }

// ── runs ─────────────────────────────────────────────────────────────────────

func (r *rig) writeDAG(name string, m *machineHome, commands ...string) {
	r.t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "name: %s\nworker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    command: |\n", name, m.id)
	for _, c := range commands {
		fmt.Fprintf(&b, "      %s\n", c)
	}
	require.NoError(r.t, os.WriteFile(filepath.Join(r.dir, "hub", "dags", name+".yaml"), []byte(b.String()), 0o600))
}

func (r *rig) enqueue(dag string) string {
	r.t.Helper()
	out := r.apiOK(http.MethodPost, "/dags/"+dag+"/enqueue", r.tokens["admin"], map[string]any{})
	id, _ := out["dagRunId"].(string)
	require.NotEmpty(r.t, id)
	return id
}

type runState struct {
	status, worker, finished, attempt, errText string
	steps                                      map[string]string
}

func (r *rig) run(dag, id string) runState {
	_, raw := r.api(http.MethodGet, "/dag-runs/"+dag+"/"+id, r.tokens["admin"], nil)
	var out struct {
		Details struct {
			Status   string `json:"statusLabel"`
			Worker   string `json:"workerId"`
			Finished string `json:"finishedAt"`
			Attempt  string `json:"attemptId"`
			Error    string `json:"error"`
			Nodes    []struct {
				Step   struct{ Name string } `json:"step"`
				Status string                `json:"statusLabel"`
			} `json:"nodes"`
		} `json:"dagRunDetails"`
	}
	_ = json.Unmarshal(raw, &out)
	s := runState{status: out.Details.Status, worker: out.Details.Worker, finished: out.Details.Finished, attempt: out.Details.Attempt, errText: out.Details.Error, steps: map[string]string{}}
	for _, n := range out.Details.Nodes {
		s.steps[n.Step.Name] = n.Status
	}
	return s
}

func terminal(status string) bool {
	switch status {
	case "succeeded", "failed", "aborted", "partially_succeeded", "cancelled", "canceled":
		return true
	}
	return false
}

func (r *rig) waitRun(dag, id string, wait time.Duration) runState {
	deadline := time.Now().Add(wait)
	var s runState
	for time.Now().Before(deadline) {
		s = r.run(dag, id)
		if terminal(s.status) {
			return s
		}
		time.Sleep(time.Second)
	}
	return s
}

func (r *rig) waitRunning(dag, id string, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if r.run(dag, id).status == "running" {
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

// ── the probe ────────────────────────────────────────────────────────────────

// probeCall sends one coordinator call with a chosen credential over route
// (grpc or channel) and reports the gRPC code (or the HTTP status for the
// channel) and the message.
func (r *rig) probeCall(route, method, token, scheme, workerID, label string) (code, message string) {
	r.t.Helper()
	labels := map[string]string{"txe.machine": label}
	var msg proto.Message
	var name string
	switch method {
	case "heartbeat", "":
		msg, name = &coordinatorv1.HeartbeatRequest{WorkerId: workerID, Labels: labels, Stats: &coordinatorv1.WorkerStats{TotalPollers: 1}}, "Heartbeat"
	case "dispatch":
		msg, name = &coordinatorv1.DispatchRequest{Task: &coordinatorv1.Task{Operation: coordinatorv1.Operation_OPERATION_START, Target: "probe-never-runs", DagRunId: "probe", WorkerSelector: labels}}, "Dispatch"
	case "cancel":
		msg, name = &coordinatorv1.RequestCancelRequest{DagName: "probe-never-runs", DagRunId: "probe"}, "RequestCancel"
	default:
		r.t.Fatalf("probe method %q", method)
	}
	if scheme == "" {
		scheme = "Bearer"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if route == "grpc" {
		conn, err := grpc.NewClient(r.coord(), grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(r.t, err)
		defer func() { _ = conn.Close() }()
		if token != "" {
			ctx = metadata.AppendToOutgoingContext(ctx, "authorization", scheme+" "+token)
		}
		client := coordinatorv1.NewCoordinatorServiceClient(conn)
		var callErr error
		switch m := msg.(type) {
		case *coordinatorv1.HeartbeatRequest:
			_, callErr = client.Heartbeat(ctx, m)
		case *coordinatorv1.DispatchRequest:
			_, callErr = client.Dispatch(ctx, m)
		case *coordinatorv1.RequestCancelRequest:
			_, callErr = client.RequestCancel(ctx, m)
		}
		st, _ := status.FromError(callErr)
		return st.Code().String(), st.Message()
	}
	body, err := proto.Marshal(msg)
	require.NoError(r.t, err)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.apiURL()+workerchannel.MountPath+"/coordinator.v1.CoordinatorService/"+name, bytes.NewReader(body))
	require.NoError(r.t, err)
	req.Header.Set("Content-Type", "application/proto")
	if token != "" {
		req.Header.Set("Authorization", scheme+" "+token)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return "000", err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.Header.Get("Content-Type") == "application/proto" {
		return fmt.Sprint(resp.StatusCode), fmt.Sprintf("<%d proto bytes>", len(raw))
	}
	return fmt.Sprint(resp.StatusCode), truncate(string(raw), 300)
}
