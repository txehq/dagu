// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/health"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	"github.com/dagucloud/dagu/v2/internal/txe/workerchannel"
)

// The rig puts the worker channel, and a proxy that can break it, between a
// real worker and a real coordinator, scheduler and DAG run. Everything is on
// loopback. The short cases run always. The real-time ones need
// TXE_CHANNEL_RIG=1: they take minutes, and the worker's 90 s owner timeout is
// a constant, so they cannot be shortened and stay true.
const (
	rigMachine = "mch_RIG"
	rigToken   = "rig-token"
)

func needRealTime(t *testing.T) {
	t.Helper()
	if os.Getenv("TXE_CHANNEL_RIG") != "1" {
		t.Skip("set TXE_CHANNEL_RIG=1 to run the real-time rig")
	}
}

type rigIdentity struct{}

func (rigIdentity) Verify(_ context.Context, token string) (authn.Principal, error) {
	if token != rigToken {
		return authn.Principal{}, errors.New("unknown token")
	}
	return authn.Principal{Class: authn.ClassWorker, ClientID: rigToken, Expires: time.Now().Add(time.Hour)}, nil
}

func (rigIdentity) ResolveMachine(context.Context, authn.Principal) (authz.Machine, authz.Reason, error) {
	return authz.Machine{MachineID: rigMachine, OwnerID: "own_RIG", Class: authn.ClassWorker}, "", nil
}

type rigAuth struct{}

func (rigAuth) HTTPAuthorization(context.Context, string) (string, error) {
	return "Bearer " + rigToken, nil
}

// faultProxy forwards TCP to one target until told otherwise.
type faultProxy struct {
	listener net.Listener
	target   string

	// throttle is a delay per read, in nanoseconds, so that a fast upload is
	// still under way when a test cuts it.
	throttle atomic.Int64

	mu    sync.Mutex
	mode  string // "", "blackhole" or "refuse"
	conns map[net.Conn]struct{}
}

func newFaultProxy(t testing.TB, target string) *faultProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	p := &faultProxy{listener: listener, target: target, conns: map[net.Conn]struct{}{}}
	go p.accept()
	t.Cleanup(func() { _ = listener.Close(); p.closeAll() })
	return p
}

func (p *faultProxy) setMode(mode string) {
	p.mu.Lock()
	p.mode = mode
	p.mu.Unlock()
	// A blackhole keeps connections open and silent, as a dead path does. On
	// the way back, and for a refusal, what was open is gone.
	if mode != "blackhole" {
		p.closeAll()
	}
}

func (p *faultProxy) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for conn := range p.conns {
		_ = conn.Close()
	}
	p.conns = map[net.Conn]struct{}{}
}

func (p *faultProxy) currentMode() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.mode
}

func (p *faultProxy) accept() {
	for {
		client, err := p.listener.Accept()
		if err != nil {
			return
		}
		switch p.currentMode() {
		case "refuse":
			_ = client.Close()
			continue
		case "blackhole":
			// Accepted and never answered.
			p.track(client)
			continue
		}
		server, err := net.Dial("tcp", p.target)
		if err != nil {
			_ = client.Close()
			continue
		}
		p.track(client)
		p.track(server)
		go p.pump(client, server)
		go p.pump(server, client)
	}
}

func (p *faultProxy) track(conn net.Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.conns[conn] = struct{}{}
}

func (p *faultProxy) pump(dst, src net.Conn) {
	buffer := make([]byte, 32<<10)
	for {
		n, err := src.Read(buffer)
		for n > 0 && p.currentMode() == "blackhole" {
			time.Sleep(50 * time.Millisecond) // held, as a dead path holds it
		}
		if delay := p.throttle.Load(); n > 0 && delay > 0 {
			time.Sleep(time.Duration(delay))
		}
		if n > 0 {
			if _, werr := dst.Write(buffer[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				_ = dst.Close()
			}
			return
		}
	}
}

// channelRig is one fixture's channel.
type channelRig struct {
	proxy   *faultProxy
	current atomic.Pointer[workerchannel.Handler]
	marker  string
}

// fenced checks a run past the owner timeout: it does not succeed, nothing
// replays it, and the next run goes through.
func (r *channelRig) fenced(t *testing.T, f *testFixture) {
	t.Helper()
	status := f.waitForStatusIn([]ir.Status{ir.Failed, ir.Aborted, ir.Succeeded}, 5*time.Minute)
	t.Logf("rig: final status %s, error %q", status.Status, status.Error)
	assert.NotEqual(t, ir.Succeeded, status.Status, "a run past the owner timeout is fenced")
	time.Sleep(20 * time.Second)
	runs, err := os.ReadFile(r.marker + ".runs")
	require.NoError(t, err)
	assert.Equal(t, 1, strings.Count(string(runs), "x"), "nothing replayed the fenced run")

	require.NoError(t, f.enqueue())
	second := f.waitForStatus(ir.Succeeded, 2*time.Minute)
	assert.NotEqual(t, status.DAGRunID, second.DAGRunID)
	t.Logf("rig: next run %s succeeded", second.DAGRunID)
}

// bind serves the channel on the coordinator's current handler.
func (r *channelRig) bind(t testing.TB, coord *test.Coordinator) {
	t.Helper()
	auth, err := transportauth.NewServer(transportauth.ServerConfig{
		Mode: authz.ModeEnforce, Verifier: rigIdentity{}, Machines: rigIdentity{}, MachinesOnly: true,
	})
	require.NoError(t, err)
	handler, err := workerchannel.NewHandler(workerchannel.Config{
		Auth: auth, Coordinator: coord.Handler(), Health: health.NewServer(),
	})
	require.NoError(t, err)
	r.current.Store(handler)
}

// edge stands where the proxy in front of the hub stands: HTTP/1.1 to the
// origin, a body limit, and a read timeout. It is a local shape of that hop, not
// a claim about any real edge.
func edge(t testing.TB, origin string) *httptest.Server {
	t.Helper()
	target, err := url.Parse(origin)
	require.NoError(t, err)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = -1
	proxy.Transport = &http.Transport{
		ForceAttemptHTTP2: false, ResponseHeaderTimeout: 125 * time.Second, DisableCompression: true,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 100_000_000)
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	return server
}

func withChannelRig(rig *channelRig) fixtureOption {
	return func(c *fixtureConfig) {
		c.workerLabels = map[string]string{txepkg.LabelMachine: rigMachine}
		c.workerChannel = func(t testing.TB, coord *test.Coordinator) (coordinator.Client, string) {
			t.Helper()
			rig.bind(t, coord)
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rig.current.Load().ServeHTTP(w, r)
			}))
			t.Cleanup(origin.Close)
			front := edge(t, origin.URL)
			rig.proxy = newFaultProxy(t, front.Listener.Addr().String())

			conn, err := workerchannel.NewConn(workerchannel.ClientConfig{
				BaseURL:     "http://" + rig.proxy.listener.Addr().String(),
				Credentials: rigAuth{},
			})
			require.NoError(t, err)
			clientConfig := coordinator.ConfigFromPeer(coord.Config.Core.Peer)
			clientConfig.Connect = func() coordinator.Connection { return conn }
			clientConfig.ArtifactSegmentBytes = 16 << 20
			require.NoError(t, clientConfig.Validate())
			registry, err := coordinator.NewStaticRegistry([]string{rig.proxy.listener.Addr().String()})
			require.NoError(t, err)
			return coordinator.New(registry, clientConfig), rigMachine
		}
	}
}

func rigDAG(body string) string {
	return fmt.Sprintf(`type: chain
worker_selector:
  %s: %s
steps:
  - name: run
    command: |
%s
`, txepkg.LabelMachine, rigMachine, indentYAMLBlock(body, 6))
}

func needPosixShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the rig's jobs are POSIX shell scripts")
	}
}

func runThroughRig(t *testing.T, script string, opts ...fixtureOption) (*testFixture, *channelRig) {
	t.Helper()
	needPosixShell(t)
	rig := &channelRig{}
	f := newTestFixture(t, rigDAG(script), append(opts, withChannelRig(rig), withLogPersistence())...)
	t.Cleanup(f.cleanup)
	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(distrTestTimeout(10 * time.Minute))
	return f, rig
}

func TestChannelRigRunsAJobToItsEnd(t *testing.T) {
	f, _ := runThroughRig(t, "echo hello from the channel")
	status := f.waitForStatus(ir.Succeeded, distrTestTimeout(60*time.Second))
	assert.Equal(t, rigMachine, status.WorkerID)
}

// A short loss, well under the owner timeout: the run does not notice.
func TestChannelRigShortOutageKeepsTheRun(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "started")
	f, rig := runThroughRig(t, "touch "+marker+"\nsleep 12\necho finished")
	require.Eventually(t, func() bool { _, err := os.Stat(marker); return err == nil }, distrTestTimeout(30*time.Second), 50*time.Millisecond)
	rig.proxy.setMode("refuse")
	time.Sleep(4 * time.Second)
	rig.proxy.setMode("")
	status := f.waitForStatus(ir.Succeeded, distrTestTimeout(60*time.Second))
	assert.Equal(t, rigMachine, status.WorkerID)
}

func realTimeOutage(t *testing.T, mode string, outage, runFor time.Duration) (*testFixture, *channelRig) {
	t.Helper()
	marker := filepath.Join(t.TempDir(), "started")
	// The first run sleeps; a later one finishes at once.
	script := fmt.Sprintf("echo x >> %[1]s.runs\nif [ -f %[1]s ]; then echo again; exit 0; fi\ntouch %[1]s\nsleep %[2]d\necho finished",
		marker, int(runFor.Seconds()))
	f, rig := runThroughRig(t, script)
	rig.marker = marker
	require.Eventually(t, func() bool { _, err := os.Stat(marker); return err == nil }, distrTestTimeout(30*time.Second), 50*time.Millisecond)
	rig.proxy.setMode(mode)
	t.Logf("rig: %s for %s", mode, outage)
	time.Sleep(outage)
	rig.proxy.setMode("")
	t.Logf("rig: path restored")
	return f, rig
}

// R8: the hub restarts under a running job. The worker reconnects by itself.
func TestChannelRigHubRestart(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "started")
	f, rig := runThroughRig(t, "touch "+marker+"\nsleep 15\necho finished")
	require.Eventually(t, func() bool { _, err := os.Stat(marker); return err == nil }, distrTestTimeout(30*time.Second), 50*time.Millisecond)
	f.coord.Restart(t)
	rig.bind(t, f.coord)
	status := f.waitForStatus(ir.Succeeded, distrTestTimeout(90*time.Second))
	assert.Equal(t, rigMachine, status.WorkerID)
}

// R10, logs: a cut during output loses no line, and none arrives twice.
func TestChannelRigLogSurvivesACut(t *testing.T) {
	f, rig := runThroughRig(t, "for i in $(seq 1 60); do echo line-$i; sleep 0.2; done")
	time.Sleep(5 * time.Second)
	rig.proxy.setMode("refuse")
	time.Sleep(4 * time.Second)
	rig.proxy.setMode("")
	status := f.waitForStatus(ir.Succeeded, distrTestTimeout(60*time.Second))
	files := findLogFiles(t, f.coord.Config.Paths.LogDir, status.Name, status.DAGRunID, "run", "stdout")
	require.NotEmpty(t, files)
	data, err := os.ReadFile(filepath.Clean(files[0]))
	require.NoError(t, err)
	var want []string
	for i := 1; i <= 60; i++ {
		want = append(want, fmt.Sprintf("line-%d", i))
	}
	var got []string
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, "line-") {
			got = append(got, line)
		}
	}
	assert.Equal(t, want, got)
}

// R10 and R14, artifacts: a file larger than any stream, cut while its segments
// are arriving, is committed once and whole.
func TestChannelRigLargeArtifactSurvivesACut(t *testing.T) {
	needPosixShell(t)
	script := strings.Join([]string{
		`mkdir -p "${DAG_RUN_ARTIFACTS_DIR}/reports"`,
		`head -c 45000000 /dev/urandom > "${DAG_RUN_ARTIFACTS_DIR}/reports/large.bin"`,
		`(sha256sum "${DAG_RUN_ARTIFACTS_DIR}/reports/large.bin" || shasum -a 256 "${DAG_RUN_ARTIFACTS_DIR}/reports/large.bin") | cut -d' ' -f1`,
	}, "\n")
	rig := &channelRig{}
	f := newTestFixture(t, rigDAG(script), withChannelRig(rig), withLogPersistence(), withArtifactPersistence(), withIsolatedWorker())
	t.Cleanup(f.cleanup)
	rig.proxy.throttle.Store(int64(3 * time.Millisecond))
	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(distrTestTimeout(5 * time.Minute))
	var heldBeforeCut atomic.Int64
	cut := make(chan struct{})
	go func() {
		defer close(cut)
		root := f.coord.Config.Paths.ArtifactDir
		deadline := time.Now().Add(distrTestTimeout(60 * time.Second))
		for time.Now().Before(deadline) {
			var held int64
			_ = filepath.WalkDir(root, func(p string, d os.DirEntry, _ error) error {
				if d != nil && !d.IsDir() && strings.Contains(p, ir.ArtifactSegmentDir) {
					if info, err := d.Info(); err == nil {
						held += info.Size()
					}
				}
				return nil
			})
			if held > 16<<20 {
				heldBeforeCut.Store(held)
				rig.proxy.setMode("refuse")
				time.Sleep(2 * time.Second)
				rig.proxy.setMode("")
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	status := f.waitForStatusIn([]ir.Status{ir.Succeeded, ir.Failed, ir.Aborted}, distrTestTimeout(3*time.Minute))
	<-cut
	require.Equal(t, ir.Succeeded, status.Status, "error %q", status.Error)
	require.Positive(t, heldBeforeCut.Load(), "the cut must land while segments are arriving")
	t.Logf("rig: cut with %d bytes held", heldBeforeCut.Load())
	data, err := os.ReadFile(filepath.Join(status.ArchiveDir, "reports", "large.bin"))
	require.NoError(t, err)
	assert.Len(t, data, 45000000)
	sum := sha256.Sum256(data)
	logs := findLogFiles(t, f.coord.Config.Paths.LogDir, status.Name, status.DAGRunID, "run", "stdout")
	require.NotEmpty(t, logs)
	logged, err := os.ReadFile(filepath.Clean(logs[0]))
	require.NoError(t, err)
	assert.Contains(t, string(logged), hex.EncodeToString(sum[:]))
	_, err = os.Stat(filepath.Join(status.ArchiveDir, ir.ArtifactSegmentDir))
	assert.ErrorIs(t, err, os.ErrNotExist, "no upload is left behind")
}

// R3: under the 90 s owner timeout. The run must finish, once.
func TestChannelRigBlackhole60s(t *testing.T) {
	needRealTime(t)
	f, _ := realTimeOutage(t, "blackhole", 60*time.Second, 75*time.Second)
	status := f.waitForStatus(ir.Succeeded, 3*time.Minute)
	assert.Equal(t, rigMachine, status.WorkerID)
	assert.Empty(t, status.Error)
}

// R4: past the owner timeout. The run is fenced once, and nothing replays it.
func TestChannelRigBlackhole120s(t *testing.T) {
	needRealTime(t)
	f, rig := realTimeOutage(t, "blackhole", 120*time.Second, 150*time.Second)
	rig.fenced(t, f)
}

// R5: the shape of the daily DNS loss, every new connection failing.
func TestChannelRigRefused120s(t *testing.T) {
	needRealTime(t)
	f, rig := realTimeOutage(t, "refuse", 120*time.Second, 150*time.Second)
	rig.fenced(t, f)
}

// R9: the worker offline for 15 minutes when work comes due. This measures what
// happens; the only hard claims are one execution at most and a truthful end.
func TestChannelRigOffline15m(t *testing.T) {
	needRealTime(t)
	marker := filepath.Join(t.TempDir(), "runs")
	rig := &channelRig{}
	f := newTestFixture(t, rigDAG("echo x >> "+marker), withChannelRig(rig), withLogPersistence())
	t.Cleanup(f.cleanup)
	rig.proxy.setMode("blackhole")
	time.Sleep(45 * time.Second) // the worker is stale before work arrives
	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(30 * time.Minute)
	time.Sleep(15 * time.Minute)
	queued := time.Now()
	status, err := f.latestStatus()
	require.NoError(t, err)
	t.Logf("rig: after 15 min offline the run is %s", status.Status)
	rig.proxy.setMode("")
	final := f.waitForStatusIn([]ir.Status{ir.Succeeded, ir.Failed, ir.Aborted, ir.Rejected}, 5*time.Minute)
	t.Logf("rig: %s %s after the path returned, error %q", final.Status, time.Since(queued).Round(time.Second), final.Error)
	data, err := os.ReadFile(marker)
	if err == nil {
		assert.LessOrEqual(t, strings.Count(string(data), "x"), 1)
	}
}
