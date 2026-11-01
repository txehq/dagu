// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package distr_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/dns/dnsmessage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/dagucloud/dagu/v2/internal/cmn/cmdutil"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/queue"
	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	"github.com/dagucloud/dagu/v2/internal/txe/workerchannel"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

func (r *channelRig) clientAs(t *testing.T, token string) coordinatorv1.CoordinatorServiceClient {
	t.Helper()
	conn, err := workerchannel.NewConn(workerchannel.ClientConfig{
		BaseURL:     "http://" + r.proxy.listener.Addr().String() + "/api/v1" + workerchannel.MountPath,
		Credentials: rigAuth{token: token},
	})
	require.NoError(t, err)
	return coordinatorv1.NewCoordinatorServiceClient(conn)
}

// Another owner's machine, with a valid credential and its own worker id, aims
// at a run in flight. Nothing it sends lands, and the run is not disturbed.
func TestChannelProofAnotherMachineCannotTouchARun(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "started")
	release := filepath.Join(t.TempDir(), "release")
	script := fmt.Sprintf("touch %s\nuntil [ -f %s ]; do sleep 0.1; done\necho finished", marker, release)
	f, rig := runThroughRig(t, script, withArtifactPersistence())
	require.Eventually(t, func() bool { _, err := os.Stat(marker); return err == nil }, distrTestTimeout(30*time.Second), 50*time.Millisecond)
	var running ir.DAGRunStatus
	require.Eventually(t, func() bool {
		var err error
		running, err = f.latestStatus()
		return err == nil && running.AttemptKey != "" && running.AttemptID != ""
	}, distrTestTimeout(30*time.Second), 50*time.Millisecond)

	other := rig.clientAs(t, rigOtherToken)
	ctx := context.Background()

	// Claiming to be the machine is refused at the door.
	_, err := other.RunHeartbeat(ctx, &coordinatorv1.RunHeartbeatRequest{WorkerId: rigMachine})
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "%v", err)

	// In its own name, the attempt is not its to refresh.
	beat, err := other.RunHeartbeat(ctx, &coordinatorv1.RunHeartbeatRequest{WorkerId: rigOtherMachine,
		RunningTasks: []*coordinatorv1.RunningTask{{DagRunId: running.DAGRunID, DagName: running.Name, AttemptKey: running.AttemptKey}}})
	require.NoError(t, err)
	assert.NotEmpty(t, beat.GetCancelledRuns(), "told the attempt is not its own")

	logs, err := other.StreamLogs(ctx)
	require.NoError(t, err)
	_ = logs.Send(&coordinatorv1.LogChunk{WorkerId: rigOtherMachine, DagName: running.Name, DagRunId: running.DAGRunID,
		AttemptId: running.AttemptID, AttemptKey: running.AttemptKey, StepName: "run",
		StreamType: coordinatorv1.LogStreamType_LOG_STREAM_TYPE_STDOUT, Data: []byte("FORGED-LOG\n")})
	_, err = logs.CloseAndRecv()
	assert.Error(t, err, "a log for another machine's attempt")

	artifacts, err := other.StreamArtifacts(ctx)
	require.NoError(t, err)
	chunk := &coordinatorv1.ArtifactChunk{WorkerId: rigOtherMachine, DagName: running.Name, DagRunId: running.DAGRunID,
		AttemptId: running.AttemptID, AttemptKey: running.AttemptKey, RelativePath: "forged.txt", Data: []byte("forged")}
	chunk.SetByteOffset(0)
	_ = artifacts.Send(chunk)
	_, err = artifacts.CloseAndRecv()
	assert.Error(t, err, "an artifact for another machine's attempt")

	_, err = other.ReportStatus(ctx, &coordinatorv1.ReportStatusRequest{WorkerId: rigOtherMachine,
		Status: &coordinatorv1.DAGRunStatusProto{}})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "an empty status is refused, and the hub stays up: %v", err)

	require.NoError(t, os.WriteFile(release, nil, 0o600))
	final := f.waitForStatus(ir.Succeeded, distrTestTimeout(60*time.Second))
	assert.Equal(t, rigMachine, final.WorkerID)
	assert.False(t, hubLogHolds(f.coord.Config.Paths.LogDir, "FORGED-LOG"))
	if final.ArchiveDir != "" {
		_, err = os.Stat(filepath.Join(final.ArchiveDir, "forged.txt"))
		assert.ErrorIs(t, err, os.ErrNotExist)
	}
}

// rigDNS answers for one name until it is told to stop: a real Go resolver is
// behind the channel's dial, and a real lookup fails.
type rigDNS struct {
	conn net.PacketConn
	down atomic.Bool
}

func newRigDNS(t *testing.T, ip [4]byte) *rigDNS {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	d := &rigDNS{conn: conn}
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil || len(query.Questions) != 1 {
				continue
			}
			answer := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true}, Questions: query.Questions}
			switch {
			case d.down.Load():
				answer.RCode = dnsmessage.RCodeServerFailure
			case query.Questions[0].Type == dnsmessage.TypeA:
				answer.Answers = []dnsmessage.Resource{{
					Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
					Body:   &dnsmessage.AResource{A: ip},
				}}
			}
			if out, err := answer.Pack(); err == nil {
				_, _ = conn.WriteTo(out, from)
			}
		}
	}()
	return d
}

// The daily loss on this path is a name that stops resolving. A real resolver
// fails here, under TLS and HTTP/2, while connections are cut.
func TestChannelProofResolverFailure(t *testing.T) {
	needPosixShell(t)
	outage := 8 * time.Second
	runFor := 18
	if os.Getenv("TXE_CHANNEL_RIG") == "1" {
		outage, runFor = 80*time.Second, 95
	}
	rig := &channelRig{}
	dns := newRigDNS(t, [4]byte{127, 0, 0, 1})
	marker := filepath.Join(t.TempDir(), "started")
	script := fmt.Sprintf("touch %s\nsleep %d\necho finished", marker, runFor)
	opts := []fixtureOption{withChannelRig(rig), withLogPersistence()}
	opts = append(opts, func(c *fixtureConfig) {
		c.workerChannel = func(t testing.TB, coord *test.Coordinator) (coordinator.Client, string) {
			t.Helper()
			rig.bind(t, coord)
			rig.origin = httptest.NewServer(rig.current.Load())
			t.Cleanup(rig.origin.Close)
			front := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				rig.current.Load().ServeHTTP(w, r)
			}))
			front.EnableHTTP2 = true
			front.StartTLS()
			t.Cleanup(front.Close)
			rig.proxy = newFaultProxy(t, front.Listener.Addr().String())
			_, port, err := net.SplitHostPort(rig.proxy.listener.Addr().String())
			require.NoError(t, err)

			resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", dns.conn.LocalAddr().String())
			}}
			transport := &http.Transport{
				DialContext:       (&net.Dialer{Resolver: resolver, Timeout: 3 * time.Second}).DialContext,
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // the rig's own certificate
				ForceAttemptHTTP2: true,
				HTTP2:             &http.HTTP2Config{SendPingTimeout: 2 * time.Second, PingTimeout: time.Second},
			}
			conn, err := workerchannel.NewConn(workerchannel.ClientConfig{
				BaseURL: "https://hub.rig.test:" + port, Credentials: rigAuth{token: rigToken}, HTTP: &http.Client{Transport: transport},
			})
			require.NoError(t, err)
			clientConfig := coordinator.ConfigFromPeer(coord.Config.Core.Peer)
			clientConfig.Connect = func() coordinator.Connection { return conn }
			require.NoError(t, clientConfig.Validate())
			registry, err := coordinator.NewStaticRegistry([]string{"hub.rig.test:" + port})
			require.NoError(t, err)
			return coordinator.New(registry, clientConfig), rigMachine
		}
	})
	f := newTestFixture(t, rigDAG(script), opts...)
	t.Cleanup(f.cleanup)
	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(distrTestTimeout(10 * time.Minute))
	require.Eventually(t, func() bool { _, err := os.Stat(marker); return err == nil }, distrTestTimeout(30*time.Second), 50*time.Millisecond)

	dns.down.Store(true)
	rig.proxy.setMode("refuse") // what is open is gone, and only a lookup could reopen it
	rig.proxy.setMode("")
	t.Logf("rig: resolver failing for %s", outage)
	_, err := (&net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", dns.conn.LocalAddr().String())
	}}).LookupHost(context.Background(), "hub.rig.test")
	require.Error(t, err, "the name must really not resolve")
	time.Sleep(outage)
	dns.down.Store(false)
	status := f.waitForStatus(ir.Succeeded, distrTestTimeout(3*time.Minute))
	assert.Equal(t, rigMachine, status.WorkerID)
}

// credentialFor writes a real machine credential for a real token endpoint.
func credentialFor(t *testing.T) string {
	t.Helper()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": rigToken, "token_type": "Bearer", "expires_in": 300, "refresh_token": "offline"})
	}))
	t.Cleanup(provider.Close)
	dir, err := os.MkdirTemp("", "rigcred")
	require.NoError(t, err)
	require.NoError(t, os.Chmod(dir, 0o700)) //nolint:gosec // the owner's own directory
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "worker-credential.json")
	require.NoError(t, transportauth.WriteMachineCredential(path, transportauth.MachineCredential{
		Schema: transportauth.CredentialSchema, Issuer: "https://issuer.rig.test", TokenEndpoint: provider.URL + "/token",
		ClientID: rigToken, Class: authn.ClassWorker, MachineID: rigMachine, RefreshToken: "offline",
	}))
	return path
}

// lockedOutput is a running process's output, read while it still writes.
type lockedOutput struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (o *lockedOutput) Write(data []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Write(data)
}

func (o *lockedOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

// startChannelWorkerProcess is `dagu worker --worker.hub-url`: the real binary,
// its real credential source, and no address of a coordinator.
func startChannelWorkerProcess(t *testing.T, f *testFixture, rig *channelRig) *osexec.Cmd {
	t.Helper()
	cmd := osexec.Command(f.coord.Config.Paths.Executable, "worker",
		"--config", f.coord.Config.Paths.ConfigFileUsed,
		"--worker.id", rigMachine,
		"--worker.health-port=0",
		"--worker.labels", "txe.machine="+rigMachine+",txe.owner=own_RIG",
		"--worker.hub-url", "http://"+rig.proxy.listener.Addr().String())
	cmdutil.SetupCommand(cmd)
	cmd.Env = append(append([]string{}, f.coord.ChildEnv...), "DAGU_WORKER_AUTH_CREDENTIAL_FILE="+credentialFor(t))
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGCONT)
		_ = cmdutil.TerminateProcessGroup(cmd, cmdutil.ForceTermination())
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("worker output:\n%s", output.String())
		}
	})
	f.waitForWorkerRegistration(rigMachine, 20*time.Second)
	return cmd
}

func channelProcessRig(t *testing.T, script string) (*testFixture, *channelRig, *osexec.Cmd) {
	t.Helper()
	needPosixShell(t)
	rig := &channelRig{}
	opts := []fixtureOption{withChannelRig(rig), withLogPersistence(), withWorkerCount(0)}
	f := newTestFixture(t, rigDAG(script), opts...)
	t.Cleanup(f.cleanup)
	cmd := startChannelWorkerProcess(t, f, rig)
	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(distrTestTimeout(10 * time.Minute))
	return f, rig, cmd
}

// The real binary on the channel runs a job, with no coordinator address and no
// cluster access of any kind.
func TestChannelProofARealWorkerProcessRunsAJob(t *testing.T) {
	f, _, _ := channelProcessRig(t, "echo from the real worker")
	final := f.waitForStatus(ir.Succeeded, distrTestTimeout(60*time.Second))
	assert.Equal(t, rigMachine, final.WorkerID)
	assert.True(t, hubLogHolds(f.coord.Config.Paths.LogDir, "from the real worker"))
}

// freezableJob is a job that says when it is working, so a test can stop it and
// see that it stopped. A step's shell leads its own process group, apart from
// the worker's, so stopping the worker alone leaves the job running.
type freezableJob struct {
	dir string
}

func newFreezableJob(t *testing.T) *freezableJob {
	t.Helper()
	return &freezableJob{dir: t.TempDir()}
}

func (j *freezableJob) script(ticks int) string {
	return fmt.Sprintf("echo $$ > %[1]s\nfor i in $(seq %[2]d); do echo tick >> %[3]s; sleep 1; done",
		filepath.Join(j.dir, "group"), ticks, filepath.Join(j.dir, "ticks"))
}

func (j *freezableJob) ticks(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(j.dir, "ticks"))
	require.NoError(t, err)
	return bytes.Count(data, []byte("tick"))
}

type frozenGroups struct {
	groups []int
}

func (g frozenGroups) thaw(t *testing.T) {
	t.Helper()
	for _, group := range g.groups {
		require.NoError(t, syscall.Kill(-group, syscall.SIGCONT))
	}
}

// freezeWith stops the job and its worker together, once the job has started,
// and proves the job stopped.
func (j *freezableJob) freezeWith(t *testing.T, worker *osexec.Cmd) frozenGroups {
	t.Helper()
	var group int
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(filepath.Join(j.dir, "group"))
		if err != nil {
			return false
		}
		if group, err = strconv.Atoi(strings.TrimSpace(string(data))); err != nil || group <= 1 {
			return false
		}
		_, err = os.Stat(filepath.Join(j.dir, "ticks"))
		return err == nil
	}, distrTestTimeout(30*time.Second), 50*time.Millisecond)
	frozen := frozenGroups{groups: []int{group, worker.Process.Pid}}
	t.Cleanup(func() {
		for _, g := range frozen.groups {
			_ = syscall.Kill(-g, syscall.SIGCONT)
		}
	})
	for _, g := range frozen.groups {
		require.NoError(t, syscall.Kill(-g, syscall.SIGSTOP))
	}
	time.Sleep(200 * time.Millisecond)
	before := j.ticks(t)
	time.Sleep(2 * time.Second)
	require.Equal(t, before, j.ticks(t), "the job stopped with its worker")
	return frozen
}

// The machine sleeping: the worker and its job stop together and resume with
// the clock moved on. The machine's own OS is not slept. A short freeze changes
// nothing.
func TestChannelProofFreezeUnderTheOwnerTimeout(t *testing.T) {
	job := newFreezableJob(t)
	f, _, cmd := channelProcessRig(t, job.script(12))
	frozen := job.freezeWith(t, cmd)
	time.Sleep(10 * time.Second)
	frozen.thaw(t)
	final := f.waitForStatus(ir.Succeeded, distrTestTimeout(90*time.Second))
	assert.Equal(t, rigMachine, final.WorkerID)
	assert.Equal(t, 12, job.ticks(t))
}

// Past the owner timeout, the worker and its job are frozen together, as on a
// machine asleep. Resumed, the worker reaches the hub before it counts its owner
// as lost, so the job carries on and finishes, once. Nothing replays it, and the
// same worker takes the next run with no restart.
func TestChannelProofFreezePastTheOwnerTimeout(t *testing.T) {
	needRealTime(t)
	job := newFreezableJob(t)
	marker := filepath.Join(job.dir, "started")
	script := fmt.Sprintf("echo x >> %[1]s.runs\nif [ -f %[1]s ]; then echo again; exit 0; fi\ntouch %[1]s\n%[2]s", marker, job.script(20))
	f, _, cmd := channelProcessRig(t, script)
	frozen := job.freezeWith(t, cmd)
	t.Logf("rig: frozen for 2m")
	time.Sleep(2 * time.Minute)
	frozen.thaw(t)
	t.Logf("rig: resumed")

	first := f.waitForStatusIn([]ir.Status{ir.Failed, ir.Aborted, ir.Succeeded}, 5*time.Minute)
	t.Logf("rig: final status %s, error %q", first.Status, first.Error)
	assert.Equal(t, ir.Succeeded, first.Status, "the job was frozen with its worker, and finishes")
	runs, err := os.ReadFile(marker + ".runs")
	require.NoError(t, err)
	assert.Equal(t, 1, bytes.Count(runs, []byte("x")), "executed once")
	assert.Equal(t, 20, job.ticks(t), "it picked up where it stopped")

	require.NoError(t, f.enqueue())
	require.Eventually(t, func() bool {
		next, err := f.latestStatus()
		return err == nil && next.DAGRunID != first.DAGRunID && next.Status == ir.Succeeded
	}, 2*time.Minute, 200*time.Millisecond, "the same worker takes the next run")
}

// startIsolatedChannelWorker is a worker process sharing nothing with the hub:
// what it holds on disk can reach the hub only over the channel.
func startIsolatedChannelWorker(t *testing.T, f *testFixture, rig *channelRig, workerID string) (*osexec.Cmd, *lockedOutput) {
	t.Helper()
	home := t.TempDir()
	cmd := osexec.Command(f.coord.Config.Paths.Executable, "worker",
		"--worker.id", workerID,
		"--worker.health-port=0",
		"--worker.labels", "txe.machine="+rigMachine+",txe.owner=own_RIG",
		"--worker.hub-url", "http://"+rig.proxy.listener.Addr().String())
	cmdutil.SetupCommand(cmd)
	cmd.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH"), "DAGU_HOME=" + filepath.Join(home, "dagu"),
		"DAGU_WORKER_AUTH_CREDENTIAL_FILE=" + credentialFor(t)}
	output := &lockedOutput{}
	cmd.Stdout, cmd.Stderr = output, output
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGCONT)
		_ = cmdutil.TerminateProcessGroup(cmd, cmdutil.ForceTermination())
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("worker output:\n%s", output.String())
		}
	})
	f.waitForWorkerRegistration(workerID, 20*time.Second)
	return cmd, output
}

// The fence itself. A worker is frozen, its attempt expires on the hub, and
// another worker of the machine finishes the run again. Then the old worker
// wakes and does everything it would have: it finishes its script, writes the
// result and reports. Nothing of that may land.
func TestChannelProofAStaleAttemptNeverOverwritesTheNewer(t *testing.T) {
	needRealTime(t)
	needPosixShell(t)
	dir := t.TempDir()
	job := newFreezableJob(t)
	first, gate := filepath.Join(dir, "first"), filepath.Join(dir, "gate")
	script := fmt.Sprintf(`mkdir -p "${DAG_RUN_ARTIFACTS_DIR}/reports"
if [ ! -f %[1]s ]; then
  touch %[1]s
  echo OLD-BEFORE
  %[3]s
  until [ -f %[2]s ]; do sleep 0.1; done
  echo OLD-AFTER
  printf old-attempt > "${DAG_RUN_ARTIFACTS_DIR}/reports/result.txt"
else
  echo NEW-ATTEMPT
  printf new-attempt > "${DAG_RUN_ARTIFACTS_DIR}/reports/result.txt"
fi`, first, gate, job.script(1))
	rig := &channelRig{}
	f := newTestFixture(t, rigDAG(script), withChannelRig(rig), withLogPersistence(), withArtifactPersistence(),
		withWorkerCount(0), withStaleThresholds(3*time.Second, 8*time.Second), withZombieDetectionInterval(500*time.Millisecond))
	t.Cleanup(f.cleanup)
	old, oldOutput := startIsolatedChannelWorker(t, f, rig, rigMachine+"@old")
	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(distrTestTimeout(10 * time.Minute))
	require.Eventually(t, func() bool { _, err := os.Stat(first); return err == nil }, distrTestTimeout(30*time.Second), 50*time.Millisecond)

	var stale ir.DAGRunStatus
	require.Eventually(t, func() bool {
		var err error
		stale, err = f.latestStatus()
		return err == nil && stale.Status == ir.Running && stale.AttemptKey != ""
	}, distrTestTimeout(30*time.Second), 50*time.Millisecond)

	frozen := job.freezeWith(t, old)
	t.Logf("rig: old worker frozen on attempt %s", stale.AttemptID)
	expired := f.waitForStatus(ir.Failed, distrTestTimeout(60*time.Second))
	t.Logf("rig: hub expired it: %q", expired.Error)

	f.setupWorkerMode(rigMachine+"@new", map[string]string{txepkg.LabelMachine: rigMachine}, "", true, nil)
	added, err := queue.EnqueueRetry(f.coord.Context, f.coord.DAGRunRepository, f.coord.QueueStore,
		f.dagWrapper.DAG, &expired, queue.EnqueueRetryOptions{Processes: f.coord.ProcRepository})
	require.NoError(t, err)
	require.True(t, added)
	// The scheduler reclaims the expired attempt's queue slot on its own 90 s
	// threshold, which this fixture does not shorten.
	newer := f.waitForStatus(ir.Succeeded, distrTestTimeout(180*time.Second))
	require.Equal(t, rigMachine+"@new", newer.WorkerID)
	t.Logf("rig: newer attempt %s succeeded", newer.AttemptID)
	result := filepath.Join(newer.ArchiveDir, "reports", "result.txt")
	data, err := os.ReadFile(filepath.Clean(result))
	require.NoError(t, err)
	require.Equal(t, "new-attempt", string(data))

	require.NoError(t, os.WriteFile(gate, nil, 0o600))
	frozen.thaw(t)
	t.Logf("rig: old worker resumed")
	time.Sleep(15 * time.Second)

	// Where the old worker's first refused call lands varies, so whether it
	// reached its artifact upload varies too. The hub is sent one regardless.
	late, err := rig.clientAs(t, rigToken).StreamArtifacts(f.coord.Context)
	require.NoError(t, err)
	_ = late.Send(&coordinatorv1.ArtifactChunk{WorkerId: rigMachine + "@old", DagName: stale.Name, DagRunId: stale.DAGRunID,
		AttemptId: stale.AttemptID, AttemptKey: stale.AttemptKey, ExecutionMarker: stale.QueuedAt,
		OwnerCoordinatorId: "coord-0", RelativePath: "reports/result.txt", Data: []byte("old-attempt"), IsFinal: true})
	_, err = late.CloseAndRecv()
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), "the old attempt's artifact: %v", err)

	after, err := f.latestStatus()
	require.NoError(t, err)
	assert.Equal(t, ir.Succeeded, after.Status)
	assert.Equal(t, newer.AttemptID, after.AttemptID)
	assert.Equal(t, newer.WorkerID, after.WorkerID)
	assert.Equal(t, newer.FinishedAt, after.FinishedAt)
	data, err = os.ReadFile(filepath.Clean(result))
	require.NoError(t, err)
	assert.Equal(t, "new-attempt", string(data), "the old attempt's result never replaced it")
	assert.False(t, hubLogHolds(f.coord.Config.Paths.LogDir, "OLD-AFTER"), "the old attempt's log never landed")
	assert.True(t, hubLogHolds(f.coord.Config.Paths.LogDir, "NEW-ATTEMPT"))
	_, err = os.Stat(filepath.Join(newer.ArchiveDir, ir.ArtifactSegmentDir))
	assert.ErrorIs(t, err, os.ErrNotExist)
	assert.Contains(t, oldOutput.String(), "superseded by newer attempt", "the hub refused the old attempt in words")
	t.Logf("rig: old worker said: %s", lastLines(oldOutput.String(), 3))
}

func lastLines(text string, n int) string {
	lines := bytes.Split(bytes.TrimSpace([]byte(text)), []byte("\n"))
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return string(bytes.Join(lines, []byte(" | ")))
}
