// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

const (
	testOwner   = "own_01K7A5ZQ8M3N4P5R6S7T8V9W0A"
	testMachine = "mch_01K7A5ZQ8M3N4P5R6S7T8V9W0C"
)

// session is one coding session's view of this machine: its own registrar
// over the shared TXE home.
type session struct {
	*Registrar
	name string
}

// machineHome creates a TXE home with a machine identity and tells the fake
// registry about the machine.
func machineHome(t *testing.T, f *fakeRegistry) txepkg.Home {
	t.Helper()
	home := txepkg.Home{Root: filepath.Join(t.TempDir(), "txe-dagu")}
	require.NoError(t, os.MkdirAll(home.Root, 0o700))
	identity := fmt.Sprintf(`{"schema":1,"machine_id":%q,"owner_id":%q,"display_name":"test-mac"}`, testMachine, testOwner)
	require.NoError(t, os.WriteFile(filepath.Join(home.Root, "machine.json"), []byte(identity), 0o600))
	f.machines[testMachine] = Machine{MachineID: testMachine, OwnerID: testOwner, DisplayName: "test-mac"}
	t.Cleanup(func() {
		_ = filepath.WalkDir(home.Root, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(p, 0o700) //nolint:gosec // let the test directory be removed
			}
			return nil
		})
	})
	return home
}

var idCounter atomic.Int64

func newSession(f *fakeRegistry, home txepkg.Home, name string) *session {
	return &session{name: name, Registrar: &Registrar{
		Client: f.client(),
		Home:   home,
		// The path policy is empty because test directories are temporary.
		Store:   &txepkg.Store{Root: home.PackagesDir()},
		Journal: txepkg.NewJournal(home),
		Actor:   Actor{Kind: ActorKindCLI, ID: "cli", Session: name, MachineID: testMachine, Client: "dagu test"},
		NewID: func(prefix string) (string, error) {
			return fmt.Sprintf("%s_%026d", prefix, idCounter.Add(1)), nil
		},
		// The test machine has no dagu installed; it is taken to have every
		// command, except where a test is about one that is missing.
		HasCommands: func(context.Context, string, [][]string) error { return nil },
	}}
}

const collectorSpec = `schema: 1
job_key: nightly-collector
title: Collect the nightly snapshot
purpose: Record a dated snapshot of the export directory each night so a missing export is noticed the next morning.
project:
  key: github.com/txehq/txe
  name: txehq/txe
targets:
  - kind: fixture.directory
    environment: test
    stable_id: {inode: "4242"}
    display_name: exports
schedule:
  cron: "0 2 * * *"
  timezone: Australia/Perth
  timeout_sec: 300
package:
  include: [collect.py, lib]
  entrypoint: [./collect.py]
env:
  SOURCE_DIR: /srv/exports
credential_refs:
  - name: LINEAR_API_KEY
    kind: file
    locator: %s
expected_outcome:
  success_criteria: ["A snapshot file exists for each night."]
lifetime:
  expires_at: "2027-01-31T00:00:00Z"
review_policy:
  cadence: "0 9 * * *"
  brief: Check that last night's snapshot exists and is not empty.
`

// worktree writes a job's files and spec into a throwaway directory, as a
// coding session's worktree would hold them, and returns the loaded spec.
func worktree(t *testing.T, credentialFile string) (*JobSpec, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "worktree")
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "lib"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "collect.py"), []byte("#!/usr/bin/env python3\nfrom lib.snapshot import summarise\n"), 0o755)) //nolint:gosec // test script
	require.NoError(t, os.WriteFile(filepath.Join(dir, "lib", "snapshot.py"), []byte("def summarise(root):\n    return {}\n"), 0o644))                //nolint:gosec // test file
	specPath := filepath.Join(dir, "job.yaml")
	require.NoError(t, os.WriteFile(specPath, fmt.Appendf(nil, collectorSpec, credentialFile), 0o644)) //nolint:gosec // test file
	spec, err := LoadJobSpec(specPath)
	require.NoError(t, err)
	return spec, dir
}

func credentialFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "linear-token")
	require.NoError(t, os.WriteFile(p, []byte("txe-sentinel-credential-1b2c3d\n"), 0o600))
	return p
}

func pendingSteps(t *testing.T, j *txepkg.Journal) map[string]txepkg.Step {
	t.Helper()
	entries, err := j.Pending()
	require.NoError(t, err)
	steps := map[string]txepkg.Step{}
	for _, e := range entries {
		steps[e.RequestID] = e.Step
	}
	return steps
}

// Registration ends with a receipt, a ready job on the hub and a read-only
// package that no longer depends on the directory it was built from.
func TestRegister(t *testing.T) {
	f := newFakeRegistry(t)
	home := machineHome(t, f)
	cc1 := newSession(f, home, "cc1-s000001")
	credential := credentialFile(t)
	spec, dir := worktree(t, credential)

	out, err := cc1.Register(context.Background(), spec)
	require.NoError(t, err)

	// The hub holds one ready job, owned by the machine's owner and
	// attributed to the session that created it.
	job := f.job(out.Receipt.JobID)
	assert.Equal(t, RegistrationReady, job.Registration.State)
	assert.Equal(t, testOwner, job.OwnerID)
	assert.Equal(t, "cc1-s000001", job.Created.By.Session)
	assert.NotEqual(t, job.OwnerID, job.Created.By.Session)

	// The receipt is on disk and matches the hub.
	receipt, err := cc1.Journal.Receipt(out.Receipt.JobID, 1)
	require.NoError(t, err)
	assert.Equal(t, job.PackageDigest, receipt.PackageDigest)
	assert.Equal(t, out.Package.Dir, receipt.PackageDir)
	assert.Empty(t, pendingSteps(t, cc1.Journal))

	// The worktree can go: the package still verifies and holds both files.
	require.NoError(t, os.RemoveAll(dir))
	pkg, err := cc1.Store.Verify(out.Receipt.JobID, receipt.PackageDigest)
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(pkg.WorkDir(), "lib", "snapshot.py"))
	assert.DirExists(t, home.OutputDir(out.Receipt.JobID))

	// The DAG runs from the package on this machine and names the credential
	// by where it is, not by what it is.
	assert.Contains(t, out.DAGSpec, `working_dir: "`+pkg.WorkDir()+`"`)
	assert.Contains(t, out.DAGSpec, `txe.machine: "`+testMachine+`"`)
	assert.Contains(t, out.DAGSpec, `key: "`+credential+`"`)
	for _, sent := range f.requests {
		assert.NotContains(t, string(sent.Body), "txe-sentinel-credential", "%s %s carried the credential", sent.Method, sent.Path)
	}
	_ = filepath.WalkDir(home.Root, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			data, readErr := os.ReadFile(p) //nolint:gosec // test directory
			require.NoError(t, readErr)
			assert.False(t, bytes.Contains(data, []byte("txe-sentinel-credential")), "%s holds the credential", p)
		}
		return nil
	})
}

// A job registered by one session is found by another before it builds
// anything, and is not registered twice.
func TestRegisterExistingJobKey(t *testing.T) {
	f := newFakeRegistry(t)
	home := machineHome(t, f)
	spec, _ := worktree(t, credentialFile(t))

	first, err := newSession(f, home, "cc1-s000001").Register(context.Background(), spec)
	require.NoError(t, err)

	cc2 := newSession(f, home, "cc2-s000002")
	_, err = cc2.Register(context.Background(), spec)
	var exists *ErrJobExists
	require.ErrorAs(t, err, &exists)
	assert.Equal(t, first.Receipt.JobID, exists.Job.JobID)
	assert.Equal(t, "cc1-s000001", exists.Job.Created.By.Session)

	assert.Equal(t, 1, f.jobCount())
	assert.Equal(t, 1, f.calls(http.MethodPost, "/txe/jobs"))
	assert.Empty(t, pendingSteps(t, cc2.Journal))
}

// Two sessions register the same job at the same moment. Both pass the
// lookup; the hub accepts one. The other gets an explicit refusal naming the
// job that won, no receipt, and no package where a worker could run it.
func TestRegisterConcurrentDuplicate(t *testing.T) {
	f := newFakeRegistry(t)
	home := machineHome(t, f)
	spec, _ := worktree(t, credentialFile(t))

	// Hold both lookups until both sessions have asked, so neither sees the
	// other's job.
	var asked sync.WaitGroup
	asked.Add(2)
	release := make(chan struct{})
	var once sync.Once
	f.beforeList = func() {
		asked.Done()
		go once.Do(func() { asked.Wait(); close(release) })
		<-release
	}

	sessions := []*session{newSession(f, home, "cc1-s000001"), newSession(f, home, "cc2-s000002")}
	outcomes := make([]*Outcome, 2)
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i, s := range sessions {
		wg.Go(func() { outcomes[i], errs[i] = s.Register(context.Background(), spec) })
	}
	wg.Wait()

	winner, loser := 0, 1
	if errs[0] != nil {
		winner, loser = 1, 0
	}
	require.NoError(t, errs[winner])
	var rejected *ErrRejected
	require.ErrorAs(t, errs[loser], &rejected)
	assert.Equal(t, CodeDuplicate, rejected.Refusal.Code)
	assert.Contains(t, string(rejected.Refusal.Current), outcomes[winner].Receipt.JobID)

	assert.Equal(t, 1, f.jobCount())
	assert.Equal(t, RegistrationReady, f.job(outcomes[winner].Receipt.JobID).Registration.State)

	// The loser's request is kept as evidence, marked refused, with its
	// package still in the staging area and nothing under packages/<job>.
	steps := pendingSteps(t, sessions[loser].Journal)
	require.Len(t, steps, 1)
	assert.Equal(t, txepkg.StepRejected, steps[rejected.RequestID])
	_, err := sessions[loser].Store.LoadStaged(rejected.RequestID)
	require.NoError(t, err)
	jobDirs, err := filepath.Glob(filepath.Join(home.PackagesDir(), "job_*"))
	require.NoError(t, err)
	assert.Len(t, jobDirs, 1)

	// A refused request cannot be resumed into a second job.
	_, err = sessions[loser].Resume(context.Background(), rejected.RequestID)
	require.ErrorContains(t, err, "cannot be resumed")
	assert.Equal(t, 1, f.jobCount())
}

// The hub saves the job but its answer is lost. The registration reports
// itself incomplete with no receipt; resuming sends the same request, the hub
// recognises it, and the result is one job.
func TestRegisterLostResponse(t *testing.T) {
	f := newFakeRegistry(t)
	home := machineHome(t, f)
	cc1 := newSession(f, home, "cc1-s000001")
	spec, _ := worktree(t, credentialFile(t))
	f.loseResponse["POST /txe/jobs"] = 1

	_, err := cc1.Register(context.Background(), spec)
	var incomplete *ErrIncomplete
	require.ErrorAs(t, err, &incomplete)
	assert.Equal(t, txepkg.StepStaged, incomplete.Step)
	receipts, _ := filepath.Glob(filepath.Join(home.ReceiptsDir(), "job_*", "v*.json"))
	assert.Empty(t, receipts, "an incomplete registration has no receipt")
	require.Equal(t, 1, f.jobCount())

	out, err := cc1.Resume(context.Background(), incomplete.RequestID)
	require.NoError(t, err)
	assert.Equal(t, 1, f.jobCount())
	assert.Equal(t, RegistrationReady, f.job(out.Receipt.JobID).Registration.State)
	assert.Empty(t, pendingSteps(t, cc1.Journal))

	// The two POSTs carried the same bytes.
	var bodies [][]byte
	for _, r := range f.requests {
		if r.Method == http.MethodPost && r.Path == "/txe/jobs" {
			bodies = append(bodies, r.Body)
		}
	}
	require.Len(t, bodies, 2)
	assert.Equal(t, string(bodies[0]), string(bodies[1]))
}

// The hub fails while marking the job ready. The package is in place and the
// job is registered, but there is no receipt until a resume completes it.
func TestRegisterFailsBeforeReady(t *testing.T) {
	f := newFakeRegistry(t)
	home := machineHome(t, f)
	cc1 := newSession(f, home, "cc1-s000001")
	spec, _ := worktree(t, credentialFile(t))

	_, err := cc1.Plan(context.Background(), spec) // a plan registers nothing
	require.NoError(t, err)
	require.Zero(t, f.jobCount())
	staging, _ := filepath.Glob(filepath.Join(home.PackagesDir(), ".staging", "*"))
	assert.Empty(t, staging, "a plan leaves no staged package")

	f.mu.Lock()
	f.failNextReady = true
	f.mu.Unlock()
	_, err = cc1.Register(context.Background(), spec)
	var incomplete *ErrIncomplete
	require.ErrorAs(t, err, &incomplete)
	assert.Equal(t, txepkg.StepCommitted, incomplete.Step)

	jobs, err := cc1.Client.ListJobs(context.Background(), JobFilter{JobKey: "nightly-collector"})
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	assert.Equal(t, RegistrationIncomplete, jobs[0].Registration.State)
	_, err = cc1.Journal.Receipt(jobs[0].JobID, 1)
	require.ErrorIs(t, err, fs.ErrNotExist)

	// Another session can finish it: the journal is on the machine, not in
	// the session that started it.
	cc3 := newSession(f, home, "cc3-s000003")
	out, err := cc3.Resume(context.Background(), incomplete.RequestID)
	require.NoError(t, err)
	assert.Equal(t, jobs[0].JobID, out.Receipt.JobID)
	assert.Equal(t, RegistrationReady, f.job(out.Receipt.JobID).Registration.State)
}

// A registration interrupted on one machine cannot be finished from another:
// only the machine that holds the package may place it and vouch for it. The
// same check guards a resume that guards a first attempt.
func TestResumeFromAnotherMachine(t *testing.T) {
	f := newFakeRegistry(t)
	home := machineHome(t, f)
	cc1 := newSession(f, home, "cc1-s000001")
	spec, _ := worktree(t, credentialFile(t))
	f.mu.Lock()
	f.failNextReady = true
	f.mu.Unlock()

	_, err := cc1.Register(context.Background(), spec)
	var incomplete *ErrIncomplete
	require.ErrorAs(t, err, &incomplete)

	// The home is now read as a different machine of the same owner.
	other := `{"schema":1,"machine_id":"mch_01K7A5ZQ8M3N4P5R6S7T8V9W0D","owner_id":"` + testOwner + `"}`
	require.NoError(t, os.WriteFile(filepath.Join(home.Root, "machine.json"), []byte(other), 0o600))
	readyBefore := 0
	for _, r := range f.requests {
		if strings.HasSuffix(r.Path, "/ready") {
			readyBefore++
		}
	}

	_, err = cc1.Resume(context.Background(), incomplete.RequestID)
	require.ErrorContains(t, err, "cannot send or finish it")

	readyAfter := 0
	for _, r := range f.requests {
		if strings.HasSuffix(r.Path, "/ready") {
			readyAfter++
		}
	}
	assert.Equal(t, readyBefore, readyAfter, "the other machine asserted nothing")
	jobs, err := cc1.Client.ListJobs(context.Background(), JobFilter{JobKey: "nightly-collector"})
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	assert.Equal(t, RegistrationIncomplete, jobs[0].Registration.State)
}

// The same holds for a request that was saved but never delivered: resuming
// it from another machine sends nothing, so no job is created or changed
// before the refusal.
func TestResumeUndeliveredRequestFromAnotherMachine(t *testing.T) {
	f := newFakeRegistry(t)
	home := machineHome(t, f)
	cc1 := newSession(f, home, "cc1-s000001")
	spec, _ := worktree(t, credentialFile(t))
	f.fail["POST /txe/jobs"] = 1

	_, err := cc1.Register(context.Background(), spec)
	var incomplete *ErrIncomplete
	require.ErrorAs(t, err, &incomplete)
	require.Equal(t, txepkg.StepStaged, incomplete.Step)
	require.Zero(t, f.jobCount())
	posts := f.calls(http.MethodPost, "/txe/jobs")

	other := `{"schema":1,"machine_id":"mch_01K7A5ZQ8M3N4P5R6S7T8V9W0D","owner_id":"` + testOwner + `"}`
	require.NoError(t, os.WriteFile(filepath.Join(home.Root, "machine.json"), []byte(other), 0o600))
	_, err = cc1.Resume(context.Background(), incomplete.RequestID)
	require.ErrorContains(t, err, "cannot send or finish it")

	assert.Equal(t, posts, f.calls(http.MethodPost, "/txe/jobs"), "the other machine sent the saved request")
	assert.Zero(t, f.jobCount())
}

// overtakenFixture leaves cc1 with an unfinished registration of version 1 of
// a job that cc2 has since moved to version 2. arrange runs first and decides
// how cc1's registration stops.
type overtaken struct {
	f                *fakeRegistry
	cc1              *session
	requestID, jobID string
}

func overtakenFixture(t *testing.T, arrange func(f *fakeRegistry)) overtaken {
	t.Helper()
	f := newFakeRegistry(t)
	home := machineHome(t, f)
	cc1 := newSession(f, home, "cc1-s000001")
	cc2 := newSession(f, home, "cc2-s000002")
	spec, dir := worktree(t, credentialFile(t))
	f.mu.Lock()
	arrange(f)
	f.mu.Unlock()

	_, err := cc1.Register(context.Background(), spec)
	var incomplete *ErrIncomplete
	require.ErrorAs(t, err, &incomplete)
	jobs, err := cc1.Client.ListJobs(context.Background(), JobFilter{JobKey: "nightly-collector"})
	require.NoError(t, err)
	require.Len(t, jobs, 1)
	jobID := jobs[0].JobID

	require.NoError(t, os.WriteFile(filepath.Join(dir, "lib", "snapshot.py"), []byte("def summarise(root):\n    return {'v': 2}\n"), 0o644)) //nolint:gosec // test file
	second, err := cc2.Update(context.Background(), jobID, 1, spec)
	require.NoError(t, err)
	require.Equal(t, 2, second.Receipt.Version)
	return overtaken{f: f, cc1: cc1, requestID: incomplete.RequestID, jobID: jobID}
}

// The hub marks version 1 ready but its answer is lost; before the first
// session resumes, another session updates the job. The job can no longer be
// marked ready for version 1, but the hub's history shows that it was, and
// the receipt is written from that.
func TestResumeRecoversReceiptAfterJobMovedOn(t *testing.T) {
	o := overtakenFixture(t, func(f *fakeRegistry) { f.loseNextReady = true })
	f, cc1, requestID, jobID := o.f, o.cc1, o.requestID, o.jobID
	readyCalls := f.calls(http.MethodPost, "/txe/jobs/"+jobID+"/ready")

	out, err := cc1.Resume(context.Background(), requestID)
	require.NoError(t, err)
	assert.Equal(t, 1, out.Receipt.Version)
	assert.Equal(t, requestID, out.Receipt.RequestID)
	assert.Contains(t, out.Receipt.Recovered, "registry event evt_")
	var event Event
	require.NoError(t, json.Unmarshal(out.Receipt.Service, &event))
	assert.Equal(t, EventReady, event.Kind)
	assert.Contains(t, event.Evidence, out.Receipt.PackageDigest)

	// The receipt is on disk, the request is closed, and nothing was asked
	// of the job's current version.
	onDisk, err := cc1.Journal.Receipt(jobID, 1)
	require.NoError(t, err)
	assert.Equal(t, out.Receipt.Recovered, onDisk.Recovered)
	assert.NotContains(t, pendingSteps(t, cc1.Journal), requestID)
	assert.Equal(t, readyCalls, f.calls(http.MethodPost, "/txe/jobs/"+jobID+"/ready"))
	assert.Equal(t, 2, f.job(jobID).Version)
	assert.Equal(t, RegistrationReady, f.job(jobID).Registration.State)
}

// Version 1 never became ready: the ready call failed, and another session
// moved the job on. The history has nothing for version 1, so no receipt is
// written, and the request says so once instead of failing every resume.
func TestResumeAfterJobMovedOnBeforeReady(t *testing.T) {
	o := overtakenFixture(t, func(f *fakeRegistry) { f.failNextReady = true })
	f, cc1, requestID, jobID := o.f, o.cc1, o.requestID, o.jobID

	_, err := cc1.Resume(context.Background(), requestID)
	var superseded *ErrSuperseded
	require.ErrorAs(t, err, &superseded)
	assert.Equal(t, 1, superseded.Version)
	assert.Equal(t, 2, superseded.Current)

	assert.Equal(t, txepkg.StepSuperseded, pendingSteps(t, cc1.Journal)[requestID])
	_, err = cc1.Journal.Receipt(jobID, 1)
	require.ErrorIs(t, err, fs.ErrNotExist)
	_, err = cc1.Resume(context.Background(), requestID)
	require.ErrorContains(t, err, "cannot be resumed")
	require.ErrorContains(t, err, "no record that version 1 was ever marked ready")

	// Version 2 is untouched.
	assert.Equal(t, 2, f.job(jobID).Version)
	assert.Equal(t, RegistrationReady, f.job(jobID).Registration.State)
}

// A registration wrote its receipt and stopped before filing its journal
// entry; then the job moved on. Resuming files the entry against the receipt
// that exists, without asking the hub's history.
func TestResumeFilesExistingReceiptAfterJobMovedOn(t *testing.T) {
	f := newFakeRegistry(t)
	home := machineHome(t, f)
	cc1 := newSession(f, home, "cc1-s000001")
	cc2 := newSession(f, home, "cc2-s000002")
	spec, dir := worktree(t, credentialFile(t))

	first, err := cc1.Register(context.Background(), spec)
	require.NoError(t, err)
	jobID, requestID := first.Receipt.JobID, first.Receipt.RequestID

	// Put the entry back where an interrupted registration would have left it.
	filed := filepath.Join(cc1.Journal.Dir, jobID, "requests", requestID+".json")
	pending := filepath.Join(cc1.Journal.Dir, "pending", requestID+".json")
	require.NoError(t, os.Rename(filed, pending))
	require.Contains(t, pendingSteps(t, cc1.Journal), requestID)

	require.NoError(t, os.WriteFile(filepath.Join(dir, "lib", "snapshot.py"), []byte("def summarise(root):\n    return {'v': 2}\n"), 0o644)) //nolint:gosec // test file
	_, err = cc2.Update(context.Background(), jobID, 1, spec)
	require.NoError(t, err)

	out, err := cc1.Resume(context.Background(), requestID)
	require.NoError(t, err)
	assert.Equal(t, first.Receipt.WrittenAt, out.Receipt.WrittenAt, "the receipt was rewritten")
	assert.Empty(t, out.Receipt.Recovered)
	assert.NotContains(t, pendingSteps(t, cc1.Journal), requestID)
	assert.FileExists(t, filed)
	assert.Zero(t, f.calls(http.MethodGet, "/txe/jobs/"+jobID+"/events"))
}

// A job registered through another context publishes through that context.
func TestPublishStepUsesRegistrationContext(t *testing.T) {
	f := newFakeRegistry(t)
	home := machineHome(t, f)
	_, dir := worktree(t, credentialFile(t))
	specPath := filepath.Join(dir, "job.yaml")
	text, err := os.ReadFile(specPath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(specPath, []byte(strings.Replace(string(text), "expected_outcome:\n", "expected_outcome:\n"+deliverablesYAML, 1)), 0o644)) //nolint:gosec // test file
	spec, err := LoadJobSpec(specPath)
	require.NoError(t, err)

	stores := t.TempDir()
	s := newSession(f, home, "cc1-s000001")
	s.Hub = HubContext{DaguHome: filepath.Join(stores, "other-hub"), Name: "staging"}
	plan, err := s.Plan(context.Background(), spec)
	require.NoError(t, err)
	assert.Contains(t, plan.DAGSpec, "txe artifacts publish --dagu-home "+filepath.Join(stores, "other-hub")+" --context staging")

	// A configuration file that moves the store travels with the home.
	s.Hub.ConfigFile = filepath.Join(stores, "hub.yaml")
	plan, err = s.Plan(context.Background(), spec)
	require.NoError(t, err)
	assert.Contains(t, plan.DAGSpec, "--dagu-home "+filepath.Join(stores, "other-hub")+" --config "+filepath.Join(stores, "hub.yaml")+" --context staging")

	// The two directories the flags resolved to in the session are named
	// outright, so a step does not have to resolve them again.
	s.Hub.ContextsDir, s.Hub.DataDir = filepath.Join(stores, "session", "contexts"), filepath.Join(stores, "session", "data")
	plan, err = s.Plan(context.Background(), spec)
	require.NoError(t, err)
	assert.Contains(t, plan.DAGSpec, "--config "+filepath.Join(stores, "hub.yaml")+
		" --contexts-dir "+filepath.Join(stores, "session", "contexts")+" --data-dir "+filepath.Join(stores, "session", "data")+" --context staging")
	s.Hub.ContextsDir, s.Hub.DataDir = "", ""

	// A store that a later run could not rely on is refused, wherever the
	// flags resolved it to.
	scratch := t.TempDir()
	s.Store.Policy = txepkg.PathPolicy{TempRoots: []string{scratch}}
	s.Hub.ContextsDir = filepath.Join(scratch, "contexts")
	_, err = s.Plan(context.Background(), spec)
	require.ErrorContains(t, err, "cannot be used by the job's own steps")
	s.Hub.ContextsDir = ""
	_, err = s.Plan(context.Background(), spec)
	require.NoError(t, err)

	s.Store.Policy = txepkg.PathPolicy{TempRoots: []string{stores}}
	_, err = s.Plan(context.Background(), spec)
	require.ErrorContains(t, err, "cannot be used by the job's own steps")
	_, err = s.Register(context.Background(), spec)
	require.ErrorContains(t, err, "cannot be used by the job's own steps")
	assert.Zero(t, f.jobCount())

	// A job without deliverables calls dagu too, for the resource check
	// before it runs, so its DAG carries the same flags and its
	// registration needs the same durable store.
	plain, _ := worktree(t, credentialFile(t))
	_, err = s.Plan(context.Background(), plain)
	require.ErrorContains(t, err, "cannot be used by the job's own steps")
	s.Store.Policy = txepkg.PathPolicy{}
	plan, err = s.Plan(context.Background(), plain)
	require.NoError(t, err)
	assert.NotContains(t, plan.DAGSpec, "txe artifacts")
	assert.Contains(t, plan.DAGSpec, "txe resource check --job ")
	assert.Contains(t, plan.DAGSpec, " --machine "+testMachine+" --dagu-home "+filepath.Join(stores, "other-hub")+" --config "+filepath.Join(stores, "hub.yaml")+" --context staging")
}

// An update names the version it changes. One made against an outdated
// version is refused and leaves the job, its package and its receipts alone.
func TestUpdate(t *testing.T) {
	f := newFakeRegistry(t)
	home := machineHome(t, f)
	cc1 := newSession(f, home, "cc1-s000001")
	cc2 := newSession(f, home, "cc2-s000002")
	spec, dir := worktree(t, credentialFile(t))

	first, err := cc1.Register(context.Background(), spec)
	require.NoError(t, err)
	jobID := first.Receipt.JobID

	// Session 2 changes the script and updates version 1.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "lib", "snapshot.py"), []byte("def summarise(root):\n    return {'v': 2}\n"), 0o644)) //nolint:gosec // test file
	second, err := cc2.Update(context.Background(), jobID, 1, spec)
	require.NoError(t, err)
	assert.Equal(t, 2, second.Receipt.Version)
	assert.NotEqual(t, first.Receipt.PackageDigest, second.Receipt.PackageDigest)
	assert.Equal(t, "cc2-s000002", f.job(jobID).Updated.By.Session)
	assert.Equal(t, testOwner, f.job(jobID).OwnerID)

	// Both versions' packages and receipts are kept.
	_, err = cc1.Store.Verify(jobID, first.Receipt.PackageDigest)
	require.NoError(t, err)
	_, err = cc1.Store.Verify(jobID, second.Receipt.PackageDigest)
	require.NoError(t, err)
	receipts, err := cc1.Journal.Receipts(jobID)
	require.NoError(t, err)
	require.Len(t, receipts, 2)

	// Session 1 still thinks the job is at version 1.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "lib", "snapshot.py"), []byte("def summarise(root):\n    return {'v': 3}\n"), 0o644)) //nolint:gosec // test file
	_, err = cc1.Update(context.Background(), jobID, 1, spec)
	var rejected *ErrRejected
	require.ErrorAs(t, err, &rejected)
	assert.Equal(t, CodeVersionConflict, rejected.Refusal.Code)
	var current Job
	require.NoError(t, json.Unmarshal(rejected.Refusal.Current, &current))
	assert.Equal(t, 2, current.Version)

	job := f.job(jobID)
	assert.Equal(t, 2, job.Version)
	assert.Equal(t, second.Receipt.PackageDigest, job.PackageDigest)
	assert.Equal(t, RegistrationReady, job.Registration.State)
	packages, err := filepath.Glob(filepath.Join(home.PackagesDir(), jobID, "sha256-*"))
	require.NoError(t, err)
	assert.Len(t, packages, 2, "the refused update placed no package")
	receipts, err = cc1.Journal.Receipts(jobID)
	require.NoError(t, err)
	assert.Len(t, receipts, 2)
}

func TestRegisterRefusals(t *testing.T) {
	t.Run("ReviewerSession", func(t *testing.T) {
		f := newFakeRegistry(t)
		home := machineHome(t, f)
		spec, _ := worktree(t, credentialFile(t))
		t.Setenv(EnvReviewer, "1")

		s := newSession(f, home, "reviewer")
		_, err := s.Register(context.Background(), spec)
		require.ErrorIs(t, err, ErrReviewerSession)
		_, err = s.Update(context.Background(), "job_x", 1, spec)
		require.ErrorIs(t, err, ErrReviewerSession)
		_, err = s.Plan(context.Background(), spec)
		require.ErrorIs(t, err, ErrReviewerSession)
		_, err = s.Resume(context.Background(), "req_x")
		require.ErrorIs(t, err, ErrReviewerSession)
		assert.Zero(t, len(f.requests), "a reviewer session sent nothing to the hub")
	})
	t.Run("MachineOfAnotherOwner", func(t *testing.T) {
		f := newFakeRegistry(t)
		home := machineHome(t, f)
		f.machines[testMachine] = Machine{MachineID: testMachine, OwnerID: "own_SOMEONE_ELSE"}
		spec, _ := worktree(t, credentialFile(t))

		_, err := newSession(f, home, "cc1-s000001").Register(context.Background(), spec)
		require.ErrorContains(t, err, "under owner own_SOMEONE_ELSE")
		assert.Zero(t, f.jobCount())
	})
	t.Run("UnknownMachine", func(t *testing.T) {
		f := newFakeRegistry(t)
		home := machineHome(t, f)
		delete(f.machines, testMachine)
		spec, _ := worktree(t, credentialFile(t))

		_, err := newSession(f, home, "cc1-s000001").Register(context.Background(), spec)
		require.ErrorContains(t, err, "does not know this machine")
	})
	t.Run("CredentialFileInPackage", func(t *testing.T) {
		f := newFakeRegistry(t)
		home := machineHome(t, f)
		spec, dir := worktree(t, credentialFile(t))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "lib", ".env"), []byte("TOKEN=abc\n"), 0o600))

		_, err := newSession(f, home, "cc1-s000001").Register(context.Background(), spec)
		require.ErrorIs(t, err, txepkg.ErrCredentialFile)
		assert.Zero(t, f.jobCount())
	})
}

// A spec that lacks the context a job needs is refused with every gap named,
// before anything is built or sent.
func TestJobSpecMissingContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job.yaml")
	require.NoError(t, os.WriteFile(path, []byte("schema: 1\ntitle: Watch something\npackage:\n  include: [run.sh]\n  entrypoint: [./run.sh]\n"), 0o644)) //nolint:gosec // test file

	_, err := LoadJobSpec(path)
	var missing *MissingContextError
	require.ErrorAs(t, err, &missing)
	joined := strings.Join(missing.Problems, "\n")
	for _, want := range []string{"job_key", "purpose", "targets", "schedule.cron", "schedule.timezone", "schedule.timeout_sec", "success_criteria", "lifetime", "review_policy.brief", "review_policy.cadence"} {
		assert.Contains(t, joined, want)
	}
}

// A misspelt key is an error, not a silently dropped field.
func TestJobSpecUnknownKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "job.yaml")
	require.NoError(t, os.WriteFile(path, []byte("schema: 1\njob_key: abc\ntitel: typo\n"), 0o644)) //nolint:gosec // test file

	_, err := LoadJobSpec(path)
	require.ErrorContains(t, err, "titel")
}

// registerWithoutLookup sends a registration as a session would after losing
// the race for a job key: its own lookup saw nothing.
func (s *session) registerWithoutLookup(ctx context.Context, spec *JobSpec) (*Outcome, error) {
	f := s.Client
	hidden := *f
	hidden.HTTP = &http.Client{Transport: hideJobs{f.HTTP.Transport}}
	r := *s.Registrar
	r.Client = &hidden
	return r.Register(ctx, spec)
}

// hideJobs answers a job listing with an empty list and passes everything
// else through.
type hideJobs struct{ next http.RoundTripper }

func (h hideJobs) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodGet && strings.HasSuffix(req.URL.Path, "/txe/jobs") {
		return &http.Response{
			StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"jobs":[]}`)), Request: req,
		}, nil
	}
	next := h.next
	if next == nil {
		next = http.DefaultTransport
	}
	return next.RoundTrip(req)
}

// A job's DAG calls the dagu installed on the machine. While that dagu lacks
// a command the DAG calls, the job is not registered: it would fail at that
// command on every run. Nothing is sent to the hub and no package is kept.
func TestRegisterRefusesAMachineWithoutTheCommands(t *testing.T) {
	f := newFakeRegistry(t)
	home := machineHome(t, f)
	spec, _ := worktree(t, credentialFile(t))
	s := newSession(f, home, "cc1-s000001")

	var asked [][]string
	var askedOf string
	s.HasCommands = func(_ context.Context, dagu string, commands [][]string) error {
		askedOf, asked = dagu, commands
		return errors.New(`it has no "dagu txe resource check" command`)
	}
	_, err := s.Register(context.Background(), spec)
	require.ErrorContains(t, err, `it has no "dagu txe resource check" command`)
	require.ErrorContains(t, err, "then register again")
	assert.Equal(t, filepath.Join(home.Root, "bin", "dagu"), askedOf)
	assert.Equal(t, [][]string{{"resource", "check"}}, asked, "a job without deliverables needs only the check")
	assert.Zero(t, f.jobCount())
	staged, err := os.ReadDir(home.PackagesDir())
	if !errors.Is(err, fs.ErrNotExist) {
		require.NoError(t, err)
	}
	assert.Empty(t, staged, "a package was staged for a job that was refused")
	_, err = s.Plan(context.Background(), spec)
	require.Error(t, err, "a dry run did not report that the job could not run here")

	// An update is refused the same way, and the job stays at its version.
	ok := newSession(f, home, "cc1-s000001")
	first, err := ok.Register(context.Background(), spec)
	require.NoError(t, err)
	_, err = s.Update(context.Background(), first.Receipt.JobID, 1, spec)
	require.ErrorContains(t, err, `it has no "dagu txe resource check" command`)
	assert.Equal(t, 1, f.jobCount())
	assert.Equal(t, 1, f.versionCount(first.Receipt.JobID), "an update was recorded for a machine that cannot run it")
}

// The installed dagu is asked through each command's own help. One that lacks
// the command answers with the help of the nearest command it has, and exits
// zero, so the answer is read, not the exit status.
func TestHasTXECommands(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in dagu is a shell script")
	}
	dir := t.TempDir()
	script := func(name, body string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700)) //nolint:gosec // a test script
		return path
	}
	// Prints what cobra prints: the usage line names the command that ran.
	has := script("has", `case "$*" in
  "txe resource check --help") printf 'Check targets.\n\nUsage:\n  dagu txe resource check [flags]\n' ;;
  "txe artifacts begin --help") printf 'Usage:\n  dagu txe artifacts begin [flags]\n' ;;
  *) printf 'Usage:\n  dagu txe [command]\n\nAvailable Commands:\n  artifacts   Record files\n  resource    Check targets\n' ;;
esac
`)
	lacks := script("lacks", `printf 'Usage:\n  dagu txe [command]\n\nAvailable Commands:\n  artifacts   Record files\n'
`)
	fails := script("fails", "exit 3\n")
	ctx := context.Background()

	require.NoError(t, HasTXECommands(ctx, has, [][]string{{"resource", "check"}, {"artifacts", "begin"}}))
	require.ErrorContains(t, HasTXECommands(ctx, has, [][]string{{"artifacts", "seal"}}), `it has no "dagu txe artifacts seal" command`)
	require.ErrorContains(t, HasTXECommands(ctx, lacks, [][]string{{"resource", "check"}}), `it has no "dagu txe resource check" command`)
	require.ErrorContains(t, HasTXECommands(ctx, fails, [][]string{{"resource", "check"}}), "failed")
	require.Error(t, HasTXECommands(ctx, filepath.Join(dir, "absent"), [][]string{{"resource", "check"}}))

	// Only the usage line counts. A parent's help that mentions the command
	// in an example, and a command with a longer name, are not the command.
	mentions := script("mentions", `printf 'Usage:\n  dagu txe artifacts [command]\n\nExamples:\n  dagu txe artifacts seal\n'
`)
	longer := script("longer", `printf 'Usage:\n  dagu txe artifacts sealed [flags]\n'
`)
	require.ErrorContains(t, HasTXECommands(ctx, mentions, [][]string{{"artifacts", "seal"}}), `it has no "dagu txe artifacts seal" command`)
	require.ErrorContains(t, HasTXECommands(ctx, longer, [][]string{{"artifacts", "seal"}}), `it has no "dagu txe artifacts seal" command`)

	for help, want := range map[string]bool{
		"Usage:\n  dagu txe artifacts seal [flags]\n":                               true,
		"Usage:\n  dagu txe artifacts seal\n":                                       true,
		"Usage:\n  dagu txe artifacts [flags]\n  dagu txe artifacts seal [flags]\n": true,
		"Record.\n\nUsage:\n  dagu txe artifacts seal [flags]\n\nFlags:\n":          true,
		"Usage:\n  dagu txe artifacts sealed [flags]\n":                             false,
		"Usage:\n  dagu txe artifacts seal now\n":                                   false,
		"Usage:\n  dagu txe artifacts [command]\n\nSee: dagu txe artifacts seal\n":  false,
		"dagu txe artifacts seal [flags]\n":                                         false,
		"":                                                                          false,
	} {
		assert.Equal(t, want, usageNames(help, []string{"txe", "artifacts", "seal"}), "%q", help)
	}
}
