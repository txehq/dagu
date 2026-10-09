// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	shaA = "sha256:" + strings.Repeat("a", 64)
	shaB = "sha256:" + strings.Repeat("b", 64)
)

// running is a run's latest execution while it runs, of the job's DAG spec,
// never queued.
func running(attemptID, spec string) RunAttempt {
	return runningQueued(attemptID, "", spec)
}

// runningQueued is an execution queued at queuedAt.
func runningQueued(attemptID, queuedAt, spec string) RunAttempt {
	return RunAttempt{AttemptID: attemptID, QueuedAt: queuedAt, SpecSHA256: spec, Status: "running"}
}

func withDeliverables(v *JobVersion) {
	v.ExpectedOutcome.Deliverables = []Deliverable{
		{Name: "snapshot", Path: "snapshot.json", Delivery: DeliveryHub, Required: true},
		{Name: "raw", Path: "raw/export.csv"},
		{Name: "notes", Path: "notes.txt", Required: true},
	}
}

func TestDeliverablesAreChecked(t *testing.T) {
	f := newFixture(t)
	for _, d := range []Deliverable{
		{Name: "Bad Name", Path: "a.txt"},
		{Name: "glob", Path: "out/*.csv"},
		{Name: "abs", Path: "/etc/passwd"},
		{Name: "escape", Path: "../x"},
		{Name: "unclean", Path: "a/./b"},
		{Name: "delivery", Path: "a.txt", Delivery: "email"},
		{Name: "stream", Path: "report.txt:hidden"},
		{Name: "hidden", Path: ".txe-partial-a"},
		{Name: "device", Path: "out/con.txt"},
		{Name: "trailing", Path: "notes."},
		{Name: "space", Path: "my notes.txt"},
		{Name: "control", Path: "a\x00b"},
		{Name: "backslash", Path: `a\b.txt`},
		{Name: "reserved", Path: "txe-attempts/a1/x.json"},
		{Name: "reserved-case", Path: "TXE-Attempts/x.json"},
	} {
		v := f.version(1)
		v.ExpectedOutcome.Deliverables = []Deliverable{d}
		_, err := f.store.Register(f.ctx, RegisterInput{JobID: f.mint(PrefixJob), RequestID: "r", OwnerID: f.owner, ProjectID: f.project,
			MachineID: f.machine, JobKey: d.Name, Version: v}, cli)
		assert.Equal(t, CodeInvalid, code(t, err), d.Name)
	}
	job := f.readyWith("k", withDeliverables)
	v, err := f.store.GetVersion(f.ctx, job.JobID, 1)
	require.NoError(t, err)
	assert.Equal(t, DeliveryMachine, v.ExpectedOutcome.Deliverables[1].Delivery, "machine is the default")
}

func TestRecordArtifacts(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", withDeliverables)
	record := func(m ArtifactManifest) (*ArtifactManifest, error) {
		var out *ArtifactManifest
		_, err := f.tx(job.JobID, cli, func(tx *JobTx) error {
			var err error
			out, err = tx.RecordArtifacts(f.ctx, f.store, "run-1", running("a1", job.DAGSpecSHA256), m)
			return err
		})
		return out, err
	}
	manifest := ArtifactManifest{AttemptID: "a1", JobVersion: 1, Artifacts: []ArtifactRecord{
		{Deliverable: "snapshot", Path: "snapshot.json", SHA256: shaA, Bytes: 11, Location: DeliveryHub, MachineID: f.machine},
		{Deliverable: "raw", Path: "raw/export.csv", SHA256: shaA, Bytes: 8, Location: DeliveryMachine, MachineID: f.machine},
		{Deliverable: "notes", Path: "notes.txt", Missing: true},
	}}
	bad := func(mutate func(a *ArtifactRecord)) ArtifactManifest {
		m := manifest
		m.Artifacts = append([]ArtifactRecord(nil), manifest.Artifacts...)
		mutate(&m.Artifacts[0])
		return m
	}
	for name, m := range map[string]ArtifactManifest{
		"undeclared":   bad(func(a *ArtifactRecord) { a.Deliverable = "other" }),
		"path":         bad(func(a *ArtifactRecord) { a.Path = "elsewhere.json" }),
		"location":     bad(func(a *ArtifactRecord) { a.Location = DeliveryMachine }),
		"machine":      bad(func(a *ArtifactRecord) { a.MachineID = "mch_01K7A5ZQ8M3N4P5R6S7T8V9W0C" }),
		"digest":       bad(func(a *ArtifactRecord) { a.SHA256 = "abc" }),
		"no version 9": {AttemptID: "a1", JobVersion: 9, Artifacts: manifest.Artifacts},
	} {
		_, err := record(m)
		assert.Equal(t, CodeInvalid, code(t, err), name)
	}

	got, err := record(manifest)
	require.NoError(t, err)
	status := map[string]ArtifactStatus{}
	for _, a := range got.Artifacts {
		status[a.Deliverable] = a.Status
	}
	assert.Equal(t, map[string]ArtifactStatus{"snapshot": ArtifactPendingUpload, "raw": ArtifactStoredOnMachine, "notes": ArtifactMissing}, status,
		"a hub copy is never available before its bytes are checked")
	j, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	missing := 0
	for _, e := range j.Exceptions {
		if e.Kind == "deliverable_missing" {
			missing++
		}
	}
	assert.Equal(t, 1, missing, "the missing required deliverable needs a person")

	again, err := record(bad(func(a *ArtifactRecord) { a.RecordedAt = "2026-10-09T13:00:00Z" }))
	require.NoError(t, err, "the same report again is a no-op, whatever the reporter's clock says")
	assert.Equal(t, got.Digest, again.Digest)
	j, err = f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Len(t, j.Exceptions, 1, "and opens no second exception")
	_, err = record(bad(func(a *ArtifactRecord) { a.SHA256 = shaB }))
	assert.Equal(t, CodeArtifactConflict, code(t, err))

	// Only the run itself can claim its deliverables: a manifest for a run
	// whose saved DAG is not the reported version's, or no run at all, is
	// refused.
	for _, spec := range []string{"", "sha256:" + strings.Repeat("0", 64)} {
		_, err = f.tx(job.JobID, cli, func(tx *JobTx) error {
			_, err := tx.RecordArtifacts(f.ctx, f.store, "run-2", running("a1", spec), manifest)
			return err
		})
		assert.Equal(t, CodeStaleBinding, code(t, err))
	}
}

func TestCheckHubArtifacts(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", func(v *JobVersion) {
		v.ExpectedOutcome.Deliverables = []Deliverable{
			{Name: "good", Path: "good.json", Delivery: DeliveryHub},
			{Name: "bad", Path: "bad.json", Delivery: DeliveryHub},
			{Name: "late", Path: "late.json", Delivery: DeliveryHub},
		}
	})
	_, err := f.tx(job.JobID, cli, func(tx *JobTx) error {
		_, err := tx.RecordArtifacts(f.ctx, f.store, "run-1", running("a1", job.DAGSpecSHA256), ArtifactManifest{AttemptID: "a1", JobVersion: 1, Artifacts: []ArtifactRecord{
			{Deliverable: "good", Path: "good.json", SHA256: shaA, Location: DeliveryHub, MachineID: f.machine},
			{Deliverable: "bad", Path: "bad.json", SHA256: shaA, Location: DeliveryHub, MachineID: f.machine},
			{Deliverable: "late", Path: "late.json", SHA256: shaA, Location: DeliveryHub, MachineID: f.machine},
		}})
		return err
	})
	require.NoError(t, err)
	hub := map[string]string{HubCopyPath(ExecutionRef("a1", ""), "good.json"): strings.Repeat("a", 64), HubCopyPath(ExecutionRef("a1", ""), "bad.json"): strings.Repeat("b", 64)}
	lookup := func(p string) (string, bool, error) {
		sha, ok := hub[p]
		return sha, ok, nil
	}
	statusOf := func(m *ArtifactManifest) map[string]ArtifactStatus {
		out := map[string]ArtifactStatus{}
		for _, a := range m.Artifacts {
			out[a.Deliverable] = a.Status
		}
		return out
	}
	m, err := f.store.CheckHubArtifacts(f.ctx, job.JobID, "run-1", ExecutionRef("a1", ""), "/hub/run-1", lookup, false)
	require.NoError(t, err)
	assert.Equal(t, map[string]ArtifactStatus{"good": ArtifactVerified, "bad": ArtifactMismatch, "late": ArtifactPendingUpload}, statusOf(m),
		"a copy not uploaded yet stays pending while the run is running")

	broken := func(string) (string, bool, error) { return "", false, errors.New("disk unavailable") }
	m, err = f.store.CheckHubArtifacts(f.ctx, job.JobID, "run-1", ExecutionRef("a1", ""), "/hub/run-1", broken, true)
	require.NoError(t, err)
	assert.Equal(t, ArtifactPendingUpload, statusOf(m)["late"], "a lookup error is not a failed upload")

	m, err = f.store.CheckHubArtifacts(f.ctx, job.JobID, "run-1", ExecutionRef("a1", ""), "/hub/run-1", lookup, true)
	require.NoError(t, err)
	assert.Equal(t, ArtifactUploadFailed, statusOf(m)["late"])
	saved, err := f.store.GetArtifacts(f.ctx, job.JobID, "run-1", ExecutionRef("a1", ""), "")
	require.NoError(t, err)
	assert.Equal(t, statusOf(m), statusOf(saved))

	j, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	kinds := map[string]int{}
	for _, e := range j.Exceptions {
		kinds[e.Kind]++
	}
	assert.Equal(t, map[string]int{"artifact_mismatch": 1, "artifact_upload_failed": 1}, kinds)
}

// Each execution of a run publishes its own manifest, written once: retries
// with different files on both paths all stay (a direct retry is a new
// attempt, a queued retry the same attempt under a later queue marker), a
// late publish from an earlier execution or one after the execution ended is
// refused, the same report again is a no-op whenever it arrives, other files
// for the same execution are a conflict, and everything reads back after a
// restart.
func TestArtifactsPerExecution(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", withDeliverables)
	spec := job.DAGSpecSHA256
	report := func(attempt, queued string, producedIn ExecutionID, sha string) ArtifactManifest {
		return ArtifactManifest{AttemptID: attempt, QueuedAt: queued, ProducedIn: producedIn, JobVersion: 1, Artifacts: []ArtifactRecord{
			{Deliverable: "snapshot", Path: "snapshot.json", SHA256: sha, Bytes: 11, Location: DeliveryHub, MachineID: f.machine},
			{Deliverable: "notes", Path: "notes.txt", SHA256: sha, Bytes: 3, Location: DeliveryMachine, MachineID: f.machine},
		}}
	}
	record := func(latest RunAttempt, m ArtifactManifest) (*ArtifactManifest, error) {
		var out *ArtifactManifest
		_, err := f.tx(job.JobID, cli, func(tx *JobTx) error {
			var err error
			out, err = tx.RecordArtifacts(f.ctx, f.store, "run-1", latest, m)
			return err
		})
		return out, err
	}
	q1, q2 := "2026-10-09T12:00:00.000000001Z", "2026-10-09T12:00:00.000000002Z"

	e1 := runningQueued("a1", q1, spec)
	e1.Snapshot = json.RawMessage(`{"attemptId":"a1","queuedAt":"` + q1 + `"}`)
	first, err := record(e1, report("a1", q1, ExecutionID{}, shaA))
	require.NoError(t, err)
	kept, err := f.store.GetRetainedExecution(f.ctx, job.JobID, "run-1", e1.Ref(), EvidencePublication)
	require.NoError(t, err)
	assert.JSONEq(t, string(e1.Snapshot), string(kept), "the publishing execution's status is kept")
	assert.Equal(t, ExecutionRef("a1", q1), first.Execution)
	assert.Equal(t, first.Execution, first.ProducedIn.Execution, "produced in the publishing execution by default")
	// A queued retry runs a1 again under q2 and writes other files.
	f.advance(time.Second)
	queued, err := record(runningQueued("a1", q2, spec), report("a1", q2, ExecutionID{}, shaB))
	require.NoError(t, err, "a queued retry is a new execution and may publish different files")
	assert.NotEqual(t, first.Execution, queued.Execution)
	// A direct retry starts a2; a3 republishes a2's files only.
	f.advance(time.Second)
	_, err = record(runningQueued("a2", q2, spec), report("a2", q2, ExecutionID{}, shaB))
	require.NoError(t, err)
	f.advance(time.Second)
	_, err = record(running("a3", spec), report("a3", "", ExecutionID{AttemptID: "a2", QueuedAt: q2}, shaB))
	require.NoError(t, err)

	// Late publishes are not recorded against the latest execution.
	_, err = record(running("a3", spec), report("a1", "2026-10-09T11:00:00Z", ExecutionID{}, shaA))
	assert.Equal(t, CodeStaleBinding, code(t, err), "an earlier execution of attempt a1")
	_, err = record(runningQueued("a1", q2, spec), report("a1", "2026-10-09T11:00:00Z", ExecutionID{}, shaA))
	assert.Equal(t, CodeStaleBinding, code(t, err), "same attempt, earlier marker, while a1 runs again")
	ended := running("a4", spec)
	ended.Finished, ended.Status = true, "failed"
	_, err = record(ended, report("a4", "", ExecutionID{}, shaA))
	assert.Equal(t, CodeStaleBinding, code(t, err), "a publish after the execution ended")

	again, err := record(ended, report("a1", q1, ExecutionID{}, shaA))
	require.NoError(t, err, "the same report again is a no-op even after the execution ended")
	assert.Equal(t, first.Digest, again.Digest)
	_, err = record(runningQueued("a1", q1, spec), report("a1", q1, ExecutionID{}, shaB))
	assert.Equal(t, CodeArtifactConflict, code(t, err), "other files for the same execution")

	restarted, err := NewFileStore(filepath.Join(filepath.Dir(f.dagsDir), "data"), WithClock(f.clock), WithDAGStore(f.dags))
	require.NoError(t, err)
	all, err := restarted.ListArtifacts(f.ctx, job.JobID, "run-1")
	require.NoError(t, err)
	var executions []string
	for _, m := range all {
		executions = append(executions, m.Execution)
	}
	assert.Equal(t, []string{ExecutionRef("a1", q1), ExecutionRef("a1", q2), ExecutionRef("a2", q2), ExecutionRef("a3", "")}, executions)
	got, err := restarted.GetArtifacts(f.ctx, job.JobID, "run-1", "", ExecutionRef("a1", q2))
	require.NoError(t, err)
	assert.Equal(t, shaB, got.Artifacts[0].SHA256)
	got, err = restarted.GetArtifacts(f.ctx, job.JobID, "run-1", "", "none")
	require.NoError(t, err)
	assert.Equal(t, ExecutionRef("a3", ""), got.Execution, "without the latest execution's manifest, the most recent")
	assert.Equal(t, ExecutionRef("a2", q2), got.ProducedIn.Execution)
	got, err = restarted.GetArtifacts(f.ctx, job.JobID, "run-1", ExecutionRef("a1", q1), "")
	require.NoError(t, err)
	assert.Equal(t, shaA, got.Artifacts[0].SHA256, "the first execution's files are kept")
}

// Hub copies are read under the publishing execution's own prefix, so two
// executions sharing a native directory never vouch for each other's bytes.
func TestHubCopiesArePerExecution(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", func(v *JobVersion) {
		v.ExpectedOutcome.Deliverables = []Deliverable{{Name: "out", Path: "out.json", Delivery: DeliveryHub}}
	})
	e1, e2 := runningQueued("a1", "q1", job.DAGSpecSHA256), runningQueued("a1", "q2", job.DAGSpecSHA256)
	for _, e := range []RunAttempt{e1, e2} {
		_, err := f.tx(job.JobID, cli, func(tx *JobTx) error {
			_, err := tx.RecordArtifacts(f.ctx, f.store, "run-1", e, ArtifactManifest{AttemptID: e.AttemptID, QueuedAt: e.QueuedAt, JobVersion: 1,
				Artifacts: []ArtifactRecord{{Deliverable: "out", Path: "out.json", SHA256: shaA, Location: DeliveryHub, MachineID: f.machine}}})
			return err
		})
		require.NoError(t, err)
	}
	var looked []string
	lookup := func(p string) (string, bool, error) {
		looked = append(looked, p)
		if p == HubCopyPath(e1.Ref(), "out.json") {
			return strings.Repeat("a", 64), true, nil
		}
		return "", false, nil
	}
	m1, err := f.store.CheckHubArtifacts(f.ctx, job.JobID, "run-1", e1.Ref(), "/hub/shared", lookup, true)
	require.NoError(t, err)
	m2, err := f.store.CheckHubArtifacts(f.ctx, job.JobID, "run-1", e2.Ref(), "/hub/shared", lookup, true)
	require.NoError(t, err)
	assert.Equal(t, ArtifactVerified, m1.Artifacts[0].Status)
	assert.Equal(t, ArtifactUploadFailed, m2.Artifacts[0].Status, "the first execution's bytes do not vouch for the second")
	assert.Equal(t, []string{"txe-attempts/" + e1.Ref() + "/out.json", "txe-attempts/" + e2.Ref() + "/out.json"}, looked)
	assert.Equal(t, "/hub/shared", m1.ArchiveDir)
	assert.Regexp(t, `^a1-[0-9a-f]{16}$`, e1.Ref(), "a portable path segment")
}
