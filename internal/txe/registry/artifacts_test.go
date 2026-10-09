// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	shaA = "sha256:" + strings.Repeat("a", 64)
	shaB = "sha256:" + strings.Repeat("b", 64)
)

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
			out, err = tx.RecordArtifacts(f.ctx, f.store, "run-1", job.DAGSpecSHA256, m)
			return err
		})
		return out, err
	}
	manifest := ArtifactManifest{JobVersion: 1, Artifacts: []ArtifactRecord{
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
		"no version 9": {JobVersion: 9, Artifacts: manifest.Artifacts},
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
			_, err := tx.RecordArtifacts(f.ctx, f.store, "run-2", spec, manifest)
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
		_, err := tx.RecordArtifacts(f.ctx, f.store, "run-1", job.DAGSpecSHA256, ArtifactManifest{JobVersion: 1, Artifacts: []ArtifactRecord{
			{Deliverable: "good", Path: "good.json", SHA256: shaA, Location: DeliveryHub, MachineID: f.machine},
			{Deliverable: "bad", Path: "bad.json", SHA256: shaA, Location: DeliveryHub, MachineID: f.machine},
			{Deliverable: "late", Path: "late.json", SHA256: shaA, Location: DeliveryHub, MachineID: f.machine},
		}})
		return err
	})
	require.NoError(t, err)
	hub := map[string]string{"good.json": strings.Repeat("a", 64), "bad.json": strings.Repeat("b", 64)}
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
	m, err := f.store.CheckHubArtifacts(f.ctx, job.JobID, "run-1", lookup, false)
	require.NoError(t, err)
	assert.Equal(t, map[string]ArtifactStatus{"good": ArtifactVerified, "bad": ArtifactMismatch, "late": ArtifactPendingUpload}, statusOf(m),
		"a copy not uploaded yet stays pending while the run is running")

	broken := func(string) (string, bool, error) { return "", false, errors.New("disk unavailable") }
	m, err = f.store.CheckHubArtifacts(f.ctx, job.JobID, "run-1", broken, true)
	require.NoError(t, err)
	assert.Equal(t, ArtifactPendingUpload, statusOf(m)["late"], "a lookup error is not a failed upload")

	m, err = f.store.CheckHubArtifacts(f.ctx, job.JobID, "run-1", lookup, true)
	require.NoError(t, err)
	assert.Equal(t, ArtifactUploadFailed, statusOf(m)["late"])
	saved, err := f.store.GetArtifacts(f.ctx, job.JobID, "run-1")
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
