// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/dagucloud/dagu/v2/internal/persis"
)

// Deliverable delivery. A machine copy stays on the machine that ran the
// job; a hub copy is also placed in the run's native artifact directory and
// uploaded to the hub.
const (
	DeliveryMachine = "machine"
	DeliveryHub     = "hub"
)

// ArtifactStatus is where a run's deliverable stands.
type ArtifactStatus string

const (
	// ArtifactPendingUpload: a hub copy whose bytes the hub has not checked.
	ArtifactPendingUpload ArtifactStatus = "pending_upload"
	// ArtifactVerified: the hub holds bytes with the recorded digest.
	ArtifactVerified ArtifactStatus = "verified"
	// ArtifactMismatch: the hub holds bytes with another digest.
	ArtifactMismatch ArtifactStatus = "mismatch"
	// ArtifactUploadFailed: the run ended and the hub copy never arrived.
	ArtifactUploadFailed ArtifactStatus = "upload_failed"
	// ArtifactStoredOnMachine: the file is only on the machine. It is not
	// retrievable through the hub.
	ArtifactStoredOnMachine ArtifactStatus = "stored_on_machine"
	// ArtifactMissing: the run did not produce the file.
	ArtifactMissing ArtifactStatus = "missing"
)

var (
	deliverableName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)
	artifactDigest  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	runIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

// checkDeliverables validates a version's deliverables: unique names, an
// exact relative file path each, and a known delivery.
func checkDeliverables(ds []Deliverable) error {
	seen := map[string]bool{}
	for i := range ds {
		d := &ds[i]
		if !deliverableName.MatchString(d.Name) || seen[d.Name] {
			return refuse(CodeInvalid, "deliverables[%d] needs a unique name matching %s", i, deliverableName)
		}
		seen[d.Name] = true
		if err := checkDeliverablePath(d.Path); err != nil {
			return refuse(CodeInvalid, "deliverable %s: %v", d.Name, err)
		}
		switch d.Delivery {
		case "":
			d.Delivery = DeliveryMachine
		case DeliveryMachine, DeliveryHub:
		default:
			return refuse(CodeInvalid, "deliverable %s delivery must be machine or hub", d.Name)
		}
	}
	return nil
}

// checkDeliverablePath requires an exact file relative to the run's output
// directory: no absolute path, no parent step, no pattern.
func checkDeliverablePath(p string) error {
	switch {
	case p == "":
		return errors.New("path is required")
	case strings.HasPrefix(p, "/") || strings.Contains(p, `\`) || (len(p) > 1 && p[1] == ':'):
		return errors.New("path must be relative")
	case strings.ContainsAny(p, "*?[]{}"):
		return errors.New("path must name one file, not a pattern")
	case path.Clean(p) != p || p == "." || strings.HasPrefix(p, "../") || p == "..":
		return errors.New("path must be clean and stay inside the run's output directory")
	}
	return nil
}

// ArtifactRecord is one deliverable of one run as the run reported it, with
// where the registry finds it now.
type ArtifactRecord struct {
	Deliverable string `json:"deliverable"`
	Path        string `json:"path"`
	// Missing is set when the run did not produce the file.
	Missing    bool   `json:"missing,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Bytes      int64  `json:"bytes,omitempty"`
	Location   string `json:"location,omitempty"`
	MachineID  string `json:"machine_id,omitempty"`
	RecordedAt string `json:"recorded_at,omitempty"`
	// Status and the fields after it are the registry's, not the run's.
	Status     ArtifactStatus `json:"status"`
	CheckedAt  *time.Time     `json:"checked_at,omitempty"`
	CheckError string         `json:"check_error,omitempty"`
}

// ArtifactManifest is a run's deliverables. It is written once per run; an
// identical report again is a no-op and a different one is refused.
type ArtifactManifest struct {
	Schema     int              `json:"schema"`
	JobID      string           `json:"job_id"`
	RunID      string           `json:"run_id"`
	JobVersion int              `json:"job_version"`
	Artifacts  []ArtifactRecord `json:"artifacts"`
	// Digest identifies the report as sent, so a replay is recognized.
	Digest   string `json:"digest"`
	Recorded Stamp  `json:"recorded"`
}

const artifactsPrefix = "artifacts/"

func artifactKey(jobID, runID string) string { return artifactsPrefix + jobID + "/" + runID }

// ArtifactLookup reports the digest of the hub's copy at path in a run's
// native artifact directory, or found false when there is none.
type ArtifactLookup func(path string) (sha256 string, found bool, err error)

// RecordArtifacts saves a run's deliverables, reported by the run's last
// step, and opens an exception for each required deliverable the run did
// not produce. The manifest is created once; an identical report again
// returns it (and repairs a missing exception), a different one is 409
// artifact_conflict.
func (tx *JobTx) RecordArtifacts(ctx context.Context, s *Store, runID string, in ArtifactManifest) (*ArtifactManifest, error) {
	j := tx.Job
	if !runIDPattern.MatchString(runID) {
		return nil, refuse(CodeInvalid, "run id %q is not valid", runID)
	}
	v, err := s.GetVersion(ctx, j.JobID, in.JobVersion)
	if err != nil {
		if ErrorCode(err) == CodeNotFound {
			return nil, refuse(CodeInvalid, "job %s has no version %d", j.JobID, in.JobVersion)
		}
		return nil, err
	}
	declared := map[string]Deliverable{}
	for _, d := range v.ExpectedOutcome.Deliverables {
		declared[d.Name] = d
	}
	reported := map[string]bool{}
	sent := make([]ArtifactRecord, 0, len(in.Artifacts))
	for _, a := range in.Artifacts {
		d, ok := declared[a.Deliverable]
		if !ok {
			return nil, refuse(CodeInvalid, "deliverable %q is not declared by version %d", a.Deliverable, in.JobVersion)
		}
		if reported[a.Deliverable] {
			return nil, refuse(CodeInvalid, "deliverable %q is reported twice", a.Deliverable)
		}
		reported[a.Deliverable] = true
		if a.Path != d.Path {
			return nil, refuse(CodeInvalid, "deliverable %q is at %q, not %q", a.Deliverable, d.Path, a.Path)
		}
		if a.Missing {
			if a.SHA256 != "" || a.Bytes != 0 || a.Location != "" {
				return nil, refuse(CodeInvalid, "missing deliverable %q carries no digest, size or location", a.Deliverable)
			}
		} else {
			switch {
			case !artifactDigest.MatchString(a.SHA256):
				return nil, refuse(CodeInvalid, "deliverable %q sha256 must be sha256:<64 hex>", a.Deliverable)
			case a.Bytes < 0:
				return nil, refuse(CodeInvalid, "deliverable %q bytes must not be negative", a.Deliverable)
			case a.Location != d.Delivery:
				return nil, refuse(CodeInvalid, "deliverable %q is delivered to the %s, not the %s", a.Deliverable, d.Delivery, a.Location)
			case a.MachineID != j.MachineID:
				return nil, refuse(CodeInvalid, "deliverable %q was produced on %s, not the job's machine %s", a.Deliverable, a.MachineID, j.MachineID)
			}
		}
		a.Status, a.CheckedAt, a.CheckError = "", nil, ""
		sent = append(sent, a)
	}
	digest, err := manifestDigest(in.JobVersion, sent)
	if err != nil {
		return nil, err
	}
	m := ArtifactManifest{Schema: SchemaVersion, JobID: j.JobID, RunID: runID, JobVersion: in.JobVersion, Digest: digest,
		Recorded: Stamp{At: tx.now, By: tx.actor}}
	for _, a := range sent {
		switch {
		case a.Missing:
			a.Status = ArtifactMissing
		case a.Location == DeliveryHub:
			a.Status = ArtifactPendingUpload
		default:
			a.Status = ArtifactStoredOnMachine
		}
		m.Artifacts = append(m.Artifacts, a)
	}
	if err := s.createJSON(ctx, artifactKey(j.JobID, runID), &m); err != nil {
		if !errors.Is(err, persis.ErrConflict) {
			return nil, err
		}
		var saved ArtifactManifest
		if err := s.getJSON(ctx, artifactKey(j.JobID, runID), &saved); err != nil {
			return nil, err
		}
		if saved.Digest != digest {
			return nil, &Error{Code: CodeArtifactConflict, Message: "run " + runID + " already reported other deliverables", Current: &saved}
		}
		m = saved
	}
	// Every required deliverable the run did not produce, whether reported
	// missing or not reported at all, needs a person.
	for _, d := range v.ExpectedOutcome.Deliverables {
		if !d.Required {
			continue
		}
		missing := !reported[d.Name]
		for _, a := range m.Artifacts {
			if a.Deliverable == d.Name && a.Missing {
				missing = true
			}
		}
		if missing {
			if err := tx.openException("deliverable_missing", "run "+runID+" did not produce required deliverable "+d.Name+" ("+d.Path+")",
				"artifact:"+runID+"/"+d.Name); err != nil {
				return nil, err
			}
		}
	}
	return &m, nil
}

func manifestDigest(version int, artifacts []ArtifactRecord) (string, error) {
	b, err := json.Marshal(map[string]any{"job_version": version, "artifacts": artifacts})
	if err != nil {
		return "", err
	}
	canon, err := CanonicalJSON(json.RawMessage(b))
	if err != nil {
		return "", fmt.Errorf("registry: manifest digest: %w", err)
	}
	return sha256Hex(canon), nil
}

// openException opens an exception unless an unresolved one of the same
// kind already names the same subject.
func (tx *JobTx) openException(kind, detail, subject string) error {
	j := tx.Job
	for _, e := range j.Exceptions {
		if e.ResolvedAt == nil && e.Kind == kind && len(e.Evidence) > 0 && e.Evidence[0] == subject {
			return nil
		}
	}
	id, err := NewID(PrefixException, tx.now)
	if err != nil {
		return err
	}
	if j.Exceptions == nil {
		j.Exceptions = map[string]*Exception{}
	}
	j.Exceptions[id] = &Exception{ExceptionID: id, Kind: kind, Detail: detail, Evidence: []string{subject}, Created: Stamp{At: tx.now, By: tx.actor}}
	tx.touch()
	return nil
}

// GetArtifacts returns a run's manifest.
func (s *Store) GetArtifacts(ctx context.Context, jobID, runID string) (*ArtifactManifest, error) {
	if !runIDPattern.MatchString(runID) {
		return nil, refuse(CodeInvalid, "run id %q is not valid", runID)
	}
	var m ArtifactManifest
	if err := s.getJSON(ctx, artifactKey(jobID, runID), &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// CheckHubArtifacts checks each hub copy still pending against the bytes
// the hub holds: matching bytes are verified, other bytes are a mismatch,
// and no bytes once the run has ended is a failed upload. A mismatch or a
// failed upload opens an exception. A copy is never reported available
// before its bytes were checked.
func (s *Store) CheckHubArtifacts(ctx context.Context, jobID, runID string, lookup ArtifactLookup, runEnded bool) (*ArtifactManifest, error) {
	for range maxProgressRounds {
		rec, err := s.col.Get(ctx, artifactKey(jobID, runID))
		if err != nil {
			if errors.Is(err, persis.ErrNotFound) {
				return nil, refuse(CodeNotFound, "run %s of job %s has no artifacts", runID, jobID)
			}
			return nil, err
		}
		var m ArtifactManifest
		if err := json.Unmarshal(rec.Data, &m); err != nil {
			return nil, fmt.Errorf("registry: decode artifacts of %s: %w", runID, err)
		}
		changed := false
		var opened []ArtifactRecord
		now := s.clock()
		for i := range m.Artifacts {
			a := &m.Artifacts[i]
			if a.Status != ArtifactPendingUpload {
				continue
			}
			sha, found, err := lookup(a.Path)
			switch {
			case err != nil:
				a.CheckError, a.CheckedAt = err.Error(), &now
			case found && "sha256:"+strings.TrimPrefix(sha, "sha256:") == a.SHA256:
				a.Status, a.CheckError, a.CheckedAt = ArtifactVerified, "", &now
			case found:
				a.Status, a.CheckError, a.CheckedAt = ArtifactMismatch, "hub copy has digest sha256:"+strings.TrimPrefix(sha, "sha256:"), &now
				opened = append(opened, *a)
			case runEnded:
				a.Status, a.CheckError, a.CheckedAt = ArtifactUploadFailed, "the run ended and its hub copy never arrived", &now
				opened = append(opened, *a)
			default:
				continue
			}
			changed = true
		}
		if !changed {
			return &m, nil
		}
		if len(opened) > 0 {
			if _, err := s.WithJobTx(ctx, jobID, reconcilerActor, func(tx *JobTx) error {
				for _, a := range opened {
					kind := "artifact_" + string(a.Status)
					if err := tx.openException(kind, "deliverable "+a.Deliverable+" of run "+runID+": "+a.CheckError, "artifact:"+runID+"/"+a.Deliverable); err != nil {
						return err
					}
				}
				return nil
			}); err != nil {
				return nil, err
			}
		}
		data, err := json.Marshal(&m)
		if err != nil {
			return nil, err
		}
		if err := s.col.CompareAndSwap(ctx, artifactKey(jobID, runID), rec.Data, data); err != nil {
			if errors.Is(err, persis.ErrConflict) {
				continue
			}
			return nil, err
		}
		return &m, nil
	}
	return nil, refuse(CodeVersionConflict, "artifacts of run %s kept changing while they were checked; retry", runID)
}
