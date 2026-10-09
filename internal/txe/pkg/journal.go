// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/fileutil"
)

// JournalSchema is the version of the journal entry and receipt formats.
const JournalSchema = 1

// Step is how far one registration or update has got. Each step is saved
// before the next begins, so an interrupted run resumes instead of restarting.
type Step string

const (
	// StepStaged: the package is built and the request is saved; nothing has
	// been sent.
	StepStaged Step = "staged"
	// StepRegistered: the service holds the job version, not yet ready.
	StepRegistered Step = "registered"
	// StepCommitted: the package is in its final location.
	StepCommitted Step = "committed"
	// StepRejected: the service refused the request. The entry and the staged
	// package are kept as evidence.
	StepRejected Step = "rejected"
	// StepSuperseded: the job moved to a later version before this request's
	// receipt was written. There is nothing left to resume.
	StepSuperseded Step = "superseded"
)

// Closed reports whether nothing more can be done for an entry at this step.
func (s Step) Closed() bool { return s == StepRejected || s == StepSuperseded }

// Operations recorded in the journal.
const (
	OpRegister = "register"
	OpUpdate   = "update"
)

// Entry is the durable record of one in-flight registration or update. Request
// holds the exact body sent, so a retry after a lost response is byte-identical
// and the service can recognise it as a replay.
type Entry struct {
	Schema    int    `json:"schema"`
	RequestID string `json:"request_id"`
	Operation string `json:"operation"`
	JobID     string `json:"job_id"`
	JobKey    string `json:"job_key,omitempty"`
	// MachineID and OwnerID are the machine the request was built on and its
	// owner. A request is only ever sent, or resumed, from that machine.
	MachineID string `json:"machine_id"`
	OwnerID   string `json:"owner_id"`
	// Version is the job version this request creates.
	Version       int             `json:"version"`
	Step          Step            `json:"step"`
	PackageDigest string          `json:"package_digest"`
	Session       string          `json:"session,omitempty"`
	Request       json.RawMessage `json:"request"`
	// Response is the service's last answer, kept verbatim.
	Response  json.RawMessage `json:"response,omitempty"`
	Error     string          `json:"error,omitempty"`
	StartedAt time.Time       `json:"started_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// Receipt is the durable proof that a job version is fully registered: the
// service saved it as ready and its package is in place on this machine. It is
// written only after both are true.
type Receipt struct {
	Schema        int    `json:"schema"`
	JobID         string `json:"job_id"`
	Version       int    `json:"version"`
	OwnerID       string `json:"owner_id"`
	ProjectID     string `json:"project_id"`
	MachineID     string `json:"machine_id"`
	PackageDigest string `json:"package_digest"`
	PackageDir    string `json:"package_dir"`
	RequestID     string `json:"request_id"`
	Session       string `json:"session,omitempty"`
	// Service is the registry's own receipt, kept verbatim.
	Service   json.RawMessage `json:"service"`
	WrittenAt time.Time       `json:"written_at"`
}

// ErrReceiptConflict reports a receipt for the same job version that came
// from a different request.
var ErrReceiptConflict = errors.New("a different receipt already exists for this job version")

// Journal stores entries under <dir>/pending and receipts under <dir>/<job id>.
type Journal struct {
	Dir string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// NewJournal returns the journal of a TXE home.
func NewJournal(home Home) *Journal { return &Journal{Dir: home.ReceiptsDir()} }

func (j *Journal) now() time.Time {
	if j.Now != nil {
		return j.Now().UTC()
	}
	return time.Now().UTC()
}

func (j *Journal) pendingPath(requestID string) (string, error) {
	if !namePattern.MatchString(requestID) {
		return "", fmt.Errorf("invalid request id %q", requestID)
	}
	return filepath.Join(j.Dir, "pending", requestID+".json"), nil
}

// Begin saves a new entry. It fails if the request ID was already used.
func (j *Journal) Begin(e Entry) (*Entry, error) {
	path, err := j.pendingPath(e.RequestID)
	if err != nil {
		return nil, err
	}
	if !namePattern.MatchString(e.JobID) {
		return nil, fmt.Errorf("invalid job id %q", e.JobID)
	}
	e.Schema = JournalSchema
	e.StartedAt = j.now()
	e.UpdatedAt = e.StartedAt
	data, err := encodeJSON(e)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create journal: %w", err)
	}
	if err := fileutil.WriteFileAtomicExclusive(path, data, 0o600); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("request %s is already in the journal; resume it instead", e.RequestID)
		}
		return nil, fmt.Errorf("write journal entry: %w", err)
	}
	return &e, nil
}

// Save replaces an entry that Begin created.
func (j *Journal) Save(e *Entry) error {
	path, err := j.pendingPath(e.RequestID)
	if err != nil {
		return err
	}
	e.UpdatedAt = j.now()
	data, err := encodeJSON(e)
	if err != nil {
		return err
	}
	if err := fileutil.WriteFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("write journal entry: %w", err)
	}
	return nil
}

// Get returns the unfinished entry for requestID.
func (j *Journal) Get(requestID string) (*Entry, error) {
	path, err := j.pendingPath(requestID)
	if err != nil {
		return nil, err
	}
	return readEntry(path)
}

// Pending lists unfinished and rejected entries, oldest first.
func (j *Journal) Pending() ([]Entry, error) {
	matches, err := filepath.Glob(filepath.Join(j.Dir, "pending", "*.json"))
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(matches))
	for _, path := range matches {
		e, err := readEntry(path)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *e)
	}
	sort.Slice(entries, func(a, b int) bool { return entries[a].StartedAt.Before(entries[b].StartedAt) })
	return entries, nil
}

// Complete writes the receipt for a finished entry and then files the entry
// beside it. The receipt is never overwritten: repeating Complete for the same
// request returns the receipt already written.
func (j *Journal) Complete(e *Entry, r Receipt) (*Receipt, error) {
	if r.JobID != e.JobID || r.Version != e.Version || r.PackageDigest != e.PackageDigest {
		return nil, fmt.Errorf("receipt for %s v%d (%s) does not match journal entry %s v%d (%s)",
			r.JobID, r.Version, r.PackageDigest, e.JobID, e.Version, e.PackageDigest)
	}
	r.Schema = JournalSchema
	r.RequestID = e.RequestID
	r.WrittenAt = j.now()

	path := j.receiptPath(e.JobID, e.Version)
	data, err := encodeJSON(r)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(filepath.Dir(path), "requests"), 0o700); err != nil {
		return nil, fmt.Errorf("create receipt directory: %w", err)
	}
	written := &r
	if err := fileutil.WriteFileAtomicExclusive(path, data, 0o600); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("write receipt: %w", err)
		}
		existing, err := j.Receipt(e.JobID, e.Version)
		if err != nil {
			return nil, err
		}
		if existing.RequestID != e.RequestID {
			return nil, fmt.Errorf("%w: %s was written by request %s", ErrReceiptConflict, path, existing.RequestID)
		}
		written = existing
	}

	pending, err := j.pendingPath(e.RequestID)
	if err != nil {
		return nil, err
	}
	filed := filepath.Join(filepath.Dir(path), "requests", e.RequestID+".json")
	if err := fileutil.ReplaceFileDurable(pending, filed); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("file journal entry: %w", err)
	}
	return written, nil
}

// Receipt reads the receipt of a job version.
func (j *Journal) Receipt(jobID string, version int) (*Receipt, error) {
	if !namePattern.MatchString(jobID) {
		return nil, fmt.Errorf("invalid job id %q", jobID)
	}
	data, err := os.ReadFile(j.receiptPath(jobID, version)) //nolint:gosec // built from a validated job id
	if err != nil {
		return nil, err
	}
	var r Receipt
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse receipt: %w", err)
	}
	return &r, nil
}

// Receipts lists the receipts held for a job, lowest version first.
func (j *Journal) Receipts(jobID string) ([]Receipt, error) {
	if !namePattern.MatchString(jobID) {
		return nil, fmt.Errorf("invalid job id %q", jobID)
	}
	matches, err := filepath.Glob(filepath.Join(j.Dir, jobID, "v*.json"))
	if err != nil {
		return nil, err
	}
	receipts := make([]Receipt, 0, len(matches))
	for _, path := range matches {
		data, err := os.ReadFile(path) //nolint:gosec // matched under the receipts directory
		if err != nil {
			return nil, err
		}
		var r Receipt
		if err := json.Unmarshal(data, &r); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		receipts = append(receipts, r)
	}
	sort.Slice(receipts, func(a, b int) bool { return receipts[a].Version < receipts[b].Version })
	return receipts, nil
}

func (j *Journal) receiptPath(jobID string, version int) string {
	return filepath.Join(j.Dir, jobID, fmt.Sprintf("v%d.json", version))
}

func readEntry(path string) (*Entry, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is built from a validated request id
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("no unfinished request %s: %w", strings.TrimSuffix(filepath.Base(path), ".json"), err)
		}
		return nil, err
	}
	var e Entry
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("parse journal entry %s: %w", path, err)
	}
	return &e, nil
}

func encodeJSON(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
