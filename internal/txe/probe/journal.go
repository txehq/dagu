// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/gofrs/flock"
)

// Journal is the machine's local memory between checks: the reports the
// registry has not acknowledged, resent unchanged under their event id, and
// when each target was last observed, so a periodic check starts with the
// targets it has waited longest to see. One journal serves every check on
// the machine, pre-run and periodic, and every change is a locked
// read-modify-write, so concurrent checks never lose each other's reports.
type Journal struct {
	path string
	lock *flock.Flock
}

// pendingReport is a report the registry has not acknowledged.
type pendingReport struct {
	// JobID is the job a pre-run report was made for; empty for periodic.
	JobID string `json:"job_id,omitempty"`
	// Key is the requested target's key, for scheduling.
	Key   string `json:"key"`
	Event Event  `json:"event"`
}

type journalState struct {
	// Undelivered holds unacknowledged reports by event id.
	Undelivered map[string]pendingReport `json:"undelivered,omitempty"`
	// Checked is when each requested target was last observed and reported.
	Checked map[string]time.Time `json:"checked,omitempty"`
}

// lockWait bounds how long a check waits for another to finish a journal
// change; changes are small, so a longer wait means something is stuck.
const lockWait = 10 * time.Second

// OpenJournal returns the journal at path; the file is created on first
// change.
func OpenJournal(path string) (*Journal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("probe: journal directory: %w", err)
	}
	return &Journal{path: path, lock: flock.New(path + ".lock")}, nil
}

func (j *Journal) locked(ctx context.Context, fn func() error) error {
	lctx, cancel := context.WithTimeout(ctx, lockWait)
	defer cancel()
	ok, err := j.lock.TryLockContext(lctx, 20*time.Millisecond)
	if err != nil || !ok {
		return fmt.Errorf("probe: journal is locked by another check: %w", errors.Join(err, lctx.Err()))
	}
	defer func() { _ = j.lock.Unlock() }()
	return fn()
}

func (j *Journal) load() (journalState, error) {
	st := journalState{Undelivered: map[string]pendingReport{}, Checked: map[string]time.Time{}}
	b, err := os.ReadFile(filepath.Clean(j.path))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return st, nil
	case err != nil:
		return st, fmt.Errorf("probe: read journal: %w", err)
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("probe: journal %s is unreadable: %w", j.path, err)
	}
	if st.Undelivered == nil {
		st.Undelivered = map[string]pendingReport{}
	}
	if st.Checked == nil {
		st.Checked = map[string]time.Time{}
	}
	return st, nil
}

func (j *Journal) save(st journalState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(j.path), ".journal-*")
	if err != nil {
		return fmt.Errorf("probe: write journal: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("probe: write journal: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("probe: write journal: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("probe: write journal: %w", err)
	}
	return os.Rename(tmp.Name(), j.path)
}

func (j *Journal) update(ctx context.Context, fn func(*journalState)) error {
	return j.locked(ctx, func() error {
		st, err := j.load()
		if err != nil {
			return err
		}
		fn(&st)
		return j.save(st)
	})
}

// hold records a report before it is sent.
func (j *Journal) hold(ctx context.Context, r pendingReport) error {
	return j.update(ctx, func(st *journalState) { st.Undelivered[r.Event.EventID] = r })
}

// delivered drops an acknowledged report and records when its requested
// target was observed.
func (j *Journal) delivered(ctx context.Context, r pendingReport, at time.Time) error {
	return j.update(ctx, func(st *journalState) {
		delete(st.Undelivered, r.Event.EventID)
		st.Checked[r.Key] = at
	})
}

// pending returns the unacknowledged reports, oldest event first; with a
// job id, only that job's pre-run reports.
func (j *Journal) pending(ctx context.Context, jobID string) ([]pendingReport, error) {
	var out []pendingReport
	err := j.locked(ctx, func() error {
		st, err := j.load()
		if err != nil {
			return err
		}
		for _, r := range st.Undelivered {
			if jobID == "" || r.JobID == jobID {
				out = append(out, r)
			}
		}
		return nil
	})
	sort.Slice(out, func(a, b int) bool { return out[a].Event.EventID < out[b].Event.EventID })
	return out, err
}

// lastChecked returns when each requested target was last observed.
func (j *Journal) lastChecked(ctx context.Context) (map[string]time.Time, error) {
	var out map[string]time.Time
	err := j.locked(ctx, func() error {
		st, err := j.load()
		out = st.Checked
		return err
	})
	return out, err
}

// TargetKey identifies a target by kind and stable identity, the way the
// registry does; the display name is not part of it.
func TargetKey(t Target) string {
	keys := make([]string, 0, len(t.StableID))
	for k := range t.StableID {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	pairs := make([][2]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, [2]string{k, t.StableID[k]})
	}
	b, _ := json.Marshal([]any{t.Kind, pairs})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// nameKey identifies the place a target lives, the way the registry matches
// replacements: kind, environment and display name.
func nameKey(t Target) string {
	b, _ := json.Marshal([]string{t.Kind, t.Environment, t.DisplayName})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
