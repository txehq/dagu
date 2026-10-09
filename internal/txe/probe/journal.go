// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
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
)

// Journal is a check's local memory between runs: the reports it could not
// deliver, resent unchanged under their event id, and when each target was
// last observed, so a periodic check starts with the targets it has waited
// longest to see and a slow target cannot starve the rest.
type Journal struct {
	path  string
	state journalState
}

type journalState struct {
	// Undelivered holds reports the registry has not acknowledged, by
	// target key. Resending one keeps its event id, which the registry
	// treats as the same report.
	Undelivered map[string]Event `json:"undelivered,omitempty"`
	// Checked is when each target was last observed and reported.
	Checked map[string]time.Time `json:"checked,omitempty"`
}

// OpenJournal reads the journal at path; a missing file is an empty one.
func OpenJournal(path string) (*Journal, error) {
	j := &Journal{path: path}
	b, err := os.ReadFile(filepath.Clean(path))
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("probe: read journal: %w", err)
	default:
		if err := json.Unmarshal(b, &j.state); err != nil {
			return nil, fmt.Errorf("probe: journal %s is unreadable: %w", path, err)
		}
	}
	if j.state.Undelivered == nil {
		j.state.Undelivered = map[string]Event{}
	}
	if j.state.Checked == nil {
		j.state.Checked = map[string]time.Time{}
	}
	return j, nil
}

// Save writes the journal atomically.
func (j *Journal) Save() error {
	b, err := json.MarshalIndent(j.state, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(j.path), 0o700); err != nil {
		return fmt.Errorf("probe: journal directory: %w", err)
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
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("probe: write journal: %w", err)
	}
	return os.Rename(tmp.Name(), j.path)
}

// Undelivered returns the reports still to deliver, in a stable order.
func (j *Journal) Undelivered() []Event {
	keys := make([]string, 0, len(j.state.Undelivered))
	for k := range j.state.Undelivered {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]Event, 0, len(keys))
	for _, k := range keys {
		out = append(out, j.state.Undelivered[k])
	}
	return out
}

func (j *Journal) hold(ev Event)      { j.state.Undelivered[TargetKey(ev.Target)] = ev }
func (j *Journal) delivered(ev Event) { delete(j.state.Undelivered, TargetKey(ev.Target)) }

// pending reports whether a report about t is still undelivered.
func (j *Journal) pending(t Target) (Event, bool) {
	ev, ok := j.state.Undelivered[TargetKey(t)]
	return ev, ok
}

func (j *Journal) checked(t Target, at time.Time) { j.state.Checked[TargetKey(t)] = at }

// LastChecked is when t was last observed and reported; zero if never.
func (j *Journal) LastChecked(t Target) time.Time { return j.state.Checked[TargetKey(t)] }

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
