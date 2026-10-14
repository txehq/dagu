// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity

import (
	"bytes"
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

	"github.com/dagucloud/dagu/v2/internal/cmn/fileutil"
)

// A transition changes a retained hub store for a new release. It is
// planned without writing, applied one record at a time with a journal so
// that it can stop anywhere and be resumed, and verified against the
// inventory taken before it. Nothing in it starts a run: it reads and
// writes files of a store whose service is stopped.
//
// In place is the normal path: only records the transform changes are
// rewritten, where they are. Import copies a hub data directory to a new
// one and is only for a real storage move; the source is never changed.

// Transition modes.
const (
	ModeInPlace = "in_place"
	ModeImport  = "import"
)

// PlanFormatV1 names the plan format.
const PlanFormatV1 = "txe.continuity.plan/v1"

// ErrConflict stops a transition: the store holds something the plan did
// not expect. Nothing is overwritten; a person resolves it and resumes.
var ErrConflict = errors.New("continuity: transition conflict")

// ErrBlocked refuses to plan a transition of a store that does not validate.
var ErrBlocked = errors.New("continuity: the source store has blocking issues")

// Transform rewrites one record of a store ("registry" or "authz") for the
// new release. It returns data unchanged when nothing applies. It must be
// deterministic: Apply runs it again and refuses a different result.
type Transform func(store, id string, data []byte) ([]byte, error)

// Identity is the transform of a release whose record format did not change.
func Identity(_, _ string, data []byte) ([]byte, error) { return data, nil }

// Plan is what a transition will do.
type Plan struct {
	Format string `json:"format"`
	Mode   string `json:"mode"`
	// Source is the digest of the inventory the plan was made from.
	Source string `json:"source"`
	Steps  []Step `json:"steps"`
	// NotCopied are parts of the source an import leaves where they are:
	// operational state that would dispatch work, and excluded areas.
	NotCopied []string `json:"not_copied,omitempty"`
	Rewrites  int      `json:"rewrites"`
	Copies    int      `json:"copies"`
}

// Step is one file the transition writes. Path is relative to the hub data
// directory, slash-separated. Before and After are SHA-256 digests of the
// exact bytes.
type Step struct {
	Path   string `json:"path"`
	Store  string `json:"store,omitempty"`
	ID     string `json:"id,omitempty"`
	Before string `json:"before"`
	After  string `json:"after"`
	// AfterRecord is the canonical digest of a rewritten record, as an
	// inventory records it.
	AfterRecord string `json:"after_record,omitempty"`
}

// JournalEntry records one step's outcome.
type JournalEntry struct {
	Seq     int       `json:"seq"`
	Path    string    `json:"path"`
	Before  string    `json:"before"`
	After   string    `json:"after"`
	Outcome string    `json:"outcome"` // done | conflict
	Detail  string    `json:"detail,omitempty"`
	At      time.Time `json:"at"`
}

// Journal outcomes.
const (
	OutcomeDone     = "done"
	OutcomeConflict = "conflict"
)

func storeDir(store string) string {
	if store == "authz" {
		return "txe/authz/v1"
	}
	return "txe/v1"
}

func rawDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// PlanTransition plans a transition of the hub data directory dataDir, whose
// inventory is inv. It writes nothing. A store that does not validate, or a
// transform that would change a record's owner or make it unreadable, is
// refused.
func PlanTransition(inv *Inventory, dataDir, mode string, transform Transform, pol Policy) (*Plan, error) {
	if mode != ModeInPlace && mode != ModeImport {
		return nil, fmt.Errorf("continuity: unknown transition mode %q", mode)
	}
	if blocking := Blocking(Validate(inv, pol)); len(blocking) > 0 {
		return nil, fmt.Errorf("%w: %d, first %s %s: %s", ErrBlocked, len(blocking), blocking[0].Code, blocking[0].ID, blocking[0].Detail)
	}
	hub := ""
	for _, r := range inv.Roots {
		if r.Area == AreaHubData {
			hub = r.Label
		}
	}
	if hub == "" {
		return nil, errors.New("continuity: the inventory has no hub data root")
	}
	p := &Plan{Format: PlanFormatV1, Mode: mode, Source: inv.Digest}
	for _, r := range inv.Records {
		if r.Store != "registry" && r.Store != "authz" {
			continue
		}
		rel := storeDir(r.Store) + "/" + r.ID + ".json"
		data, err := os.ReadFile(filepath.Join(dataDir, filepath.FromSlash(rel))) //nolint:gosec // a record of the inventory
		if err != nil {
			return nil, err
		}
		if recordDigest(data) != r.SHA256 {
			return nil, fmt.Errorf("%w: %s changed since the inventory", ErrConflict, rel)
		}
		out, err := transform(r.Store, r.ID, data)
		if err != nil {
			return nil, fmt.Errorf("continuity: transform %s: %w", rel, err)
		}
		if err := checkTransformed(r, out); err != nil {
			return nil, err
		}
		step := Step{Path: rel, Store: r.Store, ID: r.ID, Before: rawDigest(data), After: rawDigest(out), AfterRecord: recordDigest(out)}
		switch {
		case mode == ModeImport:
			p.Copies++
		case step.Before == step.After:
			continue
		default:
			p.Rewrites++
		}
		p.Steps = append(p.Steps, step)
	}
	if mode == ModeImport {
		for _, f := range inv.Files {
			if f.Root != hub {
				continue
			}
			if f.Policy == PolicyOperational || f.Link != "" {
				p.NotCopied = append(p.NotCopied, f.Path)
				continue
			}
			p.Steps = append(p.Steps, Step{Path: f.Path, Before: f.SHA256, After: f.SHA256})
			p.Copies++
		}
		for _, e := range inv.Excluded {
			if e.Root == hub {
				p.NotCopied = append(p.NotCopied, e.Path)
			}
		}
		sort.Strings(p.NotCopied)
	}
	sort.Slice(p.Steps, func(i, k int) bool { return p.Steps[i].Path < p.Steps[k].Path })
	return p, nil
}

// checkTransformed refuses a transformed record that this package can no
// longer read, or whose owner or class changed: a transition never
// reassigns ownership.
func checkTransformed(r Record, out []byte) error {
	classify := classifyRegistry
	if r.Store == "authz" {
		classify = classifyAuthz
	}
	got, issues := classify(r.ID, out)
	if len(Blocking(issues)) > 0 {
		return fmt.Errorf("%w: the transformed %s/%s does not validate: %s", ErrBlocked, r.Store, r.ID, Blocking(issues)[0].Detail)
	}
	if got.Class != r.Class || got.Owner != r.Owner {
		return fmt.Errorf("%w: the transform changes %s/%s from %s owned by %q to %s owned by %q", ErrBlocked, r.Store, r.ID, r.Class, r.Owner, got.Class, got.Owner)
	}
	return nil
}

// ApplyOptions configure Apply.
type ApplyOptions struct {
	// SourceData is the hub data directory the plan was made from.
	SourceData string
	// TargetData is the directory written: SourceData itself in place, a
	// new directory for an import.
	TargetData string
	// Journal is the journal file; an existing one is resumed.
	Journal   string
	Transform Transform
	// Interrupt, when set, is called at every point a crash could stop the
	// transition ("before_write", "after_write"); an error stops Apply
	// there as a crash would, with nothing after it done.
	Interrupt func(step int, point string) error
	Now       func() time.Time
}

// ApplyResult is what one Apply call did.
type ApplyResult struct {
	Written     int
	AlreadyDone int
}

// Apply carries out a plan. It can be run again after any interruption: a
// step journaled done is checked and skipped, a step whose write happened
// but was not journaled is recognized by its bytes, and anything else that
// differs stops the transition with ErrConflict and is never overwritten.
func Apply(ctx context.Context, plan *Plan, opts ApplyOptions) (*ApplyResult, error) {
	if plan.Format != PlanFormatV1 {
		return nil, fmt.Errorf("continuity: plan format %q is not %q", plan.Format, PlanFormatV1)
	}
	inPlace := plan.Mode == ModeInPlace
	if inPlace != samePath(opts.SourceData, opts.TargetData) {
		return nil, fmt.Errorf("continuity: an %s transition needs %s source and target", plan.Mode, map[bool]string{true: "the same", false: "different"}[inPlace])
	}
	if opts.Transform == nil {
		opts.Transform = Identity
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	journal, err := ReadJournal(opts.Journal)
	if err != nil {
		return nil, err
	}
	done := map[string]string{}
	for _, e := range journal {
		if e.Outcome == OutcomeDone {
			done[e.Path] = e.After
		}
	}
	j, err := os.OpenFile(opts.Journal, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600) //nolint:gosec // the operator's journal path
	if err != nil {
		return nil, err
	}
	defer func() { _ = j.Close() }()
	seq := len(journal)
	record := func(s Step, outcome, detail string) error {
		seq++
		b, err := json.Marshal(JournalEntry{Seq: seq, Path: s.Path, Before: s.Before, After: s.After, Outcome: outcome, Detail: detail, At: now().UTC()})
		if err != nil {
			return err
		}
		if _, err := j.Write(append(b, '\n')); err != nil {
			return err
		}
		return j.Sync()
	}
	conflict := func(s Step, detail string) error {
		if err := record(s, OutcomeConflict, detail); err != nil {
			return err
		}
		return fmt.Errorf("%w: %s: %s", ErrConflict, s.Path, detail)
	}

	res := &ApplyResult{}
	for i, s := range plan.Steps {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		target := filepath.Join(opts.TargetData, filepath.FromSlash(s.Path))
		cur, curErr := os.ReadFile(target) //nolint:gosec // a path of the plan under the target
		present := curErr == nil
		if curErr != nil && !errors.Is(curErr, fs.ErrNotExist) {
			return res, curErr
		}
		if after, ok := done[s.Path]; ok && after == s.After {
			if !present || rawDigest(cur) != s.After {
				return res, conflict(s, "changed after it was applied")
			}
			res.AlreadyDone++
			continue
		}
		if present && rawDigest(cur) == s.After {
			// Written before an interruption that came before the journal.
			if err := record(s, OutcomeDone, "found applied"); err != nil {
				return res, err
			}
			res.AlreadyDone++
			continue
		}
		src, err := os.ReadFile(filepath.Join(opts.SourceData, filepath.FromSlash(s.Path))) //nolint:gosec // a path of the plan under the source
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return res, conflict(s, "the source no longer has it")
			}
			return res, err
		}
		if rawDigest(src) != s.Before {
			return res, conflict(s, "the source changed since the plan")
		}
		if inPlace || present {
			if !inPlace || rawDigest(cur) != s.Before {
				return res, conflict(s, "the target holds something else")
			}
		}
		out := src
		if s.Store != "" {
			if out, err = opts.Transform(s.Store, s.ID, src); err != nil {
				return res, fmt.Errorf("continuity: transform %s: %w", s.Path, err)
			}
			if rawDigest(out) != s.After {
				return res, conflict(s, "the transform gives another result than it planned")
			}
		}
		if err := interrupt(opts, i, "before_write"); err != nil {
			return res, err
		}
		if err := write(target, out, inPlace); err != nil {
			if errors.Is(err, fs.ErrExist) {
				return res, conflict(s, "the target was created by someone else")
			}
			return res, err
		}
		if err := interrupt(opts, i, "after_write"); err != nil {
			return res, err
		}
		if err := record(s, OutcomeDone, ""); err != nil {
			return res, err
		}
		res.Written++
	}
	return res, nil
}

func interrupt(opts ApplyOptions, step int, point string) error {
	if opts.Interrupt == nil {
		return nil
	}
	return opts.Interrupt(step, point)
}

// write replaces a record in place or creates a new file of an import,
// atomically either way. An import never replaces a file.
func write(target string, data []byte, replace bool) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return err
	}
	if replace {
		return fileutil.WriteFileAtomic(target, data, 0o600)
	}
	return fileutil.WriteFileAtomicExclusive(target, data, 0o600)
}

func samePath(a, b string) bool {
	ca, errA := filepath.Abs(a)
	cb, errB := filepath.Abs(b)
	return errA == nil && errB == nil && filepath.Clean(ca) == filepath.Clean(cb)
}

// ReadJournal reads a journal. A missing journal is empty; a torn last
// line, left by a crash in the middle of an append, is ignored because its
// step is recognized again by its bytes.
func ReadJournal(path string) ([]JournalEntry, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the operator's journal path
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []JournalEntry
	lines := bytes.Split(data, []byte("\n"))
	for n, line := range lines {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e JournalEntry
		if err := json.Unmarshal(line, &e); err != nil {
			if n == len(lines)-1 {
				break // torn final append
			}
			return nil, fmt.Errorf("continuity: journal %s line %d: %w", path, n+1, err)
		}
		out = append(out, e)
	}
	return out, nil
}

// VerifyTransition checks the store after a transition against the
// inventory taken before it, with the strict freeze comparison. Only the
// records the plan rewrote, and the journal records as done, may differ,
// and each must now hold exactly what the plan computed. Everything else
// must be as it was; nothing may be missing or added.
func VerifyTransition(before, after *Inventory, plan *Plan, journal []JournalEntry) *Report {
	done := map[string]JournalEntry{}
	for _, e := range journal {
		if e.Outcome == OutcomeDone {
			done[e.Path] = e
		}
	}
	reconciled := map[string]bool{}
	var issues []Issue
	add := func(code, id, detail string) {
		issues = append(issues, Issue{Code: code, Severity: SeverityBlock, ID: id, Detail: detail})
	}
	if plan.Source != before.Digest {
		add("plan_mismatch", "", "the plan was made from inventory "+plan.Source+", not "+before.Digest)
	}
	later := map[string]*Record{}
	for i := range after.Records {
		r := &after.Records[i]
		later[r.Store+"/"+r.ID] = r
	}
	for _, s := range plan.Steps {
		e, ok := done[s.Path]
		if !ok || e.After != s.After {
			add("step_not_applied", s.Path, "the plan's step is not journaled done")
			continue
		}
		if s.Store == "" || s.Before == s.After {
			continue
		}
		key := s.Store + "/" + s.ID
		reconciled[key] = true
		if r := later[key]; r != nil && r.SHA256 != s.AfterRecord {
			add("step_result_differs", key, "the record holds "+r.SHA256+", not the "+s.AfterRecord+" the plan computed")
		}
	}
	rep := Compare(before, after, CompareOptions{Reconciled: reconciled})
	rep.Issues = append(rep.Issues, issues...)
	sortIssues(rep.Issues)
	return rep
}
