// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
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
	// Mode is an imported file's permission bits, where they are known.
	Mode uint32 `json:"mode,omitempty"`
	// Link is a retained symbolic link's target: the step recreates the
	// link and never follows it.
	Link string `json:"link,omitempty"`
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
	// projected is the inventory as the transition will leave it.
	projected := *inv
	projected.Records = append([]Record(nil), inv.Records...)
	for i, r := range inv.Records {
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
		before := rawDigest(data)
		out, err := transform(r.Store, r.ID, bytes.Clone(data))
		if err != nil {
			return nil, fmt.Errorf("continuity: transform %s: %w", rel, err)
		}
		got, err := checkTransformed(r, out)
		if err != nil {
			return nil, err
		}
		got.Store, got.ID, got.SHA256, got.Raw = r.Store, r.ID, recordDigest(out), rawDigest(out)
		projected.Records[i] = *got
		step := Step{Path: rel, Store: r.Store, ID: r.ID, Before: before, After: rawDigest(out), AfterRecord: recordDigest(out)}
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
			if f.Policy == PolicyOperational {
				p.NotCopied = append(p.NotCopied, f.Path)
				continue
			}
			// A retained link is recreated as a link, never followed.
			p.Steps = append(p.Steps, Step{Path: f.Path, Before: f.SHA256, After: f.SHA256, Mode: f.Mode, Link: f.Link})
			p.Copies++
		}
		for _, e := range inv.Excluded {
			if e.Root == hub {
				p.NotCopied = append(p.NotCopied, e.Path)
			}
		}
		sort.Strings(p.NotCopied)
	}
	// The transformed records must still hold together: owners, references
	// and history as Validate checks them.
	if blocking := Blocking(Validate(&projected, pol)); len(blocking) > 0 {
		return nil, fmt.Errorf("%w: the transformed store would not validate: %d, first %s %s: %s", ErrBlocked, len(blocking), blocking[0].Code, blocking[0].ID, blocking[0].Detail)
	}
	sort.Slice(p.Steps, func(i, k int) bool { return p.Steps[i].Path < p.Steps[k].Path })
	return p, nil
}

// checkTransformed refuses a transformed record that this package can no
// longer read, or whose owner or class changed: a transition never
// reassigns ownership.
func checkTransformed(r Record, out []byte) (*Record, error) {
	classify := classifyRegistry
	if r.Store == "authz" {
		classify = classifyAuthz
	}
	got, issues := classify(r.ID, out)
	if len(Blocking(issues)) > 0 {
		return nil, fmt.Errorf("%w: the transformed %s/%s does not validate: %s", ErrBlocked, r.Store, r.ID, Blocking(issues)[0].Detail)
	}
	if got.Class != r.Class || got.Owner != r.Owner {
		return nil, fmt.Errorf("%w: the transform changes %s/%s from %s owned by %q to %s owned by %q", ErrBlocked, r.Store, r.ID, r.Class, r.Owner, got.Class, got.Owner)
	}
	return got, nil
}

// ApplyOptions configure Apply.
type ApplyOptions struct {
	// SourceData is the hub data directory the plan was made from.
	SourceData string
	// TargetData is the directory written: SourceData itself in place, a
	// new directory, disjoint from the source, for an import.
	TargetData string
	// Journal is the journal file, outside both data directories; an
	// existing one is resumed.
	Journal   string
	Transform Transform
	// Interrupt, when set, is called at every point a crash could stop the
	// transition: per step "before_write", "staged", "installed" and
	// "after_write", and with step -1 "target_created", "staging_init" and
	// "staging_teardown". An error stops Apply there as a crash would,
	// with nothing after it done.
	Interrupt func(step int, point string) error
	Now       func() time.Time
}

// ApplyResult is what one Apply call did.
type ApplyResult struct {
	Written     int
	AlreadyDone int
}

// stagingPrefix names the directories a transition stages its writes in,
// at the target root on the same file system. Each transition's is its own
// (named from its plan and journal) and carries an owner marker, so a run
// clears only what an earlier run of the same transition left.
const stagingPrefix = ".txe-transition-staging"

const ownerMarker = ".owner"

// Apply carries out a plan. It can be run again after any interruption: a
// step journaled done is checked and skipped, a step whose write happened
// but was not journaled is recognized by its bytes, and anything else that
// differs stops the transition with ErrConflict and is never overwritten.
//
// Every read and write goes through an os.Root on the source and the
// target, and a step whose path passes through a link is refused, so a
// transition cannot write outside its target or read outside its source.
// It runs on a Unix host, where the store lives: the durability it relies
// on (synced directories) is not what Windows provides.
func Apply(ctx context.Context, plan *Plan, opts ApplyOptions) (*ApplyResult, error) {
	if !hasModeBits {
		return nil, errors.New("continuity: a transition runs on the Unix host that holds the store, not on Windows")
	}
	if plan.Format != PlanFormatV1 {
		return nil, fmt.Errorf("continuity: plan format %q is not %q", plan.Format, PlanFormatV1)
	}
	if opts.Transform == nil {
		opts.Transform = Identity
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	for _, s := range plan.Steps {
		if err := checkRelPath(s.Path); err != nil {
			return nil, err
		}
	}
	inPlace := plan.Mode == ModeInPlace
	if err := checkRoots(opts.SourceData, opts.TargetData, opts.Journal, inPlace); err != nil {
		return nil, err
	}
	src, err := os.OpenRoot(opts.SourceData)
	if err != nil {
		return nil, err
	}
	defer func() { _ = src.Close() }()
	if !inPlace {
		if err := mkdirDurable(opts.TargetData, func() error { return interrupt(opts, -1, "target_created") }); err != nil {
			return nil, err
		}
	}
	dst := src
	if !inPlace {
		if dst, err = os.OpenRoot(opts.TargetData); err != nil {
			return nil, err
		}
		defer func() { _ = dst.Close() }()
	}
	journalPath, err := filepath.Abs(opts.Journal)
	if err != nil {
		return nil, err
	}
	token := rawDigest([]byte(plan.Source + "\x00" + journalPath))[len("sha256:"):][:16]
	staging := stagingPrefix + "-" + token
	if err := resetStaging(dst, staging, token, opts); err != nil {
		return nil, err
	}
	journal, err := openJournal(opts.Journal)
	if err != nil {
		return nil, err
	}
	defer func() { _ = journal.f.Close() }()

	res := &ApplyResult{}
	for i, s := range plan.Steps {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		done, err := applyStep(i, s, plan, opts, src, dst, staging, journal, now)
		if err != nil {
			return res, err
		}
		if done {
			res.AlreadyDone++
		} else {
			res.Written++
		}
	}
	if err := teardown(dst, staging, token, opts); err != nil {
		return res, err
	}
	return res, syncRootDir(dst, ".")
}

// resetStaging clears what an earlier run of this transition staged, and
// refuses a staging directory it cannot show is this transition's. A new
// staging directory is prepared under a temporary name, with its owner
// marker written and synced, and only then given its name, so a crash
// while preparing it never leaves an unmarked staging directory behind.
func resetStaging(root *os.Root, staging, token string, opts ApplyOptions) error {
	// A teardown an earlier run did not finish.
	if err := removeDone(root, staging+".done", token); err != nil {
		return err
	}
	if err := teardown(root, staging, token, opts); err != nil {
		return err
	}
	init := staging + ".init"
	// An interrupted preparation holds at most this transition's marker.
	if err := removeOwned(root, init, token, true); err != nil {
		return err
	}
	if err := root.Mkdir(init, 0o750); err != nil {
		return err
	}
	if err := syncRootDir(root, "."); err != nil {
		return err
	}
	if err := interrupt(opts, -1, "staging_init"); err != nil {
		return err
	}
	f, err := root.OpenFile(init+"/"+ownerMarker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(token); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := syncRootDir(root, init); err != nil {
		return err
	}
	if err := root.Rename(init, staging); err != nil {
		return err
	}
	return syncRootDir(root, ".")
}

// teardown removes this transition's staging directory. It is first
// renamed out of the published name, so a crash while its contents are
// being removed never leaves an unmarked directory there; the renamed
// remains are recognized and finished by the next run.
func teardown(root *os.Root, staging, token string, opts ApplyOptions) error {
	info, err := root.Lstat(staging)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case !info.IsDir() || info.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%w: %s is not this transition's staging directory", ErrConflict, staging)
	}
	if owner, err := root.ReadFile(staging + "/" + ownerMarker); err != nil || string(owner) != token {
		return fmt.Errorf("%w: %s exists and was not made by this transition; it is left as it is", ErrConflict, staging)
	}
	done := staging + ".done"
	if err := root.Rename(staging, done); err != nil {
		return err
	}
	if err := syncRootDir(root, "."); err != nil {
		return err
	}
	if err := interrupt(opts, -1, "staging_teardown"); err != nil {
		return err
	}
	return removeDone(root, done, token)
}

var stagedName = regexp.MustCompile(`^[0-9a-f]{24}$`)

// removeDone finishes removing a staging directory that a teardown renamed.
// What it may still hold is only what this transition puts in staging: its
// owner marker (whole, or cut short) and staged files; anything else is a
// conflict and is left as it is.
func removeDone(root *os.Root, done, token string) error {
	info, err := root.Lstat(done)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case !info.IsDir() || info.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%w: %s is not this transition's staging directory", ErrConflict, done)
	}
	entries, err := fs.ReadDir(root.FS(), done)
	if err != nil {
		return err
	}
	for _, e := range entries {
		switch {
		case e.Name() == ownerMarker && e.Type().IsRegular():
			owner, err := root.ReadFile(done + "/" + ownerMarker)
			if err != nil || !strings.HasPrefix(token, string(owner)) {
				return fmt.Errorf("%w: %s holds another transition's marker; it is left as it is", ErrConflict, done)
			}
		case stagedName.MatchString(e.Name()) && e.Type().IsRegular():
		default:
			return fmt.Errorf("%w: %s holds %s, which this transition did not stage; it is left as it is", ErrConflict, done, e.Name())
		}
	}
	if err := root.RemoveAll(done); err != nil {
		return err
	}
	return syncRootDir(root, ".")
}

// removeOwned removes dir if it is this transition's: a plain directory
// whose owner marker holds token. With partial set, a directory holding
// nothing, or only an incomplete prefix of the marker, also counts: it is
// a preparation this transition started. Anything else is a conflict and
// is left as it is.
func removeOwned(root *os.Root, dir, token string, partial bool) error {
	info, err := root.Lstat(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil
	case err != nil:
		return err
	case !info.IsDir() || info.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%w: %s is not this transition's staging directory", ErrConflict, dir)
	}
	entries, err := fs.ReadDir(root.FS(), dir)
	if err != nil {
		return err
	}
	owned := false
	switch owner, err := root.ReadFile(dir + "/" + ownerMarker); {
	case err == nil && string(owner) == token:
		owned = true
	case partial && len(entries) == 0:
		owned = true
	case partial && err == nil && len(entries) == 1 && strings.HasPrefix(token, string(owner)):
		owned = true
	}
	if !owned {
		return fmt.Errorf("%w: %s exists and was not made by this transition; it is left as it is", ErrConflict, dir)
	}
	return root.RemoveAll(dir)
}

// applyStep carries out one step; done reports it was already applied.
func applyStep(i int, s Step, plan *Plan, opts ApplyOptions, src, dst *os.Root, staging string, j *journalFile, now func() time.Time) (bool, error) {
	inPlace := plan.Mode == ModeInPlace
	record := func(outcome, detail string) error {
		return j.append(JournalEntry{Path: s.Path, Before: s.Before, After: s.After, Outcome: outcome, Detail: detail, At: now().UTC()})
	}
	conflict := func(detail string) error {
		if err := record(OutcomeConflict, detail); err != nil {
			return err
		}
		return fmt.Errorf("%w: %s: %s", ErrConflict, s.Path, detail)
	}
	if err := noLinks(dst, s.Path); err != nil {
		return false, conflict(err.Error())
	}
	if err := noLinks(src, s.Path); err != nil {
		return false, conflict(err.Error())
	}
	if s.Link != "" {
		return applyLink(i, s, opts, src, dst, j, record, conflict)
	}
	// An import's source must still be what the plan read, whatever the
	// target holds; in place the source is the target and is checked below.
	var data []byte
	var mode fs.FileMode
	if !inPlace {
		var ok bool
		var err error
		if data, mode, ok, err = readNoFollow(src, s.Path); err != nil {
			return false, conflict(err.Error())
		}
		if !ok {
			return false, conflict("the source no longer has it")
		}
		if rawDigest(data) != s.Before {
			return false, conflict("the source changed since the plan")
		}
	}
	cur, curMode, present, err := readNoFollow(dst, s.Path)
	if err != nil {
		return false, conflict(err.Error())
	}
	applied := present && rawDigest(cur) == s.After && modeMatches(curMode, s.Mode)
	if after, ok := j.done[s.Path]; ok && after == s.After {
		if !applied {
			return false, conflict("changed after it was applied")
		}
		return true, nil
	}
	if applied {
		// Installed before an interruption that came before the journal:
		// it is made durable before it is journaled done.
		if err := syncFile(dst, s.Path); err != nil {
			return false, err
		}
		if err := syncChain(dst, path.Dir(s.Path)); err != nil {
			return false, err
		}
		return true, record(OutcomeDone, "found applied")
	}
	switch {
	case inPlace && (!present || rawDigest(cur) != s.Before):
		return false, conflict("the record holds something the plan did not read")
	case !inPlace && present:
		return false, conflict("the target holds something else")
	}
	if inPlace {
		data, mode = cur, curMode
	}
	out := data
	if s.Store != "" {
		if out, err = opts.Transform(s.Store, s.ID, bytes.Clone(data)); err != nil {
			return false, fmt.Errorf("continuity: transform %s: %w", s.Path, err)
		}
		if rawDigest(out) != s.After {
			return false, conflict("the transform gives another result than it planned")
		}
	}
	perm := mode.Perm()
	if !inPlace && s.Mode != 0 {
		perm = fs.FileMode(s.Mode)
	}
	if err := interrupt(opts, i, "before_write"); err != nil {
		return false, err
	}
	staged, err := stage(dst, staging, out, perm)
	if err != nil {
		return false, err
	}
	if err := interrupt(opts, i, "staged"); err != nil {
		return false, err
	}
	if err := install(dst, staged, s.Path, inPlace, func() error { return interrupt(opts, i, "installed") }); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, conflict("the target was created by someone else")
		}
		return false, err
	}
	if err := interrupt(opts, i, "after_write"); err != nil {
		return false, err
	}
	return false, record(OutcomeDone, "")
}

// applyLink recreates a retained symbolic link in an import, as a link to
// the same target, without following it on either side.
func applyLink(i int, s Step, opts ApplyOptions, src, dst *os.Root, j *journalFile, record func(string, string) error, conflict func(string) error) (bool, error) {
	readLink := func(root *os.Root) (string, bool, error) {
		info, err := root.Lstat(s.Path)
		if errors.Is(err, fs.ErrNotExist) {
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			return "", true, nil
		}
		target, err := root.Readlink(s.Path)
		return target, true, err
	}
	have, ok, err := readLink(src)
	switch {
	case err != nil:
		return false, err
	case !ok || have != s.Link:
		return false, conflict("the source link changed since the plan")
	}
	cur, present, err := readLink(dst)
	if err != nil {
		return false, err
	}
	if present && cur == s.Link {
		if _, done := j.done[s.Path]; done {
			return true, nil
		}
		if err := syncChain(dst, path.Dir(s.Path)); err != nil {
			return false, err
		}
		return true, record(OutcomeDone, "found applied")
	}
	if _, done := j.done[s.Path]; done {
		return false, conflict("changed after it was applied")
	}
	if present {
		return false, conflict("the target holds something else")
	}
	if err := interrupt(opts, i, "before_write"); err != nil {
		return false, err
	}
	if err := mkdirAllDurable(dst, path.Dir(s.Path)); err != nil {
		return false, err
	}
	if err := dst.Symlink(s.Link, s.Path); err != nil {
		return false, err
	}
	if err := syncChain(dst, path.Dir(s.Path)); err != nil {
		return false, err
	}
	if err := interrupt(opts, i, "after_write"); err != nil {
		return false, err
	}
	return false, record(OutcomeDone, "")
}

// checkRelPath refuses a plan path that is not a clean, relative,
// slash-separated path inside its root.
func checkRelPath(p string) error {
	switch {
	case p == "", p == ".", p == "..", strings.HasPrefix(p, "../"), path.IsAbs(p),
		strings.ContainsAny(p, "\\:"), path.Clean(p) != p,
		strings.HasPrefix(p, stagingPrefix):
		return fmt.Errorf("continuity: the plan names an unsafe path %q", p)
	}
	return nil
}

// checkRoots refuses a source and target that are not what the mode needs,
// and a journal inside either or one that is a link. Containment is decided
// on physical paths (every existing part resolved, links included) by file
// system identity, so an alias of the source or of any directory in it (a
// link, a junction, another letter case) counts as the source.
func checkRoots(source, target, journal string, inPlace bool) error {
	srcInfo, err := os.Stat(source)
	if err != nil {
		return err
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("continuity: the source %s is not a directory", source)
	}
	tgtInfo, tgtErr := os.Stat(target)
	if inPlace {
		if tgtErr != nil || !os.SameFile(srcInfo, tgtInfo) {
			return fmt.Errorf("continuity: an in-place transition writes its own source; %s is not %s", target, source)
		}
	} else {
		in, err := within(target, srcInfo)
		if err != nil || in {
			return fmt.Errorf("continuity: the import target %s is the source or inside it", target)
		}
		if tgtErr == nil {
			if in, err := within(source, tgtInfo); err != nil || in {
				return fmt.Errorf("continuity: the source %s is inside the import target", source)
			}
		}
	}
	if journal == "" {
		return errors.New("continuity: a journal path is required")
	}
	if in, err := within(journal, srcInfo); err != nil || in {
		return fmt.Errorf("continuity: the journal %s is inside the source", journal)
	}
	if tgtErr == nil {
		if in, err := within(journal, tgtInfo); err != nil || in {
			return fmt.Errorf("continuity: the journal %s is inside the target", journal)
		}
	} else if in, err := underPath(journal, target); err != nil || in {
		// The target does not exist yet: compare where both would be.
		return fmt.Errorf("continuity: the journal %s would be inside the target", journal)
	}
	// The journal file itself must be a plain file of its own: a link, or a
	// second name of another file, could be a file of a store.
	info, err := os.Lstat(journal)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	case !info.Mode().IsRegular():
		return fmt.Errorf("continuity: the journal %s is not a regular file", journal)
	case linkCount(info) > 1:
		return fmt.Errorf("continuity: the journal %s has other names (hard links); use a file of its own", journal)
	}
	return nil
}

// within reports whether p, resolved to its physical path, is dir or lies
// inside it. Every existing part of p is resolved, links included; the
// parts that do not exist yet cannot be links.
func within(p string, dir fs.FileInfo) (bool, error) {
	physical, err := physicalPath(p)
	if err != nil {
		return false, err
	}
	for cur := physical; ; {
		if info, err := os.Stat(cur); err == nil && os.SameFile(info, dir) {
			return true, nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return false, nil
		}
		cur = parent
	}
}

// underPath reports whether p would be dir or inside it, comparing their
// physical paths; it is for a dir that does not exist yet. Letter case is
// ignored where file systems usually ignore it.
func underPath(p, dir string) (bool, error) {
	pp, err := physicalPath(p)
	if err != nil {
		return false, err
	}
	dp, err := physicalPath(dir)
	if err != nil {
		return false, err
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		pp, dp = strings.ToLower(pp), strings.ToLower(dp)
	}
	rel, err := filepath.Rel(dp, pp)
	if err != nil {
		return false, nil
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))), nil
}

// physicalPath resolves the longest existing prefix of p and appends the
// rest.
func physicalPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	rest := ""
	for cur := abs; ; {
		if _, err := os.Lstat(cur); err == nil {
			resolved, err := filepath.EvalSymlinks(cur)
			if err != nil {
				return "", err
			}
			return filepath.Join(resolved, rest), nil
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return abs, nil
		}
		rest = filepath.Join(filepath.Base(cur), rest)
		cur = parent
	}
}

// mkdirDurable creates dir and any missing parents, and makes the entry of
// dir and of every directory above it durable in its parent. That is done
// on every run, also for directories that already exist: one may have been
// created by a run that stopped before it synced the parent. created is
// called after each directory this run creates, before its parent is
// synced.
func mkdirDurable(dir string, created func() error) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o750); err != nil {
		return err
	}
	if err := os.Mkdir(abs, 0o750); err == nil {
		if err := created(); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrExist) {
		return err
	}
	for d := abs; ; {
		parent := filepath.Dir(d)
		if parent == d {
			return nil
		}
		if err := fileutil.SyncDir(parent); err != nil {
			return err
		}
		d = parent
	}
}

// noLinks refuses a path whose existing parent directories under root are
// not plain directories: a link there could lead the step elsewhere.
func noLinks(root *os.Root, rel string) error {
	parts := strings.Split(rel, "/")
	for i := 1; i < len(parts); i++ {
		dir := strings.Join(parts[:i], "/")
		info, err := root.Lstat(dir)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is not a plain directory", dir)
		}
	}
	return nil
}

// readNoFollow reads a regular file under root without following a link.
func readNoFollow(root *os.Root, rel string) ([]byte, fs.FileMode, bool, error) {
	info, err := root.Lstat(rel)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, false, fmt.Errorf("%w: %s is not a regular file", ErrConflict, rel)
	}
	data, err := root.ReadFile(rel)
	if err != nil {
		return nil, 0, false, err
	}
	return data, info.Mode(), true, nil
}

func modeMatches(have fs.FileMode, want uint32) bool {
	return want == 0 || !hasModeBits || uint32(have.Perm()) == want
}

// stage writes data to a new file in the staging area and returns its name.
func stage(root *os.Root, staging string, data []byte, perm fs.FileMode) (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	name := staging + "/" + hex.EncodeToString(b[:])
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return "", err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	// The process umask may have narrowed the mode at creation.
	return name, root.Chmod(name, perm)
}

// install moves a staged file to rel: replacing what is there in place,
// never replacing anything in an import.
func install(root *os.Root, staged, rel string, replace bool, installed func() error) error {
	dir := path.Dir(rel)
	if err := mkdirAllDurable(root, dir); err != nil {
		return err
	}
	if replace {
		if err := root.Rename(staged, rel); err != nil {
			return err
		}
	} else {
		if err := root.Link(staged, rel); err != nil {
			return err
		}
		if err := root.Remove(staged); err != nil {
			return err
		}
	}
	if err := installed(); err != nil {
		return err
	}
	return syncChain(root, dir)
}

// syncChain makes durable the entries of dir and of every directory above
// it up to the root: one of them may have been created by a run that
// stopped before it synced its parent.
func syncChain(root *os.Root, dir string) error {
	for d := dir; ; d = path.Dir(d) {
		if err := syncRootDir(root, d); err != nil {
			return err
		}
		if d == "." {
			return nil
		}
	}
}

// syncFile makes a file's contents durable.
func syncFile(root *os.Root, rel string) error {
	f, err := root.Open(rel)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

// mkdirAllDurable creates dir under root, syncing each new directory into
// its parent.
func mkdirAllDurable(root *os.Root, dir string) error {
	if dir == "." {
		return nil
	}
	parts := strings.Split(dir, "/")
	for i := 1; i <= len(parts); i++ {
		p := strings.Join(parts[:i], "/")
		info, err := root.Lstat(p)
		switch {
		case err == nil && info.IsDir() && info.Mode()&fs.ModeSymlink == 0:
			continue
		case err == nil:
			return fmt.Errorf("%w: %s is not a plain directory", ErrConflict, p)
		case !errors.Is(err, fs.ErrNotExist):
			return err
		}
		if err := root.Mkdir(p, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		if err := syncRootDir(root, path.Dir(p)); err != nil {
			return err
		}
	}
	return nil
}

// syncRootDir makes a directory's entries durable where the platform needs
// it (Windows renames are written through).
func syncRootDir(root *os.Root, dir string) error {
	if !hasModeBits {
		return nil
	}
	f, err := root.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}

// journalFile is an open journal being appended to.
type journalFile struct {
	f    *os.File
	seq  int
	done map[string]string
}

// openJournal opens a journal for appending, first repairing a tail torn by
// a crash: an incomplete last line is cut off, a complete last entry gets
// its newline. The repair is synced before anything is appended.
func openJournal(p string) (*journalFile, error) {
	data, err := os.ReadFile(p) //nolint:gosec // the operator's journal path
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // the operator's journal path
	if err != nil {
		return nil, err
	}
	if n := len(data); n > 0 && data[n-1] != '\n' {
		cut := bytes.LastIndexByte(data, '\n') + 1
		var e JournalEntry
		if json.Unmarshal(data[cut:], &e) == nil {
			_, err = f.WriteAt([]byte("\n"), int64(n))
			data = append(data, '\n')
		} else {
			err = f.Truncate(int64(cut))
			data = data[:cut]
		}
		if err == nil {
			err = f.Sync()
		}
		if err != nil {
			_ = f.Close()
			return nil, err
		}
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return nil, err
	}
	j := &journalFile{f: f, done: map[string]string{}}
	for n, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e JournalEntry
		if err := json.Unmarshal(line, &e); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("continuity: journal %s line %d: %w", p, n+1, err)
		}
		j.seq = max(j.seq, e.Seq)
		if e.Outcome == OutcomeDone {
			j.done[e.Path] = e.After
		}
	}
	return j, nil
}

func (j *journalFile) append(e JournalEntry) error {
	j.seq++
	e.Seq = j.seq
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := j.f.Write(append(b, '\n')); err != nil {
		return err
	}
	if err := j.f.Sync(); err != nil {
		return err
	}
	if e.Outcome == OutcomeDone {
		j.done[e.Path] = e.After
	}
	return nil
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
// inventory taken before it, with the strict freeze comparison, and
// validates the result. Only the
// records the plan rewrote, and the journal records as done, may differ,
// and each must now hold exactly what the plan computed. Everything else
// must be as it was; nothing may be missing or added.
func VerifyTransition(before, after *Inventory, plan *Plan, journal []JournalEntry, pol Policy) *Report {
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
	hub := ""
	for _, r := range after.Roots {
		if r.Area == AreaHubData {
			hub = r.Label
		}
	}
	laterFiles := map[string]File{}
	for _, f := range after.Files {
		if f.Root == hub {
			laterFiles[f.Path] = f
		}
	}
	for _, s := range plan.Steps {
		e, ok := done[s.Path]
		if !ok || e.After != s.After {
			add("step_not_applied", s.Path, "the plan's step is not journaled done")
			continue
		}
		// Every step's result must be the exact bytes the plan computed.
		if s.Store == "" {
			if f, ok := laterFiles[s.Path]; ok && (f.SHA256 != s.After || f.Link != s.Link) {
				add("step_result_differs", s.Path, "the file is not the one the plan copied")
			}
			continue
		}
		key := s.Store + "/" + s.ID
		if r := later[key]; r != nil && r.Raw != s.After {
			add("step_result_differs", key, "the record's bytes are "+r.Raw+", not the "+s.After+" the plan computed")
		}
		if s.Before != s.After {
			reconciled[key] = true
		}
	}
	rep := Compare(before, after, CompareOptions{Reconciled: reconciled})
	rep.Issues = append(rep.Issues, issues...)
	// The result must hold together on its own, too.
	rep.Issues = append(rep.Issues, Blocking(Validate(after, pol))...)
	sortIssues(rep.Issues)
	return rep
}

func interrupt(opts ApplyOptions, step int, point string) error {
	if opts.Interrupt == nil {
		return nil
	}
	return opts.Interrupt(step, point)
}
