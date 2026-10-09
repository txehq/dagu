// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

// ErrDeliverableMissing reports that a run did not produce a deliverable its
// job requires. The manifest is still recorded, with the file marked missing.
var ErrDeliverableMissing = errors.New("a required deliverable was not produced")

// Publisher records what a run produced. It reads only the files the job's
// version declares, by exact name, from the sealed output directory of the
// execution that produced them, and only while each still has the digest its
// seal recorded. A file declared for the hub is also copied into the run's
// native artifact directory, under the publishing execution's own directory,
// which the worker uploads; every file stays on the machine as well. Nothing
// else is read or copied.
type Publisher struct {
	Client *Client
	Home   txepkg.Home
	Actor  Actor
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// PublishInput identifies the run being published.
type PublishInput struct {
	JobID      string
	JobVersion int
	RunID      string
	// Execution is the execution the publish step is running in: the Dagu
	// attempt and its queue marker. The registry accepts a manifest only
	// from the run's latest execution, so a publication that arrives late
	// from an earlier one is refused.
	Execution Execution
	// ArtifactDir is the run's native artifact directory. It is required
	// only when a deliverable is declared for the hub.
	ArtifactDir string
}

var runIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// Publish records the run's deliverables with the registry and returns the
// manifest it sent. It returns ErrDeliverableMissing, after recording, when a
// required file is absent.
//
// The files are those of a sealed execution: the publishing one when it ran
// the job itself, and never another's then; otherwise the latest that was
// sealed. The second case is a retry that ran only the publish step: the job
// did not execute again, and the manifest says which execution produced the
// bytes. A deliverable whose bytes are not the ones its seal recorded is not
// published.
//
// The manifest is sent before any file is copied for upload. If the registry
// refuses it, as it does for an execution that is no longer the run's latest
// or for other bytes under an execution already recorded, nothing in the
// artifact directory has changed.
func (p *Publisher) Publish(ctx context.Context, in PublishInput) (*ArtifactManifest, error) {
	if err := checkRun(in.JobID, in.RunID, in.Execution); err != nil {
		return nil, err
	}
	machine, err := p.Home.Machine()
	if err != nil {
		return nil, err
	}
	version, err := p.Client.JobVersion(ctx, in.JobID, in.JobVersion)
	if err != nil {
		return nil, fmt.Errorf("read version %d of %s: %w", in.JobVersion, in.JobID, err)
	}

	runRoot, err := openRunDir(p.Home, in.JobID, in.RunID)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("run %s: %w", in.RunID, ErrNotSealed)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = runRoot.Close() }()
	sealed, err := readSeals(runRoot, in.JobID, in.RunID)
	if err != nil {
		return nil, err
	}
	// An execution that sealed its own outputs publishes those. One that
	// ran the job and did not seal has no result, whatever others sealed.
	// Only one that did not run the job takes the run's latest result.
	seal := sealed.of(in.Execution)
	switch {
	case seal != nil:
	case sealed.began(in.Execution):
		return nil, fmt.Errorf("run %s: execution %s ran the job and did not seal its outputs: %w", in.RunID, in.Execution.Ref(), ErrNotSealed)
	default:
		seal = sealed.latest()
	}
	if seal == nil {
		return nil, fmt.Errorf("run %s: %w", in.RunID, ErrNotSealed)
	}
	runDir := txepkg.ExecutionOutputDir(p.Home.OutputDir(in.JobID), in.RunID, seal.Ref)
	run, err := openPath(runRoot, executionsDir+"/"+seal.Ref)
	if err != nil {
		return nil, fmt.Errorf("the sealed outputs of execution %s: %w", seal.Ref, err)
	}
	defer func() { _ = run.Close() }()

	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	manifest := &ArtifactManifest{JobVersion: in.JobVersion, Execution: in.Execution, ProducedIn: seal.Execution, Actor: p.Actor}
	var missing []string
	type upload struct{ path, sha256 string }
	var uploads []upload
	for _, d := range version.ExpectedOutcome.Deliverables {
		record := ArtifactRecord{Deliverable: d.Name, Path: d.Path}
		if err := CheckDeliverablePath(d.Path); err != nil {
			return nil, fmt.Errorf("deliverable %s: %w", d.Name, err)
		}
		// What the execution did not seal, it did not produce: a file put
		// there afterwards is not part of its result.
		was, ok := seal.file(d.Path)
		if !ok {
			record.Missing = true
			if d.Required {
				missing = append(missing, d.Path)
			}
			manifest.Artifacts = append(manifest.Artifacts, record)
			continue
		}
		sum, size, err := hashDeliverable(run, d.Path)
		if err != nil {
			return nil, fmt.Errorf("deliverable %s: %w", d.Name, err)
		}
		if "sha256:"+sum != was.SHA256 || size != was.Bytes {
			return nil, fmt.Errorf("deliverable %s (%s) of execution %s: %w", d.Name, d.Path, seal.Ref, ErrChangedAfterSeal)
		}
		record.SHA256, record.Bytes = "sha256:"+sum, size
		record.Location, record.MachineID = DeliveryMachine, machine.MachineID
		record.RecordedAt = now().UTC().Format(time.RFC3339)
		if d.Delivery == DeliveryHub {
			if in.ArtifactDir == "" {
				return nil, fmt.Errorf("deliverable %s is declared for the hub, but this run has no artifact directory", d.Name)
			}
			record.Location = DeliveryHub
			uploads = append(uploads, upload{d.Path, sum})
		}
		manifest.Artifacts = append(manifest.Artifacts, record)
	}

	path := fmt.Sprintf("/txe/jobs/%s/runs/%s/artifacts", url.PathEscape(in.JobID), url.PathEscape(in.RunID))
	if err := p.Client.Do(ctx, http.MethodPost, path, nil, manifest, nil); err != nil {
		return manifest, fmt.Errorf("record the run's artifacts: %w", err)
	}

	if len(uploads) > 0 {
		artifacts, err := openHubExecutionDir(in.ArtifactDir, in.Execution)
		if err != nil {
			return manifest, err
		}
		defer func() { _ = artifacts.Close() }()
		for _, u := range uploads {
			if err := copyDeliverable(run, artifacts, u.path, u.sha256); err != nil {
				return manifest, fmt.Errorf("deliverable %s was recorded but could not be placed for upload: %w", u.path, err)
			}
		}
	}
	if len(missing) > 0 {
		return manifest, fmt.Errorf("%w: %s (expected under %s)", ErrDeliverableMissing, strings.Join(missing, ", "), runDir)
	}
	return manifest, nil
}

// openRunDir opens a run's own output directory, one real directory at a time
// from the TXE home: "outputs", the job, "runs", the run. A symbolic link at
// any of them is refused, so a run cannot stand another directory in
// for its own. The handle returned pins the directory that was checked for
// the whole publication. A directory that does not exist is reported as
// fs.ErrNotExist.
func openRunDir(home txepkg.Home, jobID, runID string) (*os.Root, error) {
	current, err := os.OpenRoot(home.Root)
	if err != nil {
		return nil, fmt.Errorf("open the TXE home: %w", err)
	}
	for _, part := range []string{"outputs", jobID, "runs", runID} {
		next, err := openDir(current, part)
		_ = current.Close()
		if err != nil {
			return nil, fmt.Errorf("the run's output directory: %w", err)
		}
		current = next
	}
	return current, nil
}

// openArtifactDir opens the run's native artifact directory, creating it if
// the run has not used it yet. Dagu names it; its last component must be a
// real directory, so a run cannot point its uploads somewhere else by
// replacing the directory with a link.
func openArtifactDir(dir string) (*os.Root, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("create the run's artifact directory: %w", err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("open the run's artifact directory: %w", err)
	}
	named, err := os.Lstat(dir)
	if err == nil {
		err = sameDir(named, root, dir)
	}
	if err != nil {
		_ = root.Close()
		return nil, fmt.Errorf("the run's artifact directory: %w", err)
	}
	return root, nil
}

// openHubExecutionDir opens the publishing execution's directory inside the
// run's native artifact directory, creating it. The hub may keep several
// executions of a run in one artifact directory and replaces a file that
// arrives at a path it already holds, so each execution's copies go under
// its own reference and an earlier execution's bytes are never replaced.
func openHubExecutionDir(dir string, e Execution) (*os.Root, error) {
	root, err := openArtifactDir(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	attempts, err := makeDir(root, HubAttemptsDir)
	if err != nil {
		return nil, fmt.Errorf("the run's artifact directory: %w", err)
	}
	defer func() { _ = attempts.Close() }()
	execution, err := makeDir(attempts, e.Ref())
	if err != nil {
		return nil, fmt.Errorf("the run's artifact directory: %w", err)
	}
	return execution, nil
}

// openDir opens the directory called name in parent. The name must hold a
// real directory, not a link. The directory is opened first and compared
// afterwards with what the name holds, so the handle returned is the
// directory that was checked, whatever replaces the name later.
func openDir(parent *os.Root, name string) (*os.Root, error) {
	// Asked first so that a link is reported as a link, even a broken one.
	if _, err := lstatDir(parent, name); err != nil {
		return nil, err
	}
	child, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	named, err := lstatDir(parent, name)
	if err == nil {
		err = sameDir(named, child, name)
	}
	if err != nil {
		_ = child.Close()
		return nil, err
	}
	return child, nil
}

// lstatDir describes name in parent without following it, and refuses
// anything but a real directory.
func lstatDir(parent *os.Root, name string) (fs.FileInfo, error) {
	info, err := parent.Lstat(name)
	switch {
	case err != nil:
		return nil, err
	case info.Mode()&fs.ModeSymlink != 0:
		return nil, fmt.Errorf("%s is a symbolic link; it must be a real directory", name)
	case !info.IsDir():
		return nil, fmt.Errorf("%s is not a directory", name)
	}
	return info, nil
}

// sameDir checks that the opened directory is the one the name was seen to
// hold, and that the name held a real directory.
func sameDir(named fs.FileInfo, opened *os.Root, name string) error {
	if named.Mode()&fs.ModeSymlink != 0 || !named.IsDir() {
		return fmt.Errorf("%s is not a real directory", name)
	}
	info, err := opened.Stat(".")
	if err != nil {
		return err
	}
	if !os.SameFile(named, info) {
		return fmt.Errorf("%s was replaced while it was being opened", name)
	}
	return nil
}

// place is the directory that holds a file, opened, and the file's name in it.
type place struct {
	dir  *os.Root
	name string
	// owned says the directory was opened for this place and closes with it.
	owned bool
}

func (p *place) release() {
	if p.owned {
		_ = p.dir.Close()
	}
}

// descend opens the directory that holds the file rel names, beneath root,
// through real directories only. With create, missing directories are made.
// The caller releases the place when it is done with it.
func descend(root *os.Root, rel string, create bool) (*place, error) {
	parts := strings.Split(rel, "/")
	at := &place{dir: root, name: parts[len(parts)-1]}
	for _, part := range parts[:len(parts)-1] {
		if create {
			if err := at.dir.Mkdir(part, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
				at.release()
				return nil, err
			}
		}
		next, err := openDir(at.dir, part)
		at.release()
		if err != nil {
			return nil, err
		}
		at.dir, at.owned = next, true
	}
	return at, nil
}

// openRegular opens the regular file called name in dir. As with a
// directory, it is opened first and then compared with what the name holds,
// so a link put there in between is not read through.
func openRegular(dir *os.Root, name, shown string) (*os.File, error) {
	check := func() (fs.FileInfo, error) {
		info, err := dir.Lstat(name)
		switch {
		case err != nil:
			return nil, err
		case info.Mode()&fs.ModeSymlink != 0:
			return nil, fmt.Errorf("%s is a symbolic link; a deliverable must be a regular file in the run's output directory", shown)
		case !info.Mode().IsRegular():
			return nil, fmt.Errorf("%s is not a regular file", shown)
		}
		return info, nil
	}
	if _, err := check(); err != nil {
		return nil, err
	}
	f, err := dir.Open(name)
	if err != nil {
		return nil, err
	}
	named, err := check()
	if err == nil {
		var opened fs.FileInfo
		if opened, err = f.Stat(); err == nil && !os.SameFile(named, opened) {
			err = fmt.Errorf("%s was replaced while it was being opened", shown)
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// openDeliverable opens a declared file inside the run directory. A run with
// no output directory has produced none.
func openDeliverable(run *os.Root, rel string) (*os.File, error) {
	if err := CheckDeliverablePath(rel); err != nil {
		return nil, err
	}
	if run == nil {
		return nil, fs.ErrNotExist
	}
	at, err := descend(run, rel, false)
	if err != nil {
		return nil, err
	}
	defer at.release()
	return openRegular(at.dir, at.name, rel)
}

func hashDeliverable(run *os.Root, rel string) (string, int64, error) {
	f, err := openDeliverable(run, rel)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	return hashFile(f)
}

func hashFile(f io.Reader) (string, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// partialPrefix starts the name of a file that is still being copied into
// the artifact directory. No deliverable can have such a name: a deliverable's
// names never start with a dot.
const partialPrefix = ".txe-partial-"

// copyDeliverable copies one declared file into the run's artifact directory
// under the same relative path. Both ends go through directory handles and
// refuse links. The bytes written must have the digest that was recorded.
//
// The copy is written under a name of its own, made for this call, and then
// given the deliverable's name by a link, which fails if the name is taken.
// So a file already there is never replaced, by this call or by another
// publishing at the same time, and no other file is ever removed.
func copyDeliverable(run, artifacts *os.Root, rel, wantSHA256 string) error {
	src, err := openDeliverable(run, rel)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()

	at, err := descend(artifacts, rel, true)
	if err != nil {
		return fmt.Errorf("the artifact directory: %w", err)
	}
	defer at.release()
	dir, name := at.dir, at.name

	// same reports whether the name already holds the recorded bytes.
	same := func() (bool, error) {
		existing, err := openRegular(dir, name, rel)
		if err != nil {
			return false, err
		}
		defer func() { _ = existing.Close() }()
		sum, _, err := hashFile(existing)
		if err != nil {
			return false, err
		}
		if sum != wantSHA256 {
			return false, fmt.Errorf("%s is already in the artifact directory with different bytes; it is not replaced", rel)
		}
		return true, nil
	}
	if ok, err := same(); ok || !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	partial := partialPrefix + hex.EncodeToString(suffix)
	tmp, err := dir.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	// Only the file this call created is removed.
	defer func() { _ = dir.Remove(partial) }()
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(tmp, h), src)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA256 {
		return fmt.Errorf("%s changed while it was being published", rel)
	}
	if err := dir.Link(partial, name); err != nil {
		if !errors.Is(err, fs.ErrExist) {
			return err
		}
		// Another publication of this run placed the file first.
		_, err := same()
		return err
	}
	return nil
}
