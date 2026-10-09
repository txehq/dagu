// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

// ErrDeliverableMissing reports that a run did not produce a deliverable its
// job requires. The manifest is still recorded, with the file marked missing.
var ErrDeliverableMissing = errors.New("a required deliverable was not produced")

// Publisher records what a run produced. It reads only the files the job's
// current version declares, by exact name, from the run's own output
// directory. A file declared for the hub is also copied into the run's native
// artifact directory, which the worker uploads; every file stays on the
// machine as well. Nothing else is read or copied.
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
	// ArtifactDir is the run's native artifact directory. It is required
	// only when a deliverable is declared for the hub.
	ArtifactDir string
}

var runIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// Publish records the run's deliverables with the registry and returns the
// manifest it sent. It returns ErrDeliverableMissing, after recording, when a
// required file is absent.
//
// The manifest is sent before any file is copied for upload. If the registry
// refuses it, as it does when a retried run produced different bytes under a
// name already recorded, nothing in the artifact directory has changed.
func (p *Publisher) Publish(ctx context.Context, in PublishInput) (*ArtifactManifest, error) {
	if !runIDPattern.MatchString(in.JobID) || !runIDPattern.MatchString(in.RunID) {
		return nil, fmt.Errorf("invalid job id %q or run id %q", in.JobID, in.RunID)
	}
	machine, err := p.Home.Machine()
	if err != nil {
		return nil, err
	}
	version, err := p.Client.JobVersion(ctx, in.JobID, in.JobVersion)
	if err != nil {
		return nil, fmt.Errorf("read version %d of %s: %w", in.JobVersion, in.JobID, err)
	}

	runDir := filepath.Join(p.Home.OutputDir(in.JobID), "runs", in.RunID)
	run, err := openRunDir(p.Home, in.JobID, in.RunID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = run.Close() }()

	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	manifest := &ArtifactManifest{JobVersion: in.JobVersion, Actor: p.Actor}
	var missing []string
	type upload struct{ path, sha256 string }
	var uploads []upload
	for _, d := range version.ExpectedOutcome.Deliverables {
		record := ArtifactRecord{Deliverable: d.Name, Path: d.Path}
		sum, size, err := hashDeliverable(run, d.Path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			record.Missing = true
			if d.Required {
				missing = append(missing, d.Path)
			}
			manifest.Artifacts = append(manifest.Artifacts, record)
			continue
		case err != nil:
			return nil, fmt.Errorf("deliverable %s: %w", d.Name, err)
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
		// The directory is named by Dagu for this run; it may not exist yet.
		if err := os.MkdirAll(in.ArtifactDir, 0o750); err != nil {
			return manifest, fmt.Errorf("create the run's artifact directory: %w", err)
		}
		artifacts, err := os.OpenRoot(in.ArtifactDir)
		if err != nil {
			return manifest, fmt.Errorf("open the run's artifact directory: %w", err)
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

// openRunDir opens a run's own output directory. It starts from the TXE
// home's outputs directory and refuses a symbolic link at the job, at "runs"
// and at the run, so a run cannot stand another directory in for its own. The
// handle it returns pins that directory for the whole publication.
func openRunDir(home txepkg.Home, jobID, runID string) (*os.Root, error) {
	outputs, err := os.OpenRoot(filepath.Join(home.Root, "outputs"))
	if err != nil {
		return nil, fmt.Errorf("open the outputs directory: %w", err)
	}
	defer func() { _ = outputs.Close() }()
	rel := ""
	for _, part := range []string{jobID, "runs", runID} {
		rel = filepath.Join(rel, part)
		if err := requireDir(outputs, rel); err != nil {
			return nil, fmt.Errorf("the run's output directory: %w", err)
		}
	}
	return outputs.OpenRoot(rel)
}

// requireDir checks that rel, beneath root, is a real directory.
func requireDir(root *os.Root, rel string) error {
	info, err := root.Lstat(rel)
	switch {
	case err != nil:
		return err
	case info.Mode()&fs.ModeSymlink != 0:
		return fmt.Errorf("%s is a symbolic link; it must be a real directory", rel)
	case !info.IsDir():
		return fmt.Errorf("%s is not a directory", rel)
	}
	return nil
}

// openDeliverable opens a declared file inside the run directory. No
// component of its path may be a symbolic link, and the root handle keeps the
// open inside the run directory whatever happens to the path meanwhile.
func openDeliverable(run *os.Root, rel string) (*os.File, error) {
	if err := CheckDeliverablePath(rel); err != nil {
		return nil, err
	}
	parts := strings.Split(rel, "/")
	for i := range parts[:len(parts)-1] {
		if err := requireDir(run, filepath.Join(parts[:i+1]...)); err != nil {
			return nil, err
		}
	}
	name := filepath.FromSlash(rel)
	info, err := run.Lstat(name)
	switch {
	case err != nil:
		return nil, err
	case info.Mode()&fs.ModeSymlink != 0:
		return nil, fmt.Errorf("%s is a symbolic link; a deliverable must be a regular file in the run's output directory", rel)
	case !info.Mode().IsRegular():
		return nil, fmt.Errorf("%s is not a regular file", rel)
	}
	return run.Open(name)
}

func hashDeliverable(run *os.Root, rel string) (string, int64, error) {
	f, err := openDeliverable(run, rel)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// copyDeliverable copies one declared file into the run's artifact directory
// under the same relative path. Both ends go through root handles and refuse
// link components. The bytes written must have the digest that was recorded,
// and a file already there is never replaced by different bytes.
func copyDeliverable(run, artifacts *os.Root, rel, wantSHA256 string) error {
	src, err := openDeliverable(run, rel)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()

	name := filepath.FromSlash(rel)
	if parent := filepath.Dir(name); parent != "." {
		if err := artifacts.MkdirAll(parent, 0o750); err != nil {
			return err
		}
		parts := strings.Split(filepath.ToSlash(parent), "/")
		for i := range parts {
			if err := requireDir(artifacts, filepath.Join(parts[:i+1]...)); err != nil {
				return fmt.Errorf("the artifact directory: %w", err)
			}
		}
	}

	if existing, err := artifacts.Open(name); err == nil {
		h := sha256.New()
		_, copyErr := io.Copy(h, existing)
		_ = existing.Close()
		if copyErr != nil {
			return copyErr
		}
		if hex.EncodeToString(h.Sum(nil)) == wantSHA256 {
			return nil
		}
		return fmt.Errorf("%s is already in the artifact directory with different bytes; it is not replaced", rel)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	partial := name + ".txe-partial"
	_ = artifacts.Remove(partial)
	tmp, err := artifacts.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	defer func() { _ = artifacts.Remove(partial) }()
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
	return artifacts.Rename(partial, name)
}
