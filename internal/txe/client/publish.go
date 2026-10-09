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
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	manifest := &ArtifactManifest{JobVersion: in.JobVersion, Actor: p.Actor}
	var missing []string
	for _, d := range version.ExpectedOutcome.Deliverables {
		record := ArtifactRecord{Deliverable: d.Name, Path: d.Path}
		sum, size, err := hashDeliverable(runDir, d.Path)
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
			if err := copyDeliverable(runDir, d.Path, in.ArtifactDir, sum); err != nil {
				return nil, fmt.Errorf("deliverable %s: %w", d.Name, err)
			}
			record.Location = DeliveryHub
		}
		manifest.Artifacts = append(manifest.Artifacts, record)
	}

	path := fmt.Sprintf("/txe/jobs/%s/runs/%s/artifacts", url.PathEscape(in.JobID), url.PathEscape(in.RunID))
	if err := p.Client.Do(ctx, http.MethodPost, path, nil, manifest, nil); err != nil {
		return manifest, fmt.Errorf("record the run's artifacts: %w", err)
	}
	if len(missing) > 0 {
		return manifest, fmt.Errorf("%w: %s (expected under %s)", ErrDeliverableMissing, strings.Join(missing, ", "), runDir)
	}
	return manifest, nil
}

// openDeliverable opens a declared file inside the run directory. The path is
// resolved through a root handle, and no component of it may be a symbolic
// link, so a run cannot name a file outside its own directory by any route.
func openDeliverable(runDir, rel string) (*os.File, error) {
	if err := CheckDeliverablePath(rel); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(runDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()

	parts := strings.Split(rel, "/")
	for i := range parts {
		info, err := root.Lstat(filepath.Join(parts[:i+1]...))
		if err != nil {
			return nil, err
		}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			return nil, fmt.Errorf("%s is a symbolic link; a deliverable must be a regular file in the run's output directory", filepath.Join(parts[:i+1]...))
		case i < len(parts)-1 && !info.IsDir():
			return nil, fmt.Errorf("%s is not a directory", filepath.Join(parts[:i+1]...))
		case i == len(parts)-1 && !info.Mode().IsRegular():
			return nil, fmt.Errorf("%s is not a regular file", rel)
		}
	}
	return root.Open(filepath.FromSlash(rel))
}

func hashDeliverable(runDir, rel string) (string, int64, error) {
	f, err := openDeliverable(runDir, rel)
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
// under the same relative path, and checks that what was written has the
// digest that is about to be recorded.
func copyDeliverable(runDir, rel, artifactDir, wantSHA256 string) error {
	src, err := openDeliverable(runDir, rel)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()

	dst := filepath.Join(artifactDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".txe-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
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
	return os.Rename(tmp.Name(), dst)
}
