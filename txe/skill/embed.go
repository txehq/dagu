// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package txeskill carries the coding-agent skill for durable jobs inside the
// binary, so the skill a session reads always matches the CLI it calls.
package txeskill

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

// Name is the skill's directory name in an agent's skills directory.
const Name = "txe-dagu-jobs"

// current is the link, beside the unpacked revisions, to the one in use.
const current = "current"

//go:embed SKILL.md examples
var files embed.FS

// Files returns the skill's files.
func Files() fs.FS { return files }

// Revision identifies the skill's content: the first 12 hex characters of a
// SHA-256 over every file's path and bytes.
func Revision() string {
	revision, err := revisionOf(files)
	if err != nil {
		// The embedded files are always readable.
		panic(err)
	}
	return revision
}

// Unpack writes this revision under dir as <dir>/<revision> and points
// <dir>/current at it. Earlier revisions are kept. It returns the path of the
// current link, which is what agent profiles should link to: an upgrade then
// reaches every profile at once.
func Unpack(dir string) (string, error) {
	revision := Revision()
	target := filepath.Join(dir, revision)
	if _, err := os.Stat(filepath.Join(target, "SKILL.md")); errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o755); err != nil { //nolint:gosec // a skill is not private
			return "", err
		}
		staging, err := os.MkdirTemp(dir, ".unpack-*")
		if err != nil {
			return "", err
		}
		defer func() { _ = os.RemoveAll(staging) }()
		if err := writeFiles(staging); err != nil {
			return "", err
		}
		if err := os.Chmod(staging, 0o755); err != nil { //nolint:gosec // a skill is not private
			return "", err
		}
		// Another session may have unpacked the same revision meanwhile; its
		// copy is identical.
		if err := os.Rename(staging, target); err != nil && !errors.Is(err, fs.ErrExist) {
			if _, statErr := os.Stat(filepath.Join(target, "SKILL.md")); statErr != nil {
				return "", err
			}
		}
	} else if err != nil {
		return "", err
	}

	link := filepath.Join(dir, current)
	if err := replaceLink(revision, link); err != nil {
		return "", err
	}
	return link, nil
}

func writeFiles(root string) error {
	return fs.WalkDir(files, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dst := filepath.Join(root, filepath.FromSlash(path))
		if d.IsDir() {
			return os.MkdirAll(dst, 0o755) //nolint:gosec // a skill is not private
		}
		data, err := files.ReadFile(path)
		if err != nil {
			return err
		}
		// Embedding drops the executable bit; a script keeps it by its first line.
		perm := os.FileMode(0o644)
		if bytes.HasPrefix(data, []byte("#!")) {
			perm = 0o755
		}
		return os.WriteFile(dst, data, perm) //nolint:gosec // a skill is not private
	})
}

// replaceLink points link at target, replacing an earlier link. A file or
// directory that is not a link is left alone and reported.
func replaceLink(target, link string) error {
	info, err := os.Lstat(link)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return err
	case info.Mode()&fs.ModeSymlink == 0:
		return fmt.Errorf("%s exists and is not a link; move it away first", link)
	default:
		if existing, _ := os.Readlink(link); existing == target {
			return nil
		}
	}
	next := link + ".next"
	_ = os.Remove(next)
	if err := os.Symlink(target, next); err != nil {
		return err
	}
	return os.Rename(next, link)
}

// Link makes <skillsDir>/txe-dagu-jobs a link to the unpacked skill, so that
// agent profile reads the revision in use.
func Link(unpacked, skillsDir string) (string, error) {
	if err := os.MkdirAll(skillsDir, 0o755); err != nil { //nolint:gosec // a skills directory is not private
		return "", err
	}
	link := filepath.Join(skillsDir, Name)
	return link, replaceLink(unpacked, link)
}

// State is what one location holds.
type State struct {
	Path string `json:"path"`
	// Revision is the revision found there, or empty when there is none.
	Revision string `json:"revision,omitempty"`
	// Current is whether that revision is the one in this binary.
	Current bool   `json:"current"`
	Problem string `json:"problem,omitempty"`
}

// Inspect reports the revision of the skill found at path, which may be the
// unpacked current link or a profile's link to it.
func Inspect(path string) State {
	state := State{Path: path}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		state.Problem = "not installed"
		return state
	}
	revision, err := revisionOf(os.DirFS(resolved))
	if err != nil {
		state.Problem = err.Error()
		return state
	}
	state.Revision, state.Current = revision, revision == Revision()
	if !state.Current {
		state.Problem = "a different revision from this binary's"
	}
	return state
}

// revisionOf computes the revision of a copy of the skill, embedded or
// unpacked, over the embedded file names in a fixed order.
func revisionOf(dir fs.FS) (string, error) {
	var names []string
	err := fs.WalkDir(files, ".", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			names = append(names, path)
		}
		return err
	})
	if err != nil {
		return "", err
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		data, err := fs.ReadFile(dir, name)
		if err != nil {
			return "", fmt.Errorf("%s is missing or unreadable", name)
		}
		h.Write([]byte(name + "\x00" + strconv.Itoa(len(data)) + "\x00"))
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))[:12], nil
}
