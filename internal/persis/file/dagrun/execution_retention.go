// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/fileutil"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
)

// Retained executions live beside the attempt's status file:
//
//	<attempt dir>/executions/<execution ref>/{manifest.json,status.json,logs/<name>}
//
// A copy is written to a temporary directory and renamed into place, so a
// reader never sees a partial one, and it is never written again.
const (
	retainedExecutionsDir = "executions"
	retainedManifestFile  = "manifest.json"
	retainedStatusFile    = "status.json"
	retainedLogsDir       = "logs"
	retainedSchema        = 1
	// hubAttemptsDir is where a run's published copies sit in its native
	// artifact directory, one prefix per execution (see the TXE registry).
	hubAttemptsDir = "txe-attempts"
	// logsNotFinal says why logs are not claimed final.
	logsNotFinal = "not every log stream of this execution was proven finished (no matching .final record); a log may be partial"
	// finalSuffix names the coordinator's stream finalization record.
	finalSuffix = ".final"
)

var (
	// ErrRetainedExecutionConflict is a retained copy of the execution that
	// differs from the execution now, or is incomplete: it is never replaced.
	ErrRetainedExecutionConflict = errors.New("a different or incomplete copy of this execution is already retained")

	retainedName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,254}$`)
)

// WithLogDir sets the configured log directory: the only place logs are
// copied from when an execution is retained.
func WithLogDir(dir string) StoreOption {
	return func(o *options) {
		o.logDir = dir
	}
}

var _ persis.ExecutionRetainingStore = (*Store)(nil)

// retainExecution copies the finished execution held by att, before a swap
// replaces it. It runs under the run's lock.
func (store *Store) retainExecution(root ir.DAGRunRef, att *Attempt, status *ir.DAGRunStatus) error {
	if status.AttemptID == "" {
		return fmt.Errorf("retain execution: status has no attempt id")
	}
	ref := ir.ExecutionRef(status.AttemptID, status.QueuedAt)
	base := filepath.Join(filepath.Dir(att.file), retainedExecutionsDir)
	dest := filepath.Join(base, ref)

	statusData, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("retain execution: encode status: %w", err)
	}
	logs := store.executionLogs(root, status)
	artifacts := store.executionArtifacts(ref, status)

	if _, err := os.Lstat(dest); err == nil {
		return store.sameRetained(dest, statusData, logs)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("retain execution: %w", err)
	}

	if err := os.MkdirAll(base, 0o750); err != nil {
		return fmt.Errorf("retain execution: %w", err)
	}
	tmp, err := os.MkdirTemp(base, ".tmp-"+ref+"-")
	if err != nil {
		return fmt.Errorf("retain execution: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(tmp)
		}
	}()

	m := persis.RetainedExecution{
		Schema: retainedSchema, Execution: ref, AttemptID: status.AttemptID, QueuedAt: status.QueuedAt,
		Status: status.Status.String(), StatusComplete: !status.Status.IsActive() && status.Status != ir.NotStarted,
		RetainedAt:   time.Now().UTC(),
		StatusSHA256: digest(statusData), ArtifactFiles: artifacts,
	}
	if err := os.WriteFile(filepath.Join(tmp, retainedStatusFile), statusData, 0o600); err != nil {
		return fmt.Errorf("retain execution: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, retainedLogsDir), 0o750); err != nil {
		return fmt.Errorf("retain execution: %w", err)
	}
	for _, l := range logs {
		f, err := copyRegular(l.src, filepath.Join(tmp, retainedLogsDir, l.name))
		if err != nil {
			return fmt.Errorf("retain execution: copy log %s: %w", l.name, err)
		}
		f.Name = l.name
		f.Final = streamFinal(l.src, status, f.Bytes)
		m.Files = append(m.Files, f)
	}
	m.LogsFinal = len(m.Files) > 0
	for _, f := range m.Files {
		m.LogsFinal = m.LogsFinal && f.Final
	}
	if !m.LogsFinal {
		m.LogsNote = logsNotFinal
	}
	manifest, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		return fmt.Errorf("retain execution: %w", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, retainedManifestFile), manifest, 0o600); err != nil {
		return fmt.Errorf("retain execution: %w", err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		return fmt.Errorf("retain execution: %w", err)
	}
	committed = true
	return nil
}

// sameRetained accepts an existing copy only when it is complete and holds
// the same status and log bytes; anything else fails visibly.
func (store *Store) sameRetained(dest string, statusData []byte, logs []executionLog) error {
	data, err := os.ReadFile(filepath.Join(dest, retainedManifestFile)) //nolint:gosec // dest is the store's own copy directory; the file name is fixed
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrRetainedExecutionConflict, filepath.Base(dest), err)
	}
	var m persis.RetainedExecution
	if err := json.Unmarshal(data, &m); err != nil || m.Schema != retainedSchema {
		return fmt.Errorf("%w: %s: unreadable manifest", ErrRetainedExecutionConflict, filepath.Base(dest))
	}
	saved, err := os.ReadFile(filepath.Join(dest, retainedStatusFile)) //nolint:gosec // dest is the store's own copy directory; the file name is fixed
	if err != nil || digest(saved) != m.StatusSHA256 || m.StatusSHA256 != digest(statusData) {
		return fmt.Errorf("%w: %s: status differs", ErrRetainedExecutionConflict, m.Execution)
	}
	want := map[string]string{}
	for _, l := range logs {
		sum, _, err := fileDigest(l.src)
		if err != nil {
			return fmt.Errorf("retain execution: %w", err)
		}
		want[l.name] = sum
	}
	if len(want) != len(m.Files) {
		return fmt.Errorf("%w: %s: logs differ", ErrRetainedExecutionConflict, m.Execution)
	}
	for _, f := range m.Files {
		got, _, err := fileDigest(filepath.Join(dest, retainedLogsDir, f.Name))
		if err != nil || got != f.SHA256 || want[f.Name] != f.SHA256 {
			return fmt.Errorf("%w: %s: log %s differs", ErrRetainedExecutionConflict, m.Execution, f.Name)
		}
	}
	return nil
}

type executionLog struct {
	name string
	src  string
}

// executionLogs lists the execution's log files under the configured log
// directory only: the attempt's directory there (where the coordinator
// writes a worker's streams) and the status's own log paths when they lie
// inside it. Symbolic links are never followed.
func (store *Store) executionLogs(root ir.DAGRunRef, status *ir.DAGRunStatus) []executionLog {
	if store.logDir == "" {
		return nil
	}
	logRoot := filepath.Clean(store.logDir)
	seen := map[string]bool{}
	var out []executionLog
	add := func(src, name string) {
		if seen[src] {
			return
		}
		if !insideNoLinks(logRoot, src) {
			return
		}
		info, err := os.Lstat(src)
		if err != nil || !info.Mode().IsRegular() || strings.HasSuffix(src, finalSuffix) {
			return
		}
		name = retainedFileName(name)
		for i := 1; nameTaken(out, name); i++ {
			name = fmt.Sprintf("%d-%s", i, retainedFileName(filepath.Base(src)))
		}
		seen[src] = true
		out = append(out, executionLog{name: name, src: src})
	}
	rootName, rootID := root.Name, root.ID
	if rootName == "" {
		rootName, rootID = status.Name, status.DAGRunID
	}
	attemptDir := filepath.Join(logRoot, fileutil.SafeName(rootName), fileutil.SafeName(rootID), fileutil.SafeName(status.AttemptID))
	if entries, err := os.ReadDir(attemptDir); err == nil {
		for _, e := range entries {
			if e.Type().IsRegular() {
				add(filepath.Join(attemptDir, e.Name()), e.Name())
			}
		}
	}
	paths := []string{status.Log}
	for _, n := range status.Nodes {
		if n != nil {
			paths = append(paths, n.Stdout, n.Stderr)
		}
	}
	for _, p := range paths {
		if p != "" {
			add(filepath.Clean(p), filepath.Base(p))
		}
	}
	sort.Slice(out, func(i, k int) bool { return out[i].name < out[k].name })
	return out
}

// executionArtifacts lists the files the execution published under its own
// prefix in the run's native artifact directory, by digest. They are
// written once per execution, so a reference is enough; nothing is copied.
func (store *Store) executionArtifacts(ref string, status *ir.DAGRunStatus) []persis.RetainedFile {
	if status.ArchiveDir == "" || store.artifactDir == "" {
		return nil
	}
	dir := filepath.Join(filepath.Clean(status.ArchiveDir), hubAttemptsDir, ref)
	if !insideNoLinks(filepath.Clean(store.artifactDir), dir) {
		return nil
	}
	var out []persis.RetainedFile
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() {
			return nil
		}
		sum, n, err := fileDigest(p)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, p)
		out = append(out, persis.RetainedFile{Name: filepath.ToSlash(rel), Bytes: n, SHA256: sum})
		return nil
	})
	return out
}

// ListRetainedExecutions lists the retained executions of a run, oldest
// first.
func (store *Store) ListRetainedExecutions(ctx context.Context, root, dagRun ir.DAGRunRef) ([]persis.RetainedExecution, error) {
	run, err := store.findRun(ctx, root, dagRun)
	if err != nil {
		return nil, err
	}
	dirs, err := run.listAttemptDirs()
	if err != nil {
		return nil, err
	}
	var out []persis.RetainedExecution
	for _, d := range dirs {
		base := filepath.Join(run.baseDir, d, retainedExecutionsDir)
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(base, e.Name(), retainedManifestFile)) //nolint:gosec // a directory entry of the run's own executions directory; the file name is fixed
			if err != nil {
				continue
			}
			var m persis.RetainedExecution
			if json.Unmarshal(data, &m) == nil && m.Execution == e.Name() {
				out = append(out, m)
			}
		}
	}
	sort.SliceStable(out, func(i, k int) bool { return out[i].RetainedAt.Before(out[k].RetainedAt) })
	return out, nil
}

// ReadRetainedExecutionFile reads status.json or one listed log of a
// retained execution. Names are checked against the execution's manifest,
// so no path outside the copy is ever read.
func (store *Store) ReadRetainedExecutionFile(ctx context.Context, root, dagRun ir.DAGRunRef, executionRef, name string) ([]byte, error) {
	if !retainedName.MatchString(executionRef) || !retainedName.MatchString(name) {
		return nil, persis.ErrNotFound
	}
	all, err := store.ListRetainedExecutions(ctx, root, dagRun)
	if err != nil {
		return nil, err
	}
	run, err := store.findRun(ctx, root, dagRun)
	if err != nil {
		return nil, err
	}
	dirs, err := run.listAttemptDirs()
	if err != nil {
		return nil, err
	}
	for _, m := range all {
		if m.Execution != executionRef {
			continue
		}
		rel := ""
		if name == retainedStatusFile {
			rel = retainedStatusFile
		}
		for _, f := range m.Files {
			if f.Name == name {
				rel = filepath.Join(retainedLogsDir, f.Name)
			}
		}
		if rel == "" {
			return nil, persis.ErrNotFound
		}
		for _, d := range dirs {
			p := filepath.Join(run.baseDir, d, retainedExecutionsDir, executionRef, rel)
			if info, err := os.Lstat(p); err == nil && info.Mode().IsRegular() {
				return os.ReadFile(p) //nolint:gosec // name checked against the manifest; path built from fixed parts
			}
		}
	}
	return nil, persis.ErrNotFound
}

func (store *Store) findRun(ctx context.Context, root, dagRun ir.DAGRunRef) (*DAGRun, error) {
	dr := store.dataRoot(root.Name)
	run, err := dr.FindByDAGRunID(ctx, root.ID)
	if err != nil {
		return nil, err
	}
	if root.ID != dagRun.ID || root.Name != dagRun.Name {
		return run.FindSubDAGRun(ctx, dagRun.ID)
	}
	return run, nil
}

// insideNoLinks reports whether p lies inside base without passing through
// a symbolic link anywhere below base.
func insideNoLinks(base, p string) bool {
	rel, err := filepath.Rel(base, p)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return false
	}
	cur := base
	for part := range strings.SplitSeq(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
	}
	return true
}

// streamFinal reports whether the coordinator recorded the log stream at
// src as finished for this execution with exactly size bytes.
func streamFinal(src string, status *ir.DAGRunStatus, size int64) bool {
	info, err := os.Lstat(src + finalSuffix)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	data, err := os.ReadFile(src + finalSuffix) //nolint:gosec // beside a log already checked to lie inside the configured log directory
	if err != nil {
		return false
	}
	var rec struct {
		ExecutionMarker string `json:"executionMarker"`
		AttemptID       string `json:"attemptId"`
		Size            int64  `json:"size"`
	}
	if json.Unmarshal(data, &rec) != nil {
		return false
	}
	return rec.ExecutionMarker == status.QueuedAt && rec.AttemptID == status.AttemptID && rec.Size == size
}

var unsafeNameChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// retainedFileName keeps a log's own name readable (dots included) while
// making it a single safe path element.
func retainedFileName(name string) string {
	name = unsafeNameChars.ReplaceAllString(name, "_")
	if name == "" || name[0] == '.' || name[0] == '-' {
		name = "_" + name
	}
	if len(name) > 200 {
		name = name[:200]
	}
	return name
}

func nameTaken(logs []executionLog, name string) bool {
	for _, l := range logs {
		if l.name == name {
			return true
		}
	}
	return false
}

func copyRegular(src, dst string) (persis.RetainedFile, error) {
	in, err := os.Open(src) //nolint:gosec // src is a regular file inside the configured log directory
	if err != nil {
		return persis.RetainedFile{}, err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // dst is inside a fresh temporary directory
	if err != nil {
		return persis.RetainedFile{}, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return persis.RetainedFile{}, err
	}
	return persis.RetainedFile{Bytes: n, SHA256: "sha256:" + hex.EncodeToString(h.Sum(nil))}, nil
}

func fileDigest(p string) (string, int64, error) {
	f, err := os.Open(p) //nolint:gosec // callers pass paths they validated
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), n, nil
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
