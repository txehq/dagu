// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package dagrun

import (
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

// Every file the retention reads or writes is reached through an os.Root
// opened on a trusted directory (the attempt's directory, the configured log
// directory, the artifact directory), and every element below that root is
// checked not to be a symbolic link. The root confines the operation even if
// an element is replaced between that check and its use, so nothing outside
// these directories is ever read or written.

// retainExecution copies the finished execution held by att, before a swap
// replaces it. It runs under the run's lock.
func (store *Store) retainExecution(root ir.DAGRunRef, att *Attempt, status *ir.DAGRunStatus) error {
	if status.AttemptID == "" {
		return fmt.Errorf("retain execution: status has no attempt id")
	}
	ref := ir.ExecutionRef(status.AttemptID, status.QueuedAt)
	statusData, err := json.Marshal(status)
	if err != nil {
		return fmt.Errorf("retain execution: encode status: %w", err)
	}

	attRoot, err := os.OpenRoot(filepath.Dir(att.file))
	if err != nil {
		return fmt.Errorf("retain execution: %w", err)
	}
	defer func() { _ = attRoot.Close() }()
	execRoot, err := openSubRoot(attRoot, retainedExecutionsDir, true)
	if err != nil {
		return fmt.Errorf("retain execution: %w", err)
	}
	defer func() { _ = execRoot.Close() }()

	if _, err := execRoot.Lstat(ref); err == nil {
		return verifyRetained(execRoot, ref, status)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("retain execution: %w", err)
	}

	logs := store.executionLogs(root, status)
	defer logs.close()
	artifacts := store.executionArtifacts(ref, status)

	tmp := ".tmp-" + ref + "-" + rand.Text()
	if err := execRoot.Mkdir(tmp, 0o750); err != nil {
		return fmt.Errorf("retain execution: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = execRoot.RemoveAll(tmp)
		}
	}()

	m := persis.RetainedExecution{
		Schema: retainedSchema, Execution: ref, AttemptID: status.AttemptID, QueuedAt: status.QueuedAt,
		Status: status.Status.String(), StatusComplete: !status.Status.IsActive() && status.Status != ir.NotStarted,
		RetainedAt:   time.Now().UTC(),
		StatusSHA256: digest(statusData), Files: []persis.RetainedFile{}, ArtifactFiles: artifacts,
	}
	if err := writeNew(execRoot, filepath.Join(tmp, retainedStatusFile), statusData); err != nil {
		return fmt.Errorf("retain execution: %w", err)
	}
	if err := execRoot.Mkdir(filepath.Join(tmp, retainedLogsDir), 0o750); err != nil {
		return fmt.Errorf("retain execution: %w", err)
	}
	copied := map[string]persis.RetainedFile{}
	for _, l := range logs.files {
		f, err := copyPlain(logs.root, l.src, execRoot, filepath.Join(tmp, retainedLogsDir, l.name))
		if err != nil {
			return fmt.Errorf("retain execution: copy log %s: %w", l.name, err)
		}
		f.Name = l.name
		f.Final = streamFinal(logs.root, l.src, status, f)
		m.Files = append(m.Files, f)
		copied[l.src] = f
	}
	m.LogsFinal = logs.final(copied)
	if !m.LogsFinal {
		m.LogsNote = logsNotFinal
	}
	manifest, err := json.MarshalIndent(&m, "", "  ")
	if err != nil {
		return fmt.Errorf("retain execution: %w", err)
	}
	if err := writeNew(execRoot, filepath.Join(tmp, retainedManifestFile), manifest); err != nil {
		return fmt.Errorf("retain execution: %w", err)
	}
	if err := execRoot.Rename(tmp, ref); err != nil {
		return fmt.Errorf("retain execution: %w", err)
	}
	committed = true
	return nil
}

// verifyRetained accepts an existing copy of the execution when it is
// intact: its manifest names this execution and its status and logs still
// have the digests the manifest recorded. The first copy of an execution is
// its evidence and stands; the live files may have changed since (a late
// stream, a rolled-back admission), and that must not block a later retry.
// A copy that is unreadable, of another execution, or altered fails visibly.
func verifyRetained(execRoot *os.Root, ref string, status *ir.DAGRunStatus) error {
	data, err := readPlain(execRoot, filepath.Join(ref, retainedManifestFile))
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrRetainedExecutionConflict, ref, err)
	}
	var m persis.RetainedExecution
	if err := json.Unmarshal(data, &m); err != nil || m.Schema != retainedSchema {
		return fmt.Errorf("%w: %s: unreadable manifest", ErrRetainedExecutionConflict, ref)
	}
	if m.Execution != ref || m.AttemptID != status.AttemptID || m.QueuedAt != status.QueuedAt {
		return fmt.Errorf("%w: %s: the copy is of another execution", ErrRetainedExecutionConflict, ref)
	}
	saved, err := readPlain(execRoot, filepath.Join(ref, retainedStatusFile))
	if err != nil || digest(saved) != m.StatusSHA256 {
		return fmt.Errorf("%w: %s: status altered or missing", ErrRetainedExecutionConflict, ref)
	}
	for _, f := range m.Files {
		if !retainedName.MatchString(f.Name) {
			return fmt.Errorf("%w: %s: bad log name in manifest", ErrRetainedExecutionConflict, ref)
		}
		got, n, err := digestPlain(execRoot, filepath.Join(ref, retainedLogsDir, f.Name))
		if err != nil || got != f.SHA256 || n != f.Bytes {
			return fmt.Errorf("%w: %s: log %s altered or missing", ErrRetainedExecutionConflict, ref, f.Name)
		}
	}
	return nil
}

type executionLog struct {
	name string // name in the copy
	src  string // path relative to the log directory
}

// executionLogSet is what the log directory holds for one execution.
type executionLogSet struct {
	root  *os.Root // the configured log directory; nil when there is none
	files []executionLog
	// expected holds, for each log stream the status says the execution
	// produced, the places that stream can be (the status's own path, the
	// coordinator's file for a worker's stream).
	expected [][]string
	// incomplete is a discovery failure: what the directory holds is not
	// known, so nothing is claimed final.
	incomplete bool
}

func (l *executionLogSet) close() {
	if l.root != nil {
		_ = l.root.Close()
	}
}

// final reports whether the execution's logs are complete: every copied log
// was recorded final with exactly the bytes copied, and every stream the
// status names is among them. A stream that never arrived keeps the logs
// not final, as does any discovery failure.
func (l *executionLogSet) final(copied map[string]persis.RetainedFile) bool {
	if l.incomplete || len(copied) == 0 {
		return false
	}
	for _, f := range copied {
		if !f.Final {
			return false
		}
	}
	for _, places := range l.expected {
		found := false
		for _, p := range places {
			if f, ok := copied[p]; ok && f.Final {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// executionLogs lists the execution's log files under the configured log
// directory only: the attempt's directory there (where the coordinator
// writes a worker's streams) and the status's own log paths, handlers
// included, when they lie inside it. Symbolic links are never followed.
func (store *Store) executionLogs(root ir.DAGRunRef, status *ir.DAGRunStatus) *executionLogSet {
	set := &executionLogSet{}
	if store.logDir == "" {
		return set
	}
	logRoot, err := os.OpenRoot(store.logDir)
	if err != nil {
		set.incomplete = true
		return set
	}
	set.root = logRoot
	seen := map[string]bool{}
	add := func(rel string) bool {
		if seen[rel] {
			return true
		}
		if strings.HasSuffix(rel, finalSuffix) {
			return false
		}
		f, _, err := openPlain(logRoot, rel)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, errNotPlain) {
				set.incomplete = true
			}
			return false
		}
		_ = f.Close()
		name := retainedFileName(filepath.Base(rel))
		for i := 1; nameTaken(set.files, name) || reservedName(name); i++ {
			name = fmt.Sprintf("%d-%s", i, retainedFileName(filepath.Base(rel)))
		}
		seen[rel] = true
		set.files = append(set.files, executionLog{name: name, src: rel})
		return true
	}

	rootName, rootID := root.Name, root.ID
	if rootName == "" {
		rootName, rootID = status.Name, status.DAGRunID
	}
	attemptRel := filepath.Join(fileutil.SafeName(rootName), fileutil.SafeName(rootID), fileutil.SafeName(status.AttemptID))
	switch dir, err := openRootPath(logRoot, attemptRel); {
	case err == nil:
		entries, err := readDirRoot(dir)
		_ = dir.Close()
		if err != nil {
			set.incomplete = true
		}
		for _, e := range entries {
			if e.Type().IsRegular() {
				add(filepath.Join(attemptRel, e.Name()))
			}
		}
	case !errors.Is(err, fs.ErrNotExist):
		set.incomplete = true
	}

	logDir := filepath.Clean(store.logDir)
	stream := func(statusPath, hubName string, expected bool) {
		var places []string
		if rel, err := filepath.Rel(logDir, filepath.Clean(statusPath)); err == nil && filepath.IsLocal(rel) {
			places = append(places, rel)
		}
		places = append(places, filepath.Join(attemptRel, hubName))
		for _, p := range places {
			add(p)
		}
		if expected {
			set.expected = append(set.expected, places)
		}
	}
	if status.Log != "" {
		stream(status.Log, "scheduler.log", true)
	}
	for _, n := range status.NodesInRunOrder() {
		if n == nil {
			continue
		}
		// A step that never started (its dependency failed, it was skipped)
		// produced no streams, whatever paths its status names.
		ran := n.StartedAt != "" && n.StartedAt != "-" && n.Status != ir.NodeNotStarted && n.Status != ir.NodeSkipped
		step := fileutil.SafeName(n.Step.Name)
		if n.Stdout != "" {
			stream(n.Stdout, step+".stdout.log", ran)
		}
		if n.Stderr != "" {
			stream(n.Stderr, step+".stderr.log", ran)
		}
	}
	sort.Slice(set.files, func(i, k int) bool { return set.files[i].name < set.files[k].name })
	return set
}

// executionArtifacts lists the files the execution published under its own
// prefix in the run's native artifact directory, by digest. They are
// written once per execution, so a reference is enough; nothing is copied.
func (store *Store) executionArtifacts(ref string, status *ir.DAGRunStatus) []persis.RetainedFile {
	if status.ArchiveDir == "" || store.artifactDir == "" {
		return nil
	}
	rel, err := filepath.Rel(filepath.Clean(store.artifactDir), filepath.Join(filepath.Clean(status.ArchiveDir), hubAttemptsDir, ref))
	if err != nil || !filepath.IsLocal(rel) {
		return nil
	}
	artRoot, err := os.OpenRoot(store.artifactDir)
	if err != nil {
		return nil
	}
	defer func() { _ = artRoot.Close() }()
	dir, err := openRootPath(artRoot, rel)
	if err != nil {
		return nil
	}
	defer func() { _ = dir.Close() }()
	var out []persis.RetainedFile
	_ = fs.WalkDir(dir.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return nil
		}
		sum, n, err := digestPlain(dir, filepath.FromSlash(p))
		if err != nil {
			return nil
		}
		out = append(out, persis.RetainedFile{Name: p, Bytes: n, SHA256: sum})
		return nil
	})
	return out
}

// retainedCopy is a retained execution and the attempt directory holding it.
type retainedCopy struct {
	manifest   persis.RetainedExecution
	attemptDir string
}

func (store *Store) retainedCopies(ctx context.Context, root, dagRun ir.DAGRunRef) ([]retainedCopy, error) {
	run, err := store.findRun(ctx, root, dagRun)
	if err != nil {
		return nil, err
	}
	dirs, err := run.listAttemptDirs()
	if err != nil {
		return nil, err
	}
	var out []retainedCopy
	for _, d := range dirs {
		attemptDir := filepath.Join(run.baseDir, d)
		for _, m := range listRetainedIn(attemptDir) {
			out = append(out, retainedCopy{manifest: m, attemptDir: attemptDir})
		}
	}
	sort.SliceStable(out, func(i, k int) bool { return out[i].manifest.RetainedAt.Before(out[k].manifest.RetainedAt) })
	return out, nil
}

// listRetainedIn reads the manifests of the copies in one attempt directory.
func listRetainedIn(attemptDir string) []persis.RetainedExecution {
	attRoot, err := os.OpenRoot(attemptDir)
	if err != nil {
		return nil
	}
	defer func() { _ = attRoot.Close() }()
	execRoot, err := openSubRoot(attRoot, retainedExecutionsDir, false)
	if err != nil {
		return nil
	}
	defer func() { _ = execRoot.Close() }()
	entries, err := readDirRoot(execRoot)
	if err != nil {
		return nil
	}
	var out []persis.RetainedExecution
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		data, err := readPlain(execRoot, filepath.Join(e.Name(), retainedManifestFile))
		if err != nil {
			continue
		}
		var m persis.RetainedExecution
		if json.Unmarshal(data, &m) == nil && m.Execution == e.Name() {
			if m.Files == nil {
				m.Files = []persis.RetainedFile{}
			}
			out = append(out, m)
		}
	}
	return out
}

// ListRetainedExecutions lists the retained executions of a run, oldest
// first.
func (store *Store) ListRetainedExecutions(ctx context.Context, root, dagRun ir.DAGRunRef) ([]persis.RetainedExecution, error) {
	copies, err := store.retainedCopies(ctx, root, dagRun)
	if err != nil {
		return nil, err
	}
	out := make([]persis.RetainedExecution, 0, len(copies))
	for _, c := range copies {
		out = append(out, c.manifest)
	}
	return out, nil
}

// ReadRetainedExecutionFile reads status.json or one listed log of a
// retained execution. Names are checked against the execution's manifest,
// and the file is read through the attempt directory's root, so no path
// outside the copy is ever read.
func (store *Store) ReadRetainedExecutionFile(ctx context.Context, root, dagRun ir.DAGRunRef, executionRef, name string) ([]byte, error) {
	if !retainedName.MatchString(executionRef) || !retainedName.MatchString(name) {
		return nil, persis.ErrNotFound
	}
	copies, err := store.retainedCopies(ctx, root, dagRun)
	if err != nil {
		return nil, err
	}
	for _, c := range copies {
		if c.manifest.Execution != executionRef {
			continue
		}
		rel := ""
		if name == retainedStatusFile {
			rel = retainedStatusFile
		} else {
			for _, f := range c.manifest.Files {
				if f.Name == name {
					rel = filepath.Join(retainedLogsDir, f.Name)
				}
			}
		}
		if rel == "" {
			return nil, persis.ErrNotFound
		}
		attRoot, err := os.OpenRoot(c.attemptDir)
		if err != nil {
			return nil, persis.ErrNotFound
		}
		data, err := readPlain(attRoot, filepath.Join(retainedExecutionsDir, executionRef, rel))
		_ = attRoot.Close()
		if err != nil {
			return nil, persis.ErrNotFound
		}
		return data, nil
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

// errNotPlain is a path element that is a symbolic link or not of the kind
// expected, or a file that changed while it was opened.
var errNotPlain = errors.New("not a plain file or directory (a symbolic link or another kind)")

// openSubRoot opens the directory name directly below parent, creating it
// when create is set, and refuses it if it is a symbolic link.
func openSubRoot(parent *os.Root, name string, create bool) (*os.Root, error) {
	if create {
		if err := parent.Mkdir(name, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	checked, err := parent.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !checked.IsDir() {
		return nil, fmt.Errorf("%s: %w", name, errNotPlain)
	}
	if beforeOpenSubRoot != nil {
		beforeOpenSubRoot(parent, name)
	}
	sub, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	// The directory opened must be the one checked: a directory replaced in
	// between by a link to another inside the same root is refused.
	opened, err := sub.Stat(".")
	if err != nil || !os.SameFile(checked, opened) {
		_ = sub.Close()
		return nil, fmt.Errorf("%s: %w", name, errNotPlain)
	}
	return sub, nil
}

// beforeOpenSubRoot runs between a directory's check and its open; tests use
// it to replace the directory in that window.
var beforeOpenSubRoot func(parent *os.Root, name string)

// openRootPath opens the directory rel below root, element by element,
// refusing any element that is a symbolic link.
func openRootPath(root *os.Root, rel string) (*os.Root, error) {
	rel = filepath.Clean(rel)
	if rel != "." && !filepath.IsLocal(rel) {
		return nil, fmt.Errorf("%s: %w", rel, errNotPlain)
	}
	cur, owned := root, false
	for part := range strings.SplitSeq(rel, string(filepath.Separator)) {
		next, err := openSubRoot(cur, part, false)
		if owned {
			_ = cur.Close()
		}
		if err != nil {
			return nil, err
		}
		cur, owned = next, true
	}
	return cur, nil
}

// openPlain opens the regular file rel below root. No element of rel may be
// a symbolic link, and the file opened must be the one checked.
func openPlain(root *os.Root, rel string) (*os.File, os.FileInfo, error) {
	dir, err := openRootPath(root, filepath.Dir(rel))
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = dir.Close() }()
	base := filepath.Base(rel)
	checked, err := dir.Lstat(base)
	if err != nil {
		return nil, nil, err
	}
	if !checked.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s: %w", rel, errNotPlain)
	}
	f, err := dir.Open(base)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil || !os.SameFile(checked, info) {
		_ = f.Close()
		return nil, nil, fmt.Errorf("%s: %w", rel, errNotPlain)
	}
	return f, info, nil
}

func readPlain(root *os.Root, rel string) ([]byte, error) {
	f, _, err := openPlain(root, rel)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

func digestPlain(root *os.Root, rel string) (string, int64, error) {
	f, _, err := openPlain(root, rel)
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

func readDirRoot(root *os.Root) ([]fs.DirEntry, error) {
	f, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return f.ReadDir(-1)
}

// writeNew creates rel below root, which must not exist yet.
func writeNew(root *os.Root, rel string, data []byte) error {
	f, err := root.OpenFile(rel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// copyPlain copies the regular file srcRel below src to the new file dstRel
// below dst and returns its size and digest.
func copyPlain(src *os.Root, srcRel string, dst *os.Root, dstRel string) (persis.RetainedFile, error) {
	in, _, err := openPlain(src, srcRel)
	if err != nil {
		return persis.RetainedFile{}, err
	}
	defer func() { _ = in.Close() }()
	out, err := dst.OpenFile(dstRel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
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

// maxFinalRecord bounds the size of a .final record read.
const maxFinalRecord = 64 << 10

// streamFinal reports whether the coordinator recorded the log stream at
// src as finished for this execution with exactly the bytes copied: the
// record names the execution's queue marker and attempt, and its size and
// sha256 are those of the copy. The copy and the coordinator's writes are
// not serialized, so only the digest proves the copy is the finished log; a
// copy that caught a concurrent rewrite of the same length cannot match it.
func streamFinal(root *os.Root, src string, status *ir.DAGRunStatus, copied persis.RetainedFile) bool {
	f, _, err := openPlain(root, src+finalSuffix)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxFinalRecord))
	if err != nil {
		return false
	}
	var rec struct {
		ExecutionMarker string `json:"executionMarker"`
		AttemptID       string `json:"attemptId"`
		Size            int64  `json:"size"`
		SHA256          string `json:"sha256"`
	}
	if json.Unmarshal(data, &rec) != nil || rec.SHA256 == "" {
		return false
	}
	return rec.ExecutionMarker == status.QueuedAt && rec.AttemptID == status.AttemptID &&
		rec.Size == copied.Bytes && rec.SHA256 == copied.SHA256
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

// reservedName is a name the copy's own files use: a log never takes it, so
// a read of status.json is always the saved status.
func reservedName(name string) bool {
	return name == retainedStatusFile || name == retainedManifestFile
}

func nameTaken(logs []executionLog, name string) bool {
	for _, l := range logs {
		if l.name == name {
			return true
		}
	}
	return false
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
