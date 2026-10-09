// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

// A run's files on the machine, under outputs/<job>/runs/<run>/:
//
//	attempts/<attempt>/   where the job that is executing writes
//	executions/<ref>/     what an execution that succeeded wrote, sealed
//	unsealed/<name>.<n>/  what an execution that failed had written
//	seals.json            every seal of the run, oldest first
//
// A Dagu retry keeps the run ID. It starts another attempt when it goes to
// the coordinator directly, and executes again under the same attempt ID,
// with a later queue marker, when it goes through a queue. One execution is
// therefore named by both: an Execution, whose Ref is the only form used in
// a path.
//
// The job writes to a directory Dagu can name for it, the attempt's. When its
// command succeeds, the seal moves that directory under the execution's
// reference and records the digest of every file. Nothing is written over: a
// later execution starts with an empty directory, and what a failed one left
// is moved aside. The publish step reads sealed files only and refuses one
// that no longer matches its seal.
const (
	attemptsDir   = "attempts"
	executionsDir = "executions"
	unsealedDir   = "unsealed"
	sealsFile     = "seals.json"

	// HubAttemptsDir is the directory, inside a run's native artifact
	// directory, that holds each execution's hub copies. The hub can keep
	// several executions of a run in one artifact directory, so a copy is
	// never placed at the deliverable's bare path. No deliverable path may
	// start with it.
	HubAttemptsDir = "txe-attempts"
)

var (
	attemptIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)
	// queueMarkerPattern holds the characters of an RFC3339 timestamp, which
	// is what Dagu hands a step as its queue marker.
	queueMarkerPattern = regexp.MustCompile(`^[0-9TZ.:+-]{1,64}$`)
)

// ErrExecutionSealed reports that an execution's outputs were already sealed.
var ErrExecutionSealed = errors.New("this execution's outputs are already sealed")

// ErrNotSealed reports that no execution of the job in this run has sealed
// its outputs.
var ErrNotSealed = errors.New("no execution of this run has sealed its outputs")

// ErrChangedAfterSeal reports that a sealed file is not what was sealed.
var ErrChangedAfterSeal = errors.New("a sealed file is not what was sealed")

// Execution names one execution of a run: the Dagu attempt, and the queue
// marker the attempt was dispatched with. The marker is empty for a run that
// was never queued; such a run is not executed twice under one attempt.
type Execution struct {
	AttemptID string `json:"attempt_id"`
	QueuedAt  string `json:"queued_at"`
}

// Ref is the execution's portable reference: the attempt ID and the first 8
// bytes of sha256(attempt ID, a newline, the queue marker) in hex. It is the
// registry's ExecutionRef; execution-refs.json among the contract fixtures
// holds cases both sides compute.
func (e Execution) Ref() string {
	sum := sha256.Sum256([]byte(e.AttemptID + "\n" + e.QueuedAt))
	return e.AttemptID + "-" + hex.EncodeToString(sum[:8])
}

func (e Execution) check() error {
	switch {
	case !attemptIDPattern.MatchString(e.AttemptID):
		return fmt.Errorf("invalid attempt id %q", e.AttemptID)
	case strings.HasPrefix(e.QueuedAt, "${"):
		return fmt.Errorf("the run's queue marker was not resolved (%s): the worker's dagu does not provide it, or the stored marker is not a timestamp", e.QueuedAt)
	case e.QueuedAt != "" && !queueMarkerPattern.MatchString(e.QueuedAt):
		return fmt.Errorf("invalid queue marker %q", e.QueuedAt)
	}
	return nil
}

// SealedFile is one file of a sealed execution.
type SealedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

// Seal records that an execution of the job succeeded, and every regular
// file it wrote, with its digest.
type Seal struct {
	Execution
	// Ref is the execution's reference, and the name of its directory.
	Ref      string       `json:"execution"`
	SealedAt string       `json:"sealed_at"`
	Files    []SealedFile `json:"files"`
}

// file returns the sealed file at path.
func (s *Seal) file(path string) (SealedFile, bool) {
	for _, f := range s.Files {
		if f.Path == path {
			return f, true
		}
	}
	return SealedFile{}, false
}

// seals is the content of a run's seals.json. Every question about what is
// sealed is answered from this one file, which is replaced in one step, so
// two readers never see different answers from two files.
type seals struct {
	Schema int    `json:"schema"`
	JobID  string `json:"job_id"`
	RunID  string `json:"run_id"`
	Seals  []Seal `json:"seals"`
}

func (s *seals) of(e Execution) *Seal {
	for i := range s.Seals {
		if s.Seals[i].Execution == e {
			return &s.Seals[i]
		}
	}
	return nil
}

// latest is the seal of the most recent execution that succeeded.
func (s *seals) latest() *Seal {
	if len(s.Seals) == 0 {
		return nil
	}
	return &s.Seals[len(s.Seals)-1]
}

// Outputs manages the output directories of a job's runs.
type Outputs struct {
	Home txepkg.Home
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

func checkRun(jobID, runID string, e Execution) error {
	if !runIDPattern.MatchString(jobID) || !runIDPattern.MatchString(runID) {
		return fmt.Errorf("invalid job id %q or run id %q", jobID, runID)
	}
	return e.check()
}

// Begin prepares an empty output directory for the execution of the job that
// is about to start, and returns it: the attempt's directory, which is the
// one the job is told to write to. What an earlier execution left there is
// moved aside and kept. Begin refuses with ErrExecutionSealed when this
// execution already sealed its outputs.
func (o Outputs) Begin(jobID, runID string, e Execution) (string, error) {
	if err := checkRun(jobID, runID, e); err != nil {
		return "", err
	}
	run, err := makeRunDir(o.Home, jobID, runID)
	if err != nil {
		return "", err
	}
	defer func() { _ = run.Close() }()

	sealed, err := readSeals(run, jobID, runID)
	if err != nil {
		return "", err
	}
	if sealed.of(e) != nil {
		return "", fmt.Errorf("%w: execution %s of run %s", ErrExecutionSealed, e.Ref(), runID)
	}
	attempts, err := makeDir(run, attemptsDir)
	if err != nil {
		return "", err
	}
	_ = attempts.Close()
	if err := setAside(run, attemptsDir+"/"+e.AttemptID, e.AttemptID); err != nil {
		return "", fmt.Errorf("keep what an earlier execution of attempt %s wrote: %w", e.AttemptID, err)
	}
	attempt, err := makeDir(run, attemptsDir+"/"+e.AttemptID)
	if err != nil {
		return "", err
	}
	_ = attempt.Close()
	return txepkg.AttemptOutputDir(o.Home.OutputDir(jobID), runID, e.AttemptID), nil
}

// Seal records that the execution's run of the job succeeded. The attempt's
// directory is moved under the execution's reference, the digest of every
// file in it is recorded, and the execution becomes the run's result. An
// execution is sealed once.
func (o Outputs) Seal(jobID, runID string, e Execution) (*Seal, error) {
	if err := checkRun(jobID, runID, e); err != nil {
		return nil, err
	}
	run, err := openRunDir(o.Home, jobID, runID)
	if err != nil {
		return nil, fmt.Errorf("%w (was the execution begun?)", err)
	}
	defer func() { _ = run.Close() }()

	sealed, err := readSeals(run, jobID, runID)
	if err != nil {
		return nil, err
	}
	if sealed.of(e) != nil {
		return nil, fmt.Errorf("%w: execution %s of run %s", ErrExecutionSealed, e.Ref(), runID)
	}
	begun, err := openPath(run, attemptsDir+"/"+e.AttemptID)
	if err != nil {
		return nil, fmt.Errorf("the attempt's output directory: %w (was the execution begun?)", err)
	}
	_ = begun.Close()

	executions, err := makeDir(run, executionsDir)
	if err != nil {
		return nil, err
	}
	_ = executions.Close()
	ref := e.Ref()
	// A directory under this reference without a seal is what an earlier,
	// interrupted seal moved there. It is kept, out of the way.
	if err := setAside(run, executionsDir+"/"+ref, ref); err != nil {
		return nil, fmt.Errorf("keep what an interrupted seal of %s left: %w", ref, err)
	}
	if err := run.Rename(attemptsDir+"/"+e.AttemptID, executionsDir+"/"+ref); err != nil {
		return nil, fmt.Errorf("move the execution's outputs under %s: %w", ref, err)
	}
	dir, err := openPath(run, executionsDir+"/"+ref)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	files, err := sealedFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("record what execution %s wrote: %w", ref, err)
	}

	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	seal := Seal{Execution: e, Ref: ref, SealedAt: now().UTC().Format(time.RFC3339), Files: files}
	sealed.Seals = append(sealed.Seals, seal)
	if err := writeSeals(run, sealed); err != nil {
		return nil, err
	}
	return &seal, nil
}

// Sealed returns the seal of the latest execution of the job that succeeded
// in a run, or ErrNotSealed.
func (o Outputs) Sealed(jobID, runID string) (*Seal, error) {
	run, err := openRunDir(o.Home, jobID, runID)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotSealed
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = run.Close() }()
	sealed, err := readSeals(run, jobID, runID)
	if err != nil {
		return nil, err
	}
	if latest := sealed.latest(); latest != nil {
		return latest, nil
	}
	return nil, ErrNotSealed
}

// sealedFiles lists every regular file beneath dir with its digest. A link
// is not a file an execution wrote here; it is left out, and the publish
// step refuses a deliverable that is one.
func sealedFiles(dir *os.Root) ([]SealedFile, error) {
	var files []SealedFile
	err := fs.WalkDir(dir.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		f, err := openRegular(dir, path, path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		sum, size, err := hashFile(f)
		if err != nil {
			return err
		}
		files = append(files, SealedFile{Path: path, SHA256: "sha256:" + sum, Bytes: size})
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(files, func(a, b SealedFile) int { return strings.Compare(a.Path, b.Path) })
	return files, nil
}

// readSeals reads a run's seals. A run without the file has none.
func readSeals(run *os.Root, jobID, runID string) (*seals, error) {
	f, err := openRegular(run, sealsFile, sealsFile)
	if errors.Is(err, fs.ErrNotExist) {
		return &seals{Schema: 1, JobID: jobID, RunID: runID}, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 64<<20))
	if err != nil {
		return nil, err
	}
	var sealed seals
	if err := json.Unmarshal(data, &sealed); err != nil {
		return nil, fmt.Errorf("%s of run %s is not readable: %w", sealsFile, runID, err)
	}
	if sealed.Schema != 1 || sealed.JobID != jobID || sealed.RunID != runID {
		return nil, fmt.Errorf("%s in run %s is for job %s, run %s (schema %d)", sealsFile, runID, sealed.JobID, sealed.RunID, sealed.Schema)
	}
	for _, s := range sealed.Seals {
		if err := s.check(); err != nil || s.Ref != s.Execution.Ref() {
			return nil, fmt.Errorf("%s of run %s holds a seal that does not name its execution", sealsFile, runID)
		}
	}
	return &sealed, nil
}

// writeSeals replaces a run's seals in one step, so a reader sees the
// earlier content or this one.
func writeSeals(run *os.Root, sealed *seals) error {
	data, err := json.MarshalIndent(sealed, "", "  ")
	if err != nil {
		return err
	}
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	partial := partialPrefix + hex.EncodeToString(suffix)
	tmp, err := run.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	defer func() { _ = run.Remove(partial) }()
	_, err = tmp.Write(append(data, '\n'))
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = run.Rename(partial, sealsFile)
	}
	if err != nil {
		return fmt.Errorf("record the run's seals: %w", err)
	}
	return nil
}

// setAside moves the directory at rel, if it holds files, to the first free
// unsealed/<name>.<n> in the run's directory. A directory that is absent or
// empty is left alone; an empty one is removed so its name is free.
func setAside(run *os.Root, rel, name string) error {
	dir, err := openPath(run, rel)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	entries, err := fs.ReadDir(dir.FS(), ".")
	_ = dir.Close()
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return run.Remove(rel)
	}
	unsealed, err := makeDir(run, unsealedDir)
	if err != nil {
		return err
	}
	_ = unsealed.Close()
	for n := 1; ; n++ {
		aside := fmt.Sprintf("%s/%s.%d", unsealedDir, name, n)
		if _, err := run.Lstat(aside); err == nil {
			continue
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		// A rename never replaces a directory that holds files, so a name
		// taken in between is passed over too.
		err := run.Rename(rel, aside)
		if errors.Is(err, fs.ErrExist) || errors.Is(err, syscall.ENOTEMPTY) {
			continue
		}
		return err
	}
}

// openPath opens the directory at rel beneath root, through real directories
// only.
func openPath(root *os.Root, rel string) (*os.Root, error) {
	at, err := descend(root, rel, false)
	if err != nil {
		return nil, err
	}
	defer at.release()
	return openDir(at.dir, at.name)
}

// makeRunDir opens a run's directory, creating what is missing beneath the
// TXE home's outputs directory. Like openRunDir it follows no link.
func makeRunDir(home txepkg.Home, jobID, runID string) (*os.Root, error) {
	outputs := home.Root + string(os.PathSeparator) + "outputs"
	if err := os.MkdirAll(outputs, 0o750); err != nil {
		return nil, fmt.Errorf("create the outputs directory: %w", err)
	}
	current, err := os.OpenRoot(outputs)
	if err != nil {
		return nil, fmt.Errorf("open the outputs directory: %w", err)
	}
	for _, part := range []string{jobID, "runs", runID} {
		next, err := makeDir(current, part)
		_ = current.Close()
		if err != nil {
			return nil, fmt.Errorf("the run's output directory: %w", err)
		}
		current = next
	}
	return current, nil
}

// makeDir opens the directory at rel in parent, creating its last component
// if it is not there. Every component must be a real directory.
func makeDir(parent *os.Root, rel string) (*os.Root, error) {
	at, err := descend(parent, rel, false)
	if err != nil {
		return nil, err
	}
	defer at.release()
	if err := at.dir.Mkdir(at.name, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	return openDir(at.dir, at.name)
}
