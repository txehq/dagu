// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package scheduler

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/schedulerstate"
)

// A DAG with watch: starts a run for each file that arrives in a folder.
// The folder is read every watch.interval. A file counts as arrived once
// its size and modification time are the same on two readings in a row,
// so a file still being copied is left alone. Each arrival starts one run,
// with the file's path as WATCH_FILE and its name as WATCH_NAME. A file is
// remembered by its size and time, so it arrives again when it is replaced,
// or when a reading saw it gone and a later one sees it back. The files a
// folder holds when it is first watched are remembered without running: a
// watch takes what arrives, not an archive. A file that arrives while the
// scheduler is off is new when it returns.
//
// An arrival is numbered in the ledger, and the ledger is saved, before its
// run is queued; the run is named after the arrival. A run queued just
// before the scheduler stopped, with the ledger not yet saved again, is
// queued again under the same name, and the queue, which holds it, leaves
// it alone.

// watchTick is how often the watcher looks for folders due to be read.
const watchTick = time.Second

// WatchEnqueueFunc starts a run for a file that arrived, with params as
// WatchRuntimeParams gives them.
type WatchEnqueueFunc func(ctx context.Context, entry DAGEntry, runID, params string) error

// WatchRuntimeParams are the params a file's run receives.
func WatchRuntimeParams(path string) string {
	return fmt.Sprintf("%s=%s %s=%s", ir.WatchFileParam, strconv.Quote(path), ir.WatchNameParam, strconv.Quote(filepath.Base(path)))
}

// errNoArrival says a file in the ledger has no arrival to name a run after.
var errNoArrival = errors.New("the file has no arrival")

// WatchRunID names the run of the arrival the file name came with in the
// ledger: the same for every retry of that arrival, and another for each
// other arrival, the same version of the same file included. A file with
// no arrival, one the folder held when the ledger was made or one recorded
// by version 1, has no run to name.
func WatchRunID(dagName string, ledger schedulerstate.WatchLedger, name string) (string, error) {
	file, ok := ledger.Files[name]
	if !ok || file.Arrival == 0 || ledger.Epoch == "" {
		return "", fmt.Errorf("%w: %s", errNoArrival, name)
	}
	sum := sha256.Sum256([]byte("arrival\x00" + dagName + "\x00" + ledger.Epoch + "\x00" + strconv.FormatUint(file.Arrival, 10)))
	return "file-" + hex.EncodeToString(sum[:16]), nil
}

type folderWatcherConfig struct {
	Entries     func() []DAGEntry
	IsSuspended IsSuspendedFunc
	Enqueue     WatchEnqueueFunc
	// Store keeps the ledgers across restarts; nil keeps them in memory.
	Store schedulerstate.WatchStore
	Clock Clock
}

// folderWatcher reads the folders DAGs watch and starts their runs.
type folderWatcher struct {
	cfg folderWatcherConfig

	mu      sync.Mutex
	ledgers map[string]schedulerstate.WatchLedger
	// pending are the files seen once, by DAG, waiting to hold still.
	pending map[string]map[string]schedulerstate.FileMark
	// readAt is when each DAG's folder was last read.
	readAt map[string]time.Time
	// trouble is the last error reading each DAG's folder, logged once.
	trouble map[string]string
	// unsaved says the ledgers changed since they were last saved.
	unsaved bool
	// loaded says the ledgers were read from the store; loadErr is the
	// last error reading them, logged once.
	loaded  bool
	loadErr string
}

func newFolderWatcher(cfg folderWatcherConfig) *folderWatcher {
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &folderWatcher{
		cfg:     cfg,
		ledgers: map[string]schedulerstate.WatchLedger{},
		pending: map[string]map[string]schedulerstate.FileMark{},
		readAt:  map[string]time.Time{},
		trouble: map[string]string{},
	}
}

// Start reads the watched folders until ctx ends.
func (w *folderWatcher) Start(ctx context.Context) {
	ticker := time.NewTicker(watchTick)
	defer ticker.Stop()
	for {
		w.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// tick reads every watched folder that is due and queues the runs of the
// files that arrived there.
func (w *folderWatcher) tick(ctx context.Context) {
	if !w.load(ctx) {
		return
	}
	now := w.cfg.Clock()
	var read []DAGEntry
	for _, entry := range w.cfg.Entries() {
		if entry.DAG == nil || entry.DAG.Watch == nil {
			continue
		}
		if last, ok := w.readAt[entry.DAG.Name]; ok && now.Sub(last) < entry.DAG.Watch.Interval {
			continue
		}
		w.readAt[entry.DAG.Name] = now
		if w.read(ctx, entry) {
			read = append(read, entry)
		}
	}
	// An arrival is queued only once it is saved: its run is named after
	// it, and an arrival lost to a restart would be numbered again and its
	// run queued twice.
	if !w.save(ctx) {
		return
	}
	for _, entry := range read {
		w.queue(ctx, entry)
	}
	w.save(ctx)
}

// load reads the ledgers from the store, once, and reports whether they
// are read. Until they are, no folder is read: a ledger started over in
// place of one that could not be read would take the files that arrived
// while the scheduler was off as already there, and be saved over the
// arrivals the store holds. A record the store finds corrupt is started
// over by the store.
func (w *folderWatcher) load(ctx context.Context) bool {
	if w.loaded {
		return true
	}
	if w.cfg.Store != nil {
		ledgers, err := w.cfg.Store.LoadWatch(ctx)
		if err != nil {
			if w.loadErr != err.Error() {
				w.loadErr = err.Error()
				logger.Error(ctx, "Failed to load watched folders; reading them once they load", tag.Error(err))
			}
			return false
		}
		if ledgers == nil {
			ledgers = map[string]schedulerstate.WatchLedger{}
		}
		w.mu.Lock()
		w.ledgers = ledgers
		w.mu.Unlock()
	}
	w.loaded = true
	return true
}

// save saves the ledgers if they changed and reports whether what the
// store holds is what the watcher remembers. A DAG the entries leave out
// keeps its record: it may be back after an edit that did not load, and a
// file that arrived meanwhile must still run then. A record of a DAG that
// is gone for good costs a few bytes.
func (w *folderWatcher) save(ctx context.Context) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.unsaved {
		return true
	}
	if w.cfg.Store != nil {
		if err := w.cfg.Store.SaveWatch(ctx, w.ledgers); err != nil {
			logger.Error(ctx, "Failed to save watched folders; their new files wait for the next reading", tag.Error(err))
			return false
		}
	}
	w.unsaved = false
	return true
}

// read reads one DAG's folder and records what arrived there. It reports
// whether the folder could be read: a folder that could not tells nothing,
// so no file in it is taken as gone.
func (w *folderWatcher) read(ctx context.Context, entry DAGEntry) bool {
	dag := entry.DAG
	cfg := dag.Watch
	dir, err := watchDir(cfg.Path)
	if err == nil {
		var found map[string]schedulerstate.FileMark
		found, err = readFolder(dir, cfg.Pattern)
		if err == nil {
			delete(w.trouble, dag.Name)
			w.settle(ctx, entry, dir, found)
			return true
		}
	}
	// The folder may be a share that is off for a while; say so once.
	if w.trouble[dag.Name] != err.Error() {
		w.trouble[dag.Name] = err.Error()
		logger.Error(ctx, "Cannot read the watched folder", tag.DAG(dag.Name), slog.String("path", cfg.Path), tag.Error(err))
	}
	return false
}

// settle compares what the folder holds with what the ledger remembers:
// a file that has held still since the last reading arrives, and a file
// that is gone is forgotten, so it arrives again if it comes back.
func (w *folderWatcher) settle(ctx context.Context, entry DAGEntry, dir string, found map[string]schedulerstate.FileMark) {
	dag := entry.DAG
	w.mu.Lock()
	defer w.mu.Unlock()
	ledger, known := w.ledgers[dag.Name]
	if !known || ledger.Path != dir || ledger.Pattern != dag.Watch.Pattern {
		files := make(map[string]schedulerstate.WatchedFile, len(found))
		for name, mark := range found {
			files[name] = schedulerstate.WatchedFile{FileMark: mark}
		}
		w.ledgers[dag.Name] = schedulerstate.WatchLedger{Path: dir, Pattern: dag.Watch.Pattern, Files: files}
		delete(w.pending, dag.Name)
		w.unsaved = true
		logger.Info(ctx, "Watching a folder for new files",
			tag.DAG(dag.Name), slog.String("path", dir), slog.String("pattern", dag.Watch.Pattern),
			slog.Int("filesAlreadyThere", len(found)))
		return
	}
	pending := w.pending[dag.Name]
	if pending == nil {
		pending = map[string]schedulerstate.FileMark{}
		w.pending[dag.Name] = pending
	}
	for name, mark := range found {
		if file, ok := ledger.Files[name]; ok && file.Same(mark) {
			continue
		}
		if !pending[name].Same(mark) {
			pending[name] = mark
			continue
		}
		ledger.Arrive(name, mark)
		delete(pending, name)
		w.unsaved = true
	}
	for name := range ledger.Files {
		if _, present := found[name]; !present {
			delete(ledger.Files, name)
			w.unsaved = true
		}
	}
	for name := range pending {
		if _, present := found[name]; !present {
			delete(pending, name)
		}
	}
	w.ledgers[dag.Name] = ledger
}

// queue queues the run of each arrival in the DAG's ledger whose run may
// not be queued yet, unless the DAG is suspended. An arrival whose run
// could not be queued, or that came while the DAG was suspended, is tried
// again at the next reading.
func (w *folderWatcher) queue(ctx context.Context, entry DAGEntry) {
	dag := entry.DAG
	type arrival struct {
		name, path, runID string
		number            uint64
		err               error
	}
	var arrivals []arrival
	w.mu.Lock()
	ledger := w.ledgers[dag.Name]
	for name, file := range ledger.Files {
		if file.Unqueued {
			runID, err := WatchRunID(dag.Name, ledger, name)
			arrivals = append(arrivals, arrival{name: name, path: filepath.Join(ledger.Path, name), runID: runID, number: file.Arrival, err: err})
		}
	}
	w.mu.Unlock()
	if len(arrivals) == 0 {
		return
	}
	slices.SortFunc(arrivals, func(a, b arrival) int { return cmp.Compare(a.number, b.number) })
	suspended, err := isSuspendedDAG(ctx, w.cfg.IsSuspended, nil, dag, entry.DefinitionID)
	if err != nil {
		logger.Error(ctx, "Failed to check DAG suspension; leaving the files for the next reading", tag.DAG(dag.Name), tag.Error(err))
		return
	}
	if suspended {
		return
	}
	for _, a := range arrivals {
		err := a.err
		if err == nil {
			err = w.cfg.Enqueue(ctx, entry, a.runID, WatchRuntimeParams(a.path))
		}
		if err != nil {
			logger.Error(ctx, "Failed to start the run for a file", tag.DAG(dag.Name), slog.String("file", a.path), tag.Error(err))
			continue
		}
		logger.Info(ctx, "A file arrived; its run is queued", tag.DAG(dag.Name), tag.RunID(a.runID), slog.String("file", a.path))
		w.queued(dag.Name, a.name, a.number)
	}
}

// queued records that the run of an arrival is queued, unless the ledger
// has since moved on from that arrival.
func (w *folderWatcher) queued(dagName, name string, arrival uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	ledger := w.ledgers[dagName]
	file, ok := ledger.Files[name]
	if !ok || file.Arrival != arrival || !file.Unqueued {
		return
	}
	file.Unqueued = false
	ledger.Files[name] = file
	w.unsaved = true
}

// watchDir makes the watched folder absolute: a leading ~ is the home
// directory.
func watchDir(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, path[1:])
	}
	return filepath.Abs(path)
}

// inProgressExtensions are the extensions of files still being written.
var inProgressExtensions = map[string]bool{".tmp": true, ".part": true, ".partial": true, ".crdownload": true, ".download": true}

// readFolder returns the files in a folder, by name, that a watch takes:
// regular files whose names match the pattern, leaving out hidden files,
// Office lock files, and files still being written.
func readFolder(dir, pattern string) (map[string]schedulerstate.FileMark, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	found := map[string]schedulerstate.FileMark{}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "~$") || inProgressExtensions[strings.ToLower(filepath.Ext(name))] {
			continue
		}
		if pattern != "" {
			if matched, err := filepath.Match(pattern, name); err != nil || !matched {
				continue
			}
		}
		info, err := entry.Info()
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		found[name] = schedulerstate.FileMark{Size: info.Size(), ModTime: info.ModTime()}
	}
	return found, nil
}
