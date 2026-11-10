// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package scheduler

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	"github.com/dagucloud/dagu/v2/internal/schedulerstate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// watchFixture drives a folder watcher by hand: each read is one call of
// tick with the clock past the interval.
type watchFixture struct {
	t         *testing.T
	dir       string
	watcher   *folderWatcher
	store     schedulerstate.WatchStore
	entry     DAGEntry
	now       time.Time
	suspended bool

	mu sync.Mutex
	// started are the params of the runs queued, one per run: like
	// enqueueTriggeredRun, the queue leaves alone a run it already holds.
	started []string
	queued  map[ir.DAGRunRef]bool
	// runIDs are the run IDs of every call to queue a run, repeats included.
	runIDs []string
	fail   bool
}

func newWatchFixture(t *testing.T, pattern string, watchStore schedulerstate.WatchStore) *watchFixture {
	t.Helper()
	f := &watchFixture{t: t, dir: t.TempDir(), store: watchStore, now: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC), queued: map[ir.DAGRunRef]bool{}}
	f.entry = DAGEntry{DefinitionID: "inbox.yaml", DAG: &ir.DAG{Name: "inbox", Watch: &ir.WatchConfig{Path: f.dir, Pattern: pattern, Interval: 10 * time.Second}}}
	f.watcher = newFolderWatcher(folderWatcherConfig{
		Entries:     func() []DAGEntry { return []DAGEntry{f.entry} },
		IsSuspended: func(context.Context, string) (bool, error) { return f.suspended, nil },
		Enqueue: func(_ context.Context, entry DAGEntry, runID string, params string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.fail {
				return assert.AnError
			}
			f.runIDs = append(f.runIDs, runID)
			ref := ir.NewDAGRunRef(entry.DAG.Name, runID)
			if !f.queued[ref] {
				f.queued[ref] = true
				f.started = append(f.started, params)
			}
			return nil
		},
		Store: watchStore,
		Clock: func() time.Time { return f.now },
	})
	return f
}

// restart is the watcher a restarted scheduler runs: a new one, loading
// the ledgers from the same store, in front of the same queue. whileOff,
// if given, changes the folder before the new watcher starts, whose first
// reading is at start.
func (f *watchFixture) restart(whileOff ...func()) *watchFixture {
	f.t.Helper()
	again := newWatchFixture(f.t, f.entry.DAG.Watch.Pattern, f.store)
	again.dir, again.entry.DAG.Watch.Path = f.dir, f.entry.DAG.Watch.Path
	again.now = f.now
	f.mu.Lock()
	again.queued, again.started = f.queued, append([]string(nil), f.started...)
	f.mu.Unlock()
	for _, change := range whileOff {
		change()
	}
	again.watcher.Start(contextDone())
	return again
}

// read reads the folder once, as the next due tick does.
func (f *watchFixture) read() {
	f.t.Helper()
	f.now = f.now.Add(10 * time.Second)
	f.watcher.tick(context.Background())
}

func (f *watchFixture) write(name, content string, modTime time.Time) string {
	f.t.Helper()
	path := filepath.Join(f.dir, name)
	require.NoError(f.t, os.WriteFile(path, []byte(content), 0o600))
	require.NoError(f.t, os.Chtimes(path, modTime, modTime))
	return path
}

func (f *watchFixture) runs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.started...)
}

func TestWatchRunsAFileOnceItHoldsStill(t *testing.T) {
	t.Parallel()

	f := newWatchFixture(t, "*.pdf", nil)
	old := f.write("old.pdf", "already there", f.now.Add(-time.Hour))
	f.read()
	assert.Empty(t, f.runs(), "files already in the folder are left alone")

	path := f.write("invoice.pdf", "new", f.now)
	f.read()
	assert.Empty(t, f.runs(), "a file seen once may still be being written")
	f.read()
	assert.Equal(t, []string{WatchRuntimeParams(path)}, f.runs(), "a file that held still starts one run")
	f.read()
	f.read()
	assert.Len(t, f.runs(), 1, "a file runs once")

	f.write("invoice.pdf", "new content", f.now.Add(time.Minute))
	f.read()
	f.read()
	assert.Len(t, f.runs(), 2, "a replaced file runs again")

	require.NoError(t, os.Remove(old))
	f.read()
	f.write("old.pdf", "back", f.now)
	f.read()
	f.read()
	assert.Len(t, f.runs(), 3, "a file that went away and came back is new")
}

func TestWatchWaitsForAFileBeingWritten(t *testing.T) {
	t.Parallel()

	f := newWatchFixture(t, "", nil)
	f.read()
	f.write("export.csv", "part", f.now)
	f.read()
	f.write("export.csv", "part of the file", f.now.Add(5*time.Second))
	f.read()
	assert.Empty(t, f.runs(), "a file that grew is not done yet")
	f.read()
	assert.Len(t, f.runs(), 1)
}

func TestWatchLeavesOutFilesNotMeantForIt(t *testing.T) {
	t.Parallel()

	f := newWatchFixture(t, "*.pdf", nil)
	f.read()
	f.write("notes.txt", "x", f.now)
	f.write(".hidden.pdf", "x", f.now)
	f.write("~$lock.pdf", "x", f.now)
	f.write("invoice.pdf.part", "x", f.now)
	f.write("download.crdownload", "x", f.now)
	require.NoError(t, os.Mkdir(filepath.Join(f.dir, "folder.pdf"), 0o700))
	f.read()
	f.read()
	assert.Empty(t, f.runs())
}

func TestWatchHoldsFilesWhileSuspended(t *testing.T) {
	t.Parallel()

	f := newWatchFixture(t, "", nil)
	f.read()
	f.suspended = true
	path := f.write("a.txt", "x", f.now)
	f.read()
	f.read()
	f.read()
	assert.Empty(t, f.runs(), "nothing starts while the DAG is suspended")
	f.suspended = false
	f.read()
	assert.Equal(t, []string{WatchRuntimeParams(path)}, f.runs(), "the file runs once the DAG resumes")
}

// An arrival whose run waits, while the DAG is suspended or its run cannot
// be queued, is dropped when the file changes: the new version waits to
// hold still, and only it runs.
func TestWatchDropsAWaitingArrivalWhenTheFileChanges(t *testing.T) {
	t.Parallel()

	for _, hold := range []string{"suspended", "failing"} {
		t.Run(hold, func(t *testing.T) {
			t.Parallel()

			f := newWatchFixture(t, "", nil)
			f.read()
			setHold := func(on bool) {
				f.mu.Lock()
				defer f.mu.Unlock()
				if hold == "suspended" {
					f.suspended = on
				} else {
					f.fail = on
				}
			}
			setHold(true)
			path := f.write("a.csv", "part", f.now)
			f.read()
			f.read()
			require.Empty(t, f.runs())
			f.write("a.csv", "part of the file", f.now.Add(5*time.Second))
			setHold(false)
			f.read()
			assert.Empty(t, f.runs(), "the changed file has not held still")
			f.read()
			assert.Equal(t, []string{WatchRuntimeParams(path)}, f.runs(), "one run, for the version that held still")
			f.read()
			assert.Len(t, f.runs(), 1)
		})
	}
}

func TestWatchRetriesAFileWhoseRunDidNotStart(t *testing.T) {
	t.Parallel()

	f := newWatchFixture(t, "", nil)
	f.read()
	f.fail = true
	f.write("a.txt", "x", f.now)
	f.read()
	f.read()
	assert.Empty(t, f.runs())
	f.fail = false
	f.read()
	assert.Len(t, f.runs(), 1)
}

func TestWatchRemembersFilesAcrossRestarts(t *testing.T) {
	t.Parallel()

	watchStore := store.NewWatchStateStore(testutil.NewMemoryBackend().Collection("watch"))
	f := newWatchFixture(t, "", watchStore)
	f.watcher.Start(contextDone())
	f.read()
	f.write("a.txt", "x", f.now)
	f.read()
	f.read()
	require.Len(t, f.runs(), 1)

	// A new watcher, as after a restart, loads the ledger: a.txt is known,
	// and the file that arrived meanwhile is new.
	arrived := f.write("b.txt", "x", f.now)
	again := newWatchFixture(t, "", watchStore)
	again.dir, again.entry.DAG.Watch.Path = f.dir, f.dir
	again.now = f.now
	again.watcher.Start(contextDone())
	again.read()
	again.read()
	assert.Equal(t, []string{WatchRuntimeParams(arrived)}, again.runs())
}

// A run is named after the arrival: every derivation of one arrival gives
// the same valid run ID, and another arrival, of another version or of the
// same one, gives another.
func TestWatchNamesARunAfterTheArrival(t *testing.T) {
	t.Parallel()

	f := newWatchFixture(t, "", nil)
	f.read()
	f.write("a.txt", "x", f.now)
	f.read()
	f.read()
	require.Len(t, f.runIDs, 1)
	assert.Regexp(t, `^file-[0-9a-f]{32}$`, f.runIDs[0])
	assert.NoError(t, ir.ValidateDAGRunID(f.runIDs[0]))
	again, err := WatchRunID("inbox", f.watcher.ledgers["inbox"], "a.txt")
	require.NoError(t, err)
	assert.Equal(t, f.runIDs[0], again)

	f.write("a.txt", "changed", f.now.Add(time.Minute))
	f.read()
	f.read()
	require.Len(t, f.runIDs, 2)
	assert.NotEqual(t, f.runIDs[0], f.runIDs[1], "another version of the file is another run")
}

// WatchRunID is the one way to name a file's run, and it names arrivals
// only: a file with no arrival, as one the folder held when it was first
// watched or one a version 1 record holds, has no run to name, and two
// arrivals of one version are two runs.
func TestWatchRunIDNeedsAnArrival(t *testing.T) {
	t.Parallel()

	mark := schedulerstate.FileMark{Size: 1, ModTime: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)}
	ledger := schedulerstate.WatchLedger{Path: "/srv/in", Files: map[string]schedulerstate.WatchedFile{"there.txt": {FileMark: mark}}}
	_, err := WatchRunID("inbox", ledger, "there.txt")
	assert.ErrorIs(t, err, errNoArrival)
	_, err = WatchRunID("inbox", ledger, "missing.txt")
	assert.ErrorIs(t, err, errNoArrival)
	unnamed := schedulerstate.WatchLedger{Path: "/srv/in", Arrivals: 1, Files: map[string]schedulerstate.WatchedFile{"a.txt": {FileMark: mark, Arrival: 1}}}
	_, err = WatchRunID("inbox", unnamed, "a.txt")
	assert.ErrorIs(t, err, errNoArrival, "an arrival from a ledger with no epoch")

	ledger.Arrive("a.txt", mark)
	first, err := WatchRunID("inbox", ledger, "a.txt")
	require.NoError(t, err)
	ledger.Arrive("a.txt", mark)
	second, err := WatchRunID("inbox", ledger, "a.txt")
	require.NoError(t, err)
	assert.NotEqual(t, first, second, "two arrivals of the same version")
	other, err := WatchRunID("outbox", ledger, "a.txt")
	require.NoError(t, err)
	assert.NotEqual(t, second, other, "the same arrival in another DAG")
}

// A DAG the entries leave out for a while, as one being edited is, keeps
// its record, so a file that arrives meanwhile runs once the DAG is back.
func TestWatchKeepsTheRecordWhileADAGIsAway(t *testing.T) {
	t.Parallel()

	f := newWatchFixture(t, "", nil)
	f.read()
	entry := f.entry
	f.entry = DAGEntry{}
	path := f.write("a.txt", "x", f.now)
	f.read()
	f.read()
	f.entry = entry
	f.read()
	f.read()
	assert.Equal(t, []string{WatchRuntimeParams(path)}, f.runs())
}

func TestWatchStartsOverWhenTheFolderChanges(t *testing.T) {
	t.Parallel()

	f := newWatchFixture(t, "", nil)
	f.read()
	other := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(other, "there.txt"), []byte("x"), 0o600))
	f.entry.DAG.Watch.Path = other
	f.read()
	f.read()
	f.read()
	assert.Empty(t, f.runs(), "the files a newly named folder holds are left alone")
}

func TestWatchRuntimeParamsQuoteThePath(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "請求書 2026.pdf")
	params := WatchRuntimeParams(path)
	assert.Equal(t, "WATCH_FILE="+strconv.Quote(path)+" WATCH_NAME="+strconv.Quote("請求書 2026.pdf"), params)
}

func TestReadFolderKeepsTheSizeAndTime(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	at := time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)
	path := filepath.Join(dir, "a.txt")
	require.NoError(t, os.WriteFile(path, []byte("hello"), 0o600))
	require.NoError(t, os.Chtimes(path, at, at))

	found, err := readFolder(dir, "")
	require.NoError(t, err)
	require.Len(t, found, 1)
	assert.True(t, found["a.txt"].Same(schedulerstate.FileMark{Size: 5, ModTime: at}), "%+v", found["a.txt"])

	_, err = readFolder(filepath.Join(dir, "missing"), "")
	require.Error(t, err)
}

// A reading must see a file gone for its return to be an arrival: one
// moved out and back between two readings, or while the scheduler was off,
// is the file the ledger already holds.
func TestWatchTakesAFileAsGoneOnlyWhenAReadingSawIt(t *testing.T) {
	t.Parallel()

	watchStore := store.NewWatchStateStore(testutil.NewMemoryBackend().Collection("watch"))
	f := newWatchFixture(t, "", watchStore)
	f.watcher.Start(contextDone())
	f.read()
	path := f.write("a.csv", "x", f.now)
	f.read()
	f.read()
	require.Len(t, f.runs(), 1)

	away := filepath.Join(t.TempDir(), "a.csv")
	require.NoError(t, os.Rename(path, away))
	require.NoError(t, os.Rename(away, path))
	f.read()
	f.read()
	assert.Len(t, f.runs(), 1, "no reading saw it gone")

	f = f.restart(func() {
		require.NoError(t, os.Rename(path, away))
		require.NoError(t, os.Rename(away, path))
	})
	f.read()
	f.read()
	assert.Len(t, f.runs(), 1, "it went and came back while the scheduler was off")

	// Gone at a reading, back while the scheduler was off: an arrival.
	require.NoError(t, os.Rename(path, away))
	f.read()
	f = f.restart(func() { require.NoError(t, os.Rename(away, path)) })
	f.read()
	assert.Len(t, f.runs(), 2, "a reading saw it gone before the restart")
}

// A folder that cannot be read says nothing about its files: none of them
// is taken as gone, so none runs again when the folder is back.
func TestWatchDoesNotTakeAnUnreadFolderAsEmpty(t *testing.T) {
	t.Parallel()

	f := newWatchFixture(t, "", nil)
	f.read()
	f.write("a.csv", "x", f.now)
	f.read()
	f.read()
	require.Len(t, f.runs(), 1)

	away := f.dir + ".away"
	require.NoError(t, os.Rename(f.dir, away))
	f.read()
	f.read()
	require.NoError(t, os.Rename(away, f.dir))
	f.read()
	f.read()
	assert.Len(t, f.runs(), 1)
	assert.Len(t, f.runIDs, 1, "nothing was queued again")
}

// failingWatchStore is a watch store whose saves, and loads, can be made
// to fail.
type failingWatchStore struct {
	schedulerstate.WatchStore
	mu       sync.Mutex
	fail     bool
	failLoad bool
}

func (s *failingWatchStore) setFailLoad(fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failLoad = fail
}

func (s *failingWatchStore) LoadWatch(ctx context.Context) (map[string]schedulerstate.WatchLedger, error) {
	s.mu.Lock()
	fail := s.failLoad
	s.mu.Unlock()
	if fail {
		return nil, assert.AnError
	}
	return s.WatchStore.LoadWatch(ctx)
}

func (s *failingWatchStore) setFail(fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = fail
}

func (s *failingWatchStore) SaveWatch(ctx context.Context, ledgers map[string]schedulerstate.WatchLedger) error {
	s.mu.Lock()
	fail := s.fail
	s.mu.Unlock()
	if fail {
		return assert.AnError
	}
	return s.WatchStore.SaveWatch(ctx, ledgers)
}

// The scheduler stops after queuing a file's run and before saving that it
// did: the restarted watcher queues the run again under the same run ID, so
// the queue holds one run, and it is not queued a third time.
func TestWatchQueuesAnArrivalOnceAcrossACrash(t *testing.T) {
	t.Parallel()

	watchStore := &failingWatchStore{WatchStore: store.NewWatchStateStore(testutil.NewMemoryBackend().Collection("watch"))}
	f := newWatchFixture(t, "", watchStore)
	enqueue := f.watcher.cfg.Enqueue
	f.watcher.cfg.Enqueue = func(ctx context.Context, entry DAGEntry, runID, params string) error {
		err := enqueue(ctx, entry, runID, params)
		// Nothing the watcher saves after this lands, as when it stops here.
		watchStore.setFail(true)
		return err
	}
	f.watcher.Start(contextDone())
	f.read()
	f.write("a.csv", "x", f.now)
	f.read()
	f.read()
	require.Len(t, f.runs(), 1)

	watchStore.setFail(false)
	again := f.restart()
	again.read()
	assert.Len(t, again.runs(), 1, "the queue already holds the run")
	require.Len(t, again.runIDs, 1, "the arrival was queued again")
	assert.Equal(t, f.runIDs[0], again.runIDs[0], "under the same run ID")
	again.read()
	again.read()
	assert.Len(t, again.runIDs, 1, "and recorded as queued")
}

// An arrival is not queued until it is saved: a run named after an arrival
// a restart would lose could be queued twice.
func TestWatchQueuesNothingItCouldNotSave(t *testing.T) {
	t.Parallel()

	watchStore := &failingWatchStore{WatchStore: store.NewWatchStateStore(testutil.NewMemoryBackend().Collection("watch"))}
	f := newWatchFixture(t, "", watchStore)
	f.watcher.Start(contextDone())
	f.read()
	watchStore.setFail(true)
	f.write("a.csv", "x", f.now)
	f.read()
	f.read()
	f.read()
	assert.Empty(t, f.runIDs, "nothing queued while the ledger cannot be saved")

	// The scheduler restarts before the store recovers: the arrival it could
	// not save is seen again, and runs once.
	watchStore.setFail(false)
	again := f.restart()
	again.read()
	again.read()
	assert.Len(t, again.runs(), 1)
	assert.Len(t, again.runIDs, 1)
}

// A file that arrived while the ledger could not be saved runs once the
// store takes the ledger again, without a restart.
func TestWatchQueuesAnArrivalOnceItIsSaved(t *testing.T) {
	t.Parallel()

	watchStore := &failingWatchStore{WatchStore: store.NewWatchStateStore(testutil.NewMemoryBackend().Collection("watch"))}
	f := newWatchFixture(t, "", watchStore)
	f.watcher.Start(contextDone())
	f.read()
	watchStore.setFail(true)
	f.write("a.csv", "x", f.now)
	f.read()
	f.read()
	require.Empty(t, f.runIDs)
	watchStore.setFail(false)
	f.read()
	assert.Len(t, f.runs(), 1)
}

// A ledger the store cannot read for a while is waited for, not started
// over: a ledger started over would take the file that arrived while the
// scheduler was off as already there, and be saved over the one it lost.
func TestWatchWaitsForALedgerItCannotLoad(t *testing.T) {
	t.Parallel()

	watchStore := &failingWatchStore{WatchStore: store.NewWatchStateStore(testutil.NewMemoryBackend().Collection("watch"))}
	f := newWatchFixture(t, "", watchStore)
	f.watcher.Start(contextDone())
	f.read()
	f.write("a.csv", "x", f.now)
	f.read()
	f.read()
	require.Len(t, f.runs(), 1)

	watchStore.setFailLoad(true)
	arrived := ""
	again := f.restart(func() { arrived = f.write("b.csv", "x", f.now) })
	again.read()
	again.read()
	assert.Len(t, again.runs(), 1, "nothing runs before the ledger is read")
	watchStore.setFailLoad(false)
	again.read()
	again.read()
	assert.Equal(t, []string{f.runs()[0], WatchRuntimeParams(arrived)}, again.runs(), "the file that arrived meanwhile runs, and only it")
}

// Two DAGs watching one folder each start a run for a file that arrives
// there, under their own ledgers.
func TestWatchTwoDAGsOnOneFolder(t *testing.T) {
	t.Parallel()

	f := newWatchFixture(t, "", nil)
	other := DAGEntry{DefinitionID: "copy.yaml", DAG: &ir.DAG{Name: "copy", Watch: &ir.WatchConfig{Path: f.dir, Interval: 10 * time.Second}}}
	f.watcher.cfg.Entries = func() []DAGEntry { return []DAGEntry{f.entry, other} }
	f.read()
	path := f.write("a.csv", "x", f.now)
	f.read()
	f.read()
	assert.Equal(t, []string{WatchRuntimeParams(path), WatchRuntimeParams(path)}, f.runs())
	assert.Len(t, f.queued, 2)
	assert.NotEqual(t, f.watcher.ledgers["inbox"].Epoch, f.watcher.ledgers["copy"].Epoch)
}

// Another spelling of the same folder is the same folder: its ledger is
// kept, so the files there do not run again and new ones run once.
func TestWatchKeepsTheLedgerForAnotherSpellingOfTheFolder(t *testing.T) {
	t.Parallel()

	f := newWatchFixture(t, "", nil)
	f.read()
	f.write("a.csv", "x", f.now)
	f.read()
	f.read()
	require.Len(t, f.runs(), 1)
	epoch := f.watcher.ledgers["inbox"].Epoch

	f.entry.DAG.Watch.Path = f.dir + string(filepath.Separator) + "."
	f.read()
	f.read()
	assert.Len(t, f.runs(), 1)
	assert.Equal(t, epoch, f.watcher.ledgers["inbox"].Epoch)
	f.write("b.csv", "x", f.now)
	f.read()
	f.read()
	assert.Len(t, f.runs(), 2)
}

// A file written under an in-progress name and renamed into place is one
// arrival, under its final name.
func TestWatchRunsAFileRenamedIntoPlaceOnce(t *testing.T) {
	t.Parallel()

	f := newWatchFixture(t, "", nil)
	f.read()
	partial := f.write("a.csv.part", "x", f.now)
	f.read()
	f.read()
	require.Empty(t, f.runs())
	final := filepath.Join(f.dir, "a.csv")
	require.NoError(t, os.Rename(partial, final))
	f.read()
	f.read()
	f.read()
	assert.Equal(t, []string{WatchRuntimeParams(final)}, f.runs())
}

// A ledger saved as version 1 holds files with no arrival, whose runs were
// queued then: none runs again, and a later arrival of one runs once.
func TestWatchCarriesOnFromAVersion1Ledger(t *testing.T) {
	t.Parallel()

	backend := testutil.NewMemoryBackend()
	col := backend.Collection("watch")
	f := newWatchFixture(t, "", store.NewWatchStateStore(col))
	path := f.write("a.csv", "x", f.now)
	v1, err := json.Marshal(map[string]any{"version": 1, "dags": map[string]any{
		"inbox": map[string]any{"path": f.dir, "files": map[string]any{"a.csv": map[string]any{"size": 1, "modTime": f.now}}},
	}})
	require.NoError(t, err)
	require.NoError(t, col.Put(context.Background(), &persis.Record{ID: "watch", Data: v1, CreatedAt: f.now, UpdatedAt: f.now}))
	f.watcher.Start(contextDone())
	f.read()
	f.read()
	assert.Empty(t, f.runs(), "the file version 1 recorded")

	away := filepath.Join(t.TempDir(), "a.csv")
	require.NoError(t, os.Rename(path, away))
	f.read()
	require.NoError(t, os.Rename(away, path))
	f.read()
	f.read()
	assert.Len(t, f.runs(), 1)
	assert.NotEmpty(t, f.watcher.ledgers["inbox"].Epoch)
}

// contextDone is a context that has already ended, so Start loads the
// ledger and returns without waiting on its ticker.
func contextDone() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// A file moved out of the folder, seen gone, and moved back unchanged is a
// second arrival: it starts a second run, though its size and time are the
// same as the first time.
func TestWatchRunsAFileThatCameBackUnchanged(t *testing.T) {
	t.Parallel()

	f := newWatchFixture(t, "", nil)
	f.read()
	path := f.write("a.csv", "x", f.now)
	f.read()
	f.read()
	require.Len(t, f.runs(), 1)

	away := filepath.Join(t.TempDir(), "a.csv")
	require.NoError(t, os.Rename(path, away))
	f.read()
	require.NoError(t, os.Rename(away, path))
	f.read()
	f.read()
	assert.Len(t, f.runs(), 2, "the file came back: a new arrival")
}
