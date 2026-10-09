// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func newJournal(t *testing.T) *Journal {
	t.Helper()
	clock := time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)
	return &Journal{Dir: filepath.Join(t.TempDir(), "receipts"), Now: func() time.Time {
		clock = clock.Add(time.Second)
		return clock
	}}
}

func testEntry(requestID string) Entry {
	return Entry{
		RequestID:     requestID,
		Operation:     OpRegister,
		JobID:         testJob,
		JobKey:        "collector",
		Version:       1,
		Step:          StepStaged,
		PackageDigest: testDigest,
		Session:       "cc2-s855054",
		Request:       json.RawMessage(`{"job_id":"` + testJob + `"}`),
	}
}

func testReceipt() Receipt {
	return Receipt{
		JobID: testJob, Version: 1, OwnerID: "own_X", ProjectID: "prj_X", MachineID: "mch_X",
		PackageDigest: testDigest, PackageDir: "/durable/packages/x",
		Service: json.RawMessage(`{"registration":"ready"}`),
	}
}

func TestJournalBeginIsExclusive(t *testing.T) {
	j := newJournal(t)

	e, err := j.Begin(testEntry("req-1"))
	require.NoError(t, err)
	assert.Equal(t, JournalSchema, e.Schema)
	assert.False(t, e.StartedAt.IsZero())

	_, err = j.Begin(testEntry("req-1"))
	require.ErrorContains(t, err, "already in the journal")

	// The first entry is untouched by the refused second one.
	got, err := j.Get("req-1")
	require.NoError(t, err)
	assert.Equal(t, e.StartedAt, got.StartedAt)
}

func TestJournalSaveAndPending(t *testing.T) {
	j := newJournal(t)
	first, err := j.Begin(testEntry("req-1"))
	require.NoError(t, err)
	_, err = j.Begin(testEntry("req-2"))
	require.NoError(t, err)

	first.Step = StepRejected
	first.Response = json.RawMessage(`{"code":"duplicate_job"}`)
	require.NoError(t, j.Save(first))

	pending, err := j.Pending()
	require.NoError(t, err)
	require.Len(t, pending, 2)
	assert.Equal(t, "req-1", pending[0].RequestID)
	assert.Equal(t, StepRejected, pending[0].Step)
	assert.JSONEq(t, `{"code":"duplicate_job"}`, string(pending[0].Response))
	assert.Equal(t, "req-2", pending[1].RequestID)
}

func TestJournalComplete(t *testing.T) {
	j := newJournal(t)
	e, err := j.Begin(testEntry("req-1"))
	require.NoError(t, err)

	// No receipt exists until the registration completes.
	_, err = j.Receipt(testJob, 1)
	require.ErrorIs(t, err, fs.ErrNotExist)

	r, err := j.Complete(e, testReceipt())
	require.NoError(t, err)
	assert.Equal(t, "req-1", r.RequestID)

	stored, err := j.Receipt(testJob, 1)
	require.NoError(t, err)
	assert.Equal(t, r.WrittenAt, stored.WrittenAt)
	assert.JSONEq(t, `{"registration":"ready"}`, string(stored.Service))

	// The entry moved from pending to the job's request history.
	pending, err := j.Pending()
	require.NoError(t, err)
	assert.Empty(t, pending)
	assert.FileExists(t, filepath.Join(j.Dir, testJob, "requests", "req-1.json"))

	receipts, err := j.Receipts(testJob)
	require.NoError(t, err)
	require.Len(t, receipts, 1)
}

// A crash after the receipt is written but before the entry is filed must not
// produce a second receipt when the registration is resumed.
func TestJournalCompleteIsRepeatable(t *testing.T) {
	j := newJournal(t)
	e, err := j.Begin(testEntry("req-1"))
	require.NoError(t, err)
	first, err := j.Complete(e, testReceipt())
	require.NoError(t, err)

	// Put the entry back as if the move had not happened.
	filed := filepath.Join(j.Dir, testJob, "requests", "req-1.json")
	require.NoError(t, os.Rename(filed, filepath.Join(j.Dir, "pending", "req-1.json")))

	again, err := j.Complete(e, testReceipt())
	require.NoError(t, err)
	assert.Equal(t, first.WrittenAt, again.WrittenAt)
	assert.FileExists(t, filed)

	// And once more with nothing left in pending.
	_, err = j.Complete(e, testReceipt())
	require.NoError(t, err)
}

func TestJournalCompleteRefusals(t *testing.T) {
	j := newJournal(t)
	e, err := j.Begin(testEntry("req-1"))
	require.NoError(t, err)

	wrong := testReceipt()
	wrong.Version = 2
	_, err = j.Complete(e, wrong)
	require.ErrorContains(t, err, "does not match journal entry")
	_, err = j.Receipt(testJob, 1)
	require.ErrorIs(t, err, fs.ErrNotExist)

	_, err = j.Complete(e, testReceipt())
	require.NoError(t, err)

	// A different request cannot replace the receipt of the same version.
	other, err := j.Begin(testEntry("req-2"))
	require.NoError(t, err)
	_, err = j.Complete(other, testReceipt())
	require.ErrorIs(t, err, ErrReceiptConflict)
	stored, err := j.Receipt(testJob, 1)
	require.NoError(t, err)
	assert.Equal(t, "req-1", stored.RequestID)
	// The losing entry stays pending as evidence.
	_, err = j.Get("req-2")
	require.NoError(t, err)
}
