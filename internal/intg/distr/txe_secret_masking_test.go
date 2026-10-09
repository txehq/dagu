// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// hubFilesContaining returns every file in the coordinator's own storage that
// contains needle. The worker in these tests is isolated, so its directories
// are not searched: only what reached the hub is. A file that cannot be read
// fails the test, because an unread file proves nothing about its content.
func hubFilesContaining(t *testing.T, f *testFixture, needle string) []string {
	t.Helper()
	paths := f.coord.Config.Paths
	var found []string
	for _, root := range []string{paths.DataDir, paths.LogDir, paths.ArtifactDir, paths.DAGsDir} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			// A storage directory the run never created holds nothing.
			if p == root && errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			if !d.Type().IsRegular() {
				return nil
			}
			data, err := os.ReadFile(p) //nolint:gosec // test directory
			if err != nil {
				return err
			}
			if bytes.Contains(data, []byte(needle)) {
				found = append(found, p)
			}
			return nil
		})
		require.NoError(t, err, "scan hub storage under %s", root)
	}
	return found
}

// hubLog returns the hub's copy of one log of the run: a step's "stdout" or
// "stderr" log, or the run's scheduler log when step is empty.
func hubLog(t *testing.T, f *testFixture, status ir.DAGRunStatus, step, stream string) string {
	t.Helper()
	name := "scheduler.log"
	if step != "" {
		name = fmt.Sprintf("%s.%s.log", step, stream)
	}
	var content string
	found := false
	err := filepath.WalkDir(filepath.Join(f.logDir(), status.Name, status.DAGRunID), func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Name() == name {
			content, found = getLogContent(t, p), true
		}
		return err
	})
	require.NoError(t, err)
	require.True(t, found, "the hub has no %s for the run", name)
	return content
}

// A secret the worker resolves from its own disk is masked in everything it
// sends to the coordinator: step stdout, step stderr and the run's scheduler
// log, on a successful step and on a failing one. The script still receives
// the real value.
//
// The credential files are written the way such files usually are: one ends
// with a newline, which a script strips before using the value, and one holds
// several lines.
func TestSecretMasking_StreamedStepOutput(t *testing.T) {
	if goruntime.GOOS == "windows" {
		t.Skip("the fixture scripts are POSIX shell")
	}
	const (
		credential = "txe-sentinel-credential-7f3a9c41d2"
		multiHead  = "txe-sentinel-multiline-head-91c4"
		multiTail  = "txe-sentinel-multiline-tail-b7e2"
	)

	// The credentials and the proof file live on the worker's side only.
	credentials := filepath.Join(t.TempDir(), "machine-credentials")
	require.NoError(t, os.MkdirAll(credentials, 0o700))
	tokenFile := filepath.Join(credentials, "fixture-token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(credential+"\n"), 0o600))
	multiFile := filepath.Join(credentials, "fixture-multiline")
	require.NoError(t, os.WriteFile(multiFile, []byte(multiHead+"\n"+multiTail+"\n"), 0o600))
	proof := filepath.Join(t.TempDir(), "worker-output", "proof")
	require.NoError(t, os.MkdirAll(filepath.Dir(proof), 0o700))

	f := newTestFixture(t, fmt.Sprintf(`
type: graph
name: secret-masking
worker_selector:
  test: "true"
env:
  - TOKEN_FILE: %q
  - PROOF_FILE: %q
secrets:
  - name: FIXTURE_TOKEN
    provider: file
    key: %q
  - name: FIXTURE_MULTILINE
    provider: file
    key: %q
steps:
  - name: print
    run: |
      token="$(printf '%%s' "$FIXTURE_TOKEN")"
      test "$token" = "$(cat "$TOKEN_FILE")" && echo match > "$PROOF_FILE"
      echo "line=$token end"
      echo "multi-begin"
      printf '%%s\n' "$FIXTURE_MULTILINE"
      echo "multi-end"
      printf 'stderr=%%s' "$token" >&2
      printf 'unterminated=%%s' "$token"
  - name: fail
    depends: [print]
    run: |
      token="$(printf '%%s' "$FIXTURE_TOKEN")"
      echo "about to fail with $token" >&2
      sh -c 'exit 3' fail "$token"
`, tokenFile, proof, tokenFile, multiFile), withLogPersistence(), withIsolatedWorker())
	defer f.cleanup()

	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(30 * time.Second)

	status := f.waitForStatus(ir.Failed, executionStatusTimeout())
	f.assertWorkerID(status, "worker-1")

	// The script was given the real value.
	got, err := os.ReadFile(proof)
	require.NoError(t, err)
	assert.Equal(t, "match\n", string(got))

	// Every stream arrived on the hub, masked: stdout with its unterminated
	// last line and the multi-line value, stderr, the failing step's stderr,
	// and the copy of the step output in the scheduler log. Without these, a
	// run that lost its output would pass the search below.
	stdout := hubLog(t, f, status, "print", "stdout")
	assert.Contains(t, stdout, "line=******* end\n")
	assert.Contains(t, stdout, "multi-begin\n*******\nmulti-end\n")
	assert.True(t, strings.HasSuffix(stdout, "unterminated=*******"), "stdout ends %q", stdout)
	assert.Equal(t, "stderr=*******", hubLog(t, f, status, "print", "stderr"))
	assert.Contains(t, hubLog(t, f, status, "fail", "stderr"), "about to fail with *******")
	schedulerLog := hubLog(t, f, status, "", "")
	assert.Contains(t, schedulerLog, "line=******* end")
	assert.Contains(t, schedulerLog, "about to fail with *******")

	// The search reads the hub's files: it finds the masked text it should.
	assert.NotEmpty(t, hubFilesContaining(t, f, "line=******* end"))

	// Nothing the hub stores holds any of the values.
	statusJSON, err := json.Marshal(status)
	require.NoError(t, err)
	for _, value := range []string{credential, multiHead, multiTail} {
		assert.Empty(t, hubFilesContaining(t, f, value), "%s was written to hub storage", value)
		assert.NotContains(t, string(statusJSON), value)
	}
}
