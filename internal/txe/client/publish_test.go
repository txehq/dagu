// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const deliverablesYAML = `  deliverables:
    - name: snapshot
      path: snapshot.json
      type: json
      delivery: hub
      required: true
    - name: raw
      path: raw/export.csv
      delivery: machine
    - name: notes
      path: notes.txt
`

// testExecution is the execution the fixture's run starts with: a first
// attempt, dispatched from a queue.
var testExecution = Execution{AttemptID: "4f6f15", QueuedAt: "2026-10-09T23:48:55+08:00"}

// hubCopies is where a publishing execution's hub copies are placed.
func hubCopies(in PublishInput) string {
	return filepath.Join(in.ArtifactDir, HubAttemptsDir, in.Execution.Ref())
}

// publishFixture registers the collector with three deliverables and returns
// what a run of it needs: the publisher, the run's identity and the directory
// its first execution writes to, begun as the job's step begins it. The test
// writes the job's files there and seals them with run.seal.
type publishRun struct {
	registry  *fakeRegistry
	publisher *Publisher
	in        PublishInput
	dir       string
}

// write puts a file where the executing job writes.
func (r publishRun) write(t *testing.T, rel, content string) {
	t.Helper()
	path := filepath.Join(r.dir, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

// seal ends the job's step as a successful one does, and returns where the
// execution's files are kept from then on.
func (r publishRun) seal(t *testing.T) string {
	t.Helper()
	seal, err := Outputs{Home: r.publisher.Home}.Seal(r.in.JobID, r.in.RunID, r.in.Execution)
	require.NoError(t, err)
	return txepkg.ExecutionOutputDir(r.publisher.Home.OutputDir(r.in.JobID), r.in.RunID, seal.Ref)
}

func publishFixture(t *testing.T) publishRun {
	t.Helper()
	return publishFixtureWith(t, deliverablesYAML)
}

func publishFixtureWith(t *testing.T, deliverables string) publishRun {
	t.Helper()
	f := newFakeRegistry(t)
	home := machineHome(t, f)
	_, dir := worktree(t, credentialFile(t))
	specPath := filepath.Join(dir, "job.yaml")
	text, err := os.ReadFile(specPath)
	require.NoError(t, err)
	withDeliverables := strings.Replace(string(text), "expected_outcome:\n", "expected_outcome:\n"+deliverables, 1)
	require.NoError(t, os.WriteFile(specPath, []byte(withDeliverables), 0o644)) //nolint:gosec // test file
	spec, err := LoadJobSpec(specPath)
	require.NoError(t, err)

	out, err := newSession(f, home, "cc1-s000001").Register(context.Background(), spec)
	require.NoError(t, err)
	// The registered DAG has the publish step and the artifact directory.
	if strings.Contains(deliverables, "delivery: hub") {
		assert.Contains(t, out.DAGSpec, "artifacts:\n  enabled: true\n")
	}
	assert.Contains(t, out.DAGSpec, "  - name: publish\n")
	assert.Contains(t, out.DAGSpec, filepath.Join(home.Root, "bin", "dagu")+" txe artifacts publish --dagu-home "+home.ClientDir())

	in := PublishInput{JobID: out.Receipt.JobID, JobVersion: 1, RunID: "run-0001", Execution: testExecution, ArtifactDir: filepath.Join(t.TempDir(), "dagu-artifacts")}
	runDir, err := Outputs{Home: home}.Begin(in.JobID, in.RunID, in.Execution)
	require.NoError(t, err)
	require.Equal(t, filepath.Join(home.OutputDir(in.JobID), "runs", in.RunID, "attempts", testExecution.AttemptID), runDir)
	p := &Publisher{Client: f.client(), Home: home, Actor: Actor{Kind: ActorKindCLI, ID: "publish", MachineID: testMachine}}
	return publishRun{registry: f, publisher: p, in: in, dir: runDir}
}

func filesUnder(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(root, path)
			files = append(files, filepath.ToSlash(rel))
		}
		return nil
	})
	require.NoError(t, err)
	return files
}

// A run's declared files are recorded with their digests. Only the one
// declared for the hub is copied to the artifact directory; everything stays
// on the machine; a file nobody declared is neither recorded nor copied.
func TestPublish(t *testing.T) {
	run := publishFixture(t)
	f, p, in := run.registry, run.publisher, run.in
	run.write(t, "snapshot.json", `{"files":2}`)
	run.write(t, "raw/export.csv", "a,b\n1,2\n")
	run.write(t, "undeclared.log", "not a deliverable")
	sealedDir := run.seal(t)
	assert.NoDirExists(t, run.dir, "the sealed outputs are still where the job wrote them")

	manifest, err := p.Publish(context.Background(), in)
	require.NoError(t, err)

	byName := map[string]ArtifactRecord{}
	for _, a := range manifest.Artifacts {
		byName[a.Deliverable] = a
	}
	require.Len(t, byName, 3)
	assert.Equal(t, DeliveryHub, byName["snapshot"].Location)
	assert.Equal(t, "sha256:"+hashOf([]byte(`{"files":2}`)), byName["snapshot"].SHA256)
	assert.Equal(t, int64(11), byName["snapshot"].Bytes)
	assert.Equal(t, DeliveryMachine, byName["raw"].Location)
	assert.Equal(t, testMachine, byName["raw"].MachineID)
	assert.True(t, byName["notes"].Missing, "an optional file the run did not write is recorded as missing")
	assert.Equal(t, testExecution, manifest.Execution)
	assert.Equal(t, testExecution, manifest.ProducedIn)

	// The artifact directory holds exactly the hub deliverable, byte for
	// byte, under the publishing execution's reference.
	assert.Equal(t, []string{HubAttemptsDir + "/" + testExecution.Ref() + "/snapshot.json"}, filesUnder(t, in.ArtifactDir))
	copied, err := os.ReadFile(filepath.Join(hubCopies(in), "snapshot.json"))
	require.NoError(t, err)
	assert.Equal(t, `{"files":2}`, string(copied))

	// Every file is still on the machine, under the execution's reference.
	assert.ElementsMatch(t, []string{"snapshot.json", "raw/export.csv", "undeclared.log"}, filesUnder(t, sealedDir))

	// The hub received the same manifest, and a repeated publish step sends
	// it again without conflict or change.
	assert.Equal(t, *manifest, f.manifests[in.JobID+"/"+in.RunID])
	again, err := p.Publish(context.Background(), in)
	require.NoError(t, err)
	assert.Equal(t, manifest.Artifacts[0].SHA256, again.Artifacts[0].SHA256)
	assert.Len(t, f.executions, 1)
}

// The body the registry receives names the execution with two plain fields
// and the producing execution as an object of the same two.
func TestManifestWireShape(t *testing.T) {
	data, err := json.Marshal(ArtifactManifest{JobVersion: 3, Execution: testExecution,
		ProducedIn: Execution{AttemptID: "45642f"}, Artifacts: []ArtifactRecord{}})
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, testExecution.AttemptID, got["attempt_id"])
	assert.Equal(t, testExecution.QueuedAt, got["queued_at"])
	// A run that was never queued sends the empty marker, not no marker.
	assert.Equal(t, map[string]any{"attempt_id": "45642f", "queued_at": ""}, got["produced_in"])
}

// The reference of an execution is the registry's: both sides compute the
// cases in the shared fixture, whose values were worked out independently.
func TestExecutionRef(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(fixturesDir, "execution-refs.json"))
	require.NoError(t, err)
	var cases struct {
		Cases []struct {
			Execution
			Ref string `json:"execution"`
		} `json:"cases"`
	}
	require.NoError(t, json.Unmarshal(data, &cases))
	require.NotEmpty(t, cases.Cases)
	seen := map[string]bool{}
	for _, c := range cases.Cases {
		assert.Equal(t, c.Ref, c.Execution.Ref(), "%+v", c.Execution)
		assert.NoError(t, CheckDeliverablePath("x/"+c.Ref), "a reference must be usable as a path name")
		assert.False(t, seen[c.Ref], "two executions share the reference %s", c.Ref)
		seen[c.Ref] = true
	}
}

// The run's output directory must be a real directory at every level. A run
// that points "runs", or the place sealed outputs are kept, at another
// directory publishes nothing.
func TestPublishRefusesLinkedRunDirectory(t *testing.T) {
	for _, name := range []string{"runs", "executions"} {
		t.Run(name, func(t *testing.T) {
			run := publishFixture(t)
			f, p, in := run.registry, run.publisher, run.in
			run.write(t, "snapshot.json", "{}")
			sealedDir := run.seal(t)

			target := filepath.Dir(sealedDir) // executions
			if name == "runs" {
				target = filepath.Dir(filepath.Dir(target))
			}
			require.Equal(t, name, filepath.Base(target))
			moved := filepath.Join(t.TempDir(), "moved")
			require.NoError(t, os.Rename(target, moved))
			require.NoError(t, os.Symlink(moved, target))

			_, err := p.Publish(context.Background(), in)
			require.ErrorContains(t, err, "symbolic link")
			assert.Empty(t, f.manifests)
			assert.NoDirExists(t, in.ArtifactDir)
		})
	}
}

// A link inside the artifact directory cannot send a copy somewhere else.
func TestPublishRefusesLinkedArtifactDirectory(t *testing.T) {
	spec := strings.Replace(deliverablesYAML, "delivery: machine", "delivery: hub", 1)
	run := publishFixtureWith(t, spec)
	p, in := run.publisher, run.in
	run.write(t, "snapshot.json", "{}")
	run.write(t, "raw/export.csv", "a,b\n")
	run.seal(t)

	elsewhere := t.TempDir()
	require.NoError(t, os.MkdirAll(hubCopies(in), 0o750))
	require.NoError(t, os.Symlink(elsewhere, filepath.Join(hubCopies(in), "raw")))

	_, err := p.Publish(context.Background(), in)
	require.Error(t, err)
	assert.Empty(t, filesUnder(t, elsewhere), "a deliverable was written outside the artifact directory")
}

// A required file the run did not write fails the step, after the gap has
// been recorded, and names the file and where it was expected.
func TestPublishMissingRequired(t *testing.T) {
	run := publishFixture(t)
	f, p, in := run.registry, run.publisher, run.in
	sealedDir := run.seal(t)

	manifest, err := p.Publish(context.Background(), in)
	require.ErrorIs(t, err, ErrDeliverableMissing)
	require.ErrorContains(t, err, "snapshot.json")
	require.ErrorContains(t, err, sealedDir)
	require.NotNil(t, manifest)

	recorded := f.manifests[in.JobID+"/"+in.RunID]
	require.Len(t, recorded.Artifacts, 3)
	for _, a := range recorded.Artifacts {
		assert.True(t, a.Missing)
		assert.Empty(t, a.SHA256)
	}
	assert.NoDirExists(t, in.ArtifactDir)

	// With only optional deliverables the same run publishes cleanly.
	optional := publishFixtureWith(t, "  deliverables:\n    - name: notes\n      path: notes.txt\n")
	optional.seal(t)
	manifest, err = optional.publisher.Publish(context.Background(), optional.in)
	require.NoError(t, err)
	require.Len(t, manifest.Artifacts, 1)
	assert.True(t, manifest.Artifacts[0].Missing)
}

// A run in which the job's step never succeeded has no result to describe.
// Files the job wrote before it failed are not published.
func TestPublishNotSealed(t *testing.T) {
	run := publishFixture(t)
	f, p, in := run.registry, run.publisher, run.in
	run.write(t, "snapshot.json", `{"files":2}`)

	manifest, err := p.Publish(context.Background(), in)
	require.ErrorIs(t, err, ErrNotSealed)
	assert.Nil(t, manifest)
	assert.Empty(t, f.manifests)
	assert.NoDirExists(t, in.ArtifactDir)

	in.RunID = "run-never"
	_, err = p.Publish(context.Background(), in)
	require.ErrorIs(t, err, ErrNotSealed)
}

// The artifact directory itself must be a real directory: a run cannot send
// its uploads elsewhere by putting a link in its place.
func TestPublishRefusesLinkAsArtifactDirectory(t *testing.T) {
	run := publishFixture(t)
	p, in := run.publisher, run.in
	run.write(t, "snapshot.json", "{}")
	run.seal(t)

	elsewhere := t.TempDir()
	require.NoError(t, os.Symlink(elsewhere, in.ArtifactDir))

	_, err := p.Publish(context.Background(), in)
	require.ErrorContains(t, err, "artifact directory")
	assert.Empty(t, filesUnder(t, elsewhere), "a deliverable was written outside the artifact directory")
}

// Copying one deliverable never removes another, whatever they are called,
// and leaves nothing behind but the declared files.
func TestPublishKeepsEveryDeliverable(t *testing.T) {
	run := publishFixtureWith(t, `  deliverables:
    - name: first
      path: report.txt.txe-partial
      delivery: hub
    - name: second
      path: report.txt
      delivery: hub
`)
	p, in := run.publisher, run.in
	run.write(t, "report.txt.txe-partial", "first")
	run.write(t, "report.txt", "second")
	run.seal(t)

	for range 2 { // a second publication of the same execution changes nothing
		_, err := p.Publish(context.Background(), in)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"report.txt", "report.txt.txe-partial"}, filesUnder(t, hubCopies(in)))
	}
	first, err := os.ReadFile(filepath.Join(hubCopies(in), "report.txt.txe-partial"))
	require.NoError(t, err)
	assert.Equal(t, "first", string(first))
}

// A handle is accepted only if it is the directory the name was seen to hold.
func TestOpenDirDetectsReplacement(t *testing.T) {
	base := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(base, "mine"), 0o700))
	require.NoError(t, os.Mkdir(filepath.Join(base, "other"), 0o700))
	root, err := os.OpenRoot(base)
	require.NoError(t, err)
	defer func() { _ = root.Close() }()

	mine, err := openDir(root, "mine")
	require.NoError(t, err)
	defer func() { _ = mine.Close() }()

	// What a swap between the check and the open would leave: a handle on
	// one directory and a name that holds another.
	other, err := root.Lstat("other")
	require.NoError(t, err)
	require.ErrorContains(t, sameDir(other, mine, "mine"), "replaced")

	require.NoError(t, os.Symlink("other", filepath.Join(base, "link")))
	_, err = openDir(root, "link")
	require.ErrorContains(t, err, "symbolic link")
	_, err = openDir(root, "absent")
	require.ErrorIs(t, err, fs.ErrNotExist)
}

// A declared name cannot be used to reach a file outside the execution's
// directory. A link the job left is not a file it produced: it is not
// sealed, so the deliverable is missing. A link put in a sealed file's place
// afterwards is refused.
func TestPublishRefusesLinks(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "private-key")
	require.NoError(t, os.WriteFile(outside, []byte("txe-sentinel-outside"), 0o600))

	t.Run("LinkLeftByTheJob", func(t *testing.T) {
		run := publishFixture(t)
		f, p, in := run.registry, run.publisher, run.in
		require.NoError(t, os.Symlink(outside, filepath.Join(run.dir, "snapshot.json")))
		run.seal(t)

		_, err := p.Publish(context.Background(), in)
		require.ErrorIs(t, err, ErrDeliverableMissing)
		assert.True(t, f.manifests[in.JobID+"/"+in.RunID].Artifacts[0].Missing)
		assert.NoDirExists(t, in.ArtifactDir)
	})
	t.Run("LinkPutThereAfterTheSeal", func(t *testing.T) {
		run := publishFixture(t)
		f, p, in := run.registry, run.publisher, run.in
		run.write(t, "snapshot.json", "{}")
		sealedDir := run.seal(t)
		require.NoError(t, os.Remove(filepath.Join(sealedDir, "snapshot.json")))
		require.NoError(t, os.Symlink(outside, filepath.Join(sealedDir, "snapshot.json")))

		_, err := p.Publish(context.Background(), in)
		require.ErrorContains(t, err, "symbolic link")
		assert.Empty(t, f.manifests)
		assert.NoDirExists(t, in.ArtifactDir)
	})
	t.Run("DirectoryIsLink", func(t *testing.T) {
		run := publishFixture(t)
		f, p, in := run.registry, run.publisher, run.in
		run.write(t, "snapshot.json", "{}")
		run.write(t, "raw/export.csv", "a,b\n")
		sealedDir := run.seal(t)
		elsewhere := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(elsewhere, "export.csv"), []byte("a,b\n"), 0o600))
		require.NoError(t, os.RemoveAll(filepath.Join(sealedDir, "raw")))
		require.NoError(t, os.Symlink(elsewhere, filepath.Join(sealedDir, "raw")))

		_, err := p.Publish(context.Background(), in)
		require.ErrorContains(t, err, "symbolic link")
		assert.Empty(t, f.manifests)
	})
}

// A hub deliverable needs the run's artifact directory; without one the step
// fails before recording anything, so the hub is never told of bytes it will
// not receive.
func TestPublishWithoutArtifactDir(t *testing.T) {
	run := publishFixture(t)
	f, p, in := run.registry, run.publisher, run.in
	run.write(t, "snapshot.json", "{}")
	run.seal(t)
	in.ArtifactDir = ""

	_, err := p.Publish(context.Background(), in)
	require.ErrorContains(t, err, "no artifact directory")
	assert.Empty(t, f.manifests)
}

// The seal fixes what an execution produced. A file that was changed after
// it, by a process the job left running for one, is not published; a file
// that appeared after it was not produced by the execution.
func TestPublishChangedAfterSeal(t *testing.T) {
	t.Run("Changed", func(t *testing.T) {
		run := publishFixture(t)
		f, p, in := run.registry, run.publisher, run.in
		run.write(t, "snapshot.json", `{"files":2}`)
		sealedDir := run.seal(t)
		require.NoError(t, os.WriteFile(filepath.Join(sealedDir, "snapshot.json"), []byte(`{"files":3}`), 0o600))

		manifest, err := p.Publish(context.Background(), in)
		require.ErrorIs(t, err, ErrChangedAfterSeal)
		assert.Nil(t, manifest)
		assert.Empty(t, f.manifests)
		assert.NoDirExists(t, in.ArtifactDir)
	})
	t.Run("SameSizeOtherBytes", func(t *testing.T) {
		run := publishFixture(t)
		run.write(t, "snapshot.json", `{"files":2}`)
		sealedDir := run.seal(t)
		require.NoError(t, os.WriteFile(filepath.Join(sealedDir, "snapshot.json"), []byte(`{"files":7}`), 0o600))

		_, err := run.publisher.Publish(context.Background(), run.in)
		require.ErrorIs(t, err, ErrChangedAfterSeal)
		assert.Empty(t, run.registry.manifests)
	})
	t.Run("AddedAfterwards", func(t *testing.T) {
		run := publishFixture(t)
		f, p, in := run.registry, run.publisher, run.in
		run.write(t, "snapshot.json", `{"files":2}`)
		sealedDir := run.seal(t)
		require.NoError(t, os.WriteFile(filepath.Join(sealedDir, "notes.txt"), []byte("late"), 0o600))

		_, err := p.Publish(context.Background(), in)
		require.NoError(t, err)
		for _, a := range f.manifests[in.JobID+"/"+in.RunID].Artifacts {
			if a.Deliverable == "notes" {
				assert.True(t, a.Missing, "a file added after the seal was published")
			}
		}
	})
}

// nextExecution runs the job again in the same run, as execution e, writing
// content, and seals it.
func (r publishRun) nextExecution(t *testing.T, e Execution, content string) PublishInput {
	t.Helper()
	next := r.in
	next.Execution = e
	outputs := Outputs{Home: r.publisher.Home}
	dir, err := outputs.Begin(next.JobID, next.RunID, e)
	require.NoError(t, err)
	assert.Empty(t, filesUnder(t, dir), "an execution started with an earlier one's files")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "snapshot.json"), []byte(content), 0o600))
	_, err = outputs.Seal(next.JobID, next.RunID, e)
	require.NoError(t, err)
	r.registry.setLatest(next.JobID, next.RunID, e)
	return next
}

// A retry in which the job runs again publishes its own manifest, and what
// the earlier execution produced stays as it was: on the machine, among the
// hub copies, and as a manifest. That holds for a retry with a new attempt
// ID, and for one through a queue, which keeps the attempt ID and differs
// only by its queue marker.
func TestPublishRetryKeepsEarlierExecution(t *testing.T) {
	for name, second := range map[string]Execution{
		"NewAttempt":                {AttemptID: "45642f", QueuedAt: testExecution.QueuedAt},
		"SameAttemptLaterMarker":    {AttemptID: testExecution.AttemptID, QueuedAt: "2026-10-09T15:48:58.155644Z"},
		"SameAttemptOneNanosecond":  {AttemptID: testExecution.AttemptID, QueuedAt: "2026-10-09T15:48:55.000000001Z"},
		"NewAttemptOfAnUnqueuedRun": {AttemptID: "45642f"},
	} {
		t.Run(name, func(t *testing.T) {
			run := publishFixture(t)
			f, p, first := run.registry, run.publisher, run.in
			run.write(t, "snapshot.json", `{"files":2}`)
			run.seal(t)
			_, err := p.Publish(context.Background(), first)
			require.NoError(t, err)

			next := run.nextExecution(t, second, `{"files":3}`)
			manifest, err := p.Publish(context.Background(), next)
			require.NoError(t, err)
			assert.Equal(t, second, manifest.Execution)
			assert.Equal(t, second, manifest.ProducedIn)
			require.NotEqual(t, first.Execution.Ref(), second.Ref())

			outputs := p.Home.OutputDir(first.JobID)
			for _, c := range []struct {
				e    Execution
				want string
			}{{first.Execution, `{"files":2}`}, {second, `{"files":3}`}} {
				recorded, ok := f.executions[first.JobID+"/"+first.RunID+"/"+c.e.Ref()]
				require.True(t, ok, "no manifest for execution %s", c.e.Ref())
				assert.Equal(t, "sha256:"+hashOf([]byte(c.want)), recorded.Artifacts[0].SHA256)

				onHub, err := os.ReadFile(filepath.Join(first.ArtifactDir, HubAttemptsDir, c.e.Ref(), "snapshot.json"))
				require.NoError(t, err)
				assert.Equal(t, c.want, string(onHub), "hub copy of execution %s", c.e.Ref())

				onMachine, err := os.ReadFile(filepath.Join(txepkg.ExecutionOutputDir(outputs, first.RunID, c.e.Ref()), "snapshot.json"))
				require.NoError(t, err)
				assert.Equal(t, c.want, string(onMachine), "machine copy of execution %s", c.e.Ref())
			}
		})
	}
}

// A retry that runs only the publish step did not execute the job. It
// publishes the latest sealed execution's files under its own reference and
// says which execution produced them.
func TestPublishOnlyRetry(t *testing.T) {
	for name, publisher := range map[string]Execution{
		"NewAttempt":             {AttemptID: "dd13aa", QueuedAt: testExecution.QueuedAt},
		"SameAttemptLaterMarker": {AttemptID: testExecution.AttemptID, QueuedAt: "2026-10-09T15:49:03.5Z"},
	} {
		t.Run(name, func(t *testing.T) {
			run := publishFixture(t)
			f, p, in := run.registry, run.publisher, run.in
			run.write(t, "snapshot.json", `{"files":2}`)
			run.seal(t)

			in.Execution = publisher
			// The worker gives every execution an empty artifact directory.
			in.ArtifactDir = filepath.Join(t.TempDir(), "dagu-artifacts")
			f.setLatest(in.JobID, in.RunID, publisher)

			manifest, err := p.Publish(context.Background(), in)
			require.NoError(t, err)
			assert.Equal(t, publisher, manifest.Execution)
			assert.Equal(t, testExecution, manifest.ProducedIn)
			assert.Equal(t, "sha256:"+hashOf([]byte(`{"files":2}`)), manifest.Artifacts[0].SHA256)
			assert.Equal(t, []string{HubAttemptsDir + "/" + publisher.Ref() + "/snapshot.json"}, filesUnder(t, in.ArtifactDir))
			assert.NoDirExists(t, txepkg.ExecutionOutputDir(p.Home.OutputDir(in.JobID), in.RunID, publisher.Ref()),
				"a publish-only retry made an output directory")
		})
	}
}

// An execution that sealed its own outputs publishes those, even when a
// later execution has sealed since. It never takes another's result as its
// own.
func TestPublishOwnSealNotTheLatest(t *testing.T) {
	run := publishFixture(t)
	f, p, first := run.registry, run.publisher, run.in
	run.write(t, "snapshot.json", `{"files":2}`)
	run.seal(t)
	run.nextExecution(t, Execution{AttemptID: "45642f", QueuedAt: testExecution.QueuedAt}, `{"files":3}`)
	// The hub is not consulted about which execution is the latest here: the
	// point is what the publisher itself would send.
	delete(f.latest, first.JobID+"/"+first.RunID)

	manifest, err := p.Publish(context.Background(), first)
	require.NoError(t, err)
	assert.Equal(t, first.Execution, manifest.ProducedIn)
	assert.Equal(t, "sha256:"+hashOf([]byte(`{"files":2}`)), manifest.Artifacts[0].SHA256)
}

// A publication that arrives from an execution the run has moved on from is
// refused by the hub, whether the run moved on to another attempt or to a
// later marker of the same one. Nothing is placed for upload and no manifest
// is filed.
func TestPublishDelayedExecutionIsRefused(t *testing.T) {
	for name, latest := range map[string]Execution{
		"NewAttempt":             {AttemptID: "45642f", QueuedAt: testExecution.QueuedAt},
		"SameAttemptLaterMarker": {AttemptID: testExecution.AttemptID, QueuedAt: "2026-10-09T15:48:58.155644Z"},
	} {
		t.Run(name, func(t *testing.T) {
			run := publishFixture(t)
			f, p, in := run.registry, run.publisher, run.in
			run.write(t, "snapshot.json", `{"files":2}`)
			run.seal(t)
			f.setLatest(in.JobID, in.RunID, latest)

			_, err := p.Publish(context.Background(), in)
			assert.True(t, IsCode(err, "stale_binding"), "got %v", err)
			assert.Empty(t, f.manifests)
			assert.Empty(t, f.executions)
			assert.NoDirExists(t, in.ArtifactDir)
		})
	}
}

// An execution is sealed once and does not begin again once sealed. An
// execution that failed is not sealed: the job may run again in the same
// attempt, each time in an empty directory, and what it left is kept.
func TestExecutionSeal(t *testing.T) {
	run := publishFixture(t)
	in := run.in
	outputs := Outputs{Home: run.publisher.Home}
	run.write(t, "snapshot.json", `{"files":2}`)
	sealedDir := run.seal(t)

	_, err := outputs.Begin(in.JobID, in.RunID, in.Execution)
	require.ErrorIs(t, err, ErrExecutionSealed)
	_, err = outputs.Seal(in.JobID, in.RunID, in.Execution)
	require.ErrorIs(t, err, ErrExecutionSealed)
	kept, err := os.ReadFile(filepath.Join(sealedDir, "snapshot.json"))
	require.NoError(t, err)
	assert.Equal(t, `{"files":2}`, string(kept))

	other := Execution{AttemptID: "45642f", QueuedAt: in.Execution.QueuedAt}
	_, err = outputs.Seal(in.JobID, in.RunID, other)
	require.ErrorIs(t, err, fs.ErrNotExist, "an execution that never began was sealed")
	seal, err := outputs.Sealed(in.JobID, in.RunID)
	require.NoError(t, err)
	assert.Equal(t, in.Execution, seal.Execution)
	assert.Equal(t, []SealedFile{{Path: "snapshot.json", SHA256: "sha256:" + hashOf([]byte(`{"files":2}`)), Bytes: 11}}, seal.Files)

	// Three tries of the job in one attempt: a step's own retries, or a
	// queued retry after a failure.
	runRoot := filepath.Dir(filepath.Dir(run.dir))
	for n, wrote := range []string{"first try", "second try", ""} {
		dir, err := outputs.Begin(in.JobID, in.RunID, other)
		require.NoError(t, err)
		assert.Empty(t, filesUnder(t, dir), "try %d started with files", n+1)
		if wrote != "" {
			require.NoError(t, os.WriteFile(filepath.Join(dir, "snapshot.json"), []byte(wrote), 0o600))
		}
	}
	_, err = outputs.Begin(in.JobID, in.RunID, other) // a try that wrote nothing leaves nothing to keep
	require.NoError(t, err)
	for name, want := range map[string]string{"45642f.1": "first try", "45642f.2": "second try"} {
		kept, err := os.ReadFile(filepath.Join(runRoot, "unsealed", name, "snapshot.json"))
		require.NoError(t, err)
		assert.Equal(t, want, string(kept))
	}
	assert.NoDirExists(t, filepath.Join(runRoot, "unsealed", "45642f.3"))

	_, err = outputs.Sealed(in.JobID, "run-never")
	require.ErrorIs(t, err, ErrNotSealed)
}

// An execution is named by an attempt ID and a queue marker as Dagu hands
// them over. Anything else is refused before a directory is made from it.
func TestExecutionNames(t *testing.T) {
	run := publishFixture(t)
	outputs := Outputs{Home: run.publisher.Home}
	for _, bad := range []Execution{
		{AttemptID: ""}, {AttemptID: "../x"}, {AttemptID: "a/b"}, {AttemptID: ".hidden"}, {AttemptID: "a b"},
		{AttemptID: "ok", QueuedAt: "${context.attempt.queued_at}"},
		{AttemptID: "ok", QueuedAt: "2026-10-09T15:48:58,5Z"},
		{AttemptID: "ok", QueuedAt: "2026-10-09 15:48:58"},
		{AttemptID: "ok", QueuedAt: "$(id)"},
		{AttemptID: "ok", QueuedAt: "../../x"},
	} {
		_, err := outputs.Begin(run.in.JobID, run.in.RunID, bad)
		require.Error(t, err, "%+v", bad)
		_, err = outputs.Seal(run.in.JobID, run.in.RunID, bad)
		require.Error(t, err, "%+v", bad)
	}
	_, err := outputs.Begin(run.in.JobID, run.in.RunID, Execution{AttemptID: "ok", QueuedAt: "${context.attempt.queued_at}"})
	require.ErrorContains(t, err, "was not resolved")
	// A run that was never queued has an empty marker, and that is a name.
	_, err = outputs.Begin(run.in.JobID, run.in.RunID, Execution{AttemptID: "never-queued"})
	require.NoError(t, err)
}

// One file holds every seal of a run. A seal that was interrupted after the
// outputs were moved and before it was recorded leaves a directory without a
// seal; the next seal of that execution keeps it aside and does not take it
// for its own.
func TestSealsAreOneRecord(t *testing.T) {
	run := publishFixture(t)
	in := run.in
	outputs := Outputs{Home: run.publisher.Home}
	runRoot := filepath.Dir(filepath.Dir(run.dir))

	// An interrupted seal: the directory is under the reference, no record.
	stray := filepath.Join(runRoot, "executions", in.Execution.Ref())
	require.NoError(t, os.MkdirAll(stray, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(stray, "snapshot.json"), []byte("interrupted"), 0o600))
	_, err := outputs.Sealed(in.JobID, in.RunID)
	require.ErrorIs(t, err, ErrNotSealed)
	_, err = run.publisher.Publish(context.Background(), in)
	require.ErrorIs(t, err, ErrNotSealed, "files without a seal were published")

	run.write(t, "snapshot.json", "sealed")
	sealedDir := run.seal(t)
	got, err := os.ReadFile(filepath.Join(sealedDir, "snapshot.json"))
	require.NoError(t, err)
	assert.Equal(t, "sealed", string(got))
	kept, err := os.ReadFile(filepath.Join(runRoot, "unsealed", in.Execution.Ref()+".1", "snapshot.json"))
	require.NoError(t, err)
	assert.Equal(t, "interrupted", string(kept))

	run.nextExecution(t, Execution{AttemptID: "45642f", QueuedAt: in.Execution.QueuedAt}, "second")
	data, err := os.ReadFile(filepath.Join(runRoot, "seals.json"))
	require.NoError(t, err)
	var record struct {
		Seals []struct {
			Ref string `json:"execution"`
		} `json:"seals"`
	}
	require.NoError(t, json.Unmarshal(data, &record))
	require.Len(t, record.Seals, 2)
	assert.Equal(t, in.Execution.Ref(), record.Seals[0].Ref)
	entries, err := os.ReadDir(runRoot)
	require.NoError(t, err)
	for _, e := range entries {
		assert.NotContains(t, e.Name(), ".txe-partial-", "a partial seal record was left behind")
	}

	// A record that names another run, or a seal whose reference is not its
	// execution's, is not trusted.
	require.NoError(t, os.WriteFile(filepath.Join(runRoot, "seals.json"),
		[]byte(strings.Replace(string(data), in.Execution.Ref(), "4f6f15-0000000000000000", 1)), 0o600))
	_, err = outputs.Sealed(in.JobID, in.RunID)
	require.ErrorContains(t, err, "does not name its execution")
}

// The directories of a run are real directories. A link standing for any of
// them is not followed.
func TestExecutionRefusesLinks(t *testing.T) {
	elsewhere := t.TempDir()
	for _, name := range []string{"attempts", "executions", "unsealed"} {
		t.Run(name, func(t *testing.T) {
			run := publishFixture(t)
			in := run.in
			run.write(t, "snapshot.json", "{}")
			runRoot := filepath.Dir(filepath.Dir(run.dir))
			outputs := Outputs{Home: run.publisher.Home}
			if name != "attempts" {
				// A second try, so that the first one's files are set aside.
				require.NoError(t, os.RemoveAll(filepath.Join(runRoot, name)))
				require.NoError(t, os.Symlink(elsewhere, filepath.Join(runRoot, name)))
				var err error
				if name == "unsealed" {
					_, err = outputs.Begin(in.JobID, in.RunID, in.Execution)
				} else {
					_, err = outputs.Seal(in.JobID, in.RunID, in.Execution)
				}
				require.ErrorContains(t, err, "symbolic link")
			} else {
				require.NoError(t, os.RemoveAll(filepath.Join(runRoot, name)))
				require.NoError(t, os.Symlink(elsewhere, filepath.Join(runRoot, name)))
				_, err := outputs.Begin(in.JobID, in.RunID, Execution{AttemptID: "45642f"})
				require.ErrorContains(t, err, "symbolic link")
			}
			assert.Empty(t, filesUnder(t, elsewhere))
		})
	}
}

// The CLI and the registry run the same accepted and refused paths.
func TestCheckDeliverablePath(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(fixturesDir, "deliverable-paths.json"))
	require.NoError(t, err)
	var cases struct {
		Accepted []string `json:"accepted"`
		Refused  []struct {
			Path string `json:"path"`
			Why  string `json:"why"`
		} `json:"refused"`
	}
	require.NoError(t, json.Unmarshal(data, &cases))
	require.NotEmpty(t, cases.Accepted)
	require.NotEmpty(t, cases.Refused)

	for _, ok := range cases.Accepted {
		require.NoError(t, CheckDeliverablePath(ok), "%q", ok)
	}
	for _, bad := range cases.Refused {
		require.Error(t, CheckDeliverablePath(bad.Path), "%q (%s)", bad.Path, bad.Why)
	}
}

// A spec cannot declare a deliverable outside the run's directory or twice.
func TestJobSpecDeliverableRules(t *testing.T) {
	_, dir := worktree(t, credentialFile(t))
	specPath := filepath.Join(dir, "job.yaml")
	text, err := os.ReadFile(specPath)
	require.NoError(t, err)
	bad := "  deliverables:\n    - {name: a, path: ../../etc/passwd}\n    - {name: a, path: ok.txt}\n    - {name: B, path: x, delivery: everywhere}\n"
	require.NoError(t, os.WriteFile(specPath, []byte(strings.Replace(string(text), "expected_outcome:\n", "expected_outcome:\n"+bad, 1)), 0o644)) //nolint:gosec // test file

	_, err = LoadJobSpec(specPath)
	var missing *MissingContextError
	require.ErrorAs(t, err, &missing)
	joined := strings.Join(missing.Problems, "\n")
	assert.Contains(t, joined, `".."`)
	assert.Contains(t, joined, `"a" is used twice`)
	assert.Contains(t, joined, "deliverables[2].name")
	assert.Contains(t, joined, `delivery must be "machine" or "hub"`)
}

// The examples shipped with the skill are complete job specs whose packages
// build, so a session that copies one starts from something that registers.
func TestSkillExamplesAreValid(t *testing.T) {
	examples := filepath.Join("..", "..", "..", "txe", "skill", "examples")
	for _, name := range []string{"healthcheck", "collector", "validation"} {
		t.Run(name, func(t *testing.T) {
			spec, err := LoadJobSpec(filepath.Join(examples, name, "job.yaml"))
			require.NoError(t, err)

			f := newFakeRegistry(t)
			home := machineHome(t, f)
			plan, err := newSession(f, home, "cc1-s000001").Plan(context.Background(), spec)
			require.NoError(t, err)
			assert.NotEmpty(t, plan.Manifest.Files)
			assert.Contains(t, plan.DAGSpec, "type: chain\n")
			assert.Zero(t, f.jobCount(), "a plan registers nothing")
		})
	}
}
