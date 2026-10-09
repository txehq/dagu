// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

// publishFixture registers the collector with three deliverables and returns
// what a run of it needs: the publisher, the run's identity and the run's own
// output directory.
type publishRun struct {
	registry  *fakeRegistry
	publisher *Publisher
	in        PublishInput
	dir       string
}

func publishFixture(t *testing.T) publishRun {
	t.Helper()
	f := newFakeRegistry(t)
	home := machineHome(t, f)
	_, dir := worktree(t, credentialFile(t))
	specPath := filepath.Join(dir, "job.yaml")
	text, err := os.ReadFile(specPath)
	require.NoError(t, err)
	withDeliverables := strings.Replace(string(text), "expected_outcome:\n", "expected_outcome:\n"+deliverablesYAML, 1)
	require.NoError(t, os.WriteFile(specPath, []byte(withDeliverables), 0o644)) //nolint:gosec // test file
	spec, err := LoadJobSpec(specPath)
	require.NoError(t, err)

	out, err := newSession(f, home, "cc1-s000001").Register(context.Background(), spec)
	require.NoError(t, err)
	// The registered DAG has the publish step and the artifact directory.
	assert.Contains(t, out.DAGSpec, "artifacts:\n  enabled: true\n")
	assert.Contains(t, out.DAGSpec, "  - name: publish\n")
	assert.Contains(t, out.DAGSpec, filepath.Join(home.Root, "bin", "dagu")+" txe artifacts publish --dagu-home "+home.ClientDir())

	in := PublishInput{JobID: out.Receipt.JobID, JobVersion: 1, RunID: "run-0001", ArtifactDir: filepath.Join(t.TempDir(), "dagu-artifacts")}
	runDir := filepath.Join(home.OutputDir(in.JobID), "runs", in.RunID)
	require.NoError(t, os.MkdirAll(filepath.Join(runDir, "raw"), 0o700))
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
	f, p, in, runDir := run.registry, run.publisher, run.in, run.dir
	require.NoError(t, os.WriteFile(filepath.Join(runDir, "snapshot.json"), []byte(`{"files":2}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(runDir, "raw", "export.csv"), []byte("a,b\n1,2\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(runDir, "undeclared.log"), []byte("not a deliverable"), 0o600))

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

	// The artifact directory holds exactly the hub deliverable, byte for byte.
	assert.Equal(t, []string{"snapshot.json"}, filesUnder(t, in.ArtifactDir))
	copied, err := os.ReadFile(filepath.Join(in.ArtifactDir, "snapshot.json"))
	require.NoError(t, err)
	assert.Equal(t, `{"files":2}`, string(copied))

	// Every file is still on the machine.
	assert.ElementsMatch(t, []string{"snapshot.json", "raw/export.csv", "undeclared.log"}, filesUnder(t, runDir))

	// The hub received the same manifest, and a step retry sends it again
	// without conflict.
	assert.Equal(t, *manifest, f.manifests[in.JobID+"/"+in.RunID])
	_, err = p.Publish(context.Background(), in)
	require.NoError(t, err)

	// A different file under an already recorded name is refused by the hub.
	require.NoError(t, os.WriteFile(filepath.Join(runDir, "snapshot.json"), []byte(`{"files":3}`), 0o600))
	_, err = p.Publish(context.Background(), in)
	assert.True(t, IsCode(err, "artifact_conflict"), "got %v", err)
}

// A required file the run did not write fails the step, after the gap has
// been recorded, and names the file and where it was expected.
func TestPublishMissingRequired(t *testing.T) {
	run := publishFixture(t)
	f, p, in, runDir := run.registry, run.publisher, run.in, run.dir

	manifest, err := p.Publish(context.Background(), in)
	require.ErrorIs(t, err, ErrDeliverableMissing)
	require.ErrorContains(t, err, "snapshot.json")
	require.ErrorContains(t, err, runDir)
	require.NotNil(t, manifest)

	recorded := f.manifests[in.JobID+"/"+in.RunID]
	require.Len(t, recorded.Artifacts, 3)
	for _, a := range recorded.Artifacts {
		assert.True(t, a.Missing)
		assert.Empty(t, a.SHA256)
	}
	assert.NoDirExists(t, in.ArtifactDir)
}

// A declared name cannot be used to reach a file outside the run's directory.
func TestPublishRefusesLinks(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "private-key")
	require.NoError(t, os.WriteFile(outside, []byte("txe-sentinel-outside"), 0o600))

	t.Run("FileIsLink", func(t *testing.T) {
		run := publishFixture(t)
		f, p, in, runDir := run.registry, run.publisher, run.in, run.dir
		require.NoError(t, os.Symlink(outside, filepath.Join(runDir, "snapshot.json")))

		_, err := p.Publish(context.Background(), in)
		require.ErrorContains(t, err, "symbolic link")
		assert.Empty(t, f.manifests)
		assert.NoFileExists(t, filepath.Join(in.ArtifactDir, "snapshot.json"))
	})
	t.Run("DirectoryIsLink", func(t *testing.T) {
		run := publishFixture(t)
		f, p, in, runDir := run.registry, run.publisher, run.in, run.dir
		require.NoError(t, os.WriteFile(filepath.Join(runDir, "snapshot.json"), []byte("{}"), 0o600))
		require.NoError(t, os.Remove(filepath.Join(runDir, "raw")))
		elsewhere := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(elsewhere, "export.csv"), []byte("txe-sentinel-outside"), 0o600))
		require.NoError(t, os.Symlink(elsewhere, filepath.Join(runDir, "raw")))

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
	f, p, in, runDir := run.registry, run.publisher, run.in, run.dir
	require.NoError(t, os.WriteFile(filepath.Join(runDir, "snapshot.json"), []byte("{}"), 0o600))
	in.ArtifactDir = ""

	_, err := p.Publish(context.Background(), in)
	require.ErrorContains(t, err, "no artifact directory")
	assert.Empty(t, f.manifests)
}

func TestCheckDeliverablePath(t *testing.T) {
	for _, ok := range []string{"snapshot.json", "raw/export.csv", "a-b_c.1/d"} {
		require.NoError(t, CheckDeliverablePath(ok), ok)
	}
	for _, bad := range []string{"", "/etc/passwd", "~/x", "../x", "a/../../x", "a/./b", "a//b", "*.json", "snap?.json", "a/$HOME", "a`id`", `a\b`, "a\nb"} {
		require.Error(t, CheckDeliverablePath(bad), "%q", bad)
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
