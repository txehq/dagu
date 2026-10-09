// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fixturesDir holds the registration contract examples shared with the
// registry's owner.
var fixturesDir = filepath.Join("..", "..", "..", "txe", "contract", "fixtures", "registration")

// The request fixtures are the bytes this client sends, with machine-specific
// paths and the package digest replaced by fixed values. Run with
// TXE_UPDATE_FIXTURES=1 to rewrite them after a deliberate change, and tell
// the registry's owner.
func TestContractFixtures(t *testing.T) {
	f := newFakeRegistry(t)
	home := machineHome(t, f)
	credential := credentialFile(t)
	_, dir := worktree(t, credential)
	specPath := filepath.Join(dir, "job.yaml")
	text, err := os.ReadFile(specPath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(specPath, []byte(strings.Replace(string(text), "expected_outcome:\n", "expected_outcome:\n"+deliverablesYAML, 1)), 0o644)) //nolint:gosec // test file
	spec, err := LoadJobSpec(specPath)
	require.NoError(t, err)

	next := 0
	ids := func(prefix string) (string, error) {
		next++
		return fmt.Sprintf("%s_01K7A5ZQ8M3N4P5R6S7T8V9W%02d", prefix, next), nil
	}
	cc1 := newSession(f, home, "cc1-s000001")
	cc1.NewID = ids
	cc2 := newSession(f, home, "cc2-s000002")
	cc2.NewID = ids

	// register -> ready, a second registration of the same key, a stale
	// update, and one published run.
	out, err := cc1.Register(context.Background(), spec)
	require.NoError(t, err)
	f.beforeList = nil
	duplicate := *spec
	_, err = (&session{Registrar: cc2.Registrar}).registerWithoutLookup(context.Background(), &duplicate)
	require.Error(t, err)
	_, err = cc2.Update(context.Background(), out.Receipt.JobID, 7, spec)
	require.Error(t, err)

	run := PublishInput{JobID: out.Receipt.JobID, JobVersion: 1, RunID: "034cuGtOyTL7YCuMha4uBd", Execution: testExecution, ArtifactDir: filepath.Join(t.TempDir(), "artifacts")}
	outputs := Outputs{Home: home}
	runDir, err := outputs.Begin(run.JobID, run.RunID, run.Execution)
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(runDir, "raw"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(runDir, "snapshot.json"), []byte(`{"files":2}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(runDir, "raw", "export.csv"), []byte("a,b\n1,2\n"), 0o600))
	_, err = outputs.Seal(run.JobID, run.RunID, run.Execution)
	require.NoError(t, err)
	publisher := &Publisher{Client: f.client(), Home: home, Now: func() time.Time { return time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC) },
		Actor: Actor{Kind: ActorKindCLI, ID: "publish", MachineID: testMachine, Client: "dagu test"}}
	_, err = publisher.Publish(context.Background(), run)
	require.NoError(t, err)

	resolvedDir, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	specHash := regexp.MustCompile(`"dag_spec_sha256": "[0-9a-f]{64}"`)
	manifestHash := regexp.MustCompile(`"manifest_sha256": "[0-9a-f]{64}"`)
	digest := regexp.MustCompile(`sha256[:-][0-9a-f]{64}`)
	short := regexp.MustCompile(`sha256-[0-9a-f]{32}\b`)
	normalize := func(data []byte) []byte {
		var pretty bytes.Buffer
		require.NoError(t, json.Indent(&pretty, data, "", "  "))
		s := pretty.String()
		// The resolved form of the source directory comes first: it contains
		// the unresolved one.
		for _, pair := range [][2]string{
			{resolvedDir, "/Users/connor/work/example"},
			{dir, "/Users/connor/work/example"},
			{home.Root, "/Users/connor/.local/share/txe-dagu"},
			{credential, "/Users/connor/.config/txe/linear-token"},
		} {
			s = strings.ReplaceAll(s, pair[0], pair[1])
		}
		s = specHash.ReplaceAllString(s, `"dag_spec_sha256": "`+strings.Repeat("fedcba9876543210", 4)+`"`)
		s = manifestHash.ReplaceAllString(s, `"manifest_sha256": "`+strings.Repeat("0123456789abcdef", 4)+`"`)
		s = digest.ReplaceAllStringFunc(s, func(m string) string { return m[:7] + strings.Repeat("0123456789abcdef", 4) })
		s = short.ReplaceAllString(s, "sha256-"+strings.Repeat("0123456789abcdef", 2))
		return []byte(s + "\n")
	}

	want := map[string]struct {
		method, suffix string
		status         int
		response       bool
	}{
		"project.ensure.request.json":                {http.MethodPost, "/txe/projects", 200, false},
		"project.ensure.response.200.json":           {http.MethodPost, "/txe/projects", 200, true},
		"register.request.json":                      {http.MethodPost, "/txe/jobs", 201, false},
		"register.response.201.json":                 {http.MethodPost, "/txe/jobs", 201, true},
		"register.response.409.duplicate.json":       {http.MethodPost, "/txe/jobs", 409, true},
		"ready.request.json":                         {http.MethodPost, "/ready", 200, false},
		"ready.response.200.json":                    {http.MethodPost, "/ready", 200, true},
		"version.request.json":                       {http.MethodPost, "/versions", 409, false},
		"version.response.409.version_conflict.json": {http.MethodPost, "/versions", 409, true},
		"artifacts.publish.request.json":             {http.MethodPost, "/artifacts", 200, false},
		"installation.response.200.json":             {http.MethodGet, "/txe/installation", 200, true},
	}
	_, err = f.client().Installation(context.Background())
	require.NoError(t, err)

	for name, sel := range want {
		var got []byte
		for _, r := range f.requests {
			if r.Method == sel.method && strings.HasSuffix(r.Path, sel.suffix) && r.Status == sel.status {
				got = r.Body
				if sel.response {
					got = r.Response
				}
				break
			}
		}
		require.NotNil(t, got, "no exchange recorded for %s", name)
		got = normalize(got)
		path := filepath.Join(fixturesDir, name)
		if os.Getenv("TXE_UPDATE_FIXTURES") == "1" {
			require.NoError(t, os.MkdirAll(fixturesDir, 0o755))
			require.NoError(t, os.WriteFile(path, got, 0o644)) //nolint:gosec // a shared fixture
			continue
		}
		fixture, err := os.ReadFile(path)
		require.NoError(t, err, "run with TXE_UPDATE_FIXTURES=1 to create %s", name)
		assert.Equal(t, string(fixture), string(got), "%s no longer matches what the client sends or reads", name)
	}
}
