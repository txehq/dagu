// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every DAG RenderDAG writes with a publish step is the generated one.
func TestCheckGeneratedPublishAcceptsRenderedDAGs(t *testing.T) {
	for name, mutate := range map[string]func(*DAGSpec){
		"as rendered":     func(*DAGSpec) {},
		"no retry policy": func(s *DAGSpec) { s.Schedule.Retry = 0 },
		"no store flags":  func(s *DAGSpec) { s.CLI.StoreFlags = nil },
		"store flags with quotes": func(s *DAGSpec) {
			s.CLI.StoreFlags = []string{"--dagu-home", "/Users/x/it's here/client", "--contexts-dir", "/a b/c"}
		},
		"a binary path to quote": func(s *DAGSpec) { s.CLI.Dagu = "/Users/x y/bin/dagu" },
		"no credentials or env":  func(s *DAGSpec) { s.CredentialRefs, s.Env = nil, nil },
	} {
		s := testDAGSpec()
		s.Publish = &Publish{HubArtifacts: true}
		mutate(&s)
		data, err := RenderDAG(s)
		require.NoError(t, err, name)
		if err := CheckGeneratedPublish(data, identityOf(s)); err != nil {
			t.Errorf("%s: %v\n%s", name, err, data)
		}
	}
}

// A DAG whose publish step could do anything but publish, or that runs
// anything else alongside it, is not the generated one.
func TestCheckGeneratedPublishRefusesOtherDAGs(t *testing.T) {
	s := testDAGSpec()
	s.Publish = &Publish{HubArtifacts: true}
	data, err := RenderDAG(s)
	require.NoError(t, err)
	rendered := string(data)
	publishLine := `    command: "/Users/x/.local/share/txe-dagu/bin/dagu txe artifacts publish --dagu-home /Users/x/.local/share/txe-dagu/client"`
	require.Contains(t, rendered, publishLine)
	replace := func(old, new string) string {
		require.Contains(t, rendered, old)
		return strings.Replace(rendered, old, new, 1)
	}

	for name, spec := range map[string]string{
		"a shell wrapper": replace(publishLine,
			`    command: "sh -c 'touch /tmp/x; /Users/x/.local/share/txe-dagu/bin/dagu txe artifacts publish --dagu-home /Users/x/.local/share/txe-dagu/client'"`),
		"a command chained after":              replace(publishLine, strings.TrimSuffix(publishLine, `"`)+` ; rm -rf /tmp/x"`),
		"another binary":                       replace(publishLine, strings.Replace(publishLine, "/bin/dagu", "/bin/dagu2", 1)),
		"another subcommand":                   replace(publishLine, strings.Replace(publishLine, "artifacts publish", "artifacts seal", 1)),
		"another store":                        replace(publishLine, strings.Replace(publishLine, "/client\"", "/other\"", 1)),
		"an extra flag":                        replace(publishLine, strings.TrimSuffix(publishLine, `"`)+` --json"`),
		"a doubled space":                      replace(publishLine, strings.Replace(publishLine, "txe artifacts", "txe  artifacts", 1)),
		"a needless quote":                     replace(publishLine, strings.Replace(publishLine, "txe artifacts", "'txe' artifacts", 1)),
		"env on the publish step":              replace(publishLine, publishLine+"\n    env:\n      - X: \"1\""),
		"preconditions on publish":             replace(publishLine, publishLine+"\n    preconditions:\n      - condition: \"true\""),
		"a handler":                            rendered + "handler_on:\n  success:\n    command: touch /tmp/x\n",
		"a third step":                         rendered + "  - name: after\n    command: touch /tmp/x\n",
		"a second document":                    rendered + "---\nname: other\nsteps:\n  - name: x\n    command: touch /tmp/x\n",
		"a run step that is not checked first": replace("txe resource check", "txe resource nocheck"),
		"another job's variable":               replace("  - TXE_JOB_ID: \""+s.JobID+"\"", "  - TXE_JOB_ID: \"job_01K7A5ZQ8M3N4P5R6S7T8V9W0Z\""),
		"a version variable unlike the check":  replace("  - TXE_JOB_VERSION: \"2\"", "  - TXE_JOB_VERSION: \"999\""),
		"a fixed attempt":                      replace("  - TXE_ATTEMPT_ID: \"${context.attempt.id}\"", "  - TXE_ATTEMPT_ID: \"a1b2c3\""),
		"a run output elsewhere":               replace("/runs/${DAG_RUN_ID}/attempts/", "/runs/${DAG_RUN_ID}/other/"),
		"a TXE variable set again":             replace("  - TXE_DAGU_HOME:", "  - TXE_OUTPUT_DIR: \"/tmp/x\"\n  - TXE_DAGU_HOME:"),
		"artifacts turned off":                 replace("artifacts:\n  enabled: true", "artifacts:\n  enabled: false"),
		"artifacts moved":                      replace("artifacts:\n  enabled: true", "artifacts:\n  enabled: true\n  dir: /tmp/x"),
		"artifacts not a mapping":              replace("artifacts:\n  enabled: true", "artifacts: true"),
	} {
		assert.Error(t, CheckGeneratedPublish([]byte(spec), identityOf(s)), name)
	}

	s.Publish = nil
	noPublish, err := RenderDAG(s)
	require.NoError(t, err)
	assert.Error(t, CheckGeneratedPublish(noPublish, identityOf(s)), "a job without deliverables has no publish step")

	for name, id := range map[string]GeneratedIdentity{
		"another job":     {JobID: "job_01K7A5ZQ8M3N4P5R6S7T8V9W0Z", Version: s.Version, Home: s.CLI.HomeRoot},
		"another version": {JobID: s.JobID, Version: s.Version + 1, Home: s.CLI.HomeRoot},
		"another home":    {JobID: s.JobID, Version: s.Version, Home: "/elsewhere"},
	} {
		assert.Error(t, CheckGeneratedPublish(data, id), name)
	}
}

func identityOf(s DAGSpec) GeneratedIdentity {
	return GeneratedIdentity{JobID: s.JobID, Version: s.Version, Home: s.CLI.HomeRoot}
}

func TestShellSplitInvertsShellJoin(t *testing.T) {
	for _, argv := range [][]string{
		{"/bin/dagu", "txe", "artifacts", "publish"},
		{"/a b/dagu", "it's", "", "x=y", "--flag", "a'b'c"},
	} {
		split, err := shellSplit(shellJoin(argv))
		require.NoError(t, err)
		assert.Equal(t, argv, split)
	}
	for _, line := range []string{"a  b", " a", "a ", "a;b", "a 'b", `a "b"`, "a $(x)", "'a'", "a\tb"} {
		_, err := shellSplit(line)
		assert.Error(t, err, line)
	}
}
