// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package agent_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	profilepkg "github.com/dagucloud/dagu/v2/internal/profile"
	"github.com/dagucloud/dagu/v2/internal/runtime/agent"
	"github.com/dagucloud/dagu/v2/internal/spec"
	"github.com/dagucloud/dagu/v2/internal/test"
)

// identityResolver resolves no values and names one runtime identity.
type identityResolver struct{ identity string }

func (r identityResolver) ResolveRuntime(context.Context, profilepkg.RuntimeRequest) (*profilepkg.RuntimeResolved, error) {
	return &profilepkg.RuntimeResolved{Identity: r.identity}, nil
}

func TestAgentRecordsItsRuntimeIdentity(t *testing.T) {
	th := test.Setup(t)
	dag := th.DAG(t, "steps:\n  - run: echo done\n")
	dag.Agent(test.WithAgentOptions(agent.Options{ProfileResolver: identityResolver{identity: "rp1:now"}})).RunSuccess(t)

	latest, err := th.DAGRunMgr.GetLatestStatus(th.Context, dag.DAG)
	require.NoError(t, err)
	require.Equal(t, spec.RunRuntimeIdentity(dag.DAG, "rp1:now"), latest.RuntimeIdentity)
	require.NotEmpty(t, latest.RuntimeIdentity)
	require.Empty(t, latest.ExpectedRuntimeIdentity)
}

// A run seeded with automatically reused outputs stops before any step when
// its own resolve is not the identity the hub admitted it for: a profile
// changed in between, or the resolver (an older coordinator) names none.
func TestAgentRefusesASeededRunOfAnotherRuntimeIdentity(t *testing.T) {
	for name, tc := range map[string]struct {
		resolved string
		ok       bool
	}{
		"same":                {resolved: "rp1:admitted", ok: true},
		"changed since":       {resolved: "rp1:edited"},
		"unknown to resolver": {resolved: ""},
	} {
		t.Run(name, func(t *testing.T) {
			th := test.Setup(t)
			marker := filepath.Join(t.TempDir(), "executed")
			dag := th.DAG(t, fmt.Sprintf("steps:\n  - name: work\n    script: %q\n", writeFileCommand(marker, "ran")))

			runID := "seeded-run"
			prepared, err := th.DAGRunRepository.CreateAttempt(th.Context, dag.DAG, time.Now(), runID, persis.DAGRunCreateAttemptOptions{})
			require.NoError(t, err)
			require.NoError(t, prepared.Open(th.Context))
			seed := ir.NewStatusBuilder(dag.DAG).Create(runID, ir.Queued, 0, time.Time{}, ir.WithAttemptID(prepared.ID()))
			admitted := spec.RunRuntimeIdentity(dag.DAG, "rp1:admitted")
			seed.ExpectedRuntimeIdentity = admitted
			seed.RuntimeIdentity = admitted
			require.NoError(t, prepared.Write(th.Context, seed))
			require.NoError(t, prepared.Close(th.Context))

			dagAgent := dag.Agent(test.WithDAGRunID(runID), test.WithAgentOptions(agent.Options{
				RunStateStore:   persis.NewRunStateStore(th.DAGRunRepository, prepared),
				RetryTarget:     &seed,
				ProfileResolver: identityResolver{identity: tc.resolved},
			}))
			_ = dagAgent.Run(th.Context)

			latest, err := th.DAGRunMgr.GetLatestStatus(th.Context, dag.DAG)
			require.NoError(t, err)
			_, statErr := os.Stat(marker)
			if tc.ok {
				require.Equal(t, ir.Succeeded, latest.Status)
				require.NoError(t, statErr)
				require.Equal(t, admitted, latest.RuntimeIdentity)
				require.Equal(t, admitted, latest.ExpectedRuntimeIdentity, "a retry of the run is checked too")
				return
			}
			require.Equal(t, ir.Failed, latest.Status)
			require.ErrorIs(t, statErr, os.ErrNotExist, "no step ran")
			require.Contains(t, latest.Error, agent.ErrRuntimeIdentityChanged.Error())
			require.Equal(t, admitted, latest.ExpectedRuntimeIdentity, "a retry of the run is checked too")
		})
	}
}

// A dotenv file the run takes context from makes its identity unknown, also
// when the environment was resolved before the agent (a retry restored from
// its status), which reads no file itself.
func TestAgentIdentityIsUnknownWithADotenvFile(t *testing.T) {
	for _, resolvedBefore := range []bool{false, true} {
		th := test.Setup(t)
		dir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"), []byte("REGION=eu\n"), 0o600))
		dag := th.DAG(t, fmt.Sprintf("working_dir: %q\nsteps:\n  - run: echo done\n", dir))
		dag.DAG.RuntimeResolved = resolvedBefore
		// Resolved before by another process, which read the file and sent
		// the mark with the environment.
		dag.DAG.DotenvLoaded = resolvedBefore
		dag.Agent(test.WithAgentOptions(agent.Options{ProfileResolver: identityResolver{identity: "rp1:now"}})).RunSuccess(t)
		latest, err := th.DAGRunMgr.GetLatestStatus(th.Context, dag.DAG)
		require.NoError(t, err)
		require.Empty(t, latest.RuntimeIdentity, "resolved before: %v", resolvedBefore)
	}
}

// A dotenv file read before the run, and gone by the time the run checks,
// still makes its identity unknown: the mark travelled with the environment.
func TestAgentIdentityIsUnknownWhenADotenvFileWasReadBefore(t *testing.T) {
	th := test.Setup(t)
	dag := th.DAG(t, "steps:\n  - run: echo done\n")
	dag.DAG.RuntimeResolved = true
	dag.DAG.DotenvLoaded = true
	dag.Agent(test.WithAgentOptions(agent.Options{ProfileResolver: identityResolver{identity: "rp1:now"}})).RunSuccess(t)
	latest, err := th.DAGRunMgr.GetLatestStatus(th.Context, dag.DAG)
	require.NoError(t, err)
	require.Empty(t, latest.RuntimeIdentity)
}
