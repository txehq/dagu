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

	"github.com/dagucloud/dagu/v2/internal/cmn/crypto"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/store"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
	profilepkg "github.com/dagucloud/dagu/v2/internal/profile"
	"github.com/dagucloud/dagu/v2/internal/runtime/agent"
	"github.com/dagucloud/dagu/v2/internal/secret"
	secretref "github.com/dagucloud/dagu/v2/internal/secret/ref"
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
	require.Equal(t, spec.RunRuntimeIdentity(dag.DAG, "rp1:now", nil), latest.RuntimeIdentity)
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
			admitted := spec.RunRuntimeIdentity(dag.DAG, "rp1:admitted", nil)
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

// newManagedSecret has a secret store holding the global managed secret
// team/token, and the DAG source that takes it as TOKEN.
func newManagedSecret(t *testing.T) (*store.SecretStore, *secret.Secret) {
	t.Helper()
	enc, err := crypto.NewEncryptor("runtime-identity-test")
	require.NoError(t, err)
	secrets, err := store.NewSecretStore(testutil.NewMemoryBackend().Collection("secrets"), enc)
	require.NoError(t, err)
	sec, err := secret.New(secret.CreateInput{Workspace: secret.GlobalWorkspace, Ref: "team/token", ProviderType: secret.ProviderDaguManaged}, time.Now())
	require.NoError(t, err)
	require.NoError(t, secrets.Create(context.Background(), sec, &secret.WriteValueInput{Value: "v1"}))
	return secrets, sec
}

const tokenSecretYAML = "secrets:\n  - name: TOKEN\n    ref: team/token\n"

// hubIdentity is the identity the hub names for a run of dag now: the
// stored revision of each secret reference from metadata alone, as
// prospectiveRuntimeIdentity reads it.
func hubIdentity(t *testing.T, secrets secret.Store, dag *ir.DAG, profileIdentity string) string {
	t.Helper()
	resolver := secret.NewReferenceResolver(secrets, "")
	revisions := map[string]secretref.Revision{}
	for _, ref := range dag.Secrets {
		revision, err := resolver.Revision(context.Background(), ref)
		require.NoError(t, err)
		revisions[ref.Name] = revision
	}
	return spec.RunRuntimeIdentity(dag, profileIdentity, revisions)
}

// A run records the stored revision its registry secret was read from: the
// identity the hub names from metadata for the same state, and another once
// the secret is rotated (TXE-6222).
func TestAgentRecordsTheRegistrySecretRevisionItRead(t *testing.T) {
	th := test.Setup(t)
	secrets, sec := newManagedSecret(t)
	dag := th.DAG(t, tokenSecretYAML+"steps:\n  - run: echo done\n")
	dag.Agent(test.WithAgentOptions(agent.Options{SecretStore: secrets, ProfileResolver: identityResolver{identity: "rp1:now"}})).RunSuccess(t)

	latest, err := th.DAGRunMgr.GetLatestStatus(th.Context, dag.DAG)
	require.NoError(t, err)
	require.Contains(t, latest.RuntimeIdentity, ";dag_secrets=ds1:")
	require.Equal(t, hubIdentity(t, secrets, dag.DAG, "rp1:now"), latest.RuntimeIdentity, "hub and run agree")

	_, err = secrets.WriteValue(th.Context, sec.ID, secret.WriteValueInput{Value: "v2"})
	require.NoError(t, err)
	require.NotEqual(t, latest.RuntimeIdentity, hubIdentity(t, secrets, dag.DAG, "rp1:now"), "rotated since")
}

// A seeded run admitted before its registry secret was rotated stops before
// any step: it would read another value than the one the reused outputs
// were made with.
func TestAgentRefusesASeededRunAfterASecretRotation(t *testing.T) {
	for name, rotate := range map[string]bool{"unchanged": false, "rotated after admission": true} {
		t.Run(name, func(t *testing.T) {
			th := test.Setup(t)
			secrets, sec := newManagedSecret(t)
			marker := filepath.Join(t.TempDir(), "executed")
			dag := th.DAG(t, tokenSecretYAML+fmt.Sprintf("steps:\n  - name: work\n    script: %q\n", writeFileCommand(marker, "ran")))

			runID := "seeded-run"
			prepared, err := th.DAGRunRepository.CreateAttempt(th.Context, dag.DAG, time.Now(), runID, persis.DAGRunCreateAttemptOptions{})
			require.NoError(t, err)
			require.NoError(t, prepared.Open(th.Context))
			seed := ir.NewStatusBuilder(dag.DAG).Create(runID, ir.Queued, 0, time.Time{}, ir.WithAttemptID(prepared.ID()))
			admitted := hubIdentity(t, secrets, dag.DAG, "rp1:admitted")
			require.NotEmpty(t, admitted)
			seed.ExpectedRuntimeIdentity = admitted
			seed.RuntimeIdentity = admitted
			require.NoError(t, prepared.Write(th.Context, seed))
			require.NoError(t, prepared.Close(th.Context))

			if rotate {
				_, err = secrets.WriteValue(th.Context, sec.ID, secret.WriteValueInput{Value: "v2"})
				require.NoError(t, err)
			}
			_ = dag.Agent(test.WithDAGRunID(runID), test.WithAgentOptions(agent.Options{
				RunStateStore:   persis.NewRunStateStore(th.DAGRunRepository, prepared),
				RetryTarget:     &seed,
				SecretStore:     secrets,
				ProfileResolver: identityResolver{identity: "rp1:admitted"},
			})).Run(th.Context)

			latest, err := th.DAGRunMgr.GetLatestStatus(th.Context, dag.DAG)
			require.NoError(t, err)
			_, statErr := os.Stat(marker)
			if !rotate {
				require.Equal(t, ir.Succeeded, latest.Status)
				require.NoError(t, statErr)
				require.Equal(t, admitted, latest.RuntimeIdentity)
				return
			}
			require.Equal(t, ir.Failed, latest.Status)
			require.ErrorIs(t, statErr, os.ErrNotExist, "no step ran")
			require.Contains(t, latest.Error, agent.ErrRuntimeIdentityChanged.Error())
		})
	}
}

// A run that reads a secret from an external provider has no identity, also
// beside a registry reference.
func TestAgentIdentityIsUnknownWithAProviderSecret(t *testing.T) {
	th := test.Setup(t)
	secrets, _ := newManagedSecret(t)
	t.Setenv("RUNTIME_IDENTITY_PROVIDER_SECRET", "x")
	dag := th.DAG(t, tokenSecretYAML+"  - name: OTHER\n    provider: env\n    key: RUNTIME_IDENTITY_PROVIDER_SECRET\nsteps:\n  - run: echo done\n")
	dag.Agent(test.WithAgentOptions(agent.Options{SecretStore: secrets, ProfileResolver: identityResolver{identity: "rp1:now"}})).RunSuccess(t)

	latest, err := th.DAGRunMgr.GetLatestStatus(th.Context, dag.DAG)
	require.NoError(t, err)
	require.Empty(t, latest.RuntimeIdentity)
}
