// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dag"
	"github.com/dagucloud/dagu/v2/internal/runtime"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// A history read authorized before the job moved to a workspace the caller
// cannot see is repeated on the moved job, and refused.
func TestTxeReadHistoryRechecksMovedJob(t *testing.T) {
	dir := t.TempDir()
	repo := persis.NewDAGRepository(dag.NewStore(filepath.Join(dir, "dags")), persis.DAGRepositoryOptions{})
	store, err := registry.NewFileStore(filepath.Join(dir, "data"), registry.WithDAGStore(registry.NewDAGStore(repo)))
	require.NoError(t, err)
	cfg := &config.Config{}
	cfg.Server.Permissions = map[config.Permission]bool{config.PermissionWriteDAGs: true}
	a := New(repo, nil, nil, nil, runtime.Manager{}, cfg, nil, nil, prometheus.NewRegistry(), nil,
		WithTxeRegistry(store), WithAuthService(struct{ AuthService }{}))
	ctx := context.Background()
	ops := auth.WithUser(ctx, &auth.User{Username: "dev", Role: auth.RoleDeveloper, WorkspaceAccess: &auth.WorkspaceAccess{
		Grants: []auth.WorkspaceGrant{{Workspace: "ops", Role: auth.RoleDeveloper}},
	}})

	mint := func(p registry.Prefix) string {
		id, err := registry.NewID(p, time.Now())
		require.NoError(t, err)
		return id
	}
	cli := registry.Actor{Kind: registry.ActorCLI, ID: "cc3-test"}
	owner, machine := mint(registry.PrefixOwner), mint(registry.PrefixMachine)
	_, err = store.CreateOwner(ctx, registry.Owner{OwnerID: owner, DisplayName: "Connor Wang"}, cli)
	require.NoError(t, err)
	_, err = store.CreateMachine(ctx, registry.Machine{MachineID: machine, OwnerID: owner, DisplayName: "laptop"}, cli)
	require.NoError(t, err)
	project, err := store.EnsureProject(ctx, owner, "github.com/txehq/txe", "txe", cli)
	require.NoError(t, err)
	version := func(workspace string, digest byte) registry.JobVersion {
		return registry.JobVersion{
			Title: "t", Purpose: "p",
			Package: registry.Package{Digest: fmt.Sprintf("sha256:%064x", digest), Path: "/pkg", Entrypoint: "run.sh"},
			DAG: registry.DAGRef{Spec: fmt.Sprintf("labels:\n  - workspace=%s\nworker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/run.sh\n",
				workspace, machine)},
		}
	}
	jobID := mint(registry.PrefixJob)
	_, err = store.Register(ctx, registry.RegisterInput{JobID: jobID, RequestID: "r1", OwnerID: owner, ProjectID: project.ProjectID,
		MachineID: machine, JobKey: "k", Version: version("ops", 1)}, cli)
	require.NoError(t, err)

	reads := 0
	_, err = a.txeReadHistory(ops, store, jobID, func() error {
		reads++
		if reads == 1 {
			_, err := store.UpdateVersion(ctx, jobID, "u1", 1, version("secret", 2), cli)
			return err
		}
		return nil
	})
	var apiErr *Error
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusNotFound, apiErr.HTTPStatus)
	assert.Equal(t, 1, reads, "the moved job is not read again")
}

// A job file keeps its identity whatever name its YAML declares, and no
// other DAG can take a job's name.
func TestTxeJobIdentity(t *testing.T) {
	job := "job_01HZY0000000000000000000AA"
	cases := []struct {
		name, file, declared, want string
		refused                    bool
	}{
		{name: "job file", file: job + ".yaml", declared: job, want: job},
		{name: "job file without declared name", file: job + ".yaml", want: job},
		{name: "job file declaring an ordinary name", file: job + ".yaml", declared: "monitor", refused: true},
		{name: "ordinary file declaring a job name", file: "monitor.yaml", declared: job, refused: true},
		{name: "ordinary DAG", file: "monitor.yaml", declared: "monitor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := txeJobIdentity(&ir.DAG{Location: filepath.Join("/dags", tc.file), Name: tc.declared})
			if tc.refused {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestTxeArtifactDigest(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "raw"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "raw", "a.csv"), []byte("hello"), 0o600))
	sha, found, err := txeArtifactDigest(dir, "raw/a.csv")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", sha)
	_, found, err = txeArtifactDigest(dir, "none.csv")
	require.NoError(t, err)
	assert.False(t, found)
	_, found, err = txeArtifactDigest(dir, "../escape")
	require.NoError(t, err)
	assert.False(t, found, "a path outside the run's directory is never read")
}
