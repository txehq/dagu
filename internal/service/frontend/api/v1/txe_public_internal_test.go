// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/auth"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dag"
	"github.com/dagucloud/dagu/v2/internal/runtime"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// A refusal's record is returned in its API shape: a manifest's absolute
// archive directory, which the API never publishes, does not leave the hub.
func TestTxeRefusalReturnsTheAPIShape(t *testing.T) {
	manifest := &registry.ArtifactManifest{JobID: "job_x", RunID: "run-1", Execution: "e1", ArchiveDir: "/srv/dagu/artifacts/secret/run-1"}
	err := txeError(&registry.Error{Code: registry.CodeArtifactConflict, Message: "conflict", Current: manifest})
	apiErr, ok := err.(*Error)
	require.True(t, ok)
	data, mErr := json.Marshal(apiErr.Details["current"])
	require.NoError(t, mErr)
	assert.NotContains(t, string(data), "archive_dir")
	assert.NotContains(t, string(data), "/srv/dagu")
	assert.Contains(t, string(data), `"run_id":"run-1"`)

	job := &registry.Job{JobID: "job_x"}
	err = txeError(&registry.Error{Code: registry.CodeVersionConflict, Message: "conflict", Current: job})
	apiErr, ok = err.(*Error)
	require.True(t, ok)
	_, isAPIJob := apiErr.Details["current"].(api.TxeJob)
	assert.True(t, isAPIJob, "a job is returned as the API's TxeJob")

	other := registry.ExecutionPreparing{RunID: "run-1", Execution: "e1"}
	err = txeError(&registry.Error{Code: registry.CodeNotReady, Message: "preparing", Current: other})
	apiErr, ok = err.(*Error)
	require.True(t, ok)
	assert.Equal(t, other, apiErr.Details["current"], "other records unchanged")
}

// A refusal whose record the registry read after the caller was authorized
// (the job moved to a workspace the caller cannot see meanwhile) neither
// returns nor names it; a caller who can see the job still gets it.
func TestTxeVisibleRefusalHidesAJobThatMoved(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	repo := persis.NewDAGRepository(dag.NewStore(filepath.Join(dir, "dags")), persis.DAGRepositoryOptions{})
	store, err := registry.NewFileStore(filepath.Join(dir, "data"), registry.WithDAGStore(registry.NewDAGStore(repo)))
	require.NoError(t, err)
	cfg := &config.Config{}
	cfg.Server.Permissions = map[config.Permission]bool{config.PermissionWriteDAGs: true}
	a := New(repo, nil, nil, nil, runtime.Manager{}, cfg, nil, nil, prometheus.NewRegistry(), nil,
		WithTxeRegistry(store), WithAuthService(struct{ AuthService }{}))
	admin := auth.WithUser(ctx, &auth.User{Username: "admin", Role: auth.RoleAdmin, WorkspaceAccess: auth.AllWorkspaceAccess()})
	ops := auth.WithUser(ctx, &auth.User{Username: "dev", Role: auth.RoleDeveloper, WorkspaceAccess: &auth.WorkspaceAccess{
		Grants: []auth.WorkspaceGrant{{Workspace: "ops", Role: auth.RoleDeveloper}}}})

	cli := registry.Actor{Kind: registry.ActorCLI, ID: "test"}
	owner, machine := mustID(t, registry.PrefixOwner), mustID(t, registry.PrefixMachine)
	_, err = store.CreateOwner(admin, registry.Owner{OwnerID: owner, DisplayName: "o"}, cli)
	require.NoError(t, err)
	_, err = store.CreateMachine(admin, registry.Machine{MachineID: machine, OwnerID: owner, DisplayName: "m"}, cli)
	require.NoError(t, err)
	project, err := store.EnsureProject(admin, owner, "github.com/x/y", "y", cli)
	require.NoError(t, err)
	jobID := mustID(t, registry.PrefixJob)
	job, err := store.Register(admin, registry.RegisterInput{JobID: jobID, RequestID: "r", OwnerID: owner, ProjectID: project.ProjectID,
		MachineID: machine, JobKey: "k", Version: registry.JobVersion{Title: "t", Purpose: "p",
			Package: registry.Package{Digest: "sha256:" + strings.Repeat("0", 64), Path: "/pkg", Entrypoint: "run.sh"},
			DAG:     registry.DAGRef{Spec: "labels:\n  - workspace=secret\nworker_selector:\n  txe.machine: " + machine + "\nsteps:\n  - name: run\n    run: /pkg/run.sh\n"}}}, cli)
	require.NoError(t, err)

	refused := &registry.Error{Code: registry.CodeVersionConflict, Message: "job is at version 2, not 1", Current: job}
	re, ok := a.txeVisibleRefusal(ops, store, refused).(*registry.Error)
	require.True(t, ok)
	assert.Equal(t, registry.CodeVersionConflict, re.Code)
	assert.Nil(t, re.Current, "the moved job's record")
	assert.NotContains(t, re.Message, "version 2")

	re, ok = a.txeVisibleRefusal(admin, store, refused).(*registry.Error)
	require.True(t, ok)
	assert.NotNil(t, re.Current, "a caller who sees the job gets it")
	assert.Equal(t, refused.Message, re.Message)

	// A successful change's result, re-read after it, is likewise returned
	// only to a caller who can see it now.
	_, err = a.txeVisibleResult(ops, store, job)
	var apiErr *Error
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, http.StatusNotFound, apiErr.HTTPStatus)
	got, err := a.txeVisibleResult(admin, store, job)
	require.NoError(t, err)
	assert.Equal(t, job.JobID, got.JobID)
}

func mustID(t *testing.T, p registry.Prefix) string {
	t.Helper()
	id, err := registry.NewID(p, time.Now())
	require.NoError(t, err)
	return id
}
