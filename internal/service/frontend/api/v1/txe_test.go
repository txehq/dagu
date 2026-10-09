// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dag"
	"github.com/dagucloud/dagu/v2/internal/runtime"
	apiv1 "github.com/dagucloud/dagu/v2/internal/service/frontend/api/v1"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

func newTxeTestAPI(t *testing.T) *apiv1.API {
	t.Helper()
	dir := t.TempDir()
	repo := persis.NewDAGRepository(dag.NewStore(filepath.Join(dir, "dags")), persis.DAGRepositoryOptions{})
	store, err := registry.NewFileStore(filepath.Join(dir, "data"), registry.WithDAGStore(registry.NewDAGStore(repo)))
	require.NoError(t, err)
	cfg := &config.Config{}
	cfg.Server.Permissions = map[config.Permission]bool{config.PermissionWriteDAGs: true}
	return apiv1.New(repo, nil, nil, nil, runtime.Manager{}, cfg, nil, nil, prometheus.NewRegistry(), nil, apiv1.WithTxeRegistry(store))
}

func mint(t *testing.T, p registry.Prefix) string {
	t.Helper()
	id, err := registry.NewID(p, time.Now())
	require.NoError(t, err)
	return id
}

// The /txe API registers a job end to end, refuses stale writes with 409 and
// the registry code in details, and retires without losing history.
func TestTxeAPIRegistrationAndRetirement(t *testing.T) {
	ctx := context.Background()
	a := newTxeTestAPI(t)
	cliActor := &apigen.TxeActor{Kind: apigen.TxeActorKindCli, Id: "cc3-test"}
	owner, machine := mint(t, registry.PrefixOwner), mint(t, registry.PrefixMachine)

	_, err := a.CreateTxeOwner(ctx, apigen.CreateTxeOwnerRequestObject{Body: &apigen.TxeOwnerCreateRequest{OwnerId: owner, DisplayName: "Connor Wang", Actor: cliActor}})
	require.NoError(t, err)
	_, err = a.CreateTxeMachine(ctx, apigen.CreateTxeMachineRequestObject{Body: &apigen.TxeMachineCreateRequest{MachineId: machine, OwnerId: owner, DisplayName: "laptop", Actor: cliActor}})
	require.NoError(t, err)
	projResp, err := a.EnsureTxeProject(ctx, apigen.EnsureTxeProjectRequestObject{Body: &apigen.TxeProjectEnsureRequest{OwnerId: owner, Key: "github.com/txehq/txe", Actor: cliActor}})
	require.NoError(t, err)
	project := projResp.(apigen.EnsureTxeProject200JSONResponse).ProjectId

	jobID := mint(t, registry.PrefixJob)
	spec := fmt.Sprintf("worker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/run.sh\n", machine)
	digest := fmt.Sprintf("sha256:%064x", 7)
	reg := &apigen.TxeRegisterRequest{
		JobId: jobID, RequestId: "r1", OwnerId: owner, ProjectId: project, MachineId: machine, JobKey: "health:pvc",
		Version: apigen.TxeJobVersionInput{
			Title: "pvc health", Purpose: "watch pvc",
			Package: apigen.TxePackage{Digest: digest, Path: "/pkg", Entrypoint: "run.sh"},
			Dag:     apigen.TxeDAGRef{Spec: spec},
		},
		Actor: cliActor,
	}
	regResp, err := a.RegisterTxeJob(ctx, apigen.RegisterTxeJobRequestObject{Body: reg})
	require.NoError(t, err)
	job := regResp.(apigen.RegisterTxeJob201JSONResponse)
	assert.Equal(t, apigen.TxeRegistrationStateIncomplete, job.Registration.State)

	readyResp, err := a.MarkTxeJobReady(ctx, apigen.MarkTxeJobReadyRequestObject{JobId: jobID, Body: &apigen.TxeReadyRequest{
		Package: apigen.TxePackageEvidence{Digest: digest, Path: "/pkg", MachineId: machine}, Actor: cliActor}})
	require.NoError(t, err)
	receipt := readyResp.(apigen.MarkTxeJobReady200JSONResponse)
	assert.Equal(t, apigen.TxeRegistrationStateReady, receipt.Registration)
	assert.Equal(t, owner, receipt.OwnerId)

	verResp, err := a.GetTxeJobVersion(ctx, apigen.GetTxeJobVersionRequestObject{JobId: jobID, Version: 1})
	require.NoError(t, err)
	assert.Equal(t, "watch pvc", verResp.(apigen.GetTxeJobVersion200JSONResponse).Purpose)

	_, err = a.UpdateTxeJobVersion(ctx, apigen.UpdateTxeJobVersionRequestObject{JobId: jobID, Body: &apigen.TxeVersionRequest{
		RequestId: "u1", ExpectedVersion: 5, Version: reg.Version, Actor: cliActor}})
	var apiErr *apiv1.Error
	require.True(t, errors.As(err, &apiErr), "got %v", err)
	assert.Equal(t, http.StatusConflict, apiErr.HTTPStatus)
	assert.Equal(t, string(registry.CodeVersionConflict), apiErr.Details["code"])
	assert.NotNil(t, apiErr.Details["current"])

	human := &apigen.TxeActor{Kind: apigen.TxeActorKindHuman, Id: "connor"}
	reason := apigen.TxeLifecycleRequestReasonManual
	trResp, err := a.TransitionTxeJob(ctx, apigen.TransitionTxeJobRequestObject{JobId: jobID, Body: &apigen.TxeLifecycleRequest{
		Op: apigen.TxeLifecycleRequestOpRetire, Reason: &reason, Actor: human}})
	require.NoError(t, err)
	retired := trResp.(apigen.TransitionTxeJob200JSONResponse)
	assert.Equal(t, apigen.TxeLifecycleRetired, retired.Lifecycle)
	require.NotNil(t, retired.Retirement)

	evResp, err := a.ListTxeJobEvents(ctx, apigen.ListTxeJobEventsRequestObject{JobId: jobID})
	require.NoError(t, err)
	assert.Len(t, evResp.(apigen.ListTxeJobEvents200JSONResponse).Events, 3)

	_, err = a.GetTxeJob(ctx, apigen.GetTxeJobRequestObject{JobId: mint(t, registry.PrefixJob)})
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, http.StatusNotFound, apiErr.HTTPStatus)
}
