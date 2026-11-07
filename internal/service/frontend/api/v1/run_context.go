// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"fmt"
	"net/http"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/spec"
)

// loadSavedRunDAG loads a stored DAG as POST /dags/{fileName}/start runs it,
// with the same refusals. Every route that decides something about a start
// of the saved DAG loads it here, so it cannot decide for a DAG the start
// would refuse (TXE-6145).
func (a *API) loadSavedRunDAG(ctx context.Context, fileName string) (*ir.DAG, error) {
	if err := a.isAllowed(config.PermissionRunDAGs); err != nil {
		return nil, err
	}
	dag, err := a.dagRepository.GetDetails(ctx, fileName, persis.DAGLoadOptions{AllowBuildErrors: true})
	if err != nil {
		return nil, &Error{
			HTTPStatus: http.StatusNotFound,
			Code:       api.ErrorCodeNotFound,
			Message:    fmt.Sprintf("DAG %s not found", fileName),
		}
	}
	if err := a.requireDAGExecute(ctx, dag); err != nil {
		return nil, err
	}
	if err := a.txeAdmitDAG(ctx, dag); err != nil {
		return nil, err
	}
	if err := a.txeRefuseLocalJobRun(dag); err != nil {
		return nil, err
	}
	return dag, nil
}

// loadDraftRunDAG loads a submitted spec as POST /dag-runs runs it, with the
// same refusals: the workspace the spec names is checked before the spec is
// loaded, and the loaded DAG is decided as a write to the DAG it runs as.
// Every route that decides something about a start of a draft loads it
// here (TXE-6145). The caller calls cleanup when it is done with the DAG.
func (a *API) loadDraftRunDAG(ctx context.Context, specContent string, name *string, labels, dagRunID string, extraLoadOpts ...spec.LoadOption) (*ir.DAG, func(), error) {
	if err := a.isAllowed(config.PermissionRunDAGs); err != nil {
		return nil, func() {}, err
	}
	if err := a.requireDAGWriteForWorkspace(ctx, submittedSpecRuntimeWorkspaceName(specContent, labels)); err != nil {
		return nil, func() {}, err
	}
	dag, cleanup, err := a.loadInlineDAG(ctx, specContent, name, dagRunID, extraLoadOpts...)
	if err != nil {
		return nil, func() {}, err
	}
	if err := txeRefuseInlineJobDAG(dag.Name); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	// An inline spec runs a definition that is not stored: it is decided
	// as a write to the DAG it runs as.
	if err := a.txeNativeWriteClosed(ctx, func() error { return a.requireDAGWriteForWorkspace(ctx, runtimeWorkspaceName(dag, labels)) },
		[]byte(specContent), dag.Name); err != nil {
		cleanup()
		return nil, func() {}, err
	}
	return dag, cleanup, nil
}
