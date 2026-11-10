// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger"
	"github.com/dagucloud/dagu/v2/internal/cmn/logger/tag"
	"github.com/dagucloud/dagu/v2/internal/intake"
	"github.com/dagucloud/dagu/v2/internal/ir"
	profilepkg "github.com/dagucloud/dagu/v2/internal/profile"
	secretpkg "github.com/dagucloud/dagu/v2/internal/secret"
	secretref "github.com/dagucloud/dagu/v2/internal/secret/ref"
	"github.com/dagucloud/dagu/v2/internal/spec"
	"github.com/dagucloud/dagu/v2/internal/workspace"
)

// maxReuseRuntimeRuns bounds the runs one reuse-runtime request compares.
const maxReuseRuntimeRuns = 50

// prospectiveRuntimeIdentity is the runtime identity a run of dag with
// profileName would take now (see profile.Resolver.RuntimeIdentity), read
// without any value. Empty when it cannot be known: the DAG takes context
// without a server-side version, no profile store is configured, or a layer
// or a secret reference cannot be read. A change after this read is caught
// by the run, which checks its own identity before any step.
func (a *API) prospectiveRuntimeIdentity(ctx context.Context, dag *ir.DAG, profileName string) string {
	if a.profileStore == nil || spec.HasUnversionedRuntimeContext(dag) {
		return ""
	}
	workspaceName, _ := workspace.WorkspaceNameFromLabels(dag.Labels)
	identity, err := profilepkg.NewResolver(a.profileStore, a.secretStore).RuntimeIdentity(ctx, profilepkg.RuntimeRequest{
		ProfileName: profileName,
		Workspace:   workspaceName,
	})
	if err != nil {
		logger.Warn(ctx, "Runtime profile identity unknown", tag.DAG(dag.Name), tag.Error(err))
		return ""
	}
	secrets, err := a.registrySecretRevisions(ctx, dag, workspaceName)
	if err != nil {
		logger.Warn(ctx, "DAG secret revisions unknown", tag.DAG(dag.Name), tag.Error(err))
		return ""
	}
	return spec.RunRuntimeIdentity(dag, identity, secrets)
}

// registrySecretRevisions names, by secret name, the stored revision each
// registry secret reference of dag resolves to now, from metadata alone. A
// secret that is missing, disabled or not managed is an error.
func (a *API) registrySecretRevisions(ctx context.Context, dag *ir.DAG, workspaceName string) (map[string]secretref.Revision, error) {
	if len(dag.Secrets) == 0 {
		return nil, nil
	}
	if a.secretStore == nil {
		return nil, errors.New("secret store is not configured")
	}
	resolver := secretpkg.NewReferenceResolver(a.secretStore, workspaceName)
	revisions := make(map[string]secretref.Revision, len(dag.Secrets))
	for _, ref := range dag.Secrets {
		revision, err := resolver.Revision(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("secret %q: %w", ref.Name, err)
		}
		revisions[ref.Name] = revision
	}
	return revisions, nil
}

// reuseRuntimeAPIError maps a refusal of AdmitReuseRuntime to its response.
func reuseRuntimeAPIError(err error) error {
	if refusal, ok := errors.AsType[*intake.ReuseRuntimeError](err); ok {
		return &Error{
			HTTPStatus: http.StatusConflict,
			Code:       api.ErrorCodeConflict,
			Message:    refusal.Message,
		}
	}
	if bad, ok := errors.AsType[*intake.RunStepSourceError](err); ok {
		return badSelectedStepsRequest(bad.Message)
	}
	return err
}

// CheckDAGReuseRuntime implements api.StrictServerInterface. It answers,
// for each named run, whether a step run of the DAG started now could reuse
// its outputs automatically: the server decides the step run's profile and
// compares identities, and no identity leaves it. A run the caller may not
// reuse answers as one that does not exist.
func (a *API) CheckDAGReuseRuntime(ctx context.Context, request api.CheckDAGReuseRuntimeRequestObject) (api.CheckDAGReuseRuntimeResponseObject, error) {
	if request.Body == nil {
		return nil, badSelectedStepsRequest("request body is required")
	}
	runIDs, err := reuseRuntimeRunIDs(request.Body.RunIds)
	if err != nil {
		return nil, err
	}

	var (
		dag         *ir.DAG
		profileName string
	)
	if specContent := valueOf(request.Body.Spec); specContent != "" {
		// A draft's steps run through POST /dag-runs: the same load and
		// refusals, and only an explicit profile (none here).
		probeID, err := ir.NewDAGRunID()
		if err != nil {
			return nil, fmt.Errorf("error generating probe ID: %w", err)
		}
		// Loaded without evaluation: a comparison runs no command of the
		// draft (params eval and the like) and reads nothing it names.
		draft, cleanup, err := a.loadDraftRunDAG(ctx, specContent, request.Body.Name, "", probeID, spec.WithoutEval())
		if err != nil {
			return nil, err
		}
		defer cleanup()
		dag = draft
	} else {
		saved, err := a.loadSavedRunDAG(ctx, request.FileName)
		if err != nil {
			return nil, err
		}
		dag = saved
		// The profile the start route takes with no override. One that
		// cannot be taken leaves the identity unknown: the start would be
		// refused for it anyway.
		name, err := a.runProfileForDAG(ctx, request.FileName, dagWorkspaceName(dag), nil)
		if err != nil {
			dag = nil
		}
		profileName = name
	}

	identity := ""
	if dag != nil {
		identity = a.prospectiveRuntimeIdentity(ctx, dag, profileName)
	}
	runs := make([]struct {
		DagRunId api.DAGRunId                     `json:"dagRunId"`
		Runtime  api.ReuseRuntimeCheckRunsRuntime `json:"runtime"`
	}, 0, len(runIDs))
	for _, runID := range runIDs {
		answer := api.ReuseRuntimeCheckRunsRuntimeUnknown
		if identity != "" {
			if recorded := a.reusableRunIdentity(ctx, dag.Name, runID); recorded != "" {
				answer = api.ReuseRuntimeCheckRunsRuntimeDifferent
				if recorded == identity {
					answer = api.ReuseRuntimeCheckRunsRuntimeSame
				}
			}
		}
		runs = append(runs, struct {
			DagRunId api.DAGRunId                     `json:"dagRunId"`
			Runtime  api.ReuseRuntimeCheckRunsRuntime `json:"runtime"`
		}{DagRunId: runID, Runtime: answer})
	}
	return api.CheckDAGReuseRuntime200JSONResponse{Runs: runs}, nil
}

// reusableRunIdentity is the recorded runtime identity of a run of the DAG
// that the caller may reuse; empty when the run is missing, not visible to
// the caller, or recorded no identity. The three are not told apart.
func (a *API) reusableRunIdentity(ctx context.Context, dagName, runID string) string {
	attempt, err := a.dagRunRepository.FindAttempt(ctx, ir.NewDAGRunRef(dagName, runID))
	if err != nil {
		return ""
	}
	status, err := attempt.ReadStatus(ctx)
	if err != nil || status == nil {
		return ""
	}
	if err := a.requireDAGRunStatusExecute(ctx, status); err != nil {
		return ""
	}
	return status.RuntimeIdentity
}

// reuseRuntimeRunIDs validates the run IDs of a reuse-runtime request and
// drops repeats, keeping the first.
func reuseRuntimeRunIDs(raw []api.DAGRunId) ([]string, error) {
	if len(raw) == 0 {
		return nil, badSelectedStepsRequest("runIds must name at least one run")
	}
	if len(raw) > maxReuseRuntimeRuns {
		return nil, badSelectedStepsRequest(fmt.Sprintf("runIds names more than %d runs", maxReuseRuntimeRuns))
	}
	seen := make(map[string]struct{}, len(raw))
	ids := make([]string, 0, len(raw))
	for _, id := range raw {
		runID := strings.TrimSpace(id)
		if runID == "" {
			return nil, badSelectedStepsRequest("runIds must not be empty")
		}
		if err := validateDAGRunID(runID); err != nil {
			return nil, err
		}
		if _, dup := seen[runID]; dup {
			continue
		}
		seen[runID] = struct{}{}
		ids = append(ids, runID)
	}
	return ids, nil
}
