// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// A bound written in a job spec reaches the real registry as it was written,
// or the spec is refused and nothing reaches the registry at all. Before the
// client refused it, "maximum: 0.49999999999999999" was sent as 0.5, the
// registry admitted 0.5, and a parameter of 0.5 was granted.
func TestTxeClientSchemaNumbersAgainstTheHub(t *testing.T) {
	server := builtinServer(t)
	token := loginAndGetToken(t, server, "admin", "adminpass")
	ctx := context.Background()
	c := txeclient.New(fmt.Sprintf("http://127.0.0.1:%d/api/v1", server.Config.Server.Port), token, http.DefaultClient)

	installation, err := c.Installation(ctx)
	require.NoError(t, err)
	require.Contains(t, installation.Capabilities, txeclient.CapabilityParamSchema)

	cli := txeclient.Actor{Kind: txeclient.ActorKindCLI, ID: "cc2-test"}
	owner, machine := mint(t, registry.PrefixOwner), mint(t, registry.PrefixMachine)
	require.NoError(t, c.Do(ctx, http.MethodPost, "/txe/owners", nil,
		map[string]any{"owner_id": owner, "display_name": "Connor Wang", "actor": cli}, nil))
	require.NoError(t, c.Do(ctx, http.MethodPost, "/txe/machines", nil,
		map[string]any{"machine_id": machine, "owner_id": owner, "display_name": "laptop", "actor": cli}, nil))
	project, err := c.EnsureProject(ctx, owner, "github.com/txehq/txe", "", cli)
	require.NoError(t, err)

	// action reads a permitted action as a job spec writes it.
	action := func(maximum string) (txeclient.PermittedAction, error) {
		var a txeclient.PermittedAction
		err := yaml.Unmarshal([]byte("name: rebalance\ntimeout_sec: 60\nroutine: true\nparam_schema:\n"+
			"  type: object\n  properties:\n    share:\n      type: number\n      minimum: 0\n      maximum: "+maximum+"\n"+
			"  required: [share]\n  additionalProperties: false\n"), &a)
		return a, err
	}
	digest := fmt.Sprintf("sha256:%064x", 7)
	register := func(jobID string, a txeclient.PermittedAction) (*txeclient.Job, error) {
		return c.RegisterJob(ctx, txeclient.RegisterRequest{
			JobID: jobID, RequestID: "r1", OwnerID: owner, ProjectID: project.ProjectID, MachineID: machine, JobKey: "key:" + jobID,
			Version: txeclient.JobVersion{
				Title: "t", Purpose: "p",
				Package:      txeclient.Package{Digest: digest, Path: "/pkg", Entrypoint: "run.sh"},
				DAG:          txeclient.DAGRef{Spec: fmt.Sprintf("worker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/run.sh\n", machine)},
				ReviewPolicy: txeclient.ReviewPolicy{PermittedActions: []txeclient.PermittedAction{a}},
			},
			Actor: cli,
		})
	}
	registered := func() int {
		jobs, err := c.ListJobs(ctx, txeclient.JobFilter{MachineID: machine})
		require.NoError(t, err)
		return len(jobs)
	}

	// grant asks the registry to authorize the action with these parameters.
	type claim struct {
		ClaimID string `json:"claim_id"`
		Fence   int64  `json:"fence"`
	}
	grant := func(jobID string, held claim, params string) error {
		review, err := registry.ReviewID(jobID, 0)
		require.NoError(t, err)
		actionID, err := registry.RoutineActionID(review, registry.ActionSpec{Name: "rebalance", Params: json.RawMessage(params)})
		require.NoError(t, err)
		return c.Do(ctx, http.MethodPost, "/txe/jobs/"+jobID+"/effect-grants", nil, map[string]any{
			"action_id": actionID, "job_version": 1, "package_digest": digest,
			"routine": map[string]any{"review_id": review, "claim_id": held.ClaimID, "fence": held.Fence,
				"spec": map[string]any{"name": "rebalance", "params": json.RawMessage(params)}},
		}, nil)
	}
	var refused *txeclient.Error
	// noGrant shows that the parameter the written bound excludes, 0.5, gets
	// nothing for a job that was never registered.
	noGrant := func(jobID string) {
		assert.Zero(t, registered())
		require.ErrorAs(t, c.Do(ctx, http.MethodPost, "/txe/jobs/"+jobID+"/claims", nil,
			map[string]any{"kind": "review", "ttl_sec": 600, "reviewer": map[string]any{"machine_id": machine}, "actor": cli}, nil), &refused)
		assert.Equal(t, http.StatusNotFound, refused.Status)
		require.ErrorAs(t, grant(jobID, claim{ClaimID: "none", Fence: 1}, `{"share":0.5}`), &refused)
		assert.Equal(t, http.StatusNotFound, refused.Status)
	}

	// The spec is refused when it is read: there is no action to send, so
	// no job, and no grant for the 0.5 the written bound excludes.
	_, err = action("0.49999999999999999")
	require.ErrorContains(t, err, "the number 0.49999999999999999 would be sent as 0.5, a different number")
	noGrant(mint(t, registry.PrefixJob))

	// A schema held as JSON is sent byte for byte, so the registry sees the
	// number as written and refuses it in its own words.
	exact, err := action("0.5")
	require.NoError(t, err)
	asWritten := exact
	asWritten.ParamSchema = txeclient.ParamSchema(`{"type":"object","properties":{"share":{"type":"number","minimum":0,"maximum":0.49999999999999999}},"required":["share"],"additionalProperties":false}`)
	jobID := mint(t, registry.PrefixJob)
	_, err = register(jobID, asWritten)
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, http.StatusBadRequest, refused.Status)
	assert.Contains(t, refused.Message, "0.49999999999999999 cannot be checked exactly")
	noGrant(jobID)

	// The client sends what was written and does not judge it. 0.1 is sent
	// as 0.1, and this registry, which compares binary fractions, refuses it.
	tenth, err := action("0.1")
	require.NoError(t, err)
	assert.Contains(t, string(tenth.ParamSchema), `"maximum":0.1,"minimum":0,`)
	jobID = mint(t, registry.PrefixJob)
	_, err = register(jobID, tenth)
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, http.StatusBadRequest, refused.Status)
	assert.Contains(t, refused.Message, "0.1 cannot be checked exactly")
	noGrant(jobID)

	// A bound that is exact is registered as written and enforced as written.
	jobID = mint(t, registry.PrefixJob)
	job, err := register(jobID, exact)
	require.NoError(t, err)
	_, err = c.MarkReady(ctx, jobID, txeclient.ReadyRequest{ExpectedRevision: job.Revision,
		Package: txeclient.PackageEvidence{Digest: digest, Path: "/pkg", MachineID: machine}, Actor: cli})
	require.NoError(t, err)
	stored, err := c.JobVersion(ctx, jobID, 1)
	require.NoError(t, err)
	assert.JSONEq(t, `{"type":"object","properties":{"share":{"type":"number","minimum":0,"maximum":0.5}},"required":["share"],"additionalProperties":false}`,
		string(stored.ReviewPolicy.PermittedActions[0].ParamSchema))
	assert.Contains(t, string(stored.ReviewPolicy.PermittedActions[0].ParamSchema), `"maximum":0.5`)

	var held claim
	require.NoError(t, c.Do(ctx, http.MethodPost, "/txe/jobs/"+jobID+"/claims", nil,
		map[string]any{"kind": "review", "ttl_sec": 600, "reviewer": map[string]any{"machine_id": machine}, "actor": cli}, &held))
	authorize := func(params string) error { return grant(jobID, held, params) }
	var actions json.RawMessage
	for _, params := range []string{`{"share":0.75}`, `{"share":0.5000000000000001}`, `{"share":-0.25}`} {
		require.ErrorAs(t, authorize(params), &refused, params)
		assert.Equal(t, http.StatusBadRequest, refused.Status, params)
	}
	require.NoError(t, c.Do(ctx, http.MethodGet, "/txe/jobs/"+jobID+"/actions", nil, nil, &actions))
	assert.NotContains(t, string(actions), "rebalance", "a refused parameter leaves no action behind")
	require.NoError(t, authorize(`{"share":0.5}`))
	require.NoError(t, c.Do(ctx, http.MethodGet, "/txe/jobs/"+jobID+"/actions", nil, nil, &actions))
	assert.Contains(t, string(actions), "rebalance")
}
