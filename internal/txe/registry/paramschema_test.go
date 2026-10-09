// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const restartSchema = `{
	"type": "object",
	"properties": {
		"mode": {"type": "string", "enum": ["soft", "hard"]},
		"replicas": {"type": "integer", "minimum": 1, "maximum": 5}
	},
	"required": ["mode"],
	"additionalProperties": false
}`

// A param_schema is checked when a version is registered: one that is not a
// schema, refers to a remote document, or uses a keyword nothing enforces
// is refused, so a version never promises an unenforced restriction.
func TestParamSchemaIsCheckedAtRegistration(t *testing.T) {
	f := newFixture(t)
	for name, schema := range map[string]string{
		"not JSON":           `{`,
		"not an object":      `"string"`,
		"remote reference":   `{"$ref": "https://example.com/schema.json"}`,
		"unenforced format":  `{"type": "object", "properties": {"when": {"type": "string", "format": "date-time"}}}`,
		"unknown keyword":    `{"type": "object", "x-max-cost": 3}`,
		"invalid constraint": `{"type": "object", "minProperties": "two"}`,
		"nested remote $ref": `{"type": "object", "properties": {"a": {"$ref": "other.json#/x"}}}`,
	} {
		v := f.version(1)
		v.ReviewPolicy.PermittedActions[1].ParamSchema = json.RawMessage(schema)
		jobID := f.mint(PrefixJob)
		_, err := f.store.Register(f.ctx, RegisterInput{JobID: jobID, RequestID: "req-" + jobID, OwnerID: f.owner, ProjectID: f.project,
			MachineID: f.machine, JobKey: "k-" + jobID, Version: v}, cli)
		assert.Equal(t, CodeInvalid, code(t, err), name)
	}
	v := f.version(1)
	v.ReviewPolicy.PermittedActions[1].ParamSchema = json.RawMessage(restartSchema)
	jobID := f.mint(PrefixJob)
	_, err := f.store.Register(f.ctx, RegisterInput{JobID: jobID, RequestID: "req-" + jobID, OwnerID: f.owner, ProjectID: f.project,
		MachineID: f.machine, JobKey: "k-ok", Version: v}, cli)
	require.NoError(t, err, "an enforceable schema with a local $defs is fine")
}

// Every attempt of an action is granted only with parameters its
// permitted action's param_schema accepts; a refused attempt writes nothing.
func TestActionParamsAreValidatedBeforeTheGrant(t *testing.T) {
	f := newFixture(t)
	job := f.readyWith("k", func(v *JobVersion) {
		v.ReviewPolicy.PermittedActions[1].ParamSchema = json.RawMessage(restartSchema) // restart (routine)
		v.ReviewPolicy.PermittedActions[2].ParamSchema = json.RawMessage(restartSchema) // resize (approved)
	})
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	grant := func(params string) error {
		review, err := ReviewID(job.JobID, job.Checkpoint.Version)
		require.NoError(t, err)
		spec := ActionSpec{Name: "restart"}
		if params != "" {
			spec.Params = json.RawMessage(params)
		}
		actionID, err := RoutineActionID(review, spec)
		require.NoError(t, err)
		_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
			_, err := tx.Authorize(EffectRequest{ActionID: actionID, JobVersion: job.Version, PackageDigest: job.PackageDigest,
				Routine: &RoutineEffect{ReviewID: review, ClaimID: c.ClaimID, Fence: c.Fence, Spec: spec}})
			return err
		})
		return err
	}
	for name, params := range map[string]string{
		"value outside the enum":   `{"mode": "medium"}`,
		"wrong type":               `{"mode": "soft", "replicas": "3"}`,
		"above the maximum":        `{"mode": "soft", "replicas": 9}`,
		"not an integer":           `{"mode": "soft", "replicas": 2.5}`,
		"missing a required field": `{"replicas": 2}`,
		"an undeclared field":      `{"mode": "soft", "force": true}`,
		"absent params":            ``,
	} {
		assert.Equal(t, CodeInvalid, code(t, grant(params)), name)
	}
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Empty(t, got.Actions, "a refused attempt writes nothing")

	require.NoError(t, grant(`{"mode": "hard", "replicas": 5}`))

	// An approved action is checked the same way before its grant.
	ec := c
	var p *Proposal
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		var err error
		p, err = tx.PutProposal(ec.ClaimID, ec.Fence, Proposal{ProposalID: f.mint(PrefixProposal),
			Action: ActionSpec{Name: "resize", Params: json.RawMessage(`{"mode": "medium"}`)}})
		return err
	})
	require.NoError(t, err)
	d, err := decide(f, job.JobID, p, VerdictApprove, ProposalDecided, "k-1")
	require.NoError(t, err)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error { return tx.ReleaseClaim(ec.ClaimID, ec.Fence) })
	require.NoError(t, err)
	xc := acquire(t, f, job.JobID, ClaimExecution, time.Hour)
	actionID, err := ApprovedActionID(p.ProposalID, d.DecisionID)
	require.NoError(t, err)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.Authorize(EffectRequest{ActionID: actionID, JobVersion: job.Version, PackageDigest: job.PackageDigest,
			Approved: &ApprovedEffect{ProposalID: p.ProposalID, DecisionID: d.DecisionID, ClaimID: xc.ClaimID, Fence: xc.Fence}})
		return err
	})
	assert.Equal(t, CodeInvalid, code(t, err), "an approved action outside its schema is not granted")
}
