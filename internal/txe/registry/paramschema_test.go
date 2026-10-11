// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"encoding/json"
	"strings"
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
		"not JSON":            `{`,
		"not an object":       `"string"`,
		"remote reference":    `{"$ref": "https://example.com/schema.json"}`,
		"unenforced format":   `{"type": "object", "properties": {"when": {"type": "string", "format": "date-time"}}}`,
		"unknown keyword":     `{"type": "object", "x-max-cost": 3}`,
		"invalid constraint":  `{"type": "object", "minProperties": "two"}`,
		"nested remote $ref":  `{"type": "object", "properties": {"a": {"$ref": "other.json#/x"}}}`,
		"draft-07":            `{"$schema": "http://json-schema.org/draft-07/schema#", "type": "object", "dependentRequired": {"a": ["b"]}}`,
		"nested dialect":      `{"type": "object", "properties": {"a": {"$schema": "https://json-schema.org/draft/2020-12/schema"}}}`,
		"unknown type":        `{"type": "int"}`,
		"multipleOf zero":     `{"type": "integer", "multipleOf": 0}`,
		"multipleOf":          `{"type": "number", "multipleOf": 0.75}`,
		"negative minLength":  `{"type": "string", "minLength": -1}`,
		"invalid pattern":     `{"type": "string", "pattern": "("}`,
		"inexact bound":       `{"type": "integer", "maximum": 9007199254740993}`,
		"duplicate key":       `{"type": "object", "type": "string"}`,
		"required not unique": `{"type": "object", "required": ["a", "a"]}`,
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
	require.NoError(t, err, "an enforceable schema is fine")
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
		"beyond 2^53":              `{"mode": "soft", "replicas": 9007199254740993}`,
		"rounds to an integer":     `{"mode": "soft", "replicas": 1.0000000000000001}`,
		"duplicate key":            `{"mode": "medium", "mode": "soft"}`,
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

// Under draft 2020-12 a dependentRequired restriction is enforced.
func TestParamSchemaDraft202012KeywordsAreEnforced(t *testing.T) {
	pa := PermittedAction{Name: "deploy", ParamSchema: json.RawMessage(`{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"properties": {"destination": {"type": "string"}, "approval": {"type": "string"}},
		"dependentRequired": {"destination": ["approval"]}
	}`)}
	_, err := compileParamSchema(pa.ParamSchema)
	require.NoError(t, err)
	assert.Equal(t, CodeInvalid, ErrorCode(checkActionParams(pa, json.RawMessage(`{"destination": "production"}`))))
	require.NoError(t, checkActionParams(pa, json.RawMessage(`{"destination": "production", "approval": "cab-1"}`)))
}

// Only numbers that are exactly a float64 are admitted, so bounds and
// equality compare the numbers themselves; integer-valued keywords are read
// by value.
func TestParamSchemaNumbersAreExact(t *testing.T) {
	_, err := compileParamSchema(json.RawMessage(`{"type": "number", "maximum": 0.1}`))
	assert.Error(t, err, "0.1 is not exactly a float64")
	pa := PermittedAction{Name: "scale", ParamSchema: json.RawMessage(`{"type": "object", "properties": {"f": {"type": "number", "maximum": 0.5}}}`)}
	_, err = compileParamSchema(pa.ParamSchema)
	require.NoError(t, err)
	require.NoError(t, checkActionParams(pa, json.RawMessage(`{"f": 0.5}`)))
	assert.Equal(t, CodeInvalid, ErrorCode(checkActionParams(pa, json.RawMessage(`{"f": 0.75}`))), "above the bound")
	assert.Equal(t, CodeInvalid, ErrorCode(checkActionParams(pa, json.RawMessage(`{"f": 0.10000000000000001}`))), "not exactly a float64")
	assert.Equal(t, CodeInvalid, ErrorCode(checkActionParams(pa, json.RawMessage(`{"f": 0.3}`))), "not exactly a float64")
	for _, spelling := range []string{"1", "1.0", "1e0"} {
		_, err := compileParamSchema(json.RawMessage(`{"type": "array", "maxItems": ` + spelling + `}`))
		assert.NoError(t, err, spelling)
	}
	_, err = compileParamSchema(json.RawMessage(`{"type": "array", "maxItems": 1.5}`))
	assert.Error(t, err)
}

// The check bounds its own work: a huge exponent, a very long number or a
// deeply nested value is refused before any exact arithmetic.
func TestParamSchemaBoundsItsWork(t *testing.T) {
	pa := PermittedAction{Name: "scale", ParamSchema: json.RawMessage(`{"type": "object"}`)}
	for name, params := range map[string]string{
		"huge exponent": `{"f": 1e1000000000}`,
		"tiny exponent": `{"f": 1e-1000000000}`,
		"long literal":  `{"f": 1` + strings.Repeat("0", 100) + `}`,
		"deep nesting":  `{"f": ` + strings.Repeat("[", 100) + strings.Repeat("]", 100) + `}`,
	} {
		start := time.Now()
		assert.Equal(t, CodeInvalid, ErrorCode(checkActionParams(pa, json.RawMessage(params))), name)
		assert.Less(t, time.Since(start), time.Second, name)
	}
}

// Patterns are Go RE2, as documented: \s is ASCII-only, so a non-breaking
// space is not whitespace to the registry.
func TestParamSchemaPatternsAreGoRE2(t *testing.T) {
	pa := PermittedAction{Name: "tag", ParamSchema: json.RawMessage(`{"type": "object", "properties": {"t": {"type": "string", "pattern": "^[^\\s]+$"}}}`)}
	_, err := compileParamSchema(pa.ParamSchema)
	require.NoError(t, err)
	assert.Equal(t, CodeInvalid, ErrorCode(checkActionParams(pa, json.RawMessage(`{"t": "a b"}`))), "an ASCII space is whitespace")
	require.NoError(t, checkActionParams(pa, json.RawMessage(`{"t": "a\u00a0b"}`)), "U+00A0 is not whitespace in Go RE2")
}
