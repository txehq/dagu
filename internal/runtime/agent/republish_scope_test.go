// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package agent

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cmnvalue "github.com/dagucloud/dagu/v2/internal/cmn/value"
	"github.com/dagucloud/dagu/v2/internal/ir"
	profilepkg "github.com/dagucloud/dagu/v2/internal/profile"
	secretref "github.com/dagucloud/dagu/v2/internal/secret/ref"
)

// A republish keeps only the TXE variables; the job's own variables, params
// and their definitions, dotenv files and secrets stay out, and the DAG it was given is unchanged
// (TXE-5067).
func TestRepublishScopedDAG(t *testing.T) {
	dag := &ir.DAG{
		Name: "job_1",
		Env: []string{"TXE_JOB_ID=job_1", "TXE_ATTEMPT_ID=${context.attempt.id}", "TXE_DAGU_HOME=/h",
			"BASH_ENV=/tmp/x", "LD_PRELOAD=/tmp/x.so", "TARGET=vol-1", "TXE_CUSTOM=job-set"},
		Secrets:       []secretref.Ref{{Name: "LINEAR_API_KEY", Provider: "file", Key: "/k"}},
		Dotenv:        []string{".env"},
		Params:        []string{"P=1"},
		DefaultParams: "P=1",
		ParamsJSON:    `{"P":"1"}`,
		ParamDefs:     []ir.ParamDef{{Name: "P", Default: "1"}},
		ParamSchema:   []byte(`{"type":"object"}`),
	}
	scoped := republishScopedDAG(dag)
	require.NotNil(t, scoped)
	assert.Equal(t, []string{"TXE_JOB_ID=job_1", "TXE_ATTEMPT_ID=${context.attempt.id}", "TXE_DAGU_HOME=/h"}, scoped.Env)
	assert.Empty(t, scoped.Secrets)
	assert.Empty(t, scoped.Dotenv)
	assert.Empty(t, scoped.Params)
	assert.Empty(t, scoped.DefaultParams)
	assert.Empty(t, scoped.ParamsJSON)
	assert.Empty(t, scoped.ParamDefs)
	assert.Empty(t, scoped.ParamSchema)
	assert.Len(t, dag.Env, 7, "the given DAG is not changed")
	assert.Len(t, dag.Secrets, 1)
	assert.Nil(t, republishScopedDAG(nil))
}

// A republish resolves no runtime profile, selected or a workspace's
// defaults, and inherits no parent run's variables, so a profile's
// variables and secrets cannot reach the publish step (TXE-5067).
func TestRepublishScopedOptions(t *testing.T) {
	opts := Options{
		ProfileName:     "ops",
		ProfileStore:    stubProfileStore{},
		ProfileResolver: stubProfileResolver{},
		InheritedEnvs:   []cmnvalue.EnvEntry{{Key: "BASH_ENV", Value: "/tmp/x"}},
		WorkerID:        "w1",
	}
	scoped := republishScopedOptions(opts)
	assert.Empty(t, scoped.ProfileName)
	assert.Nil(t, scoped.ProfileStore)
	assert.Nil(t, scoped.ProfileResolver)
	assert.Empty(t, scoped.InheritedEnvs)
	assert.Equal(t, "w1", scoped.WorkerID, "other options are kept")

	a := &Agent{profileName: scoped.ProfileName, profileStore: scoped.ProfileStore, profileResolver: scoped.ProfileResolver}
	values, err := a.resolveProfile(context.Background())
	require.NoError(t, err)
	assert.Empty(t, values.defaultEnvs)
	assert.Empty(t, values.defaultSecrets)
	assert.Empty(t, values.selectedEnvs)
	assert.Empty(t, values.selectedSecrets)
}

type stubProfileStore struct{ profilepkg.Store }

type stubProfileResolver struct{ profilepkg.RuntimeResolver }
