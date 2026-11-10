// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package spec

import (
	"maps"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	secretref "github.com/dagucloud/dagu/v2/internal/secret/ref"
)

func TestHasUnversionedRuntimeContext(t *testing.T) {
	t.Parallel()

	known := map[string]*ir.DAG{
		"plain":                {Steps: []ir.Step{{Name: "a"}}},
		"a new hub's base":     {BaseConfigData: []byte("# Base\ntype: graph\noverlap_policy: skip\nlog_output: separate\nhist_retention_days: 30\nmax_clean_up_time_sec: 5\nmax_active_steps: 10\nmax_output_size: 1048576\ncatchup_window: \"6h\"\n")},
		"a container":          {Container: &ir.Container{Image: "alpine"}},
		"dotenv is the run's":  {Dotenv: []string{".env"}},
		"registry secret refs": {Secrets: []secretref.Ref{{Name: "TOKEN", Ref: "team/token"}}},
	}
	for name, dag := range known {
		assert.False(t, HasUnversionedRuntimeContext(dag), name)
	}

	unknown := map[string]*ir.DAG{
		"DAG secrets":       {Secrets: []secretref.Ref{{Name: "TOKEN"}}},
		"a provider secret": {Secrets: []secretref.Ref{{Name: "TOKEN", Provider: "env", Key: "TOKEN"}}},
		"a provider secret beside a registry ref": {Secrets: []secretref.Ref{
			{Name: "A", Ref: "team/a"}, {Name: "B", Provider: "file", Key: "b.txt"},
		}},
		// A pinned provider version is immutable at the provider, but which
		// account a host's credentials reach is not the hub's to know.
		"a pinned AWS version":        {Secrets: []secretref.Ref{{Name: "T", Provider: "aws", Key: "arn:aws:secretsmanager:eu-west-1:1:secret:t", Options: map[string]string{"version_id": "v1"}}}},
		"a pinned GCP version":        {Secrets: []secretref.Ref{{Name: "T", Provider: "gcp", Key: "projects/p/secrets/t/versions/3"}}},
		"base secrets":                {BaseConfigData: []byte("secrets:\n  - name: T\n    ref: team/t\n")},
		"base dotenv":                 {BaseConfigData: []byte("dotenv: base.env\n")},
		"a sub-DAG of this file":      {Steps: []ir.Step{{Name: "a", SubDAG: &ir.SubDAG{Name: "local-child"}}}, LocalDAGs: map[string]*ir.DAG{"local-child": {Name: "local-child"}}},
		"a sub-DAG named at run time": {Steps: []ir.Step{{Name: "a", SubDAG: &ir.SubDAG{Name: "${CHILD}"}}}},
		"base env":                    {BaseConfigData: []byte("env:\n  - A: 1\n")},
		"base type other":             {BaseConfigData: []byte("type: chain\n")},
		"base that does not parse":    {BaseConfigData: []byte(":\n  - [")},
		"DAG container env_file":      {Container: &ir.Container{Image: "alpine", EnvFile: []string{"credentials.env"}}},
		"step container env_file":     {Steps: []ir.Step{{Name: "a", Container: &ir.Container{Image: "alpine", EnvFile: []string{"x.env"}}}}},
		"sub-DAG step":                {Steps: []ir.Step{{Name: "a", SubDAG: &ir.SubDAG{Name: "child"}}}},
		"sub-DAG in a nested foreach body": {Steps: []ir.Step{{Name: "outer", Foreach: &ir.ForeachConfig{Steps: []ir.Step{
			{Name: "inner", Foreach: &ir.ForeachConfig{Steps: []ir.Step{{Name: "call", SubDAG: &ir.SubDAG{Name: "child"}}}}},
		}}}}},
		"env_file in a handler's foreach body": {HandlerOn: ir.HandlerOn{Init: &ir.Step{Name: "init", Foreach: &ir.ForeachConfig{Steps: []ir.Step{
			{Name: "prep", Container: &ir.Container{Image: "alpine", EnvFile: []string{"x.env"}}},
		}}}}},
	}
	for name, dag := range unknown {
		assert.True(t, HasUnversionedRuntimeContext(dag), name)
	}
}

// Every lifecycle handler is a step the run may execute: a new kind of
// handler is covered without a change here.
func TestHasUnversionedRuntimeContextSeesEveryHandler(t *testing.T) {
	t.Parallel()

	typ := reflect.TypeFor[ir.HandlerOn]()
	for i := range typ.NumField() {
		field := typ.Field(i)
		dag := &ir.DAG{}
		reflect.ValueOf(&dag.HandlerOn).Elem().Field(i).Set(reflect.ValueOf(&ir.Step{Name: field.Name, SubDAG: &ir.SubDAG{Name: "child"}}))
		assert.True(t, HasUnversionedRuntimeContext(dag), "handler %s calls a sub-DAG", field.Name)
	}
	assert.Empty(t, runSteps(&ir.DAG{}))
}

func TestRunRuntimeIdentity(t *testing.T) {
	t.Parallel()

	dag := &ir.DAG{MaxOutputSize: 1024}
	assert.Empty(t, RunRuntimeIdentity(dag, "", nil), "an unknown profile state stays unknown")
	assert.Empty(t, RunRuntimeIdentity(&ir.DAG{Secrets: []secretref.Ref{{Name: "T"}}}, "rp1:x", nil))
	assert.NotEqual(t, RunRuntimeIdentity(dag, "rp1:x", nil), RunRuntimeIdentity(&ir.DAG{MaxOutputSize: 2048}, "rp1:x", nil))
	assert.Equal(t, RunRuntimeIdentity(dag, "rp1:x", nil), RunRuntimeIdentity(&ir.DAG{MaxOutputSize: 1024}, "rp1:x", nil))
}

// Registry secret references are named by the stored revision each resolved
// to; a DAG without secrets keeps the identity it had before (TXE-6222).
func TestRunRuntimeIdentityNamesRegistrySecrets(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "rp1:x;max_output_size=1024", RunRuntimeIdentity(&ir.DAG{MaxOutputSize: 1024}, "rp1:x", nil),
		"a DAG without secrets is unchanged")

	dag := &ir.DAG{Secrets: []secretref.Ref{{Name: "A", Ref: "team/a"}, {Name: "B", Ref: "team/b"}}}
	revisions := map[string]secretref.Revision{"A": {SecretID: "sa", Version: 1}, "B": {SecretID: "sb", Version: 4}}
	with := func(name string, revision secretref.Revision) map[string]secretref.Revision {
		changed := maps.Clone(revisions)
		changed[name] = revision
		return changed
	}
	x := RunRuntimeIdentity(dag, "rp1:x", revisions)
	require.NotEmpty(t, x)
	assert.True(t, strings.HasPrefix(x, "rp1:x;max_output_size=0;dag_secrets=ds1:"), x)

	assert.Equal(t, x, RunRuntimeIdentity(&ir.DAG{Secrets: []secretref.Ref{dag.Secrets[1], dag.Secrets[0]}}, "rp1:x", revisions),
		"the order secrets are listed in")
	assert.Equal(t, x, RunRuntimeIdentity(dag, "rp1:x", with("UNUSED", secretref.Revision{SecretID: "s", Version: 1})),
		"a revision of no secret of the DAG")
	assert.NotEqual(t, x, RunRuntimeIdentity(dag, "rp1:x", with("B", secretref.Revision{SecretID: "sb", Version: 5})), "a new version")
	assert.NotEqual(t, x, RunRuntimeIdentity(dag, "rp1:x", with("B", secretref.Revision{SecretID: "sc", Version: 4})), "another secret")
	assert.NotEqual(t, x, RunRuntimeIdentity(&ir.DAG{Secrets: []secretref.Ref{{Name: "A", Ref: "team/a"}, {Name: "C", Ref: "team/b"}}}, "rp1:x",
		map[string]secretref.Revision{"A": revisions["A"], "C": revisions["B"]}), "the same secret set as another variable")
	assert.NotEqual(t, x, RunRuntimeIdentity(dag, "rp1:y", revisions), "another profile state")

	for name, unknown := range map[string]map[string]secretref.Revision{
		"no revisions":     nil,
		"a secret without": {"A": revisions["A"]},
		"no version":       with("B", secretref.Revision{SecretID: "sb"}),
		"no secret ID":     with("B", secretref.Revision{Version: 4}),
	} {
		assert.Empty(t, RunRuntimeIdentity(dag, "rp1:x", unknown), name)
	}
	assert.Empty(t, RunRuntimeIdentity(&ir.DAG{Secrets: []secretref.Ref{{Name: "A", Ref: "team/a"}, {Name: "A", Ref: "team/b"}}}, "rp1:x", revisions),
		"two secrets that set one variable")
	assert.Empty(t, RunRuntimeIdentity(&ir.DAG{Secrets: []secretref.Ref{{Name: "A", Ref: "team/a"}, {Name: "B", Provider: "env", Key: "B"}}}, "rp1:x", revisions),
		"a provider secret beside a registry ref")
	assert.Empty(t, RunRuntimeIdentity(dag, "", revisions), "an unknown profile state")
}
