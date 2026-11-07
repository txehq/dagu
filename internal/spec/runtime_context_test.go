// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package spec

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dagucloud/dagu/v2/internal/ir"
	secretref "github.com/dagucloud/dagu/v2/internal/secret/ref"
)

func TestHasUnversionedRuntimeContext(t *testing.T) {
	t.Parallel()

	known := map[string]*ir.DAG{
		"plain":               {Steps: []ir.Step{{Name: "a"}}},
		"a new hub's base":    {BaseConfigData: []byte("# Base\ntype: graph\noverlap_policy: skip\nlog_output: separate\nhist_retention_days: 30\nmax_clean_up_time_sec: 5\nmax_active_steps: 10\nmax_output_size: 1048576\ncatchup_window: \"6h\"\n")},
		"a container":         {Container: &ir.Container{Image: "alpine"}},
		"dotenv is the run's": {Dotenv: []string{".env"}},
	}
	for name, dag := range known {
		assert.False(t, HasUnversionedRuntimeContext(dag), name)
	}

	unknown := map[string]*ir.DAG{
		"DAG secrets":              {Secrets: []secretref.Ref{{Name: "TOKEN"}}},
		"base env":                 {BaseConfigData: []byte("env:\n  - A: 1\n")},
		"base type other":          {BaseConfigData: []byte("type: chain\n")},
		"base that does not parse": {BaseConfigData: []byte(":\n  - [")},
		"DAG container env_file":   {Container: &ir.Container{Image: "alpine", EnvFile: []string{"credentials.env"}}},
		"step container env_file":  {Steps: []ir.Step{{Name: "a", Container: &ir.Container{Image: "alpine", EnvFile: []string{"x.env"}}}}},
		"sub-DAG step":             {Steps: []ir.Step{{Name: "a", SubDAG: &ir.SubDAG{Name: "child"}}}},
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
	assert.Empty(t, RunRuntimeIdentity(dag, ""), "an unknown profile state stays unknown")
	assert.Empty(t, RunRuntimeIdentity(&ir.DAG{Secrets: []secretref.Ref{{Name: "T"}}}, "rp1:x"))
	assert.NotEqual(t, RunRuntimeIdentity(dag, "rp1:x"), RunRuntimeIdentity(&ir.DAG{MaxOutputSize: 2048}, "rp1:x"))
	assert.Equal(t, RunRuntimeIdentity(dag, "rp1:x"), RunRuntimeIdentity(&ir.DAG{MaxOutputSize: 1024}, "rp1:x"))
}
