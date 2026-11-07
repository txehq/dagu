// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package spec_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/spec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// builderEdgesFixture holds definitions and the dependencies the builder
// gives each step, by step name. The UI's step hash graph is checked against
// the same file (stepHashes.test.ts), so a dependency the builder adds and
// the hash leaves out, such as the chain edge a step with depends of its
// own still gets, fails there.
const builderEdgesFixture = "../../ui/src/features/visual-editor/run/__tests__/testdata/builder-edges.json"

type builderEdgesCase struct {
	Name    string              `json:"name"`
	Spec    string              `json:"spec"`
	Depends map[string][]string `json:"depends"`
}

// The fixture's dependencies are the builder's own: each case is built here
// and compared. Set DAGU_UPDATE_BUILDER_EDGES=1 to rewrite the file from the
// builder after adding a case.
func TestBuilderEdgesFixtureIsTheBuildersOwn(t *testing.T) {
	data, err := os.ReadFile(filepath.FromSlash(builderEdgesFixture))
	require.NoError(t, err)
	var cases []builderEdgesCase
	require.NoError(t, json.Unmarshal(data, &cases))
	require.NotEmpty(t, cases)
	for i, c := range cases {
		dag, err := spec.LoadYAML(t.Context(), []byte(c.Spec))
		require.NoError(t, err, c.Name)
		byKey := map[string]string{}
		for _, step := range dag.Steps {
			byKey[step.Name] = step.Name
			if step.ID != "" {
				byKey[step.ID] = step.Name
			}
		}
		built := map[string][]string{}
		for _, step := range dag.Steps {
			deps := []string{}
			for _, dep := range step.Depends {
				name, ok := byKey[dep]
				require.True(t, ok, "%s: %s depends on unknown %s", c.Name, step.Name, dep)
				deps = append(deps, name)
			}
			slices.Sort(deps)
			built[step.Name] = slices.Compact(deps)
		}
		if os.Getenv("DAGU_UPDATE_BUILDER_EDGES") != "" {
			cases[i].Depends = built
			continue
		}
		assert.Equal(t, built, c.Depends, "%s: the fixture says what the builder builds", c.Name)
	}
	if os.Getenv("DAGU_UPDATE_BUILDER_EDGES") != "" {
		out, err := json.MarshalIndent(cases, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.FromSlash(builderEdgesFixture), append(out, '\n'), 0o600))
	}
}

// A chain step cannot name dependencies of its own: the builder refuses the
// definition, so the chain edge is the only dependency a chain step has.
func TestChainRefusesExplicitDepends(t *testing.T) {
	_, err := spec.LoadYAML(t.Context(), []byte("type: chain\nsteps:\n  - name: a\n    run: echo a\n  - name: b\n    run: echo b\n  - name: c\n    depends: [a]\n    run: echo c\n"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "depends field is not allowed for DAGs with type 'chain'")
}
