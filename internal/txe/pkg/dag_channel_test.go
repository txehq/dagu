// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	runtimeexec "github.com/dagucloud/dagu/v2/internal/runtime/executor"
	"github.com/dagucloud/dagu/v2/internal/spec"
)

// The worker channel does not carry workspace bundles. A bundle exists only for
// a DAG with file dependencies, so a rendered job must never have any.
func TestARenderedJobHasNoFileDependencies(t *testing.T) {
	for name, publish := range map[string]*Publish{"plain": nil, "publishing": {HubArtifacts: true}} {
		s := testDAGSpec()
		s.Publish = publish
		data, err := RenderDAG(s)
		require.NoError(t, err, name)
		dag, err := spec.LoadYAML(context.Background(), data, spec.WithoutEval())
		require.NoError(t, err, name)
		assert.False(t, runtimeexec.HasDAGFileDependencies(dag), name)
	}
}
