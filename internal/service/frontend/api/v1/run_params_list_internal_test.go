// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
)

// A run's parameters reach the client as the list the run received, so a
// value's whitespace and where it ends are kept. A record that keeps only the
// joined listing sends no list: the client then treats the parameters as
// unknown rather than split them back wrongly (TXE-5923).
func TestRunParamsList(t *testing.T) {
	t.Parallel()
	list := runParamsList(ir.DAGRunStatus{Params: "A=1 B=2", ParamsList: []string{"A=1 B=2"}})
	require.NotNil(t, list)
	assert.Equal(t, []string{"A=1 B=2"}, *list, "one value, kept whole")

	assert.Nil(t, runParamsList(ir.DAGRunStatus{Params: "A=1"}), "a joined listing alone is unknown")

	none := runParamsList(ir.DAGRunStatus{})
	require.NotNil(t, none)
	assert.Empty(t, *none, "a run with no parameters has an empty list")

	summary := toDAGRunSummary(ir.DAGRunStatus{Name: "wf", ParamsList: []string{"A=a  b"}})
	require.NotNil(t, summary.ParamsList)
	assert.Equal(t, []string{"A=a  b"}, *summary.ParamsList)
}
