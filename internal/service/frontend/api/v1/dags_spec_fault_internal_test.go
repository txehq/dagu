// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/spec"
	"github.com/stretchr/testify/require"
)

// An update that failed for a reason of no author-caused kind is never
// answered as a validation error, even when the submitted spec has a fault
// of its own; and a fault of another kind than the update's is not either.
func TestSubmittedSpecFaultNeedsAFaultOfTheUpdatesKind(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const scalarDocument = "just a string\n"

	for name, updateErr := range map[string]error{
		"plain":     errors.New("disk failure"),
		"not_exist": os.ErrNotExist,
		"wrapped":   errors.Join(errors.New("failed to locate DAG"), os.ErrPermission),
	} {
		require.Nil(t, submittedSpecFault(ctx, "x", scalarDocument, updateErr), name)
	}

	_, syntaxErr := spec.LoadYAML(ctx, []byte("steps: [\n"), spec.WithoutEval(), spec.WithName("x"))
	require.Error(t, syntaxErr)
	require.Nil(t, submittedSpecFault(ctx, "x", scalarDocument, syntaxErr), "a fault of another kind")
	require.Nil(t, submittedSpecFault(ctx, "x", "steps:\n  - id: a\n    run: echo hi\n", syntaxErr), "a spec with no fault")

	_, nodeErr := spec.LoadYAML(ctx, []byte(scalarDocument), spec.WithoutEval(), spec.WithName("x"))
	require.Error(t, nodeErr)
	fault := submittedSpecFault(ctx, "x", scalarDocument, nodeErr)
	require.NotNil(t, fault)
	require.Equal(t, []string{"failed to decode document 0: [1:1] string was used where mapping is expected\n>  1 | just a string\n       ^\n"}, fault.ToStringList())
}
