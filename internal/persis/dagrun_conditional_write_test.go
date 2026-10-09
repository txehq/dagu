// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package persis

import (
	"context"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/dagrun"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/stretchr/testify/require"
)

// noConditionalAttempt is an attempt whose store cannot write conditionally.
type noConditionalAttempt struct {
	dagrun.Attempt
}

// A repository attempt over a store without conditional writes refuses one
// and writes nothing, so a caller can fall back to a verified path.
func TestEventingAttemptWriteIfLatestUnsupported(t *testing.T) {
	t.Parallel()

	writer, ok := newEventingAttempt(&noConditionalAttempt{}, nil).(dagrun.ConditionalWriter)
	require.True(t, ok)
	err := writer.WriteIfLatest(context.Background(), ir.DAGRunStatus{}, func(*ir.DAGRunStatus) error {
		require.FailNow(t, "the check must not run")
		return nil
	})
	require.ErrorIs(t, err, dagrun.ErrConditionalWriteUnsupported)
}
