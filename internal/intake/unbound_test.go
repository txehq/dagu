// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package intake_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/intake"
	"github.com/dagucloud/dagu/v2/internal/ir"
)

// A run no hub principal asks for (a webhook delivery) that reaches the queue
// without the owner rule's decision is refused before anything is created, so
// a new path that queues one without the rule fails closed (TXE-5923).
func TestAnUnboundRunNeedsTheOwnerDecision(t *testing.T) {
	t.Parallel()
	_, err := intake.EnqueueRun(context.Background(), intake.QueueRequest{
		DAG:         &ir.DAG{Name: "ci"},
		DAGRunID:    "run-1",
		TriggerType: ir.TriggerTypeWebhook,
		// No repository or queue: the refusal comes before either is used.
	})
	require.ErrorIs(t, err, intake.ErrUnboundTriggerUndecided)
}
