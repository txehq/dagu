// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dagucloud/dagu/v2/internal/ir"
)

// An execution keeps the retry request of its source status only when that
// status is the queued status that admitted it; a direct retry's source is
// the earlier, finished execution, whose request is not this execution's.
func TestOwnRetryRequest(t *testing.T) {
	request := &ir.RetryRequest{ID: "r1", ActionID: "act-1", ActionAttempt: "1", BindingDigest: "d", RetryOf: "x"}
	a := &Agent{dagRunAttemptID: "a1"}
	assert.Equal(t, request, a.ownRetryRequest(&ir.DAGRunStatus{AttemptID: "a0", Status: ir.Queued, RetryRequest: request}), "run from its queued admission")
	assert.Nil(t, a.ownRetryRequest(&ir.DAGRunStatus{AttemptID: "a0", Status: ir.Failed, RetryRequest: request}), "a direct retry's earlier execution")
	assert.Nil(t, a.ownRetryRequest(&ir.DAGRunStatus{AttemptID: "a1", Status: ir.Failed, RetryRequest: request}), "a finished execution, even of this attempt")
	assert.Nil(t, a.ownRetryRequest(nil))
}
