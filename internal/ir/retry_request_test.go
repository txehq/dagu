// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package ir

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The correlation's ID is fixed by the action attempt, the run and the
// expected execution, and differs when any of them does.
func TestNewRetryRequest(t *testing.T) {
	run := NewDAGRunRef("job", "run-1")
	a, err := NewRetryRequest(run, "a1", "q1", "act-1", "1", "sha256:d")
	require.NoError(t, err)
	again, err := NewRetryRequest(run, "a1", "q1", "act-1", "1", "sha256:d")
	require.NoError(t, err)
	assert.Equal(t, a, again)
	assert.Len(t, a.ID, 64)
	assert.Equal(t, ExecutionRef("a1", "q1"), a.RetryOf)
	assert.Equal(t, RetryRequest{ID: a.ID, ActionID: "act-1", ActionAttempt: "1", BindingDigest: "sha256:d", RetryOf: a.RetryOf}, *a)

	for _, other := range []func() (*RetryRequest, error){
		func() (*RetryRequest, error) { return NewRetryRequest(run, "a1", "q1", "act-1", "2", "sha256:d") },
		func() (*RetryRequest, error) { return NewRetryRequest(run, "a1", "q1", "act-2", "1", "sha256:d") },
		func() (*RetryRequest, error) { return NewRetryRequest(run, "a1", "q1", "act-1", "1", "sha256:e") },
		func() (*RetryRequest, error) { return NewRetryRequest(run, "a1", "q2", "act-1", "1", "sha256:d") },
		func() (*RetryRequest, error) { return NewRetryRequest(run, "a2", "q1", "act-1", "1", "sha256:d") },
		func() (*RetryRequest, error) {
			return NewRetryRequest(NewDAGRunRef("job", "run-2"), "a1", "q1", "act-1", "1", "sha256:d")
		},
	} {
		b, err := other()
		require.NoError(t, err)
		assert.NotEqual(t, a.ID, b.ID)
	}

	_, err = NewRetryRequest(run, "a1", "q1", "", "1", "sha256:d")
	assert.ErrorIs(t, err, ErrInvalidRetryRequest)
	assert.Nil(t, (*RetryRequest)(nil).Clone())
}
