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
	// The canonical form, pinned: sha256 of
	// {"actionAttempt":"1","actionId":"act-1","bindingDigest":"sha256:d",
	//  "expected":{"attemptId":"a1","queuedAt":"q1"},"run":{"name":"job","id":"run-1"}}
	// with no whitespace.
	assert.Equal(t, "1bd70964d76fb1639b8f3478358ee7f851890711cee34452fb45887115296024", a.ID)
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
