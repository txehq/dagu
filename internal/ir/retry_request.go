// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package ir

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// RetryRequest correlates an execution with the request that admitted it: a
// conditional retry made for one attempt of one action. The hub writes it on
// the admitted execution's first status and keeps it on every later status
// of that execution; a worker's report never sets or changes it. Its fields
// are those of an abandonment record's request correlation, plus RetryOf.
type RetryRequest struct {
	// ID is derived by the hub from the other fields, the run and the
	// expected execution (NewRetryRequest), so each action attempt has its
	// own.
	ID            string `json:"id"`
	ActionID      string `json:"actionId"`
	ActionAttempt string `json:"actionAttempt"`
	BindingDigest string `json:"bindingDigest"`
	// RetryOf is the ExecutionRef of the execution the request retried.
	RetryOf string `json:"retryOf"`
}

// ErrInvalidRetryRequest is returned for a request without an action ID,
// action attempt or binding digest.
var ErrInvalidRetryRequest = errors.New("a retry request needs actionId, actionAttempt and bindingDigest")

// NewRetryRequest returns the correlation of a conditional retry of run that
// expects execution (expectedAttemptID, expectedQueuedAt), made for the given
// action attempt. Its ID is the sha256, in hex, of the canonical JSON of all
// of them.
func NewRetryRequest(run DAGRunRef, expectedAttemptID, expectedQueuedAt, actionID, actionAttempt, bindingDigest string) (*RetryRequest, error) {
	if actionID == "" || actionAttempt == "" || bindingDigest == "" {
		return nil, ErrInvalidRetryRequest
	}
	type expected struct {
		AttemptID string `json:"attemptId"`
		QueuedAt  string `json:"queuedAt"`
	}
	type runRef struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	}
	data, err := json.Marshal(struct {
		ActionAttempt string   `json:"actionAttempt"`
		ActionID      string   `json:"actionId"`
		BindingDigest string   `json:"bindingDigest"`
		Expected      expected `json:"expected"`
		Run           runRef   `json:"run"`
	}{actionAttempt, actionID, bindingDigest, expected{expectedAttemptID, expectedQueuedAt}, runRef(run)})
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return &RetryRequest{
		ID:            hex.EncodeToString(sum[:]),
		ActionID:      actionID,
		ActionAttempt: actionAttempt,
		BindingDigest: bindingDigest,
		RetryOf:       ExecutionRef(expectedAttemptID, expectedQueuedAt),
	}, nil
}

// Clone returns a copy of r, or nil.
func (r *RetryRequest) Clone() *RetryRequest {
	if r == nil {
		return nil
	}
	c := *r
	return &c
}
