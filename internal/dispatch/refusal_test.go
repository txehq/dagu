// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package dispatch

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The coordinator's two refusals for want of a worker are told apart from
// each other and from every other failure, as the coordinator returns them
// and as the client wraps them, by their gRPC status alone.
func TestDispatchRefusals(t *testing.T) {
	noMatch := status.Error(codes.FailedPrecondition, NoMatchingWorkersMessage)
	noWorker := status.Error(codes.Unavailable, NoAvailableWorkersMessage)

	for name, err := range map[string]error{"as returned": noMatch, "wrapped": fmt.Errorf("dispatch: %w", noMatch)} {
		assert.True(t, IsNoMatchingWorker(err), name)
		assert.False(t, IsNoAvailableWorker(err), name)
	}
	for name, err := range map[string]error{"as returned": noWorker, "wrapped": fmt.Errorf("dispatch: %w", noWorker)} {
		assert.True(t, IsNoAvailableWorker(err), name)
		assert.False(t, IsNoMatchingWorker(err), name)
	}
	for name, err := range map[string]error{
		"nil":                     nil,
		"another refusal":         status.Error(codes.FailedPrecondition, "distributed dispatch requires DAG run storage"),
		"the coordinator is down": status.Error(codes.Unavailable, "connection refused"),
		"a plain error":           errors.New("boom"),
		// Only the coordinator's status is the refusal, not a message that
		// mentions it.
		"another code naming it":   status.Error(codes.Internal, NoMatchingWorkersMessage),
		"a plain error naming it":  errors.New(NoAvailableWorkersMessage),
		"the same code, more text": status.Error(codes.FailedPrecondition, "workspace of DAG \""+NoMatchingWorkersMessage+"\" is missing"),
	} {
		assert.False(t, IsNoMatchingWorker(err), name)
		assert.False(t, IsNoAvailableWorker(err), name)
	}
}
