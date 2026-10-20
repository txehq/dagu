// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package dispatch

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The coordinator refuses a dispatch with these when no worker can take the
// task, so that every caller tells the two apart the same way.
const (
	// NoMatchingWorkersMessage: workers are connected, but none may take the
	// task, because none has the labels its selector names or, with machine
	// pinning enforced, none is the machine it is pinned to.
	NoMatchingWorkersMessage = "no workers match the required selector"
	// NoAvailableWorkersMessage: no healthy worker is connected at all.
	NoAvailableWorkersMessage = "no available workers"
)

// IsNoMatchingWorker reports whether err is the coordinator's refusal of a
// task no connected worker may take: its gRPC status, as returned or
// wrapped, never a message that merely mentions it.
func IsNoMatchingWorker(err error) bool {
	return isRefusal(err, codes.FailedPrecondition, NoMatchingWorkersMessage)
}

// IsNoAvailableWorker reports whether err is the coordinator's refusal for
// want of any healthy worker, by its gRPC status as IsNoMatchingWorker.
func IsNoAvailableWorker(err error) bool {
	return isRefusal(err, codes.Unavailable, NoAvailableWorkersMessage)
}

// isRefusal reports whether err carries, as returned or wrapped, the gRPC
// status the coordinator refuses with: its code and exactly its message. A
// status of the same code whose message only contains the words is another
// failure, and wrapping adds text only outside the status.
func isRefusal(err error, code codes.Code, message string) bool {
	var carrier interface{ GRPCStatus() *status.Status }
	if !errors.As(err, &carrier) {
		return false
	}
	st := carrier.GRPCStatus()
	return st != nil && st.Code() == code && st.Message() == message
}
