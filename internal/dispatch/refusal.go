// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package dispatch

import (
	"strings"

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

func isRefusal(err error, code codes.Code, message string) bool {
	if err == nil {
		return false
	}
	st, ok := status.FromError(err)
	return ok && st.Code() == code && strings.Contains(st.Message(), message)
}
