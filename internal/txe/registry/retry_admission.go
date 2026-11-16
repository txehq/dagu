// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

// Refusals of a queued retry of a registered job's run (TXE-7518). A queued
// retry runs an execution of the job again; it starts only for the retry
// request of a person's approved dagu.retry_run decision, recorded on the
// queued status by the hub that admitted it.
const (
	// AdmitRetryUnbound refuses a queued retry that carries no retry request:
	// nothing approved it. The local CLI cannot carry one.
	AdmitRetryUnbound AdmitCode = "retry_unbound"
	// AdmitRetryMismatch refuses a queued retry whose retry request was not
	// made for this run's retried execution: it names no execution of the
	// run, or its ID is not the one the hub derives for it.
	AdmitRetryMismatch AdmitCode = "retry_request_mismatch"
)
