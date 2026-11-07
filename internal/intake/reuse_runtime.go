// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package intake

import (
	"fmt"

	"github.com/dagucloud/dagu/v2/internal/ir"
)

// ReuseRuntimeError refuses a selected-steps run whose automatically reused
// outputs do not come from a run of the new run's runtime identity. Its
// message names the step and the run.
type ReuseRuntimeError struct {
	Message string
}

func (e *ReuseRuntimeError) Error() string { return e.Message }

// ReuseRuntimeRequest is what the runtime identity admission of a
// selected-steps run looks at.
type ReuseRuntimeRequest struct {
	DAG *ir.DAG
	// Automatic names, by step name or ID, the skipped steps whose outputs
	// the client reuses on its own choice rather than the user's.
	Automatic []string
	// Identity is the runtime identity the new run would take now; empty
	// when unknown.
	Identity string
	// Source is the run named by outputsFromRunId, if any.
	Source *ir.DAGRunStatus
	// FromRuns are the runs named by outputsFromRuns.
	FromRuns RunStepSources
	// Reused is where each skipped step took its outputs from.
	Reused []ir.ReusedInput
	// SuppliedOutputs is true when the request supplied output values.
	SuppliedOutputs bool
}

// ReuseRuntimeAdmission is the identity a selected-steps run is seeded with.
type ReuseRuntimeAdmission struct {
	// Identity is what the seed records as its runtime identity: the new
	// run's when every carried node and the copied work directory come from
	// runs of that identity, else empty.
	Identity string
	// Expected is the identity the run must resolve before any step; set
	// only when some outputs were reused automatically.
	Expected string
}

// AdmitReuseRuntime checks that each automatically reused step carries its
// outputs from a run of the new run's runtime identity, and says what the
// seed records (TXE-6145). An unknown identity, on either side, is never the
// same. A step reused on the user's choice is not checked: it only stops
// the run's own identity from being known. A step in Automatic that carries
// nothing reuses nothing and is passed over; one whose outputs the request
// supplies, or that names no step, is a bad request (*RunStepSourceError);
// one whose run is of another or an unknown identity is refused
// (*ReuseRuntimeError).
func AdmitReuseRuntime(req ReuseRuntimeRequest) (ReuseRuntimeAdmission, error) {
	runs := make(map[string]*ir.DAGRunStatus, len(req.FromRuns)+1)
	if req.Source != nil {
		runs[req.Source.DAGRunID] = req.Source
	}
	for _, run := range req.FromRuns {
		if run != nil {
			runs[run.DAGRunID] = run
		}
	}
	byStep := make(map[string]ir.ReusedInput, len(req.Reused))
	for _, in := range req.Reused {
		byStep[in.Step] = in
	}
	same := func(in ir.ReusedInput) bool {
		run := runs[in.RunID]
		return in.Via == ir.ReusedInputViaRun && run != nil && req.Identity != "" && run.RuntimeIdentity == req.Identity
	}

	for _, ref := range req.Automatic {
		name, err := resolveStepName(req.DAG, ref)
		if err != nil {
			return ReuseRuntimeAdmission{}, &RunStepSourceError{Message: fmt.Sprintf("automaticReuse: %v", err)}
		}
		in, ok := byStep[name]
		if !ok {
			// The step carries nothing: nothing is reused to check.
			continue
		}
		if in.Via != ir.ReusedInputViaRun {
			return ReuseRuntimeAdmission{}, &RunStepSourceError{Message: fmt.Sprintf("automaticReuse names step %s, whose outputs the request supplies rather than a run", name)}
		}
		if !same(in) {
			return ReuseRuntimeAdmission{}, &ReuseRuntimeError{Message: fmt.Sprintf(
				"step %s cannot reuse outputs of run %s automatically: that run did not run under the runtime profile state this run takes, or the state of either is not known; choose the run explicitly, or run the step", name, in.RunID)}
		}
	}

	admission := ReuseRuntimeAdmission{}
	if len(req.Automatic) > 0 {
		admission.Expected = req.Identity
	}
	known := req.Identity != "" && !req.SuppliedOutputs
	if req.Source != nil && req.Source.RuntimeIdentity != req.Identity {
		// The work directory is copied from the source run.
		known = false
	}
	for _, in := range req.Reused {
		if !same(in) {
			known = false
		}
	}
	if known {
		admission.Identity = req.Identity
	}
	return admission, nil
}
