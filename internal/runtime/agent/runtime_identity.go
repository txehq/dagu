// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package agent

import (
	"errors"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/spec"
)

// ErrRuntimeIdentityChanged stops a run whose outputs were reused
// automatically when its own runtime identity is not the one the hub checked
// the reused outputs against: a profile layer changed in between, or the
// identity cannot be known here (TXE-6145).
var ErrRuntimeIdentityChanged = errors.New(ir.StartupFailure{Code: ir.StartupFailureRuntimeIdentityChanged}.Message())

// runIdentity is the runtime identity of a run of dag whose profile layers
// resolved to profileIdentity (spec.RunRuntimeIdentity): unknown, too, when
// a dotenv file of the run exists, whether this process read it or an
// earlier one resolved the environment before (RuntimeResolved).
func runIdentity(dag *ir.DAG, profileIdentity string, dotenvFiles []string) string {
	if len(dotenvFiles) > 0 {
		return ""
	}
	return spec.RunRuntimeIdentity(dag, profileIdentity)
}

// recordedRuntimeIdentity is the identity a run records. A run that carries
// nodes of an earlier status (a retry, or a seeded run with reused outputs)
// keeps it only when that status was of the same identity: its nodes did not
// all see one state otherwise.
func recordedRuntimeIdentity(dag *ir.DAG, profileIdentity string, dotenvFiles []string, carried *ir.DAGRunStatus) string {
	identity := runIdentity(dag, profileIdentity, dotenvFiles)
	if identity == "" || carried == nil {
		return identity
	}
	for _, node := range carried.Nodes {
		if node != nil && node.Status != ir.NodeNotStarted {
			if carried.RuntimeIdentity != identity {
				return ""
			}
			break
		}
	}
	return identity
}

// checkExpectedRuntimeIdentity refuses a run seeded with automatically
// reused outputs whose own identity is not the expected one. A run with no
// expectation is not checked. The expectation stays on every status of the
// run, so a retry of it is checked as well.
func checkExpectedRuntimeIdentity(dag *ir.DAG, profileIdentity string, dotenvFiles []string, carried *ir.DAGRunStatus) error {
	if carried == nil || carried.ExpectedRuntimeIdentity == "" {
		return nil
	}
	if runIdentity(dag, profileIdentity, dotenvFiles) != carried.ExpectedRuntimeIdentity {
		return ErrRuntimeIdentityChanged
	}
	return nil
}
