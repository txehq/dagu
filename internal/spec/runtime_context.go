// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package spec

import (
	"strconv"

	"github.com/dagucloud/dagu/v2/internal/ir"
)

// RunRuntimeIdentity is the runtime identity of a run of dag whose profile
// layers resolved to profileIdentity (see profile.RuntimeResolved.Identity):
// the one rule the hub, deciding a reuse, and the run, checking it, both
// apply. It is unknown (empty) when the profile identity is, or when the run
// takes context the hub keeps no version of. The effective settings that
// bound what a step outputs are part of it (TXE-6145).
func RunRuntimeIdentity(dag *ir.DAG, profileIdentity string) string {
	if profileIdentity == "" || HasUnversionedRuntimeContext(dag) {
		return ""
	}
	return profileIdentity + ";max_output_size=" + strconv.Itoa(dag.MaxOutputSize)
}

// baseSettingsWithoutRuntimeContext are the base configuration settings that
// change nothing a step sees, or that RunRuntimeIdentity covers: scheduling,
// history, logging, and the output limit. They are what a new hub's base
// configuration holds. Any other setting (env, secrets, dotenv, shell,
// container, params, ...) is context that the hub keeps no version of.
var baseSettingsWithoutRuntimeContext = map[string]bool{
	"overlap_policy":        true,
	"log_output":            true,
	"hist_retention_days":   true,
	"hist_retention_runs":   true,
	"max_clean_up_time_sec": true,
	"max_active_steps":      true,
	"max_active_runs":       true,
	"max_output_size":       true,
	"catchup_window":        true,
}

// HasUnversionedRuntimeContext reports whether a run of dag takes context
// that the hub holds no version of: DAG-level secrets from their providers,
// a base configuration with any setting beyond scheduling, history and
// logging, a container env_file, or a sub-DAG, which resolves context of its
// own. Graph steps and lifecycle handlers count alike: an init handler runs
// before the graph. A run with such context has no runtime identity, so its
// outputs are never reused automatically (TXE-6145; TXE-6222 tracks a
// version for each source).
//
// Dotenv files are not decided here: every DAG names ".env", and whether a
// file exists is known only where the run reads it. The run decides that
// from the files it read, or that were read for it (ir.DAG.DotenvLoaded).
func HasUnversionedRuntimeContext(dag *ir.DAG) bool {
	if dag == nil {
		return true
	}
	if len(dag.Secrets) > 0 || baseConfigHasRuntimeContext(dag.BaseConfigData) || containerHasEnvFile(dag.Container) {
		return true
	}
	for _, step := range runSteps(dag) {
		if step.SubDAG != nil || containerHasEnvFile(step.Container) {
			return true
		}
	}
	return false
}

// runSteps lists every step a run of dag may execute: the graph steps, the
// lifecycle handlers, and the bodies of foreach steps among them, nested
// ones included.
func runSteps(dag *ir.DAG) []*ir.Step {
	steps := make([]*ir.Step, 0, len(dag.Steps)+6)
	var visit func(step *ir.Step)
	visit = func(step *ir.Step) {
		steps = append(steps, step)
		if step.Foreach != nil {
			for i := range step.Foreach.Steps {
				visit(&step.Foreach.Steps[i])
			}
		}
	}
	for i := range dag.Steps {
		visit(&dag.Steps[i])
	}
	h := dag.HandlerOn
	for _, handler := range []*ir.Step{h.Init, h.Failure, h.Success, h.Abort, h.Exit, h.Wait} {
		if handler != nil {
			visit(handler)
		}
	}
	return steps
}

// containerHasEnvFile reports whether a container reads env files: values
// the hub keeps no version of.
func containerHasEnvFile(container *ir.Container) bool {
	return container != nil && len(container.EnvFile) > 0
}

// baseConfigHasRuntimeContext reports whether base configuration data sets
// anything a step could see. Data that does not parse counts as such.
func baseConfigHasRuntimeContext(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	values, err := unmarshalData(data)
	if err != nil {
		return true
	}
	for key, value := range values {
		if key == "type" && value == ir.TypeGraph {
			// The default type; any other changes how steps depend.
			continue
		}
		if !baseSettingsWithoutRuntimeContext[key] {
			return true
		}
	}
	return false
}
