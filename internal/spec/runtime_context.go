// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package spec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"

	"github.com/dagucloud/dagu/v2/internal/ir"
	secretref "github.com/dagucloud/dagu/v2/internal/secret/ref"
)

// RunRuntimeIdentity is the runtime identity of a run of dag whose profile
// layers resolved to profileIdentity (see profile.RuntimeResolved.Identity)
// and whose registry secret references resolved to secrets, by secret name:
// the one rule the hub, deciding a reuse, and the run, checking it, both
// apply. It is unknown (empty) when the profile identity is, when a secret
// reference has no stored revision, or when the run takes context the hub
// keeps no version of. The effective settings that bound what a step
// outputs are part of it (TXE-6145).
//
// A DAG without secrets keeps the identity it had before secret references
// were covered (TXE-6222).
func RunRuntimeIdentity(dag *ir.DAG, profileIdentity string, secrets map[string]secretref.Revision) string {
	if profileIdentity == "" || HasUnversionedRuntimeContext(dag) {
		return ""
	}
	identity := profileIdentity + ";max_output_size=" + strconv.Itoa(dag.MaxOutputSize)
	if len(dag.Secrets) == 0 {
		return identity
	}
	secretsIdentity := registrySecretsIdentity(dag.Secrets, secrets)
	if secretsIdentity == "" {
		return ""
	}
	return identity + ";dag_secrets=" + secretsIdentity
}

// registrySecretsIdentityPrefix marks the version of the encoding of a
// DAG's registry secret revisions.
const registrySecretsIdentityPrefix = "ds1:"

// registrySecretRevision names the stored state one DAG secret took: the
// variable it sets, the managed secret, and the version of its value.
type registrySecretRevision struct {
	Name     string `json:"name"`
	SecretID string `json:"secretId"`
	Version  int    `json:"version"`
}

// registrySecretsIdentity names the stored state of every secret in refs,
// all of them registry references, from revisions: a digest of their
// canonical structured form, which holds no value and nothing derived from
// one. Empty when a secret has no stored revision, or two secrets set one
// name.
func registrySecretsIdentity(refs []secretref.Ref, revisions map[string]secretref.Revision) string {
	canonical := make([]registrySecretRevision, 0, len(refs))
	seen := make(map[string]bool, len(refs))
	for _, ref := range refs {
		revision, ok := revisions[ref.Name]
		if ref.Ref == "" || seen[ref.Name] || !ok || !revision.Known() {
			return ""
		}
		seen[ref.Name] = true
		canonical = append(canonical, registrySecretRevision{Name: ref.Name, SecretID: revision.SecretID, Version: revision.Version})
	}
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].Name < canonical[j].Name })
	data, err := json.Marshal(canonical)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return registrySecretsIdentityPrefix + hex.EncodeToString(sum[:])
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
// that the hub holds no version of: DAG-level secrets from external
// providers (a registry reference has a stored revision, which
// RunRuntimeIdentity names), a base configuration with any setting beyond scheduling, history and
// logging, a container env_file, or a sub-DAG, which resolves context of its
// own. Graph steps and lifecycle handlers count alike: an init handler runs
// before the graph. A run with such context has no runtime identity, so its
// outputs are never reused automatically (TXE-6145, TXE-6222).
//
// Dotenv files are not decided here: every DAG names ".env", and whether a
// file exists is known only where the run reads it. The run decides that
// from the files it read, or that were read for it (ir.DAG.DotenvLoaded).
func HasUnversionedRuntimeContext(dag *ir.DAG) bool {
	if dag == nil {
		return true
	}
	if hasProviderSecret(dag.Secrets) || baseConfigHasRuntimeContext(dag.BaseConfigData) || containerHasEnvFile(dag.Container) {
		return true
	}
	for _, step := range runSteps(dag) {
		if step.SubDAG != nil || containerHasEnvFile(step.Container) {
			return true
		}
	}
	return false
}

// hasProviderSecret reports whether any secret is read from an external
// provider rather than a registry reference. A provider holds the value's
// version, if any, outside the hub, and reading it would mean calling the
// provider.
func hasProviderSecret(refs []secretref.Ref) bool {
	for _, ref := range refs {
		if ref.Ref == "" {
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
