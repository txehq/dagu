// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/template"
)

// ReconcileDAGVersion changes whenever the rendered DAG's shape changes, so
// an installer can tell its copy is stale.
const ReconcileDAGVersion = 1

// Defaults for a rendered reconcile DAG.
const (
	DefaultReconcileSchedule   = "*/15 * * * *"
	DefaultReconcileTimeoutSec = 600
)

// ReconcileDAGConfig is what a machine supplies to render its periodic
// reconcile DAG.
type ReconcileDAGConfig struct {
	// MachineID is the registry machine whose targets the DAG observes.
	MachineID string
	// Schedule is the check's cron; DefaultReconcileSchedule when empty.
	Schedule string
	// DaguBin is the dagu binary the step runs.
	DaguBin string
	// StoreFlags are the flags that point `dagu txe` at the machine's CLI
	// context (--dagu-home, --context, ...). A step inherits the worker's
	// DAGU_HOME, which has no txe context, so they are required.
	StoreFlags []string
	// Env are variables for the step: Dagu passes a step only an allowlist
	// of the worker's environment, so DAGU_HOME, TXE_DAGU_HOME and any
	// environment credential the probes read have to be named here.
	Env map[string]string
	// TimeoutSec bounds one run; DefaultReconcileTimeoutSec when zero.
	TimeoutSec int
}

var (
	machineIDPattern = regexp.MustCompile(`^mch_[0-9A-HJKMNP-TV-Z]{26}$`)
	envNamePattern   = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	// wordPattern keeps the binary and flags plain words, so they cannot
	// carry shell syntax into the rendered command.
	wordPattern     = regexp.MustCompile(`^[A-Za-z0-9_./=:@+-]+$`)
	schedulePattern = regexp.MustCompile(`^[0-9*/,\- ]+$`)
	// secretPattern matches names and values that look like credentials.
	// The rendered DAG is stored on the hub in plain text, so only
	// references and paths may enter it; a caller's mistake fails closed.
	secretPattern = regexp.MustCompile(`(?i)token|secret|passw|credential|api[_-]?key|bearer`)
	// keyPrefixPattern matches values that start like a known API key.
	keyPrefixPattern = regexp.MustCompile(`(?i)^(dagu_|lin_api_|(sk|ghp|gho|xox[abp])[-_])`)
	// pathPattern is a plain absolute or home-relative path.
	pathPattern = regexp.MustCompile(`^[A-Za-z0-9_./~-]+$`)
)

// looksSecret reports whether a value could be a credential rather than a
// path or a plain word: a credential-like word, a known key prefix, or a
// long run without separators.
func looksSecret(s string) bool {
	if secretPattern.MatchString(s) || keyPrefixPattern.MatchString(s) {
		return true
	}
	return len(s) >= 32 && !strings.ContainsAny(s, "/.")
}

const reconcileTemplate = `# Periodic target reconciliation for TXE jobs on machine {{.MachineID}}.
# Rendered by probe.RenderReconcileDAG; do not edit the installed copy.
# txe-probe-dag-version: {{.Version}}
#
# Observes the reconcile-mode targets of this machine's jobs, and the targets
# of resource events this machine has not finished reporting, and reports
# each observation to the registry. It never retires anything itself.
description: {{yaml .Description}}
schedule: {{yaml .Schedule}}
overlap_policy: skip
max_active_runs: 1
timeout_sec: {{.TimeoutSec}}
worker_selector:
  txe.machine: {{yaml .MachineID}}
{{- if .Vars}}
env:
{{- range .Vars}}
  - {{.Name}}: {{yaml .Value}}
{{- end}}
{{- end}}
steps:
  - id: check
    command: {{yaml .Command}}
`

type reconcileVar struct{ Name, Value string }

// RenderReconcileDAG renders the machine's periodic reconcile DAG. The
// output is deterministic: the same config always renders the same bytes,
// so an installer re-registers only when they differ.
func RenderReconcileDAG(cfg ReconcileDAGConfig) (string, []byte, error) {
	if !machineIDPattern.MatchString(cfg.MachineID) {
		return "", nil, fmt.Errorf("probe: machine id %q is not a registry machine id", cfg.MachineID)
	}
	if !wordPattern.MatchString(cfg.DaguBin) {
		return "", nil, fmt.Errorf("probe: dagu binary %q must be a plain path", cfg.DaguBin)
	}
	for _, f := range cfg.StoreFlags {
		if !wordPattern.MatchString(f) {
			return "", nil, fmt.Errorf("probe: store flag %q must be a plain word", f)
		}
		if looksSecret(f) {
			return "", nil, fmt.Errorf("probe: store flag %q looks like a credential; only references may enter the DAG", f)
		}
	}
	schedule := cfg.Schedule
	if schedule == "" {
		schedule = DefaultReconcileSchedule
	}
	if !schedulePattern.MatchString(schedule) || len(strings.Fields(schedule)) != 5 {
		return "", nil, fmt.Errorf("probe: schedule %q is not a five-field cron", schedule)
	}
	timeout := cfg.TimeoutSec
	if timeout == 0 {
		timeout = DefaultReconcileTimeoutSec
	}
	if timeout < 0 {
		return "", nil, fmt.Errorf("probe: timeout %d is negative", timeout)
	}
	vars := make([]reconcileVar, 0, len(cfg.Env))
	for name, value := range cfg.Env {
		if !envNamePattern.MatchString(name) {
			return "", nil, fmt.Errorf("probe: env name %q is not an environment variable name", name)
		}
		if secretPattern.MatchString(name) || looksSecret(value) || !pathPattern.MatchString(value) {
			return "", nil, fmt.Errorf("probe: env %s must be a plain path, never a credential; the DAG is stored on the hub", name)
		}
		vars = append(vars, reconcileVar{name, value})
	}
	sort.Slice(vars, func(i, j int) bool { return vars[i].Name < vars[j].Name })

	command := strings.Join(append([]string{cfg.DaguBin, "txe", "resource", "check", "--machine", cfg.MachineID}, cfg.StoreFlags...), " ")
	tmpl, err := template.New("reconcile").Funcs(template.FuncMap{"yaml": yamlString}).Option("missingkey=error").Parse(reconcileTemplate)
	if err != nil {
		return "", nil, fmt.Errorf("probe: parse reconcile template: %w", err)
	}
	var out bytes.Buffer
	if err := tmpl.Execute(&out, map[string]any{
		"MachineID":   cfg.MachineID,
		"Version":     ReconcileDAGVersion,
		"Description": "Reconcile TXE job targets on " + cfg.MachineID,
		"Schedule":    schedule,
		"TimeoutSec":  timeout,
		"Vars":        vars,
		"Command":     command,
	}); err != nil {
		return "", nil, fmt.Errorf("probe: render reconcile DAG: %w", err)
	}
	return ReconcileDAGName(cfg.MachineID), out.Bytes(), nil
}

// yamlString quotes s as a YAML scalar; a JSON string is valid YAML.
func yamlString(s string) (string, error) {
	b, err := json.Marshal(s)
	return string(b), err
}
