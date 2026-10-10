// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"text/template"

	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/txe/reviewer"
)

// DAGConfig is what a machine supplies to render its reviewer DAGs.
type DAGConfig struct {
	// MachineID is the registry machine the reviewer runs on.
	MachineID string
	// Schedule is the tick cron; it is not a job's review cadence.
	Schedule string
	// StateDir is a durable local directory outside any worktree.
	StateDir string
	// ReviewCommand is the command prefix for the review steps.
	ReviewCommand string
	// Provider is the harness provider that launches the agent.
	Provider string
	// AgentConfigDir, when set, is the agent profile used for reviews.
	AgentConfigDir string
	// Env are extra variables for the review steps. Dagu passes steps only
	// an allowlist of the worker's environment, so anything the steps need
	// beyond PATH and HOME has to be named here.
	Env map[string]string
	// AgentModel, when set, is the model the agent profile is configured
	// with. Disabling the profile's settings also drops its model choice,
	// so the installer reads it from the profile and passes it here. It is
	// the profile's own value carried over, not a model picked for reviews.
	AgentModel string
	// AuthCheck is the agent CLI's login status command; empty disables it.
	AuthCheck string
	// TimeoutSec bounds one whole review run.
	TimeoutSec int
	// AgentTimeoutSec bounds the agent step.
	AgentTimeoutSec int
}

// RenderedDAGs are the two DAG documents to install on the service.
type RenderedDAGs struct {
	ReviewerName string
	Reviewer     string
	DecideName   string
	Decide       string
}

const machineIDPrefix = "mch_"

// ReviewerEnv marks a process as running inside a review.
const ReviewerEnv = "TXE_DAGU_REVIEWER"

var (
	envNamePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	// authCheckPattern keeps the command a plain word list, so it cannot
	// carry shell syntax into the rendered step.
	authCheckPattern  = regexp.MustCompile(`^[A-Za-z0-9_./ -]*$`)
	agentModelPattern = regexp.MustCompile(`^[A-Za-z0-9_.:\[\]-]{0,128}$`)
)

var machineIDPattern = regexp.MustCompile(`^mch_[0-9A-HJKMNP-TV-Z]{26}$`)

// ReviewerDAGName is the name of a machine's periodic reviewer DAG. Dagu
// limits a DAG name to 39 characters, so the name carries the machine id
// without its prefix.
func ReviewerDAGName(machineID string) string {
	return "txe-reviewer-" + strings.TrimPrefix(machineID, machineIDPrefix)
}

// DecideDAGName is the name of the DAG whose runs carry a machine's proposals.
func DecideDAGName(machineID string) string {
	return registry.DecideTaskDAG(machineID)
}

func (c DAGConfig) withDefaults() (DAGConfig, error) {
	if !machineIDPattern.MatchString(c.MachineID) {
		return c, fmt.Errorf("invalid machine id %q", c.MachineID)
	}
	if strings.TrimSpace(c.StateDir) == "" {
		return c, errors.New("state dir is required")
	}
	if c.Schedule == "" {
		c.Schedule = "*/10 * * * *"
	}
	if c.ReviewCommand == "" {
		c.ReviewCommand = "dagu txe review"
	}
	if c.Provider == "" {
		c.Provider = "claude"
		if c.AuthCheck == "" {
			c.AuthCheck = "claude auth status"
		}
	}
	if !agentModelPattern.MatchString(c.AgentModel) {
		return c, fmt.Errorf("invalid agent model %q", c.AgentModel)
	}
	if !authCheckPattern.MatchString(c.AuthCheck) {
		return c, fmt.Errorf("invalid auth check command %q", c.AuthCheck)
	}
	if c.TimeoutSec <= 0 {
		c.TimeoutSec = 900
	}
	if c.AgentTimeoutSec <= 0 {
		c.AgentTimeoutSec = 600
	}
	if c.AgentTimeoutSec >= c.TimeoutSec {
		return c, errors.New("agent timeout must be shorter than the run timeout")
	}
	return c, nil
}

// RenderDAGs renders the reviewer and decision DAGs for one machine.
func RenderDAGs(cfg DAGConfig) (RenderedDAGs, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return RenderedDAGs{}, err
	}
	var schema bytes.Buffer
	if err := json.Compact(&schema, []byte(reviewer.DecisionSchema)); err != nil {
		return RenderedDAGs{}, fmt.Errorf("decision schema: %w", err)
	}
	env := map[string]string{}
	for name, value := range cfg.Env {
		if !envNamePattern.MatchString(name) {
			return RenderedDAGs{}, fmt.Errorf("invalid environment variable name %q", name)
		}
		env[name] = value
	}
	// Job registration refuses to run under this variable, so a review can
	// never register work or launch another reviewer.
	env[ReviewerEnv] = "1"
	if cfg.AgentConfigDir != "" {
		env["CLAUDE_CONFIG_DIR"] = cfg.AgentConfigDir
	}
	names := make([]string, 0, len(env))
	for name := range env {
		names = append(names, name)
	}
	sort.Strings(names)
	type envVar struct{ Name, Value string }
	vars := make([]envVar, 0, len(names))
	for _, name := range names {
		vars = append(vars, envVar{name, env[name]})
	}
	data := struct {
		DAGConfig
		Prompt string
		Schema string
		Vars   []envVar
	}{cfg, strings.TrimSpace(unixLines(reviewer.Prompt)), schema.String(), vars}

	out := RenderedDAGs{
		ReviewerName: ReviewerDAGName(cfg.MachineID),
		DecideName:   DecideDAGName(cfg.MachineID),
	}
	if out.Reviewer, err = renderTemplate("reviewer", reviewer.ReviewerDAG, data); err != nil {
		return RenderedDAGs{}, err
	}
	if out.Decide, err = renderTemplate("decide", reviewer.DecideDAG, data); err != nil {
		return RenderedDAGs{}, err
	}
	return out, nil
}

// unixLines gives embedded text the same line endings whatever checked the
// source out. A Windows checkout can carry CRLF into the embedded files, and
// the rendered DAGs and the agent's prompt must be the same bytes on every
// build.
func unixLines(text string) string {
	return strings.ReplaceAll(text, "\r\n", "\n")
}

func renderTemplate(name, text string, data any) (string, error) {
	tmpl, err := template.New(name).Funcs(template.FuncMap{"yaml": yamlString}).Option("missingkey=error").Parse(unixLines(text))
	if err != nil {
		return "", fmt.Errorf("parse %s template: %w", name, err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render %s template: %w", name, err)
	}
	return buf.String(), nil
}

// yamlString renders a value as a YAML double-quoted scalar. A JSON string
// is one, so no machine-supplied text can change the document's structure.
func yamlString(s string) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}
