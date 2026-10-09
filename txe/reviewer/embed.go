// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

// Package reviewer holds the reviewer's DAG templates, agent prompt and
// decision schema.
package reviewer

import _ "embed"

// ReviewerDAG is the template of the per-machine periodic reviewer DAG.
//
//go:embed reviewer.yaml.tmpl
var ReviewerDAG string

// DecideDAG is the template of the DAG whose runs carry one proposal each.
//
//go:embed decide.yaml.tmpl
var DecideDAG string

// Prompt is the fixed instruction given to the review agent.
//
//go:embed prompt.md
var Prompt string

// DecisionSchema is the JSON Schema of the agent's structured decision.
//
//go:embed decision.schema.json
var DecisionSchema string
