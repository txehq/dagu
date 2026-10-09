// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// AgentAction is one follow-up the agent asks for.
type AgentAction struct {
	Name     string            `json:"name"`
	TargetID string            `json:"target_id"`
	Params   map[string]string `json:"params,omitempty"`
	Reason   string            `json:"reason"`
}

// AgentDecision is the structured output of one review. It is a request:
// Apply decides what actually runs.
type AgentDecision struct {
	Outcome            Outcome       `json:"outcome"`
	Reasoning          string        `json:"reasoning"`
	EvidenceRunIDs     []string      `json:"evidence_run_ids"`
	Actions            []AgentAction `json:"actions,omitempty"`
	Question           string        `json:"question,omitempty"`
	NextReviewAfterSec int           `json:"next_review_after_sec,omitempty"`
}

// AgentFailure describes an agent run that produced no usable decision.
type AgentFailure struct {
	Kind    ExceptionKind
	Message string
}

func (f *AgentFailure) Error() string {
	return fmt.Sprintf("txe review: %s: %s", f.Kind, f.Message)
}

var (
	authFailurePattern = regexp.MustCompile(`(?i)(please run /login|invalid api key|authentication[_ ]error|oauth token has expired|not logged in|401 unauthorized)`)
	paramNamePattern   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

const maxFailureMessageLen = 400

// agentEnvelope is the JSON wrapper agent CLIs print around a result.
type agentEnvelope struct {
	IsError          *bool                      `json:"is_error"`
	Result           json.RawMessage            `json:"result"`
	StructuredOutput json.RawMessage            `json:"structured_output"`
	ModelUsage       map[string]json.RawMessage `json:"modelUsage"`
	Usage            struct {
		Input         int `json:"input_tokens"`
		CacheCreation int `json:"cache_creation_input_tokens"`
		CacheRead     int `json:"cache_read_input_tokens"`
		Output        int `json:"output_tokens"`
	} `json:"usage"`
}

// AgentUsage returns the input and output tokens the agent CLI reports for
// the invocation. Input includes cached context, which is still context the
// agent was given.
func AgentUsage(raw []byte) (input, output int) {
	var env agentEnvelope
	if json.Unmarshal(raw, &env) != nil {
		return 0, 0
	}
	u := env.Usage
	return u.Input + u.CacheCreation + u.CacheRead, u.Output
}

// AgentModels returns the models the agent CLI reports having used, so the
// review record names what actually ran instead of what was configured.
func AgentModels(raw []byte) []string {
	var env agentEnvelope
	if json.Unmarshal(raw, &env) != nil {
		return nil
	}
	models := make([]string, 0, len(env.ModelUsage))
	for name := range env.ModelUsage {
		models = append(models, name)
	}
	sort.Strings(models)
	return models
}

// ParseAgentOutput extracts the decision from an agent CLI's stdout. It
// accepts the bare decision object, a result envelope carrying it as
// structured output, or an envelope whose result text is the decision.
func ParseAgentOutput(raw []byte) (AgentDecision, error) {
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return AgentDecision{}, &AgentFailure{Kind: ExceptionReviewerFailed, Message: "the agent produced no output"}
	}
	if authFailurePattern.MatchString(text) && !strings.Contains(text, `"outcome"`) {
		return AgentDecision{}, &AgentFailure{Kind: ExceptionReviewerAuth, Message: clip(text)}
	}

	candidates := []string{text}
	var env agentEnvelope
	if json.Unmarshal([]byte(text), &env) == nil {
		if env.IsError != nil && *env.IsError {
			kind := ExceptionReviewerFailed
			if authFailurePattern.MatchString(text) {
				kind = ExceptionReviewerAuth
			}
			return AgentDecision{}, &AgentFailure{Kind: kind, Message: clip(rawText(env.Result))}
		}
		// Structured output is preferred over free text when both exist.
		candidates = []string{string(env.StructuredOutput), rawText(env.Result), text}
	}
	for _, c := range candidates {
		if d, ok := decodeDecision(c); ok {
			return d, nil
		}
	}
	return AgentDecision{}, &AgentFailure{Kind: ExceptionReviewerFailed, Message: "the agent output contains no decision object: " + clip(text)}
}

// ClassifyAgentFailure explains an agent run that produced no output from
// what the launcher logged about it. The log is only ever a diagnosis: it is
// never read as a decision.
func ClassifyAgentFailure(log []byte) *AgentFailure {
	text := strings.TrimSpace(string(log))
	switch {
	case text == "":
		return &AgentFailure{Kind: ExceptionReviewerFailed, Message: "the agent produced no output"}
	case authFailurePattern.MatchString(text):
		return &AgentFailure{Kind: ExceptionReviewerAuth, Message: "the agent is not logged in on this machine: " + clip(authFailurePattern.FindString(text))}
	default:
		return &AgentFailure{Kind: ExceptionReviewerFailed, Message: "the agent failed without a decision: " + clipTail(text)}
	}
}

func clipTail(s string) string {
	if len(s) > maxFailureMessageLen {
		return "..." + s[len(s)-maxFailureMessageLen:]
	}
	return s
}

func rawText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

func decodeDecision(text string) (AgentDecision, bool) {
	text = strings.TrimSpace(text)
	if start, end := strings.Index(text, "{"), strings.LastIndex(text, "}"); start >= 0 && end > start {
		text = text[start : end+1]
	} else {
		return AgentDecision{}, false
	}
	var d AgentDecision
	if err := json.Unmarshal([]byte(text), &d); err != nil || d.Outcome == "" {
		return AgentDecision{}, false
	}
	return d, true
}

func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxFailureMessageLen {
		return s[:maxFailureMessageLen] + "..."
	}
	return s
}

// validate checks the decision against the packet it was made from. A
// decision that cites evidence the reviewer was never shown is rejected.
func (d AgentDecision) validate(p Packet) error {
	switch d.Outcome {
	case OutcomeContinue, OutcomeAct, OutcomeWaitHuman, OutcomePauseUnavailable, OutcomeComplete, OutcomeRetire:
	default:
		return fmt.Errorf("unknown outcome %q", d.Outcome)
	}
	if strings.TrimSpace(d.Reasoning) == "" {
		return errors.New("reasoning is required")
	}
	for _, id := range d.EvidenceRunIDs {
		if !p.hasRun(id) {
			return fmt.Errorf("evidence run %q is not in the packet", id)
		}
	}
	if d.Outcome == OutcomeWaitHuman && strings.TrimSpace(d.Question) == "" {
		return errors.New("wait_human requires a question")
	}
	for _, a := range d.Actions {
		if strings.TrimSpace(a.Name) == "" {
			return errors.New("an action has no name")
		}
		for name := range a.Params {
			if !paramNamePattern.MatchString(name) {
				return fmt.Errorf("action %q has an invalid parameter name %q", a.Name, name)
			}
		}
	}
	return nil
}
