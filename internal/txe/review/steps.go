// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Steps are the entry points of the reviewer's DAG steps. Each call is one
// short process; the only thing carried between them is the prepared file.
type Steps struct {
	Reviewer  *Reviewer
	MachineID string
	// StateDir holds the hand-off between a run's steps. It must be durable
	// and outside any worktree.
	StateDir string
	// AuthCheck is an optional command that reports whether the agent CLI
	// is logged in, without calling a model. It runs only after an agent
	// produced nothing, to tell a missing login from any other failure.
	AuthCheck []string
}

var (
	runIDPattern    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
	recordIDPattern = regexp.MustCompile(`^[a-z]{3}_[0-9A-Za-z]{1,64}$`)
)

const (
	maxAgentOutput  = 4 << 20
	maxAgentLogTail = 16 << 10
)

func (s *Steps) preparedPath(runID string) (string, error) {
	if !runIDPattern.MatchString(runID) {
		return "", fmt.Errorf("invalid run id %q", runID)
	}
	return filepath.Join(s.StateDir, "reviews", runID, "prepared.json"), nil
}

// Prepare claims the first due job it can and writes that job's context
// packet to stdout. It writes nothing when no job is due, which the DAG's
// later steps treat as nothing to do.
func (s *Steps) Prepare(ctx context.Context, runID string, stdout io.Writer) error {
	path, err := s.preparedPath(runID)
	if err != nil {
		return err
	}
	due, err := s.Reviewer.Registry.DueJobs(ctx, s.MachineID, s.Reviewer.now())
	if err != nil {
		return fmt.Errorf("list due jobs: %w", err)
	}
	// One job that cannot be prepared must not starve the others, so its
	// error is reported only when the tick found nothing else to review.
	var failed error
	for _, jobID := range due {
		prepared, err := s.Reviewer.Prepare(ctx, jobID)
		if err != nil {
			failed = errors.Join(failed, fmt.Errorf("prepare %s: %w", jobID, err))
			continue
		}
		if prepared.Skipped != "" {
			continue
		}
		if err := writeJSONFile(path, prepared); err != nil {
			// Without the hand-off the claim could never be used.
			_ = s.Reviewer.Registry.ReleaseClaim(ctx, prepared.Claim)
			return fmt.Errorf("save prepared review: %w", err)
		}
		return json.NewEncoder(stdout).Encode(prepared.Packet)
	}
	return failed
}

// StepResult is what a step prints for the run log.
type StepResult struct {
	JobID    string    `json:"job_id,omitempty"`
	ReviewID string    `json:"review_id,omitempty"`
	Applied  *Applied  `json:"applied,omitempty"`
	Failure  string    `json:"failure,omitempty"`
	Executed *Executed `json:"executed,omitempty"`
}

// Apply reads the agent's output and applies it to the run's prepared review.
// An unusable output becomes a visible exception; it is not an error of the
// step, because the review ended in a recorded state. agentLog is the path of
// the agent step's stderr log, which the harness fills when the agent fails;
// it is used only to say why there was no output.
func (s *Steps) Apply(ctx context.Context, runID string, agentOutput io.Reader, agentLog string, stdout io.Writer) error {
	path, err := s.preparedPath(runID)
	if err != nil {
		return err
	}
	var prepared Prepared
	data, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &prepared); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	raw, err := io.ReadAll(io.LimitReader(agentOutput, maxAgentOutput))
	if err != nil {
		return fmt.Errorf("read agent output: %w", err)
	}

	result := StepResult{JobID: prepared.Packet.Job.ID, ReviewID: prepared.Packet.ReviewID}
	reviewer := *s.Reviewer
	if models := AgentModels(raw); len(models) > 0 {
		reviewer.AgentClient = strings.TrimSpace(reviewer.AgentClient + " " + strings.Join(models, ","))
	}
	reviewer.AgentInputTokens, reviewer.AgentOutputTokens = AgentUsage(raw)

	decision, err := ParseAgentOutput(raw)
	if err != nil && strings.TrimSpace(string(raw)) == "" {
		failure := ClassifyAgentFailure(readLogTail(agentLog))
		if failure.Kind != ExceptionReviewerAuth && !s.agentLoggedIn(ctx) {
			failure = &AgentFailure{Kind: ExceptionReviewerAuth, Message: "the agent is not logged in on this machine"}
		}
		err = failure
	}
	var applied Applied
	if err == nil {
		applied, err = reviewer.Apply(ctx, prepared, decision)
	}
	var failure *AgentFailure
	switch {
	case errors.As(err, &failure):
		if failErr := reviewer.Fail(ctx, prepared, failure); failErr != nil {
			return failErr
		}
		result.Failure = failure.Error()
	case err != nil:
		return err
	default:
		result.Applied = &applied
	}
	return json.NewEncoder(stdout).Encode(result)
}

// Execute runs the single effect an approve decision authorizes.
func (s *Steps) Execute(ctx context.Context, jobID, proposalID, decisionID string, stdout io.Writer) error {
	// These arrive as run parameters and task input, which anyone able to
	// enqueue or complete the run controls.
	for prefix, id := range map[string]string{"job_": jobID, "prp_": proposalID, "dec_": decisionID} {
		if !strings.HasPrefix(id, prefix) || !recordIDPattern.MatchString(id) {
			return fmt.Errorf("invalid %sid %q", prefix, id)
		}
	}
	executed, err := s.Reviewer.Execute(ctx, jobID, proposalID, decisionID)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(StepResult{JobID: jobID, Executed: &executed})
}

const authCheckTimeout = 30 * time.Second

// agentLoggedIn runs the auth check. It reports false only on a clear
// answer: a status object saying loggedIn is false. Only that one field is
// read; the rest of the status can name the account and is never recorded.
func (s *Steps) agentLoggedIn(ctx context.Context) bool {
	if len(s.AuthCheck) == 0 {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, authCheckTimeout)
	defer cancel()
	// #nosec G204 -- the command is rendered into the DAG by the installer.
	out, _ := exec.CommandContext(ctx, s.AuthCheck[0], s.AuthCheck[1:]...).Output()
	var status struct {
		LoggedIn *bool `json:"loggedIn"`
	}
	if json.Unmarshal(out, &status) != nil || status.LoggedIn == nil {
		return true
	}
	return *status.LoggedIn
}

// readLogTail returns the end of a log file, or nothing if it is unreadable.
func readLogTail(path string) []byte {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil
	}
	if len(data) > maxAgentLogTail {
		data = data[len(data)-maxAgentLogTail:]
	}
	return data
}

func writeJSONFile(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// EnqueueFunc enqueues one run of a DAG with an explicit run id. It must
// return ErrRunExists when that run id was already enqueued.
type EnqueueFunc func(ctx context.Context, dag, runID string, params map[string]string) error

// ErrRunExists means the run id is already taken, so the run was opened by
// an earlier attempt.
var ErrRunExists = errors.New("txe review: run already exists")

// RunOpener makes a proposal answerable by enqueueing its own run of the
// decision DAG. The run stops at a native human task and holds no process.
type RunOpener struct {
	Enqueue EnqueueFunc
}

var _ DecisionOpener = (*RunOpener)(nil)

// OpenDecision implements DecisionOpener.
func (o *RunOpener) OpenDecision(ctx context.Context, proposal Proposal) error {
	task := proposal.NativeTask
	err := o.Enqueue(ctx, task.DAG, task.RunID, map[string]string{
		"JOB_ID":      proposal.JobID,
		"PROPOSAL_ID": proposal.ID,
	})
	if errors.Is(err, ErrRunExists) {
		return nil
	}
	return err
}
