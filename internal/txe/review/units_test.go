// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/txe/review"
	"github.com/dagucloud/dagu/v2/internal/txe/review/reviewtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAgentOutput(t *testing.T) {
	bare := `{"outcome":"continue","reasoning":"fine","evidence_run_ids":["run-1"]}`
	tests := []struct {
		name    string
		raw     string
		outcome review.Outcome
		failure review.ExceptionKind
	}{
		{name: "bare decision", raw: bare, outcome: review.OutcomeContinue},
		{name: "structured output wins over result text", raw: `{"type":"result","is_error":false,"result":"{\"outcome\":\"retire\",\"reasoning\":\"x\"}","structured_output":` + bare + `}`, outcome: review.OutcomeContinue},
		{name: "result text only", raw: `{"type":"result","is_error":false,"result":"Here it is:\n` + "```json\\n" + `{\"outcome\":\"act\",\"reasoning\":\"x\"}` + "\\n```" + `"}`, outcome: review.OutcomeAct},
		{name: "empty", raw: "  ", failure: review.ExceptionReviewerFailed},
		{name: "plain auth error", raw: "Invalid API key · Please run /login", failure: review.ExceptionReviewerAuth},
		{name: "enveloped auth error", raw: `{"type":"result","is_error":true,"result":"OAuth token has expired. Please run /login"}`, failure: review.ExceptionReviewerAuth},
		// Captured from claude 2.1.295 run with a profile that is not logged in.
		{name: "real not-logged-in envelope", raw: `{"type":"result","subtype":"success","is_error":true,"result":"Not logged in · Please run /login","terminal_reason":"api_error","modelUsage":{}}`, failure: review.ExceptionReviewerAuth},
		{name: "enveloped other error", raw: `{"type":"result","is_error":true,"result":"overloaded"}`, failure: review.ExceptionReviewerFailed},
		{name: "prose without a decision", raw: "I could not decide.", failure: review.ExceptionReviewerFailed},
		{name: "object without outcome", raw: `{"reasoning":"x"}`, failure: review.ExceptionReviewerFailed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d, err := review.ParseAgentOutput([]byte(tc.raw))
			if tc.failure == "" {
				require.NoError(t, err)
				assert.Equal(t, tc.outcome, d.Outcome)
				return
			}
			var failure *review.AgentFailure
			require.ErrorAs(t, err, &failure)
			assert.Equal(t, tc.failure, failure.Kind)
		})
	}
}

// A decision whose reasoning merely mentions a login error is still a
// decision.
func TestDecisionMentioningLoginIsNotAnAuthFailure(t *testing.T) {
	d, err := review.ParseAgentOutput([]byte(`{"outcome":"pause_unavailable","reasoning":"the script printed: not logged in","evidence_run_ids":[]}`))
	require.NoError(t, err)
	assert.Equal(t, review.OutcomePauseUnavailable, d.Outcome)
}

func TestAgentModels(t *testing.T) {
	raw := []byte(`{"type":"result","modelUsage":{"model-b":{},"model-a":{}}}`)
	assert.Equal(t, []string{"model-a", "model-b"}, review.AgentModels(raw))
	assert.Empty(t, review.AgentModels([]byte("not json")))
}

func TestDerivedIDs(t *testing.T) {
	rev0 := review.ReviewID("job_A", 0)
	assert.Regexp(t, `^rev_[0-9A-HJKMNP-TV-Z]{26}$`, rev0)
	assert.Equal(t, rev0, review.ReviewID("job_A", 0))
	assert.NotEqual(t, rev0, review.ReviewID("job_A", 1))
	assert.NotEqual(t, rev0, review.ReviewID("job_B", 0))

	a := review.RoutineActionID(rev0, "notify", "t1", nil)
	assert.Equal(t, a, review.RoutineActionID(rev0, "notify", "t1", map[string]string{}))
	assert.NotEqual(t, a, review.RoutineActionID(review.ReviewID("job_A", 1), "notify", "t1", nil), "a later episode is a new action")
	assert.NotEqual(t, a, review.RoutineActionID(rev0, "notify", "t1", map[string]string{"k": "v"}))
	assert.Equal(t,
		review.RoutineActionID(rev0, "notify", "t1", map[string]string{"a": "1", "b": "2"}),
		review.RoutineActionID(rev0, "notify", "t1", map[string]string{"b": "2", "a": "1"}))
	assert.NotEqual(t, review.ApprovedActionID("prp_1", "dec_1"), review.ApprovedActionID("prp_1", "dec_2"))

	runID := review.DecisionRunID(review.UncertainProposalID(a, 1))
	assert.Regexp(t, `^txe-[0-9a-z]{26}$`, runID)
}

func TestRenderDAGs(t *testing.T) {
	cfg := review.DAGConfig{
		MachineID:      "mch_0000000000000000000F1XT001",
		StateDir:       "/var/lib/txe/state",
		AgentConfigDir: "/home/reviewer/.claude-reviewer",
		AgentModel:     "opus[1m]",
		Env:            map[string]string{"TXE_DAGU_HOME": "/home/x/txe: #weird"},
	}
	dags, err := review.RenderDAGs(cfg)
	require.NoError(t, err)

	assert.Equal(t, "txe-reviewer-0000000000000000000F1XT001", dags.ReviewerName)
	assert.Equal(t, "txe-decide-0000000000000000000F1XT001", dags.DecideName)
	assert.Less(t, len(dags.ReviewerName), 40, "Dagu rejects DAG names of 40 characters or more")
	assert.Less(t, len(dags.DecideName), 40)

	for _, want := range []string{
		`txe.machine: "mch_0000000000000000000F1XT001"`,
		"overlap_policy: skip",
		"max_active_runs: 1",
		"timeout_sec: 900",
		`- TXE_DAGU_REVIEWER: "1"`,
		`- CLAUDE_CONFIG_DIR: "/home/reviewer/.claude-reviewer"`,
		`- TXE_DAGU_HOME: "/home/x/txe: #weird"`,
		"dagu txe review prepare --machine mch_0000000000000000000F1XT001 --run-id ${DAG_RUN_ID}",
		"action: harness.run",
		`provider: "claude"`,
		`tools: [""]`,
		`model: "opus[1m]"`,
		`setting-sources: [""]`,
		"strict-mcp-config: true",
		"no-session-persistence: true",
		`dagu txe review apply --run-id ${DAG_RUN_ID} --agent-log "${agent.stderr}" --auth-check "claude auth status"`,
	} {
		assert.Contains(t, dags.Reviewer, want)
	}
	assert.NotContains(t, dags.Reviewer, "human.task", "a waiting task would hold the reviewer DAG")
	assert.NotContains(t, dags.Reviewer, "name:")

	for _, want := range []string{
		"action: human.task",
		"required: [decision_id, verdict]",
		`dagu txe review execute --job "$TXE_JOB_ID" --proposal "$TXE_PROPOSAL_ID" --decision "$TXE_DECISION_ID"`,
		`- TXE_DAGU_REVIEWER: "1"`,
	} {
		assert.Contains(t, dags.Decide, want)
	}
	assert.NotContains(t, dags.Decide, "--job ${JOB_ID}", "a run parameter must not be shell text")
	// harness.run drops an option whose value is an empty string, so the
	// isolating flags must never be rendered as one.
	assert.NotContains(t, dags.Reviewer, `tools: ""`)
	assert.NotContains(t, dags.Reviewer, `setting-sources: ""`)
	assert.NotContains(t, dags.Decide, "schedule:")
	assert.NotContains(t, dags.Decide, "max_active_runs", "unanswered proposals must not queue behind each other")
}

func TestRenderDAGsRejectsBadConfig(t *testing.T) {
	valid := review.DAGConfig{MachineID: "mch_0000000000000000000F1XT001", StateDir: "/s"}
	tests := map[string]func(c *review.DAGConfig){
		"machine id":    func(c *review.DAGConfig) { c.MachineID = "mch_x\nsteps: []" },
		"state dir":     func(c *review.DAGConfig) { c.StateDir = " " },
		"env name":      func(c *review.DAGConfig) { c.Env = map[string]string{"bad-name": "x"} },
		"agent timeout": func(c *review.DAGConfig) { c.TimeoutSec, c.AgentTimeoutSec = 60, 60 },
		"auth check":    func(c *review.DAGConfig) { c.AuthCheck = `x"; rm -rf ~; "` },
		"agent model":   func(c *review.DAGConfig) { c.AgentModel = "opus --dangerously-skip-permissions" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			mutate(&cfg)
			_, err := review.RenderDAGs(cfg)
			require.Error(t, err)
		})
	}
}

func shellAction(script string, idempotency review.Idempotency) review.DeclaredAction {
	return review.DeclaredAction{Name: "a", Command: []string{"/bin/sh", "-c", script}, Idempotency: idempotency, TimeoutSec: 1}
}

// The effect runner reports what it actually knows: a clean exit is applied
// with a receipt, exit 3 is an explicit no-op, and a timeout of anything
// that can have an external effect is unknown.
func TestCommandEffector(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	dir := t.TempDir()
	job := review.Job{ID: "job_A", OwnerID: "own_A", WorkingDir: dir}
	action := review.Action{ID: "act_1", Name: "a", TargetID: "t1", Params: map[string]string{"size_gb": "200; rm -rf /"}}
	e := &review.CommandEffector{}
	ctx := context.Background()

	res := e.Run(ctx, job, shellAction(`printf '%s|%s|%s\n' "$TXE_IDEMPOTENCY_KEY" "$TXE_TARGET_ID" "$TXE_PARAM_SIZE_GB" > seen.txt; echo noise; echo receipt-42`, review.IdempotencyNone), action)
	assert.Equal(t, review.EffectApplied, res.Status)
	assert.Equal(t, "receipt-42", res.Receipt)
	seen, err := os.ReadFile(filepath.Join(dir, "seen.txt"))
	require.NoError(t, err)
	assert.Equal(t, "act_1|t1|200; rm -rf /\n", string(seen), "a parameter is data, never shell text")

	assert.Equal(t, review.EffectNotApplied, e.Run(ctx, job, shellAction("exit 3", review.IdempotencyNone), action).Status)
	assert.Equal(t, review.EffectUnknown, e.Run(ctx, job, shellAction("exit 1", review.IdempotencyNone), action).Status)
	assert.Equal(t, review.EffectUnknown, e.Run(ctx, job, shellAction("exit 1", review.IdempotencyKeyed), action).Status,
		"a keyed action can fail after it applied its effect")
	assert.Equal(t, review.EffectUnknown, e.Run(ctx, job, shellAction("exit 1", review.Idempotency("typo")), action).Status,
		"an unrecognised class is not read as harmless")
	assert.Equal(t, review.EffectNotApplied, e.Run(ctx, job, shellAction("exit 1", review.IdempotencyReadOnly), action).Status)

	start := time.Now()
	assert.Equal(t, review.EffectUnknown, e.Run(ctx, job, shellAction("sleep 30", review.IdempotencyKeyed), action).Status)
	assert.Equal(t, review.EffectNotApplied, e.Run(ctx, job, shellAction("sleep 30", review.IdempotencyReadOnly), action).Status)
	assert.Less(t, time.Since(start), 20*time.Second, "the action timeout is enforced")

	missing := review.DeclaredAction{Name: "a", Command: []string{filepath.Join(dir, "no-such-binary")}, Idempotency: review.IdempotencyNone}
	assert.Equal(t, review.EffectNotApplied, e.Run(ctx, job, missing, action).Status, "a process that never started applied nothing")

	probe := shellAction("true", review.IdempotencyNone)
	assert.Equal(t, review.EffectUnknown, e.Probe(ctx, job, probe, action).Status, "no probe declared")
	probe.Reconcile = []string{"/bin/sh", "-c", "echo found"}
	assert.Equal(t, review.EffectApplied, e.Probe(ctx, job, probe, action).Status)
	probe.Reconcile = []string{"/bin/sh", "-c", "exit 3"}
	assert.Equal(t, review.EffectNotApplied, e.Probe(ctx, job, probe, action).Status)
	probe.Reconcile = []string{"/bin/sh", "-c", "exit 1"}
	assert.Equal(t, review.EffectUnknown, e.Probe(ctx, job, probe, action).Status)
}

func (f *fixture) steps(holder, stateDir string) *review.Steps {
	return &review.Steps{Reviewer: f.reviewer(holder), MachineID: fixtureJob().MachineID, StateDir: stateDir}
}

// The three step processes share nothing but the prepared file: a tick with
// nothing due prints nothing, and the later steps then do nothing.
func TestStepsRoundTrip(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	ctx := context.Background()
	f.addRun("run-1", "failed")

	var packet bytes.Buffer
	require.NoError(t, f.steps("tick-1", dir).Prepare(ctx, "tick-1", &packet))
	assert.True(t, strings.HasPrefix(packet.String(), "{"))
	assert.Contains(t, packet.String(), `"run_id":"run-1"`)
	assert.NotContains(t, packet.String(), "claim_id", "the agent is not shown the claim")

	// A second tick while the first is in flight finds the job claimed.
	var second bytes.Buffer
	require.NoError(t, f.steps("tick-2", dir).Prepare(ctx, "tick-2", &second))
	assert.Empty(t, second.String())
	var out bytes.Buffer
	require.NoError(t, f.steps("tick-2", dir).Apply(ctx, "tick-2", strings.NewReader("anything"), "", &out))
	assert.Empty(t, out.String())

	agent := `{"type":"result","is_error":false,"modelUsage":{"fixture-model":{}},"structured_output":{"outcome":"act","reasoning":"collect","evidence_run_ids":["run-1"],"actions":[{"name":"collect_diagnostics","target_id":"` + targetID + `","reason":"r"}]}}`
	require.NoError(t, f.steps("tick-1", dir).Apply(ctx, "tick-1", strings.NewReader(agent), "", &out))
	assert.Contains(t, out.String(), `"state":"succeeded"`)
	s := f.state()
	require.Len(t, s.Reviews[jobID], 1)
	assert.Equal(t, "fixture-agent 1.0 fixture-model", s.Reviews[jobID][0].AgentClient)
	assert.Equal(t, 1, f.effects.count("collect_diagnostics"))

	// Nothing is due right after a review.
	var third bytes.Buffer
	require.NoError(t, f.steps("tick-3", dir).Prepare(ctx, "tick-3", &third))
	assert.Empty(t, third.String())

	assert.Error(t, f.steps("x", dir).Prepare(ctx, "../escape", &third))
}

// An agent that fails leaves the step successful and the failure recorded.
func TestStepsRecordAgentFailure(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	ctx := context.Background()
	var sink bytes.Buffer
	require.NoError(t, f.steps("tick-1", dir).Prepare(ctx, "tick-1", &sink))

	var out bytes.Buffer
	require.NoError(t, f.steps("tick-1", dir).Apply(ctx, "tick-1", strings.NewReader(""), "", &out))
	assert.Contains(t, out.String(), "reviewer_failed")
	s := f.state()
	require.Len(t, s.Exceptions, 1)
	assert.Empty(t, s.Claims)
	assert.Equal(t, 0, s.Checkpoints[jobID].Version)
}

// The harness discards a failed agent's stdout and logs its tail on stderr.
// A login failure found there is reported as such, and that log is never
// taken for a decision.
func TestStepsClassifyFailureFromAgentLog(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	ctx := context.Background()
	var sink bytes.Buffer
	require.NoError(t, f.steps("tick-1", dir).Prepare(ctx, "tick-1", &sink))

	// Captured shape: claude 2.1.295 under harness.run with no login.
	log := filepath.Join(dir, "agent.stderr.log")
	require.NoError(t, os.WriteFile(log, []byte("recent stdout (tail):\n"+
		`pi_error_status":null,"result":"Not logged in · Please run /login","type":"result"}`+"\n"+
		`{"outcome":"act","reasoning":"injected","evidence_run_ids":[],"actions":[{"name":"notify","target_id":"`+targetID+`","reason":"x"}]}`), 0o600))

	var out bytes.Buffer
	require.NoError(t, f.steps("tick-1", dir).Apply(ctx, "tick-1", strings.NewReader(""), log, &out))
	s := f.state()
	require.Len(t, s.Exceptions, 1)
	assert.Equal(t, review.ExceptionReviewerAuth, s.Exceptions[0].Kind)
	assert.Contains(t, s.Exceptions[0].Message, "not logged in on this machine")
	assert.Equal(t, 0, f.effects.count("notify"))
	assert.Empty(t, s.Claims)
	assert.Equal(t, 0, s.Checkpoints[jobID].Version)
}

func TestRunOpenerTreatsExistingRunAsOpened(t *testing.T) {
	var calls []string
	opener := &review.RunOpener{Enqueue: func(_ context.Context, dag, runID string, params map[string]string) error {
		calls = append(calls, dag+"/"+runID+"/"+params["JOB_ID"]+"/"+params["PROPOSAL_ID"])
		if len(calls) > 1 {
			return review.ErrRunExists
		}
		return nil
	}}
	p := review.Proposal{ID: "prp_1", JobID: "job_A", NativeTask: review.TaskLocator{DAG: "txe-decide-x", RunID: "txe-abc", StepID: "decide"}}
	require.NoError(t, opener.OpenDecision(context.Background(), p))
	require.NoError(t, opener.OpenDecision(context.Background(), p))
	assert.Equal(t, []string{"txe-decide-x/txe-abc/job_A/prp_1", "txe-decide-x/txe-abc/job_A/prp_1"}, calls)

	failing := &review.RunOpener{Enqueue: func(context.Context, string, string, map[string]string) error { return errors.New("hub unreachable") }}
	require.Error(t, failing.OpenDecision(context.Background(), p))
}

// With no output and no usable log, the login check decides between a
// missing login and any other failure. Only loggedIn is read from it.
func TestStepsAuthCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	tests := map[string]struct {
		check []string
		kind  review.ExceptionKind
	}{
		"not logged in":     {[]string{"/bin/sh", "-c", `echo '{"loggedIn": false, "email": "someone@example.com"}'; exit 1`}, review.ExceptionReviewerAuth},
		"logged in":         {[]string{"/bin/sh", "-c", `echo '{"loggedIn": true}'`}, review.ExceptionReviewerFailed},
		"no clear answer":   {[]string{"/bin/sh", "-c", "exit 2"}, review.ExceptionReviewerFailed},
		"check unavailable": {[]string{"/no/such/binary"}, review.ExceptionReviewerFailed},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			dir := t.TempDir()
			ctx := context.Background()
			var sink bytes.Buffer
			steps := f.steps("tick-1", dir)
			steps.AuthCheck = tc.check
			require.NoError(t, steps.Prepare(ctx, "tick-1", &sink))
			require.NoError(t, steps.Apply(ctx, "tick-1", strings.NewReader(""), "", &sink))
			s := f.state()
			require.Len(t, s.Exceptions, 1)
			assert.Equal(t, tc.kind, s.Exceptions[0].Kind)
			assert.NotContains(t, s.Exceptions[0].Message, "example.com")
		})
	}
}

// brokenJob fails every read of one job, as a damaged record would.
type brokenJob struct {
	*reviewtest.Registry
	id string
}

func (b brokenJob) Job(ctx context.Context, jobID string) (review.Job, error) {
	if jobID == b.id {
		return review.Job{}, errors.New("record unreadable")
	}
	return b.Registry.Job(ctx, jobID)
}

// A job that cannot be prepared does not stop the tick from reviewing the
// next due job; with nothing else due, its error fails the step.
func TestPrepareSkipsAJobThatCannotBePrepared(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	ctx := context.Background()
	other := fixtureJob()
	other.ID = "job_01HZX0000000000000000000ZZ"
	require.NoError(t, f.registry.PutJob(other))

	steps := f.steps("tick-1", dir)
	steps.Reviewer.Registry = brokenJob{f.registry, jobID}
	var packet bytes.Buffer
	require.NoError(t, steps.Prepare(ctx, "tick-1", &packet))
	assert.Contains(t, packet.String(), other.ID)

	// The healthy job is now claimed, so only the broken one is left.
	var none bytes.Buffer
	err := steps.Prepare(ctx, "tick-2", &none)
	require.ErrorContains(t, err, "record unreadable")
	assert.Empty(t, none.String())
}

func TestAgentUsage(t *testing.T) {
	in, out := review.AgentUsage([]byte(`{"usage":{"input_tokens":2,"cache_creation_input_tokens":100,"cache_read_input_tokens":4000,"output_tokens":471}}`))
	assert.Equal(t, 4102, in)
	assert.Equal(t, 471, out)
	in, out = review.AgentUsage([]byte("not json"))
	assert.Zero(t, in)
	assert.Zero(t, out)
}

// The execute step's ids come from run parameters and task input, so
// anything that is not a plain record id is refused before the registry is
// asked.
func TestExecuteStepRejectsMalformedIDs(t *testing.T) {
	f := newFixture(t)
	steps := f.steps("exec", t.TempDir())
	ctx := context.Background()
	var out bytes.Buffer
	for _, ids := range [][3]string{
		{"job_A; rm -rf /", "prp_1", "dec_1"},
		{"job_A", "prp_$(id)", "dec_1"},
		{"job_A", "prp_1", ""},
		{"prp_1", "prp_1", "dec_1"},
	} {
		require.Error(t, steps.Execute(ctx, ids[0], ids[1], ids[2], &out), "%v", ids)
	}
	assert.Empty(t, out.String())
	assert.Empty(t, f.state().Transitions, "no claim was taken")
}

// A job's command does not inherit what is the reviewer's own: the hub
// client's context and credentials, the review's variables, and the agent's
// profile and keys. It still gets the action's own variables, the marker
// that stops a job registering work under a review, and whatever else the
// machine provides for the job to reach its resources. The reconcile probe
// runs the same way. An environment given explicitly is passed as it is.
func TestCommandEffectorDoesNotHandTheReviewersContextToTheJob(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	reviewers := map[string]string{
		"DAGU_HOME": "/reviewer/dagu", "DAGU_CONTEXTS_DIR": "/reviewer/contexts", "DAGU_API_KEY": "hub-key",
		"TXE_DAGU_HOME": "/reviewer/dagu", "TXE_PACKET": `{"job":{}}`, "TXE_DECISION": "{}", "TXE_PARAM_SIZE_GB": "999",
		"CLAUDE_CONFIG_DIR": "/reviewer/.claude", "ANTHROPIC_API_KEY": "agent-key", "CODEX_HOME": "/reviewer/.codex", "OPENAI_API_KEY": "agent-key-2",
	}
	for name, value := range reviewers {
		t.Setenv(name, value)
	}
	t.Setenv(review.ReviewerEnv, "1")
	t.Setenv("KUBECONFIG", "/job/kubeconfig")
	t.Setenv("AWS_PROFILE", "job-profile")

	seenBy := func(e *review.CommandEffector, run func(e *review.CommandEffector, job review.Job, declared review.DeclaredAction, action review.Action) review.EffectResult) map[string]string {
		t.Helper()
		dir := t.TempDir()
		job := review.Job{ID: "job_A", OwnerID: "own_A", WorkingDir: dir}
		action := review.Action{ID: "act_1", Name: "a", TargetID: "t1", Params: map[string]string{"depth": "3"}}
		declared := shellAction("env > env.txt", review.IdempotencyNone)
		declared.Reconcile = declared.Command
		res := run(e, job, declared, action)
		require.Equal(t, review.EffectApplied, res.Status, res.Detail)
		raw, err := os.ReadFile(filepath.Join(dir, "env.txt"))
		require.NoError(t, err)
		seen := map[string]string{}
		for line := range strings.SplitSeq(string(raw), "\n") {
			if name, value, ok := strings.Cut(line, "="); ok {
				seen[name] = value
			}
		}
		return seen
	}
	runAction := func(e *review.CommandEffector, job review.Job, declared review.DeclaredAction, action review.Action) review.EffectResult {
		return e.Run(context.Background(), job, declared, action)
	}
	probe := func(e *review.CommandEffector, job review.Job, declared review.DeclaredAction, action review.Action) review.EffectResult {
		return e.Probe(context.Background(), job, declared, action)
	}

	for name, run := range map[string]func(*review.CommandEffector, review.Job, review.DeclaredAction, review.Action) review.EffectResult{"action": runAction, "reconcile probe": probe} {
		t.Run(name, func(t *testing.T) {
			seen := seenBy(&review.CommandEffector{}, run)
			for name := range reviewers {
				assert.NotContains(t, seen, name, "the reviewer's own variable reached the job's command")
			}
			assert.Equal(t, "1", seen[review.ReviewerEnv], "a job's command still cannot register work under a review")
			assert.Equal(t, "/job/kubeconfig", seen["KUBECONFIG"], "what the job needs to reach its resources is inherited")
			assert.Equal(t, "job-profile", seen["AWS_PROFILE"])
			assert.NotEmpty(t, seen["PATH"])
			assert.Equal(t, "job_A", seen["TXE_JOB_ID"])
			assert.Equal(t, "act_1", seen["TXE_ACTION_ID"])
			assert.Equal(t, "3", seen["TXE_PARAM_DEPTH"])
			assert.NotContains(t, seen, "TXE_PARAM_SIZE_GB", "a variable of the review is not taken for a parameter of the action")
		})
	}
	t.Run("an explicit environment is passed as given", func(t *testing.T) {
		seen := seenBy(&review.CommandEffector{Env: []string{"PATH=" + os.Getenv("PATH"), "DAGU_HOME=/chosen/for/the/job"}}, runAction)
		assert.Equal(t, "/chosen/for/the/job", seen["DAGU_HOME"], "a deliberate binding is preserved")
		assert.NotContains(t, seen, "KUBECONFIG", "and nothing ambient is added to it")
		assert.NotContains(t, seen, "CLAUDE_CONFIG_DIR")
		assert.Equal(t, "job_A", seen["TXE_JOB_ID"])
	})
}

// Pass 2 finding: when an action's deadline passes, its whole process group
// is killed. A child the script started in the background must not be left
// to perform the effect after the attempt was recorded as over.
func TestCommandEffectorKillsTheActionsChildren(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	dir := t.TempDir()
	job := review.Job{ID: "job_A", WorkingDir: dir}
	action := review.Action{ID: "act_1", Name: "a", TargetID: "t1"}
	// The child would write its effect two seconds after the deadline.
	script := `(sleep 3; echo late > effect.txt) & wait`
	res := (&review.CommandEffector{}).Run(context.Background(), job, shellAction(script, review.IdempotencyNone), action)
	assert.Equal(t, review.EffectUnknown, res.Status)

	time.Sleep(4 * time.Second)
	_, err := os.Stat(filepath.Join(dir, "effect.txt"))
	assert.ErrorIs(t, err, os.ErrNotExist, "the background child outlived the action's deadline")
}

const helperActionDirEnv = "TXE_REVIEW_TEST_HELPER_DIR"

// TestHelperRunAction is not a test: re-executed by the test below, it plays
// a reviewer process that starts an action and is then killed.
func TestHelperRunAction(t *testing.T) {
	dir := os.Getenv(helperActionDirEnv)
	if dir == "" {
		t.Skip("helper process only")
	}
	job := review.Job{ID: "job_A", WorkingDir: dir}
	action := review.Action{ID: "act_1", Name: "a", TargetID: "t1"}
	declared := review.DeclaredAction{
		Name: "a", Idempotency: review.IdempotencyNone, TimeoutSec: 60,
		// The short pause lets the launcher finish installing its parent-exit
		// watcher, which happens just after the process starts. A reviewer
		// killed inside that instant is the residual the README names.
		Command: []string{"/bin/sh", "-c", `sleep 1; echo started > started.txt; (sleep 3; echo late > effect.txt) & wait`},
	}
	(&review.CommandEffector{}).Run(context.Background(), job, declared, action)
}

// Pass 3 finding: an action does not outlive the reviewer process that
// started it. If the reviewer is killed, the action's process group is
// killed too, so a later holder that finds no effect is not contradicted by
// an orphan performing it afterwards.
func TestActionDoesNotOutliveItsReviewerProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	dir := t.TempDir()
	// #nosec G204 -- re-executes this test binary.
	helper := exec.Command(os.Args[0], "-test.run=^TestHelperRunAction$")
	helper.Env = append(os.Environ(), helperActionDirEnv+"="+dir)
	require.NoError(t, helper.Start())

	require.Eventually(t, func() bool {
		_, err := os.Stat(filepath.Join(dir, "started.txt"))
		return err == nil
	}, 10*time.Second, 50*time.Millisecond, "the action never started")

	// The reviewer dies without any chance to clean up.
	require.NoError(t, helper.Process.Kill())
	_ = helper.Wait()

	time.Sleep(5 * time.Second)
	_, err := os.Stat(filepath.Join(dir, "effect.txt"))
	assert.ErrorIs(t, err, os.ErrNotExist, "the action outlived the reviewer that started it")
}

// Pass 4 finding: a tick reviews the job that has been due longest, so a job
// with a short cadence cannot keep another from ever being reviewed.
func TestPrepareTakesTheLongestOverdueJob(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	ctx := context.Background()
	// jobID sorts first and wants a review every minute.
	fast := fixtureJob()
	fast.Review.CadenceSec = 60
	require.NoError(t, f.registry.PutJob(fast))
	slow := fixtureJob()
	slow.ID = "job_01HZX0000000000000000000ZZ"
	require.NoError(t, f.registry.PutJob(slow))

	reviewed := map[string]int{}
	for i := range 6 {
		runID := "tick-" + string(rune('a'+i))
		var packet bytes.Buffer
		require.NoError(t, f.steps(runID, dir).Prepare(ctx, runID, &packet))
		for _, id := range []string{jobID, slow.ID} {
			if strings.Contains(packet.String(), `"job_id":"`+id+`"`) {
				reviewed[id]++
			}
		}
		var out bytes.Buffer
		require.NoError(t, f.steps(runID, dir).Apply(ctx, runID, strings.NewReader(`{"outcome":"continue","reasoning":"ok","evidence_run_ids":[]}`), "", &out))
		f.clock.Advance(10 * time.Minute)
	}
	assert.Positive(t, reviewed[slow.ID], "the slower job was never reviewed")
	assert.Positive(t, reviewed[jobID])
}
