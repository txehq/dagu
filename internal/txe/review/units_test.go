// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package review_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
		"artifacts:\n  enabled: true",
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
		`dagu txe review apply --machine mch_0000000000000000000F1XT001 --run-id ${DAG_RUN_ID} --agent-log "${agent.stderr}" --auth-check "claude auth status"`,
	} {
		assert.Contains(t, dags.Reviewer, want)
	}
	assert.NotContains(t, dags.Reviewer, "human.task", "a waiting task would hold the reviewer DAG")
	assert.NotContains(t, dags.Reviewer, "name:")

	for _, want := range []string{
		"action: human.task",
		"required: [decision_id, verdict]",
		"enum: [approve, reject, redirect, retry, pause, snooze, retire, superseded]",
		`dagu txe review execute --machine mch_0000000000000000000F1XT001 --run-id ${DAG_RUN_ID} --job "$TXE_JOB_ID" --proposal "$TXE_PROPOSAL_ID" --decision "$TXE_DECISION_ID"`,
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

// With an artifact directory, the packet and the decision are written there
// by the step itself and the review record points at them.
func TestStepsSaveReviewArtifacts(t *testing.T) {
	f := newFixture(t)
	dir, artifacts := t.TempDir(), t.TempDir()
	ctx := context.Background()
	f.addRun("run-1", "succeeded")
	steps := f.steps("tick-1", dir)
	steps.ArtifactDir = artifacts

	var packet, out bytes.Buffer
	require.NoError(t, steps.Prepare(ctx, "tick-1", &packet))
	saved, err := os.ReadFile(filepath.Join(artifacts, "txe-review", "packet.json"))
	require.NoError(t, err)
	assert.Contains(t, string(saved), `"run_id": "run-1"`)
	assert.NotContains(t, string(saved), "claim_id", "the artifact holds the packet, not the claim")

	require.NoError(t, steps.Apply(ctx, "tick-1", strings.NewReader(`{"outcome":"continue","reasoning":"fine","evidence_run_ids":["run-1"]}`), "", &out))
	saved, err = os.ReadFile(filepath.Join(artifacts, "txe-review", "decision.json"))
	require.NoError(t, err)
	assert.Contains(t, string(saved), `"outcome": "continue"`)

	rev := f.state().Reviews[jobID][0]
	// The local hand-off is recorded as a reference to a file on this
	// machine, with the digest of the bytes the decision was made from.
	handoff, err := os.ReadFile(filepath.Join(dir, "reviews", "tick-1", "prepared.json"))
	require.NoError(t, err)
	sum := sha256.Sum256(handoff)
	assert.Equal(t, review.LocalFile{
		MachineID: fixtureJob().MachineID,
		Path:      filepath.Join(dir, "reviews", "tick-1", "prepared.json"),
		SHA256:    hex.EncodeToString(sum[:]),
	}, rev.Handoff)
	assert.Equal(t, "txe-review/packet.json", rev.PacketArtifact)
	assert.Equal(t, "txe-review/decision.json", rev.DecisionArtifact)
}

// Closing completes the run's task with a system marker, never a human
// verdict, and reports what the service said about the task.
func TestRunOpenerClosesWithASystemMarker(t *testing.T) {
	var calls []string
	result := error(nil)
	o := &review.RunOpener{Complete: func(_ context.Context, task review.TaskLocator, input map[string]string) error {
		calls = append(calls, task.DAG+"/"+task.RunID+"/"+task.StepID+" "+input["decision_id"]+" "+input["verdict"])
		return result
	}}
	p := review.Proposal{ID: "prp_1", NativeTask: review.TaskLocator{DAG: "txe-decide-x", RunID: "txe-abc", StepID: "decide"}}
	outcome, err := o.CloseDecision(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, review.ClosureClosed, outcome)
	assert.Equal(t, []string{"txe-decide-x/txe-abc/decide dec_superseded superseded"}, calls)

	result = review.ErrTaskAnswered
	outcome, err = o.CloseDecision(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, review.ClosureAnswered, outcome)

	result = review.ErrRunMissing
	outcome, err = o.CloseDecision(context.Background(), p)
	require.NoError(t, err)
	assert.Equal(t, review.ClosureMissing, outcome, "an unknown run is recorded as missing, not as closed")

	result = errors.New("hub unreachable")
	outcome, err = o.CloseDecision(context.Background(), p)
	require.Error(t, err)
	assert.Equal(t, review.ClosureFailed, outcome)

	_, err = (&review.RunOpener{}).CloseDecision(context.Background(), p)
	require.Error(t, err)
}

// A job whose scripts print a lot cannot blow up the packet, and cannot use
// volume to hide results either: runs that do not fit are left for the next
// review instead of being covered without their output.
func TestPacketIsBoundedWithoutHidingEvidence(t *testing.T) {
	f := newFixture(t)
	big := strings.Repeat("x", 2048)
	for i := range 40 {
		steps := make([]review.StepEvidence, 0, 20)
		for j := range 20 {
			steps = append(steps, review.StepEvidence{Name: fmt.Sprintf("step-%d", j), Status: "succeeded", Stdout: big, Stderr: big})
		}
		require.NoError(t, f.registry.AddRun(jobID, review.RunEvidence{RunID: fmt.Sprintf("run-%02d", i), Status: "succeeded", Steps: steps}))
	}
	prepared := f.prepare("reviewer-a")
	packet := prepared.Packet
	raw, err := json.Marshal(packet)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(raw), 256<<10)
	require.NotEmpty(t, packet.NewRuns)
	assert.Less(t, len(packet.NewRuns), 40)
	assert.True(t, packet.MoreRunsPending)
	assert.Equal(t, "run-00", packet.NewRuns[0].RunID, "the oldest runs are reviewed first")
	for _, run := range packet.NewRuns {
		require.Len(t, run.Steps, 12, "at most the last steps of a run are kept")
		assert.Equal(t, "step-19", run.Steps[11].Name)
		assert.Len(t, run.Steps[11].Stdout, 2048, "a run in the packet keeps its step output")
	}

	// The checkpoint advances only over the runs that were shown, and the
	// rest are due again at once.
	last := packet.NewRuns[len(packet.NewRuns)-1].RunID
	f.apply("reviewer-a", prepared, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "ok"})
	cp := f.state().Checkpoints[jobID]
	assert.Equal(t, last, cp.RunCursor)
	assert.Equal(t, f.clock.Now().Add(time.Minute), cp.NextReviewAt)
	f.clock.Advance(time.Minute)
	next := f.prepare("reviewer-b").Packet
	assert.Greater(t, next.NewRuns[0].RunID, last)
}

// One run that is alone too large has its step output shortened to its
// ends, and the packet says so.
func TestOversizedSingleRunIsShortenedAndFlagged(t *testing.T) {
	f := newFixture(t)
	huge := strings.Repeat("y", 200<<10)
	require.NoError(t, f.registry.AddRun(jobID, review.RunEvidence{RunID: "run-big", Status: "failed", Steps: []review.StepEvidence{
		{Name: "a", Status: "failed", Stdout: huge + "END-A", Stderr: huge + "END-ERR"},
	}}))
	packet := f.prepare("reviewer-a").Packet
	raw, err := json.Marshal(packet)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(raw), 256<<10)
	assert.True(t, packet.EvidenceTrimmed)
	require.Len(t, packet.NewRuns, 1)
	assert.True(t, strings.HasSuffix(packet.NewRuns[0].Steps[0].Stdout, "END-A"), "the end of the output is what is kept")
	assert.True(t, strings.HasSuffix(packet.NewRuns[0].Steps[0].Stderr, "END-ERR"))
}

// Every list in the packet is bounded. Human feedback beyond the bound is
// not skipped: it stays after the cursor and comes in the next review.
func TestPacketListsAreBoundedAndFeedbackIsNotSkipped(t *testing.T) {
	f := newFixture(t)
	// 60 questions, each answered by the owner.
	for round := range 3 {
		prepared := f.prepare(fmt.Sprintf("reviewer-%d", round))
		var actions []review.AgentAction
		for i := range 20 {
			actions = append(actions, act("expand_volume", map[string]string{"size_gb": fmt.Sprint(round*100 + i)}))
		}
		f.apply("r", prepared, review.AgentDecision{Outcome: review.OutcomeAct, Reasoning: "ask", Actions: actions})
		f.clock.Advance(2 * time.Hour)
	}
	proposals := f.state().Proposals[jobID]
	require.Len(t, proposals, 60)
	for _, p := range proposals {
		_, err := f.registry.Decide(jobID, p.ID, review.VerdictReject, "", "connor")
		require.NoError(t, err)
	}

	first := f.prepare("reviewer-x")
	require.Len(t, first.Packet.HumanFeedback, 50)
	assert.True(t, first.Packet.MoreRunsPending, "more feedback is waiting")
	f.apply("reviewer-x", first, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "read 50"})
	f.clock.Advance(time.Minute)
	second := f.prepare("reviewer-y")
	require.Len(t, second.Packet.HumanFeedback, 10, "the rest arrives next, none skipped")
	assert.NotEqual(t, first.Packet.HumanFeedback[49].ID, second.Packet.HumanFeedback[0].ID)
}

// A job whose own registered context is larger than the packet limit is not
// reviewed from a cut-down version of it, and does not go quiet either: it
// is raised as an exception, deferred, and its claim released.
func TestOversizedJobContextIsRaisedNotSilentlySkipped(t *testing.T) {
	f := newFixture(t)
	job := fixtureJob()
	job.Purpose = strings.Repeat("p", 300<<10)
	require.NoError(t, f.registry.PutJob(job))
	prepared, err := f.reviewer("reviewer-a").Prepare(context.Background(), jobID)
	require.NoError(t, err)
	assert.Equal(t, review.SkipUnreviewable, prepared.Skipped)
	s := f.state()
	require.Len(t, s.Exceptions, 1)
	assert.Equal(t, review.ExceptionContextTooLarge, s.Exceptions[0].Kind)
	assert.Empty(t, s.Claims, "the claim is released")
	assert.Equal(t, f.clock.Now().Add(time.Hour), s.Checkpoints[jobID].NextReviewAt, "it is not retried on every tick")
	assert.Equal(t, 0, s.Checkpoints[jobID].Version)
}

// An action already in front of the owner is not proposed again by a later
// review, even when the agent could not see the earlier proposal.
func TestAnOpenProposalIsNotDuplicated(t *testing.T) {
	f := newFixture(t)
	ask := review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Grow it.",
		Actions: []review.AgentAction{act("expand_volume", map[string]string{"size_gb": "200"})},
	}
	f.apply("reviewer-a", f.prepare("reviewer-a"), ask)
	require.Len(t, f.state().Proposals[jobID], 1)

	first := f.state().Proposals[jobID][0]
	f.clock.Advance(2 * time.Hour)
	applied := f.apply("reviewer-b", f.prepare("reviewer-b"), ask)
	assert.Len(t, f.state().Proposals[jobID], 1)
	assert.Contains(t, applied.Review.Notes[0], "already proposed")
	// Its decision run is opened again, which repairs a proposal whose
	// first review died before the run was enqueued.
	assert.Equal(t, 2, f.opener.opened[first.NativeTask.RunID])

	// A different size is a different request.
	f.clock.Advance(2 * time.Hour)
	other := ask
	other.Actions = []review.AgentAction{act("expand_volume", map[string]string{"size_gb": "400"})}
	f.apply("reviewer-c", f.prepare("reviewer-c"), other)
	assert.Len(t, f.state().Proposals[jobID], 2)
}

// retryFixture is a job whose run-1 failed at attempt att-1, with a retry of
// it proposed by the reviewer and decided "retry" by the owner.
type retryFixture struct {
	*fixture
	runs     *runs
	proposal review.Proposal
	decision review.Decision
}

func (f *retryFixture) executor(holder string) *review.Reviewer {
	r := f.reviewer(holder)
	r.Runs, r.RetryObserve = f.runs, 20*time.Millisecond
	return r
}

func newRetryFixture(t *testing.T) *retryFixture {
	t.Helper()
	f := &retryFixture{fixture: newFixture(t), runs: newRuns()}
	f.addRun("run-1", "failed")
	f.runs.fail("run-1", "att-1")
	_, err := f.executor("reviewer-a").Apply(context.Background(), f.prepare("reviewer-a"), review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "It failed once.", EvidenceRunIDs: []string{"run-1"},
		Actions: []review.AgentAction{{Name: review.RetryRunAction, Params: map[string]string{"run_id": "run-1"}, Reason: "transient"}},
	})
	require.NoError(t, err)
	f.proposal = f.state().Proposals[jobID][0]
	f.decision, err = f.registry.Decide(jobID, f.proposal.ID, review.VerdictRetry, "", "connor")
	require.NoError(t, err)
	return f
}

func (f *retryFixture) execute(holder string) review.Executed {
	f.t.Helper()
	out, err := f.executor(holder).Execute(context.Background(), jobID, f.proposal.ID, f.decision.ID)
	require.NoError(f.t, err)
	return out
}

// The reserved retry: the reviewer proposes re-running one exact run it was
// shown, bound to the failed attempt it saw. Nothing runs until the owner
// answers "retry"; then that run is retried once, and the journal's receipt
// is the new attempt the service was observed to start.
func TestRetryRunIsProposedAndRunsOnceOnTheOwnersRetry(t *testing.T) {
	f := newFixture(t)
	f.addRun("run-1", "failed")
	require.NoError(t, f.registry.AddRun(jobID, review.RunEvidence{RunID: "run-old", JobVersion: 1, Status: "failed", SpecSHA256: "sha256:older", AttemptID: "att-1"}))
	require.NoError(t, f.registry.AddRun(jobID, review.RunEvidence{RunID: "run-anon", JobVersion: 1, Status: "failed", SpecSHA256: specDigest}))
	service := newRuns()
	service.fail("run-1", "att-1")
	withRetry := func(holder string) *review.Reviewer {
		r := f.reviewer(holder)
		r.Runs, r.RetryObserve = service, 20*time.Millisecond
		return r
	}
	prepared := f.prepare("reviewer-a")
	_, err := withRetry("reviewer-a").Apply(context.Background(), prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "It failed once.", EvidenceRunIDs: []string{"run-1"},
		Actions: []review.AgentAction{
			{Name: review.RetryRunAction, Params: map[string]string{"run_id": "run-1"}, Reason: "transient"},
			{Name: review.RetryRunAction, Params: map[string]string{"run_id": "run-unknown"}, Reason: "not shown"},
			{Name: review.RetryRunAction, Params: map[string]string{"run_id": "run-old"}, Reason: "older version"},
			{Name: review.RetryRunAction, Params: map[string]string{"run_id": "run-1", "attempt_id": "att-9"}, Reason: "agent picks the attempt"},
			{Name: review.RetryRunAction, Params: map[string]string{"run_id": "run-anon"}, Reason: "no attempt id"},
		},
	})
	require.NoError(t, err)
	assert.Empty(t, service.retried, "a retry never runs on the agent's request")
	proposals := f.state().Proposals[jobID]
	require.Len(t, proposals, 5)
	retry, question := proposals[0], proposals[1]
	assert.Equal(t, review.ProposalAction, retry.Kind)
	assert.Equal(t, map[string]string{
		"run_id": "run-1", "attempt_id": "att-1", "run_spec_sha256": specDigest, "package_digest": f.state().Jobs[jobID].PackageDigest,
	}, retry.Params, "the retry is bound to the failed attempt, the snapshot it ran and that version's package")
	assert.Contains(t, retry.AllowedVerdicts, review.VerdictRetry)
	assert.NotContains(t, retry.AllowedVerdicts, review.VerdictApprove)
	assert.Equal(t, review.ProposalQuestion, question.Kind, "a run the reviewer was not shown cannot be retried")
	assert.Equal(t, review.ProposalQuestion, proposals[2].Kind, "a run of an older version is never retried")
	assert.Contains(t, proposals[2].Question, "run-old")
	assert.Equal(t, review.ProposalQuestion, proposals[3].Kind, "the agent names the run and nothing else")
	assert.Equal(t, review.ProposalQuestion, proposals[4].Kind, "a run whose attempt is not identified cannot be bound")

	// "retry" is not an answer to an ordinary question.
	_, err = f.registry.Decide(jobID, question.ID, review.VerdictRetry, "", "connor")
	require.ErrorIs(t, err, reviewtest.ErrVerdictNotAllowed)

	decided, err := f.registry.Decide(jobID, retry.ID, review.VerdictRetry, "", "connor")
	require.NoError(t, err)
	ctx := context.Background()
	out, err := withRetry("executor").Execute(ctx, jobID, retry.ID, decided.ID)
	require.NoError(t, err)
	require.Empty(t, out.Skipped)
	assert.Equal(t, review.ActionSucceeded, out.Action.State)
	assert.Equal(t, "att-2", out.Action.Receipt, "the receipt is the attempt that was observed to start")
	assert.Contains(t, out.Action.Detail, "running", "and says what that attempt was doing, not that the job succeeded")
	assert.Equal(t, []string{"run-1"}, service.retried)

	out, err = withRetry("executor").Execute(ctx, jobID, retry.ID, decided.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, out.Skipped)
	assert.Len(t, service.retried, 1, "one decision retries the run once")

	// Without a way to retry configured, nothing is attempted.
	out, err = f.reviewer("executor").Execute(ctx, jobID, retry.ID, decided.ID)
	require.NoError(t, err)
	assert.NotEmpty(t, out.Skipped)
}

// A decision is about one failed attempt. When the run has moved on since,
// by any other retry, nothing is dispatched on its strength.
func TestRetryRunIsNotDispatchedForAnAttemptThatIsNoLongerLatest(t *testing.T) {
	for name, move := range map[string]func(*runs){
		"another retry already started a new attempt": func(r *runs) { r.start("run-1") },
		"a later attempt already succeeded": func(r *runs) {
			r.state["run-1"] = review.RunState{AttemptID: "att-2", Status: "succeeded", Succeeded: true}
		},
		"a later attempt failed too": func(r *runs) { r.fail("run-1", "att-2") },
	} {
		t.Run(name, func(t *testing.T) {
			f := newRetryFixture(t)
			move(f.runs)
			out := f.execute("executor")
			assert.Contains(t, out.Skipped, "att-1")
			assert.Contains(t, out.Skipped, "nothing is retried")
			assert.Empty(t, f.state().Actions[jobID], "no effect was granted or journaled")
			assert.Empty(t, f.runs.retried, "the service was never asked")
			// Asking again changes nothing.
			assert.NotEmpty(t, f.execute("executor").Skipped)
			assert.Empty(t, f.runs.retried)
		})
	}
}

// While the service cannot be read, nothing is granted or journaled, so the
// decision keeps its one attempt for when the service is back.
func TestRetryRunWaitsWhileTheRunCannotBeRead(t *testing.T) {
	f := newRetryFixture(t)
	f.runs.readErr = errors.New("hub unreachable")
	_, err := f.executor("executor").Execute(context.Background(), jobID, f.proposal.ID, f.decision.ID)
	require.ErrorContains(t, err, "hub unreachable")
	assert.Empty(t, f.state().Actions[jobID])
	assert.Empty(t, f.runs.retried)

	f.runs.readErr = nil
	out := f.execute("executor")
	assert.Equal(t, review.ActionSucceeded, out.Action.State)
	assert.Len(t, f.runs.retried, 1)
}

// The run can move on between the check and the dispatch, after the effect
// was granted. Nothing is dispatched then either, and the journal says so.
func TestRetryRunGrantedForAnAttemptThatThenMovedOnIsNotDispatched(t *testing.T) {
	f := newRetryFixture(t)
	reads := 0
	moving := &movingRuns{runs: f.runs, onRead: func() {
		// The first read is the executor's check; the run is retried by
		// someone else before the second, which follows the grant.
		if reads++; reads == 2 {
			f.runs.start("run-1")
		}
	}}
	r := f.reviewer("executor")
	r.Runs, r.RetryObserve = moving, 20*time.Millisecond
	out, err := r.Execute(context.Background(), jobID, f.proposal.ID, f.decision.ID)
	require.NoError(t, err)
	assert.Equal(t, review.ActionFailed, out.Action.State)
	assert.Contains(t, out.Action.Detail, "not dispatched")
	assert.Empty(t, f.runs.retried)
}

// movingRuns calls onRead before every read of a run's state.
type movingRuns struct {
	*runs
	onRead func()
}

func (m *movingRuns) RunState(ctx context.Context, job, run string) (review.RunState, error) {
	m.onRead()
	return m.runs.RunState(ctx, job, run)
}

// A refusal by the service started nothing and is recorded as such.
func TestRetryRunRefusedByTheServiceIsNotApplied(t *testing.T) {
	f := newRetryFixture(t)
	f.runs.retry = func(string) error { return fmt.Errorf("%w: run is active", review.ErrRunNotRetryable) }
	out := f.execute("executor")
	assert.Equal(t, review.ActionFailed, out.Action.State)
	assert.Contains(t, out.Action.Detail, "not dispatched")
	assert.Len(t, f.runs.retried, 1)
}

// The service accepting a retry is not evidence that an attempt started.
// With no new attempt observed the outcome is uncertain. It is never
// dispatched again: a later look at the run settles it when a new attempt
// is there, and otherwise the owner is asked.
func TestRetryRunAcceptedButUnobservedIsUncertainAndNeverRedispatched(t *testing.T) {
	for name, tc := range map[string]struct {
		retry func(string) error
	}{
		"accepted, no attempt seen":  {retry: func(string) error { return nil }},
		"the call failed in transit": {retry: func(string) error { return errors.New("connection reset") }},
	} {
		t.Run(name, func(t *testing.T) {
			f := newRetryFixture(t)
			f.runs.retry = tc.retry
			out := f.execute("executor")
			assert.Equal(t, review.ActionUncertain, out.Action.State)
			assert.Empty(t, out.Action.Receipt, "no attempt is named that was not observed")
			require.Len(t, f.runs.retried, 1)

			// The next review looks at the run again. Still the same
			// attempt: that proves nothing, so the owner is asked.
			f.clock.Advance(2 * time.Hour)
			r := f.executor("reviewer-b")
			prepared, err := r.Prepare(context.Background(), jobID)
			require.NoError(t, err)
			_, err = r.Apply(context.Background(), prepared, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "waiting"})
			require.NoError(t, err)
			action := f.state().Actions[jobID][0]
			assert.Equal(t, review.ActionEscalated, action.State)
			assert.Len(t, f.runs.retried, 1, "absence never causes another dispatch")
			var escalation review.Proposal
			for _, p := range f.state().Proposals[jobID] {
				if p.Kind == review.ProposalUncertain {
					escalation = p
				}
			}
			assert.Equal(t, review.UncertainProposalID(action.ID, 1), escalation.ID)
		})
	}
}

// An unobserved retry is settled as soon as the run shows a later attempt.
func TestRetryRunUnobservedIsSettledWhenTheNewAttemptAppears(t *testing.T) {
	f := newRetryFixture(t)
	f.runs.retry = func(string) error { return nil }
	out := f.execute("executor")
	require.Equal(t, review.ActionUncertain, out.Action.State)

	// The dispatch landed after all.
	f.runs.fail("run-1", "att-2")
	f.clock.Advance(2 * time.Hour)
	r := f.executor("reviewer-b")
	prepared, err := r.Prepare(context.Background(), jobID)
	require.NoError(t, err)
	_, err = r.Apply(context.Background(), prepared, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "waiting"})
	require.NoError(t, err)
	action := f.state().Actions[jobID][0]
	assert.Equal(t, review.ActionSucceeded, action.State)
	assert.Equal(t, "att-2", action.Receipt)
	assert.Contains(t, action.Detail, "failed", "the receipt says what the new attempt was, not that the job succeeded")
	assert.Len(t, f.runs.retried, 1)
}

// An owner's "retry" on an uncertain effect allows exactly one more attempt.
// The escalation carries the reserved action name and the journaled action.
func TestUncertainRetryAllowsExactlyOneMoreAttempt(t *testing.T) {
	f := newFixture(t)
	f.effects.run = func(review.Action) (review.EffectResult, bool) {
		return review.EffectResult{Status: review.EffectUnknown, Detail: "timed out"}, true
	}
	notify := review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Notify.",
		Actions: []review.AgentAction{act("notify", nil)},
	}
	f.apply("reviewer-a", f.prepare("reviewer-a"), notify)
	f.clock.Advance(2 * time.Hour)
	f.apply("reviewer-b", f.prepare("reviewer-b"), review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "waiting"})

	escalation := f.state().Proposals[jobID][0]
	first := f.state().Actions[jobID][0]
	assert.Equal(t, review.UncertainEffectAction, escalation.ActionName)
	assert.Equal(t, map[string]string{"action_id": first.ID}, escalation.Params)
	assert.Equal(t, review.UncertainProposalID(first.ID, 1), escalation.ID)
	_, err := f.registry.Decide(jobID, escalation.ID, review.VerdictRetry, "It did not go out.", "connor")
	require.NoError(t, err)

	// The one permitted attempt also ends unknown.
	f.clock.Advance(2 * time.Hour)
	f.apply("reviewer-c", f.prepare("reviewer-c"), notify)
	assert.Equal(t, 2, f.effects.count("notify"))

	// The old answer is used up: the intent is blocked again, by the new
	// attempt and independently in the registry.
	f.clock.Advance(2 * time.Hour)
	next := f.prepare("reviewer-d")
	applied := f.apply("reviewer-d", next, notify)
	assert.Empty(t, applied.Executed)
	assert.Equal(t, 2, f.effects.count("notify"))
	assert.True(t, f.state().ConsumedResolutions[escalation.ID])
}
