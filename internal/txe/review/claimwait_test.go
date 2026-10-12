package review_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/spec"
	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/dagucloud/dagu/v2/internal/txe/review"
	"github.com/dagucloud/dagu/v2/internal/txe/review/reviewtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func stepOf(t *testing.T, dag *ir.DAG, id string) ir.Step {
	t.Helper()
	for _, step := range dag.Steps {
		if step.ID == id || step.Name == id {
			return step
		}
	}
	t.Fatalf("no step %q in the rendered DAG", id)
	return ir.Step{}
}

// A tick that dies keeps its job claimed until the claim's lifetime is over.
// A decision approved meanwhile cannot run until then, and it must run by
// itself afterwards. The decision DAG is rendered so that its execute step
// waits for longer than a claim can live, on that one failure only, and so
// that no run outlives its own claim. Read from the DAG as Dagu loads it.
func TestTheDecisionDAGOutwaitsADeadClaim(t *testing.T) {
	cfg := review.DAGConfig{MachineID: "mch_0000000000000000000F1XT001", StateDir: "/var/lib/txe/state"}
	dags, err := review.RenderDAGs(cfg)
	require.NoError(t, err)
	decide, err := spec.LoadYAML(context.Background(), []byte(dags.Decide))
	require.NoError(t, err)
	reviewer, err := spec.LoadYAML(context.Background(), []byte(dags.Reviewer))
	require.NoError(t, err)

	execute := stepOf(t, decide, "execute")
	policy := execute.RetryPolicy
	assert.Equal(t, []int{review.ExitClaimHeld}, policy.ExitCodes, "only a held claim is waited for")
	assert.Equal(t, time.Minute, policy.Interval)
	assert.Equal(t, 22, policy.Limit)
	assert.Zero(t, policy.Backoff, "the waits are even, so their sum is known")

	// The waits alone outlast the longest a claim lives, with room to spare;
	// the tries themselves only add to that.
	waits := time.Duration(policy.Limit) * policy.Interval
	assert.GreaterOrEqual(t, waits, review.MaxClaimTTL+2*time.Minute)
	assert.Less(t, waits, review.MaxClaimTTL+5*time.Minute, "and the wait is bounded")

	// One try is one whole run of the step under its own timeout, shorter
	// than a claim, so an execution claim covers the try that takes it. A
	// review run is shorter than its claim too.
	assert.Equal(t, 15*time.Minute, execute.Timeout)
	assert.Less(t, execute.Timeout, review.MaxClaimTTL)
	assert.Less(t, reviewer.Timeout, review.MaxClaimTTL)
	// The decision run has a timeout of its own for its process after the
	// person answered: every wait, one whole try, and room to end. A base
	// configuration with a shorter one does not replace it.
	assert.Equal(t, waits+execute.Timeout+5*time.Minute, decide.Timeout)
	inherited, err := spec.LoadYAML(context.Background(), []byte(dags.Decide), spec.WithBaseConfigContent([]byte("timeout_sec: 900\n")))
	require.NoError(t, err)
	assert.Equal(t, decide.Timeout, inherited.Timeout, "a shorter inherited timeout would end the wait before the claim does")
	assert.Equal(t, 22, stepOf(t, inherited, "execute").RetryPolicy.Limit)

	// Nothing else in either DAG retries.
	assert.Zero(t, stepOf(t, decide, "decide").RetryPolicy.Limit)
	for _, step := range reviewer.Steps {
		assert.Zero(t, step.RetryPolicy.Limit, step.ID)
	}

	// A shorter interval gives more tries, never a shorter wait; and a run
	// that could outlive its claim is refused.
	for _, interval := range []int{1, 7, 45, 60, 90, 600} {
		c := cfg
		c.ClaimWaitIntervalSec = interval
		total := time.Duration(c.ClaimWaitRetries()) * time.Duration(interval) * time.Second
		assert.GreaterOrEqual(t, total, review.MaxClaimTTL+2*time.Minute, "interval %d", interval)
		assert.Less(t, total, review.MaxClaimTTL+2*time.Minute+time.Duration(interval)*time.Second, "interval %d", interval)
		rendered, err := review.RenderDAGs(c)
		require.NoError(t, err)
		assert.Contains(t, rendered.Decide, fmt.Sprintf("limit: %d\n      interval_sec: %d\n      exit_code: [75]", c.ClaimWaitRetries(), interval))
	}
	for name, mutate := range map[string]func(c *review.DAGConfig){
		"a run as long as a claim":  func(c *review.DAGConfig) { c.TimeoutSec, c.AgentTimeoutSec = 1200, 600 },
		"a run longer than a claim": func(c *review.DAGConfig) { c.TimeoutSec, c.AgentTimeoutSec = 3600, 600 },
		"an interval too long":      func(c *review.DAGConfig) { c.ClaimWaitIntervalSec = 601 },
	} {
		c := cfg
		mutate(&c)
		_, err := review.RenderDAGs(c)
		require.Error(t, err, name)
	}
}

// The retry policy as rendered, run by Dagu itself: a step that exits with
// the claim-held code is tried again after the interval until it succeeds,
// and a step that fails any other way is not tried again.
func TestTheRenderedRetryPolicyWaitsOnlyForAHeldClaim(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	dags, err := review.RenderDAGs(review.DAGConfig{MachineID: "mch_0000000000000000000F1XT001", StateDir: "/s", ClaimWaitIntervalSec: 1})
	require.NoError(t, err)
	// The policy exactly as the decision DAG carries it.
	_, rest, found := strings.Cut(dags.Decide, "    retry_policy:\n")
	require.True(t, found)
	policy, _, found := strings.Cut(rest, "    # Parameters and task input")
	require.True(t, found)
	require.Contains(t, policy, "exit_code: [75]")

	run := func(t *testing.T, script string) (attempts int, elapsed time.Duration, err error) {
		t.Helper()
		dir := t.TempDir()
		count := filepath.Join(dir, "count")
		path := filepath.Join(dir, "step.sh")
		require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\nn=$(cat "+count+" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "+count+"\n"+script+"\n"), 0o700))
		th := test.Setup(t)
		dag := th.DAG(t, "steps:\n  - id: execute\n    run: "+path+"\n    timeout_sec: 20\n    retry_policy:\n"+policy)
		agent := dag.Agent()
		ctx, cancel := context.WithTimeout(agent.Context, 60*time.Second)
		defer cancel()
		started := time.Now()
		err = agent.Run(ctx)
		elapsed = time.Since(started)
		data, readErr := os.ReadFile(count)
		require.NoError(t, readErr)
		_, scanErr := fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &attempts)
		require.NoError(t, scanErr)
		return attempts, elapsed, err
	}

	t.Run("a held claim is waited for until it is gone", func(t *testing.T) {
		attempts, elapsed, err := run(t, `[ "$n" -lt 4 ] && exit 75; exit 0`)
		require.NoError(t, err)
		assert.Equal(t, 4, attempts, "three tries met the claim, the fourth ran")
		assert.GreaterOrEqual(t, elapsed, 3*time.Second, "one interval before each new try")
	})
	for name, code := range map[string]int{"an ordinary failure": 1, "another code": 2, "a code next to it": 74} {
		t.Run(name+" is not tried again", func(t *testing.T) {
			attempts, _, err := run(t, fmt.Sprintf("exit %d", code))
			require.Error(t, err)
			assert.Equal(t, 1, attempts)
		})
	}
}

// Against the real registry and its clock: a review claims the job and dies.
// A person approves a proposal. The execute step meets the dead claim on
// every try and does nothing; once the claim's lifetime is over the same
// step takes its own claim and runs the action once. A further try runs
// nothing. Nobody released the dead claim.
func TestRemoteAnApprovedActionRunsOnceAfterADeadClaimExpires(t *testing.T) {
	ctx := context.Background()
	type world struct {
		f        *remoteFixture
		proposal review.Proposal
		decision string
		executor func() *review.Reviewer
	}
	start := func(t *testing.T) world {
		t.Helper()
		f := newRemoteFixture(t)
		at := func(holder string) *review.Reviewer {
			r := f.reviewer(holder)
			r.Now = func() time.Time { return time.Now().Add(*f.ahead) }
			return r
		}
		first := at("tick-1")
		prepared, err := first.Prepare(ctx, f.jobID)
		require.NoError(t, err)
		_, err = first.Apply(ctx, prepared, review.AgentDecision{
			Outcome: review.OutcomeAct, Reasoning: "grow", EvidenceRunIDs: []string{"run-1"},
			Actions: []review.AgentAction{{Name: "expand_volume", TargetID: f.targetID(), Params: map[string]string{"size_gb": "200"}, Reason: "grow"}},
		})
		require.NoError(t, err)
		open, err := f.remote.OpenProposals(ctx, f.jobID)
		require.NoError(t, err)
		require.Len(t, open, 1)

		// The next tick claims the job for a review and dies with the claim.
		*f.ahead += 2 * time.Hour
		dead, err := at("tick-dead").Prepare(ctx, f.jobID)
		require.NoError(t, err)
		require.Empty(t, dead.Skipped)
		require.NotNil(t, f.job().Claim)

		approved, err := f.decide(open[0], 1, "approve")
		require.NoError(t, err)
		return world{f: f, proposal: open[0], decision: approved.Decision.DecisionID, executor: func() *review.Reviewer { return at("decide-run") }}
	}

	t.Run("it waits, then runs once", func(t *testing.T) {
		w := start(t)
		claim := *w.f.job().Claim
		// Every try inside the claim's lifetime meets the claim and nothing
		// else: no effect, no action record, the claim untouched.
		for range 3 {
			_, err := w.executor().Execute(ctx, w.f.jobID, w.proposal.ID, w.decision)
			require.ErrorIs(t, err, review.ErrClaimHeld)
			*w.f.ahead += 3 * time.Minute
		}
		assert.Zero(t, w.f.fx.count("expand_volume"))
		actions, err := w.f.remote.Actions(ctx, w.f.jobID)
		require.NoError(t, err)
		assert.Empty(t, actions)
		held := w.f.job().Claim
		require.NotNil(t, held)
		assert.Equal(t, claim.ClaimID, held.ClaimID, "the dead review's claim is still the job's")
		assert.Equal(t, claim.Fence, held.Fence)

		// Past the claim's lifetime the same step runs the action.
		*w.f.ahead += 2 * time.Minute
		out, err := w.executor().Execute(ctx, w.f.jobID, w.proposal.ID, w.decision)
		require.NoError(t, err)
		require.Empty(t, out.Skipped)
		assert.Equal(t, review.ActionSucceeded, out.Action.State)
		assert.Equal(t, w.decision, out.Action.DecisionID)
		assert.Equal(t, 1, w.f.fx.count("expand_volume"))

		// A try after that, as a retry of the run would be, runs nothing.
		out, err = w.executor().Execute(ctx, w.f.jobID, w.proposal.ID, w.decision)
		require.NoError(t, err)
		assert.NotEmpty(t, out.Skipped)
		assert.Equal(t, 1, w.f.fx.count("expand_volume"), "the action ran exactly once")
		actions, err = w.f.remote.Actions(ctx, w.f.jobID)
		require.NoError(t, err)
		require.Len(t, actions, 1)
		assert.Equal(t, 1, actions[0].Attempt)
		last := w.f.job().Claim
		require.NotNil(t, last)
		assert.Equal(t, "execution", string(last.Kind))
		assert.Equal(t, "released", string(last.State), "the execution claim was given back")
		assert.Greater(t, last.Fence, claim.Fence, "taken over from the dead claim by its expiry, not by a release")
	})

	// Each try reads the decision and the job again: an approval that
	// stopped holding while it waited runs nothing.
	t.Run("an approval that stops holding during the wait runs nothing", func(t *testing.T) {
		w := start(t)
		_, err := w.executor().Execute(ctx, w.f.jobID, w.proposal.ID, w.decision)
		require.ErrorIs(t, err, review.ErrClaimHeld)

		// The owner retires the job while the approval waits.
		require.NoError(t, w.f.remote.Transport.Do(ctx, http.MethodPost, "/txe/jobs/"+w.f.jobID+"/lifecycle", map[string]any{
			"op": "retire", "reason": "manual", "detail": "no longer wanted",
			"actor": map[string]string{"kind": "cli", "id": "cc5-test"},
		}, nil))
		*w.f.ahead += 11 * time.Minute
		out, err := w.executor().Execute(ctx, w.f.jobID, w.proposal.ID, w.decision)
		require.NoError(t, err)
		assert.NotEmpty(t, out.Skipped)
		assert.Zero(t, w.f.fx.count("expand_volume"))
	})
}

// The whole chain, with nothing stood in for but the registry's storage: the
// execute step exactly as the decision DAG renders it, run by Dagu with its
// own retries, calling a real step command (the fixture's, which runs the
// same Steps.Execute and exits with the same codes as dagu's) against a
// registry in which a dead review really holds the job's claim until that
// claim's lifetime is over. Nobody retries anything by hand.
func TestAnApprovedDecisionRunsItselfOnceTheDeadClaimExpires(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	if testing.Short() {
		t.Skip("builds a command and waits for a claim to expire")
	}
	ctx := context.Background()
	bin := filepath.Join(t.TempDir(), "txe-review-fixture")
	build := exec.Command("go", "build", "-o", bin, "./reviewtest/cmd/txe-review-fixture")
	build.Env = append(os.Environ(), "GOFLAGS=-mod=readonly")
	out, err := build.CombinedOutput()
	require.NoError(t, err, string(out))

	type world struct {
		dir, registry, effects, job, proposal, decision string
		reg                                             *reviewtest.Registry
	}
	// A job with one action that needs a person, a proposal for it that a
	// person approved, and a review that claimed the job for claimFor and
	// died.
	start := func(t *testing.T, claimFor time.Duration) world {
		t.Helper()
		w := world{dir: t.TempDir()}
		w.registry, w.effects = filepath.Join(w.dir, "registry.json"), filepath.Join(w.dir, "effects.log")
		w.reg = reviewtest.Open(w.registry)
		job := fixtureJob()
		job.WorkingDir = w.dir
		job.Review.Actions = []review.DeclaredAction{{
			Name: "expand_volume", Routine: false, Params: []string{"size_gb"}, Idempotency: review.IdempotencyNone, TimeoutSec: 20,
			Command: []string{"/bin/sh", "-c", `echo "expanded to $TXE_PARAM_SIZE_GB by $TXE_ACTION_ID" >> ` + w.effects + `; echo receipt-$TXE_ACTION_ID`},
		}}
		require.NoError(t, w.reg.PutJob(job))
		w.job = job.ID
		reviewer := func(holder string, ttl time.Duration) *review.Reviewer {
			return &review.Reviewer{
				MachineID: job.MachineID, Registry: w.reg, Effector: &review.CommandEffector{}, Opener: &opener{},
				Holder: holder, AgentClient: "fixture-agent 1.0", DecideDAG: review.DecideDAGName(job.MachineID), ClaimTTL: ttl,
			}
		}
		first := reviewer("tick-1", time.Minute)
		prepared, err := first.Prepare(ctx, job.ID)
		require.NoError(t, err)
		applied, err := first.Apply(ctx, prepared, review.AgentDecision{
			Outcome: review.OutcomeAct, Reasoning: "grow", Actions: []review.AgentAction{act("expand_volume", map[string]string{"size_gb": "200"})},
		})
		require.NoError(t, err)
		require.Len(t, applied.Proposals, 1)
		w.proposal = applied.Proposals[0]
		decided, err := w.reg.Decide(job.ID, w.proposal, review.VerdictApprove, "", "connor")
		require.NoError(t, err)
		w.decision = decided.ID
		// The next tick's review claims the job and dies.
		_, err = w.reg.AcquireClaim(ctx, review.ClaimRequest{JobID: job.ID, Kind: review.ClaimReview, Holder: "tick-dead", TTL: claimFor})
		require.NoError(t, err)
		return w
	}
	// The execute step as the decision DAG carries it, with the one-second
	// interval a test can wait for and the decision id given as a
	// parameter, since no person's task comes before it here.
	stepDAG := func(t *testing.T, w world) string {
		t.Helper()
		dags, err := review.RenderDAGs(review.DAGConfig{
			MachineID: fixtureJob().MachineID, StateDir: w.dir, ReviewCommand: bin, ClaimWaitIntervalSec: 1,
			Env: map[string]string{"TXE_FIXTURE_REGISTRY": w.registry, "TXE_FIXTURE_STATE_DIR": w.dir, "TXE_FIXTURE_MACHINE": fixtureJob().MachineID},
		})
		require.NoError(t, err)
		head, rest, found := strings.Cut(dags.Decide, "steps:\n")
		require.True(t, found)
		_, step, found := strings.Cut(rest, "  - id: execute\n")
		require.True(t, found)
		require.Contains(t, step, "exit_code: [75]")
		step = strings.Replace(step, "    depends: decide\n", "", 1)
		step = strings.Replace(step, "${steps.decide.outputs.decision_id}", "${DECISION_ID}", 1)
		head = strings.Replace(head, "  - PROPOSAL_ID: \"\"\n", "  - PROPOSAL_ID: \""+w.proposal+"\"\n  - DECISION_ID: \""+w.decision+"\"\n", 1)
		head = strings.Replace(head, "  - JOB_ID: \"\"\n", "  - JOB_ID: \""+w.job+"\"\n", 1)
		// The worker selector names a machine no test worker has.
		head = strings.Replace(head, "worker_selector:\n  txe.machine: \""+fixtureJob().MachineID+"\"\n", "", 1)
		require.NotContains(t, head, "worker_selector")
		return head + "steps:\n  - id: execute\n" + step
	}
	effects := func(t *testing.T, w world) []string {
		t.Helper()
		data, err := os.ReadFile(w.effects)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		require.NoError(t, err)
		return strings.Split(strings.TrimSpace(string(data)), "\n")
	}
	actions := func(w world) (out []review.Action) {
		w.reg.View(func(s *reviewtest.State) { out = append(out, s.Actions[w.job]...) })
		return out
	}

	t.Run("it waits for the claim and then runs the action once", func(t *testing.T) {
		const claimFor = 6 * time.Second
		w := start(t, claimFor)
		th := test.Setup(t)
		dagAgent := th.DAG(t, stepDAG(t, w))
		agent := dagAgent.Agent()
		runCtx, cancel := context.WithTimeout(agent.Context, 90*time.Second)
		defer cancel()
		started := time.Now()
		require.NoError(t, agent.Run(runCtx), "the run succeeds by itself")
		elapsed := time.Since(started)

		assert.GreaterOrEqual(t, elapsed, claimFor-2*time.Second, "not before the dead claim's lifetime was over")
		assert.Less(t, elapsed, 60*time.Second)
		require.Len(t, effects(t, w), 1, "the action ran exactly once")
		assert.Contains(t, effects(t, w)[0], "expanded to 200")
		done := actions(w)
		require.Len(t, done, 1)
		assert.Equal(t, review.ActionSucceeded, done[0].State)
		assert.Equal(t, w.decision, done[0].DecisionID, "under the decision the person made")
		var transitions []string
		w.reg.View(func(s *reviewtest.State) { transitions = s.Transitions })
		joined := strings.Join(transitions, "\n")
		assert.Contains(t, joined, "granted to tick-dead (review)")
		assert.Contains(t, joined, "expired", "the dead claim ended by its lifetime; nobody released it")
		assert.NotContains(t, joined, "granted to tick-dead (review)\nclaim clm_000002 fence 2 released")

		// The same run started again, as a retry from the dashboard would
		// be, runs nothing more.
		dagAgain := th.DAG(t, stepDAG(t, w))
		again := dagAgain.Agent()
		require.NoError(t, again.Run(runCtx))
		assert.Len(t, effects(t, w), 1)
		assert.Len(t, actions(w), 1)
	})

	// A run that ends before the claim does is a failed run with nothing
	// done, and the retry a person then makes runs the action once.
	t.Run("a run cut short does nothing, and its retry runs the action once", func(t *testing.T) {
		w := start(t, 8*time.Second)
		th := test.Setup(t)
		dagAgent := th.DAG(t, stepDAG(t, w))
		agent := dagAgent.Agent()
		short, cancel := context.WithTimeout(agent.Context, 3*time.Second)
		require.Error(t, agent.Run(short), "cut short while the claim was still live")
		cancel()
		assert.Empty(t, effects(t, w))
		assert.Empty(t, actions(w))

		time.Sleep(6 * time.Second)
		dagRetry := th.DAG(t, stepDAG(t, w))
		retry := dagRetry.Agent()
		runCtx, cancelRun := context.WithTimeout(retry.Context, 60*time.Second)
		defer cancelRun()
		require.NoError(t, retry.Run(runCtx))
		assert.Len(t, effects(t, w), 1)
		require.Len(t, actions(w), 1)
		assert.Equal(t, review.ActionSucceeded, actions(w)[0].State)
	})

	// A failure that is not a held claim is not waited on: the step is tried
	// once and the run fails, with the reason in its log.
	t.Run("a decision the registry does not know fails at once", func(t *testing.T) {
		w := start(t, time.Second)
		time.Sleep(1500 * time.Millisecond)
		require.NoError(t, os.Chmod(w.registry, 0o000))
		t.Cleanup(func() { _ = os.Chmod(w.registry, 0o600) })
		th := test.Setup(t)
		dagAgent := th.DAG(t, stepDAG(t, w))
		agent := dagAgent.Agent()
		runCtx, cancel := context.WithTimeout(agent.Context, 30*time.Second)
		defer cancel()
		started := time.Now()
		require.Error(t, agent.Run(runCtx))
		assert.Less(t, time.Since(started), 10*time.Second, "no wait for a failure that waiting does not change")
		assert.Empty(t, effects(t, w))
	})
}
