package review_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/review"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// onWrite is a registry that does something once, right before the first
// write of a kind reaches it: the moment a job is updated under a review.
type onWrite struct {
	review.Registry
	proposal, finish, record, checkpoint func()
}

func once(f *func()) {
	if *f != nil {
		g := *f
		*f = nil
		g()
	}
}

func (w *onWrite) CreateProposal(ctx context.Context, claim review.Claim, draft review.Proposal) (review.Proposal, error) {
	once(&w.proposal)
	return w.Registry.CreateProposal(ctx, claim, draft)
}

func (w *onWrite) FinishAction(ctx context.Context, req review.FinishRequest) error {
	once(&w.finish)
	return w.Registry.FinishAction(ctx, req)
}

func (w *onWrite) RecordReview(ctx context.Context, claim review.Claim, rev review.Review) error {
	once(&w.record)
	return w.Registry.RecordReview(ctx, claim, rev)
}

func (w *onWrite) AdvanceCheckpoint(ctx context.Context, claim review.Claim, next review.Checkpoint, expected int) error {
	once(&w.checkpoint)
	return w.Registry.AdvanceCheckpoint(ctx, claim, next, expected)
}

// A job updated while it is being reviewed ends that review: the registry
// ends the review's claim, and the review's next write is refused. That is
// not a failure of the review. It is abandoned, records nothing, leaves the
// checkpoint where it was, and the next tick reviews the job as it now is.
// An action already begun is in the journal and is never run again.
func TestAReviewIsAbandonedWhenItsJobChangesUnderIt(t *testing.T) {
	ctx := context.Background()
	update := func(f *fixture) func() {
		return func() {
			v2 := fixtureJob()
			v2.Version = 2
			v2.Purpose = "Watch free space on the data volume, and its inodes."
			require.NoError(f.t, f.registry.PutJob(v2))
		}
	}
	expand := review.AgentDecision{Outcome: review.OutcomeAct, Reasoning: "Expand.", Actions: []review.AgentAction{act("expand_volume", map[string]string{"size_gb": "200"})}}
	notify := review.AgentDecision{Outcome: review.OutcomeAct, Reasoning: "Notify.", Actions: []review.AgentAction{act("notify", nil)}}
	carryOn := review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "fine"}
	nothingRecorded := func(t *testing.T, f *fixture) {
		t.Helper()
		s := f.state()
		assert.Empty(t, s.Reviews[jobID], "no review is recorded")
		assert.Zero(t, s.Checkpoints[jobID].Version, "the checkpoint does not move")
		assert.Empty(t, s.Claims, "no claim is left")
		assert.Empty(t, s.Exceptions, "nobody is told of a failure that is not one")
	}

	for name, at := range map[string]func(w *onWrite, do func()){
		"before the proposal is filed":      func(w *onWrite, do func()) { w.proposal = do },
		"before the review is recorded":     func(w *onWrite, do func()) { w.record = do },
		"before the checkpoint is advanced": func(w *onWrite, do func()) { w.checkpoint = do },
	} {
		t.Run("updated "+name, func(t *testing.T) {
			f := newFixture(t)
			f.addRun("run-1", "failed")
			prepared := f.prepare("reviewer-a")
			w := &onWrite{Registry: f.registry}
			at(w, update(f))
			r := f.reviewer("reviewer-a")
			r.Registry = w
			applied, err := r.Apply(ctx, prepared, expand)
			require.NoError(t, err, "the step does not fail")
			assert.Equal(t, "the job moved from version 1 to version 2 under the review", applied.Aborted)
			assert.Empty(t, applied.Review.ID)
			if name != "before the proposal is filed" {
				// What was already filed is said; the registry has
				// superseded it with the old version.
				assert.Len(t, applied.Proposals, 1)
			}
			s := f.state()
			if name == "before the checkpoint is advanced" {
				// The review record was taken before the update; the
				// episode is still open and the job is reviewed again.
				assert.Len(t, s.Reviews[jobID], 1)
			} else {
				assert.Empty(t, s.Reviews[jobID])
			}
			assert.Zero(t, s.Checkpoints[jobID].Version)
			assert.Empty(t, s.Claims)
			assert.Empty(t, s.Exceptions)

			// The next tick reviews version 2.
			f.clock.Advance(2 * time.Minute)
			next := f.prepare("reviewer-b")
			require.Empty(t, next.Skipped)
			assert.Equal(t, 2, next.Packet.Job.Version)
			f.apply("reviewer-b", next, carryOn)
			want := 1
			if name == "before the checkpoint is advanced" {
				// The recorded review is that episode's decision: the next
				// review first completes it, then is an episode of its own.
				want = 2
			}
			assert.Equal(t, want, f.state().Checkpoints[jobID].Version)
		})
	}

	t.Run("updated while an action is running: the effect happens once and is settled later", func(t *testing.T) {
		f := newFixture(t)
		prepared := f.prepare("reviewer-a")
		f.effects.run = func(review.Action) (review.EffectResult, bool) {
			update(f)()
			return review.EffectResult{Status: review.EffectApplied, Receipt: "receipt-notify"}, true
		}
		applied, err := f.reviewer("reviewer-a").Apply(ctx, prepared, notify)
		require.NoError(t, err)
		assert.Contains(t, applied.Aborted, "moved from version 1 to version 2")
		nothingRecorded(t, f)
		require.Len(t, applied.Executed, 1, "the attempt that ran is said, as the registry holds it")
		assert.Equal(t, review.ActionUncertain, applied.Executed[0].State)
		action := f.state().Actions[jobID][0]
		assert.Equal(t, review.ActionUncertain, action.State, "the registry interrupted the attempt with the claim")
		assert.Equal(t, 1, f.effects.count("notify"))

		// The next review settles the attempt of version 1 with the owner
		// and does not make the effect again, even when asked to.
		f.effects.run = nil
		f.clock.Advance(2 * time.Minute)
		next := f.prepare("reviewer-b")
		require.Empty(t, next.Skipped)
		assert.Equal(t, review.ActionEscalated, f.state().Actions[jobID][0].State)
		f.apply("reviewer-b", next, notify)
		assert.Equal(t, 1, f.effects.count("notify"), "the effect happened once")
	})

	t.Run("updated while what an earlier claim left open is being settled", func(t *testing.T) {
		f := newFixture(t)
		job := fixtureJob()
		job.Review.Actions[1].Reconcile = []string{"probe"}
		require.NoError(t, f.registry.PutJob(job))
		dying := f.reviewer("reviewer-a")
		dying.Registry = crashAfterEffect{f.registry}
		_, err := dying.Apply(ctx, f.prepare("reviewer-a"), notify)
		require.ErrorIs(t, err, errCrash)
		f.clock.Advance(11 * time.Minute)
		f.effects.probe = func(review.Action) review.EffectResult {
			return review.EffectResult{Status: review.EffectApplied}
		}
		r := f.reviewer("reviewer-b")
		r.Registry = &onWrite{Registry: f.registry, finish: func() {
			v2 := job
			v2.Version = 2
			require.NoError(t, f.registry.PutJob(v2))
		}}
		prepared, err := r.Prepare(ctx, jobID)
		require.NoError(t, err, "preparing does not fail")
		assert.Equal(t, review.SkipJobChanged, prepared.Skipped)
		assert.Contains(t, prepared.SkipDetail, "moved from version 1 to version 2")
		assert.Empty(t, f.state().Claims)
		assert.Equal(t, 1, f.effects.count("notify"))
	})

	// A claim that is stale for any other reason is still a failure: the
	// job is as the review read it, so nothing explains the refusal away.
	t.Run("a claim that simply expired and was taken is still an error", func(t *testing.T) {
		f := newFixture(t)
		prepared := f.prepare("reviewer-a")
		f.clock.Advance(11 * time.Minute)
		f.prepare("reviewer-b")
		_, err := f.reviewer("reviewer-a").Apply(ctx, prepared, expand)
		require.ErrorIs(t, err, review.ErrStaleFence)
	})
	t.Run("a job that cannot be read again leaves the refusal an error", func(t *testing.T) {
		f := newFixture(t)
		prepared := f.prepare("reviewer-a")
		unreadable := errors.New("connection reset")
		w := &onWrite{Registry: f.registry}
		reads := &failReadsAfter{Registry: w, err: unreadable}
		w.proposal = func() { update(f)(); reads.fail = true }
		r := f.reviewer("reviewer-a")
		r.Registry = reads
		_, err := r.Apply(ctx, prepared, expand)
		require.ErrorIs(t, err, review.ErrStaleFence)
	})

	t.Run("an agent that failed on a job that changed leaves nothing to put off and tells nobody", func(t *testing.T) {
		f := newFixture(t)
		prepared := f.prepare("reviewer-a")
		update(f)()
		require.NoError(t, f.reviewer("reviewer-a").Fail(ctx, prepared, &review.AgentFailure{Kind: review.ExceptionReviewerFailed, Message: "no output"}))
		assert.True(t, f.state().Checkpoints[jobID].NextReviewAt.IsZero(), "the job is due as it now is")
		assert.Empty(t, f.state().Exceptions, "no exception about a review nobody needs")

		// On a job that did not change the owner is told, as before.
		f = newFixture(t)
		require.NoError(t, f.reviewer("reviewer-a").Fail(ctx, f.prepare("reviewer-a"), &review.AgentFailure{Kind: review.ExceptionReviewerFailed, Message: "no output"}))
		require.Len(t, f.state().Exceptions, 1)
		assert.False(t, f.state().Checkpoints[jobID].NextReviewAt.IsZero())
	})

	// The agent's judgement that the job is unreachable is about the version
	// it was shown. It is told to the owner only once the review is
	// recorded, so an abandoned review says nothing about the new version.
	t.Run("an unreachable verdict on a job that changed tells nobody", func(t *testing.T) {
		unreachable := review.AgentDecision{Outcome: review.OutcomePauseUnavailable, Reasoning: "the cluster does not answer"}
		f := newFixture(t)
		prepared := f.prepare("reviewer-a")
		r := f.reviewer("reviewer-a")
		r.Registry = &onWrite{Registry: f.registry, record: update(f)}
		applied, err := r.Apply(ctx, prepared, unreachable)
		require.NoError(t, err)
		assert.NotEmpty(t, applied.Aborted)
		assert.Empty(t, f.state().Exceptions)

		f = newFixture(t)
		f.apply("reviewer-a", f.prepare("reviewer-a"), unreachable)
		require.Len(t, f.state().Exceptions, 1)
		assert.Equal(t, review.ExceptionUnavailable, f.state().Exceptions[0].Kind)
		require.Len(t, f.state().Reviews[jobID], 1)
	})

	// Whatever a write of the review failed with, a job that changed makes
	// the review void: the registry refuses in more ways than a stale claim.
	t.Run("any refusal on a job that changed abandons the review", func(t *testing.T) {
		for name, refusal := range map[string]error{
			"the action is no longer permitted": &review.GuardDeniedError{Reason: review.DenyNotPermitted, Detail: "action expand_volume is not declared"},
			"an invalid proposal":               &review.TransportError{Status: 400, Code: "invalid", Message: "proposal id does not match the job's version"},
			"a stale binding":                   &review.GuardDeniedError{Reason: review.DenyDecisionStale, Detail: "binding changed"},
		} {
			f := newFixture(t)
			prepared := f.prepare("reviewer-a")
			r := f.reviewer("reviewer-a")
			r.Registry = &refuseProposals{Registry: f.registry, err: refusal, before: update(f)}
			applied, err := r.Apply(ctx, prepared, expand)
			require.NoError(t, err, name)
			assert.NotEmpty(t, applied.Aborted, name)

			// The same refusal on a job that did not change is an error.
			f = newFixture(t)
			prepared = f.prepare("reviewer-a")
			r = f.reviewer("reviewer-a")
			r.Registry = &refuseProposals{Registry: f.registry, err: refusal}
			_, err = r.Apply(ctx, prepared, expand)
			require.Error(t, err, name)
		}
	})
}

// refuseProposals is a registry that refuses every proposal with err, after
// doing before once.
type refuseProposals struct {
	review.Registry
	err    error
	before func()
}

func (r *refuseProposals) CreateProposal(context.Context, review.Claim, review.Proposal) (review.Proposal, error) {
	once(&r.before)
	return review.Proposal{}, r.err
}

// failReadsAfter is a registry whose job cannot be read once fail is set.
type failReadsAfter struct {
	review.Registry
	err  error
	fail bool
}

func (r *failReadsAfter) Job(ctx context.Context, jobID string) (review.Job, error) {
	if r.fail {
		return review.Job{}, r.err
	}
	return r.Registry.Job(ctx, jobID)
}

// Against the real registry over its HTTP API: a proposal carries the
// version its review read, an update ends the review's claim, and a review
// that meets that at any write is abandoned without an error, an exception
// or a second effect.
func TestRemoteAnUpdateUnderAReviewAbandonsIt(t *testing.T) {
	ctx := context.Background()
	type world struct {
		f          *remoteFixture
		id, target string
		update     func()
		updateTo   func(change func(*apigen.TxeJobVersionInput), markReady bool)
		reviewer   func(holder string) *review.Reviewer
	}
	start := func(t *testing.T) world {
		t.Helper()
		f := newRemoteFixture(t)
		first := f.job()
		actor := &apigen.TxeActor{Kind: apigen.TxeActorKindCli, Id: "cc5-test"}
		id, err := registry.NewID(registry.PrefixJob, time.Now())
		require.NoError(t, err)
		digest, dir := fmt.Sprintf("sha256:%064x", 41), t.TempDir()
		none := apigen.TxePermittedActionIdempotency("none")
		version := func(purpose string) apigen.TxeJobVersionInput {
			return apigen.TxeJobVersionInput{
				Title: "Volume", Purpose: purpose,
				Package: apigen.TxePackage{Digest: digest, Path: dir, Entrypoint: "run.sh"},
				Dag:     apigen.TxeDAGRef{Spec: fmt.Sprintf("worker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/volume.sh\n", first.MachineID)},
				Targets: &[]apigen.TxeTarget{{Kind: "fixture.volume", StableId: map[string]string{"cluster_uid": "c-1", "uid": "vol-9"}}},
				ReviewPolicy: &apigen.TxeReviewPolicy{
					Brief: new("Watch it."), Cadence: new("1h"), MaxAttempts: new(1),
					PermittedActions: &[]apigen.TxePermittedAction{
						{Name: "notify", Routine: true, Command: new("true"), Idempotency: &none, TimeoutSec: 30},
						{Name: "expand_volume", Routine: false, Command: new("true"), Idempotency: &none, TimeoutSec: 30},
					},
				},
			}
		}
		local := map[int]apigen.TxeJobVersionInput{1: version("Watch free space.")}
		require.NoError(t, f.remote.Transport.Do(ctx, http.MethodPost, "/txe/jobs", apigen.TxeRegisterRequest{
			JobId: id, RequestId: "abandon-1", OwnerId: first.OwnerID, ProjectId: first.ProjectID, MachineId: first.MachineID, JobKey: "volume:9",
			Version: local[1], Actor: actor,
		}, nil))
		ready := func() {
			require.NoError(t, f.remote.Transport.Do(ctx, http.MethodPost, "/txe/jobs/"+id+"/ready", apigen.TxeReadyRequest{
				Package: apigen.TxePackageEvidence{Digest: digest, Path: dir, MachineId: first.MachineID}, Actor: actor,
			}, nil))
		}
		ready()
		latest := 1
		f.remote.LocalVersion = func(jobID string, v int) (json.RawMessage, error) {
			in, ok := local[v]
			if jobID != id || !ok {
				return nil, errors.New("not registered from this machine")
			}
			return json.Marshal(in)
		}
		f.remote.LocalLatest = func(string) (int, string, error) { return latest, first.OwnerID, nil }
		return world{
			f: f, id: id,
			target: registry.TargetKey(registry.Target{Kind: "fixture.volume", StableID: map[string]string{"cluster_uid": "c-1", "uid": "vol-9"}}),
			update: func() {
				local[2] = version("Watch free space and inodes.")
				latest = 2
				require.NoError(t, f.remote.Transport.Do(ctx, http.MethodPost, "/txe/jobs/"+id+"/versions", apigen.TxeVersionRequest{
					Actor: actor, ExpectedVersion: 1, RequestId: "abandon-2", Version: local[2],
				}, nil))
				ready()
			},
			updateTo: func(change func(*apigen.TxeJobVersionInput), markReady bool) {
				v2 := version("Watch free space and inodes.")
				change(&v2)
				local[2] = v2
				latest = 2
				require.NoError(t, f.remote.Transport.Do(ctx, http.MethodPost, "/txe/jobs/"+id+"/versions", apigen.TxeVersionRequest{
					Actor: actor, ExpectedVersion: 1, RequestId: "abandon-2", Version: v2,
				}, nil))
				if markReady {
					ready()
				}
			},
			reviewer: func(holder string) *review.Reviewer { return f.reviewer(holder) },
		}
	}
	stored := func(t *testing.T, w world) *registry.Job {
		t.Helper()
		job, err := w.f.store.GetJob(ctx, w.id)
		require.NoError(t, err)
		return job
	}
	expand := func(w world) review.AgentDecision {
		return review.AgentDecision{Outcome: review.OutcomeAct, Reasoning: "Expand.", Actions: []review.AgentAction{{Name: "expand_volume", TargetID: w.target, Reason: "r"}}}
	}
	notify := func(w world) review.AgentDecision {
		return review.AgentDecision{Outcome: review.OutcomeAct, Reasoning: "Notify.", Actions: []review.AgentAction{{Name: "notify", TargetID: w.target, Reason: "r"}}}
	}

	t.Run("a proposal is filed against the version its review read", func(t *testing.T) {
		w := start(t)
		r := w.reviewer("tick-1")
		prepared, err := r.Prepare(ctx, w.id)
		require.NoError(t, err)
		applied, err := r.Apply(ctx, prepared, expand(w))
		require.NoError(t, err)
		require.Len(t, applied.Proposals, 1)
		job := stored(t, w)
		require.Contains(t, job.Proposals, applied.Proposals[0])
		assert.Equal(t, 1, job.Proposals[applied.Proposals[0]].JobVersion)

		// One made against a version the job is not at is refused.
		next, err := w.reviewer("tick-2").Prepare(ctx, w.id)
		require.NoError(t, err)
		stale := review.ProposalID(next.Packet.ReviewID, review.ProposalQuestion, "", "", nil, "?")
		_, err = w.f.remote.CreateProposal(ctx, next.Claim, review.Proposal{
			ID: stale, JobID: w.id, JobVersion: 7, Kind: review.ProposalQuestion, Question: "?",
			ReviewID: next.Packet.ReviewID, AllowedVerdicts: []review.Verdict{review.VerdictReject},
			NativeTask: review.TaskLocator{DAG: review.DecideDAGName(w.f.remote.MachineID), RunID: review.DecisionRunID(stale), StepID: "decide"},
		})
		require.ErrorIs(t, err, review.ErrConflict)
	})

	for name, at := range map[string]func(w *onWrite, do func()){
		"between the prepared packet and the first write": nil,
		"before the proposal is filed":                    func(w *onWrite, do func()) { w.proposal = do },
		"before the review is recorded":                   func(w *onWrite, do func()) { w.record = do },
	} {
		t.Run("updated "+name, func(t *testing.T) {
			w := start(t)
			r := w.reviewer("tick-1")
			prepared, err := r.Prepare(ctx, w.id)
			require.NoError(t, err)
			if at == nil {
				w.update()
			} else {
				hook := &onWrite{Registry: w.f.remote}
				at(hook, w.update)
				r.Registry = hook
			}
			applied, err := r.Apply(ctx, prepared, expand(w))
			require.NoError(t, err, "the step does not fail")
			assert.Contains(t, applied.Aborted, "version")
			job := stored(t, w)
			assert.Equal(t, 2, job.Version)
			assert.Zero(t, job.Checkpoint.Version, "the checkpoint does not move")
			assert.Empty(t, job.Exceptions)
			for _, p := range job.Proposals {
				assert.NotEqual(t, registry.ProposalOpen, p.State, "no proposal of the old version is left open")
			}
			// The next tick reviews version 2.
			next := w.reviewer("tick-2")
			again, err := next.Prepare(ctx, w.id)
			require.NoError(t, err)
			require.Empty(t, again.Skipped)
			assert.Equal(t, 2, again.Packet.Job.Version)
			_, err = next.Apply(ctx, again, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "fine"})
			require.NoError(t, err)
			assert.Equal(t, 1, stored(t, w).Checkpoint.Version)
		})
	}

	t.Run("updated while an action is running: one effect, settled later, never repeated", func(t *testing.T) {
		w := start(t)
		r := w.reviewer("tick-1")
		prepared, err := r.Prepare(ctx, w.id)
		require.NoError(t, err)
		w.f.fx.run = func(review.Action) (review.EffectResult, bool) {
			w.update()
			return review.EffectResult{Status: review.EffectApplied, Receipt: "receipt-notify"}, true
		}
		applied, err := r.Apply(ctx, prepared, notify(w))
		require.NoError(t, err)
		assert.Contains(t, applied.Aborted, "moved from version 1 to version 2")
		assert.Equal(t, 1, w.f.fx.count("notify"))
		require.Len(t, applied.Executed, 1, "the attempt that ran is said, as the registry holds it")
		assert.Equal(t, review.ActionUncertain, applied.Executed[0].State)
		actions, err := w.f.remote.Actions(ctx, w.id)
		require.NoError(t, err)
		require.Len(t, actions, 1)
		assert.Equal(t, review.ActionUncertain, actions[0].State, "the registry interrupted the attempt when it ended the claim")
		assert.Zero(t, stored(t, w).Checkpoint.Version)

		w.f.fx.run = nil
		next := w.reviewer("tick-2")
		again, err := next.Prepare(ctx, w.id)
		require.NoError(t, err)
		require.Empty(t, again.Skipped)
		_, err = next.Apply(ctx, again, notify(w))
		require.NoError(t, err)
		assert.Equal(t, 1, w.f.fx.count("notify"), "the effect happened once")
	})

	// The new version no longer declares the action the review asks a
	// person about: the registry refuses the proposal for that reason, not
	// as a stale claim, and the review is abandoned all the same.
	t.Run("updated to a version without the proposed action", func(t *testing.T) {
		w := start(t)
		r := w.reviewer("tick-1")
		prepared, err := r.Prepare(ctx, w.id)
		require.NoError(t, err)
		r.Registry = &onWrite{Registry: w.f.remote, proposal: func() {
			w.updateTo(func(v *apigen.TxeJobVersionInput) {
				kept := (*v.ReviewPolicy.PermittedActions)[:1]
				v.ReviewPolicy.PermittedActions = &kept
			}, true)
		}}
		applied, err := r.Apply(ctx, prepared, expand(w))
		require.NoError(t, err)
		assert.Contains(t, applied.Aborted, "moved from version 1 to version 2")
		job := stored(t, w)
		assert.Zero(t, job.Checkpoint.Version)
		assert.Empty(t, job.Exceptions)
		assert.Empty(t, job.Proposals)
	})

	// An update that is not finished leaves the registration not ready: the
	// review is abandoned, and the job is then skipped until it is.
	t.Run("updated and not yet ready", func(t *testing.T) {
		w := start(t)
		r := w.reviewer("tick-1")
		prepared, err := r.Prepare(ctx, w.id)
		require.NoError(t, err)
		r.Registry = &onWrite{Registry: w.f.remote, record: func() {
			w.updateTo(func(*apigen.TxeJobVersionInput) {}, false)
		}}
		applied, err := r.Apply(ctx, prepared, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "fine"})
		require.NoError(t, err)
		assert.NotEmpty(t, applied.Aborted)
		job := stored(t, w)
		assert.Equal(t, registry.RegistrationIncomplete, job.Registration.State)
		assert.Zero(t, job.Checkpoint.Version)
		assert.Empty(t, job.Exceptions)
		again, err := w.reviewer("tick-2").Prepare(ctx, w.id)
		require.NoError(t, err)
		assert.Equal(t, review.SkipNotRegistered, again.Skipped)
	})

	// The agent's verdict that the job is unreachable is not told to the
	// owner of a job that changed under the review.
	t.Run("an unreachable verdict on a job that changed tells nobody", func(t *testing.T) {
		w := start(t)
		r := w.reviewer("tick-1")
		prepared, err := r.Prepare(ctx, w.id)
		require.NoError(t, err)
		r.Registry = &onWrite{Registry: w.f.remote, record: w.update}
		applied, err := r.Apply(ctx, prepared, review.AgentDecision{Outcome: review.OutcomePauseUnavailable, Reasoning: "the cluster does not answer"})
		require.NoError(t, err)
		assert.NotEmpty(t, applied.Aborted)
		job := stored(t, w)
		assert.Empty(t, job.Exceptions)
		assert.Equal(t, registry.AvailabilityReady, job.Availability.State)
	})

	t.Run("a claim that expired and was taken, on an unchanged job, is still an error", func(t *testing.T) {
		w := start(t)
		prepared, err := w.reviewer("tick-1").Prepare(ctx, w.id)
		require.NoError(t, err)
		*w.f.ahead += time.Hour
		later := w.reviewer("tick-2")
		later.Now = func() time.Time { return time.Now().Add(*w.f.ahead) }
		_, err = later.Prepare(ctx, w.id)
		require.NoError(t, err)
		_, err = w.reviewer("tick-1").Apply(ctx, prepared, expand(w))
		require.ErrorIs(t, err, review.ErrStaleFence)
		assert.Equal(t, 1, stored(t, w).Version)
	})
}
