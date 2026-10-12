package review_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"testing"
	"time"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/review"
	"github.com/dagucloud/dagu/v2/internal/txe/review/reviewtest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An action that does not return before its timeout is stopped when its
// grant ends. By the time its outcome is recorded the registry has itself
// marked the expired attempt interrupted, and it refuses a second record of
// that. The review is not lost over it: the registry holds exactly the
// outcome being recorded, so it is recorded. Seen on the staging hub, where
// the review failed with "cannot settle uncertain action as uncertain".
func TestAnActionThatRunsToTheEndOfItsGrantIsStillReviewed(t *testing.T) {
	notify := review.AgentDecision{Outcome: review.OutcomeAct, Reasoning: "Notify.", Actions: []review.AgentAction{act("notify", nil)}}
	collect := review.AgentDecision{Outcome: review.OutcomeAct, Reasoning: "Collect.", Actions: []review.AgentAction{act("collect_diagnostics", nil)}}

	t.Run("an effect that may have happened is uncertain and the review is recorded", func(t *testing.T) {
		f := newFixture(t)
		// The command applies its effect and hangs to the end of the grant.
		f.effects.run = func(review.Action) (review.EffectResult, bool) {
			f.clock.Advance(3 * time.Minute)
			return review.EffectResult{Status: review.EffectUnknown, Detail: "action timed out"}, true
		}
		applied := f.apply("reviewer-a", f.prepare("reviewer-a"), notify)
		require.Len(t, applied.Executed, 1)
		assert.Equal(t, review.ActionUncertain, applied.Executed[0].State)
		s := f.state()
		assert.Equal(t, review.ActionUncertain, s.Actions[jobID][0].State)
		require.Len(t, s.Reviews[jobID], 1, "the review is recorded")
		assert.Equal(t, 1, s.Checkpoints[jobID].Version)
		assert.Equal(t, 1, f.effects.count("notify"))
	})

	t.Run("a read-only action is closed as failed and the review is recorded", func(t *testing.T) {
		f := newFixture(t)
		f.effects.run = func(review.Action) (review.EffectResult, bool) {
			f.clock.Advance(3 * time.Minute)
			return review.EffectResult{Status: review.EffectNotApplied, Detail: "action timed out"}, false
		}
		applied := f.apply("reviewer-a", f.prepare("reviewer-a"), collect)
		require.Len(t, applied.Executed, 1)
		assert.Equal(t, review.ActionFailed, applied.Executed[0].State)
		s := f.state()
		assert.Equal(t, review.ActionFailed, s.Actions[jobID][0].State)
		require.Len(t, s.Reviews[jobID], 1)
	})

	// A refusal is taken for "already recorded" only on what the registry
	// holds, never on the refusal itself.
	refused := &review.TransportError{Status: http.StatusConflict, Code: "action_state", Message: "cannot settle uncertain action as uncertain"}
	for name, held := range map[string]func(*review.Action){
		"another state":            func(a *review.Action) { a.State = review.ActionExecuting },
		"another attempt":          func(a *review.Action) { a.Attempt++ },
		"another grant":            func(a *review.Action) { a.GrantID = "grt_other" },
		"bound to something else":  func(a *review.Action) { a.BindingDigest = "sha256:other" },
		"another action entirely":  func(a *review.Action) { a.ID = "act_OTHER" },
		"a success, another state": func(a *review.Action) { a.State = review.ActionSucceeded; a.Receipt = "receipt-notify" },
	} {
		t.Run("a refused record is an error when the registry holds "+name, func(t *testing.T) {
			f := newFixture(t)
			f.effects.run = func(review.Action) (review.EffectResult, bool) {
				return review.EffectResult{Status: review.EffectUnknown, Detail: "action timed out"}, true
			}
			r := f.reviewer("reviewer-a")
			r.Registry = &settleFails{Registry: f.registry, err: refused, held: held}
			_, err := r.Apply(context.Background(), f.prepare("reviewer-a"), notify)
			require.ErrorIs(t, err, refused)
			assert.Empty(t, f.state().Reviews[jobID])
		})
	}
	t.Run("a refused record is an error when the registry cannot be read back", func(t *testing.T) {
		f := newFixture(t)
		f.effects.run = func(review.Action) (review.EffectResult, bool) {
			return review.EffectResult{Status: review.EffectUnknown}, true
		}
		r := f.reviewer("reviewer-a")
		r.Registry = &settleFails{Registry: f.registry, err: refused, unreadable: errors.New("connection reset")}
		_, err := r.Apply(context.Background(), f.prepare("reviewer-a"), notify)
		require.ErrorIs(t, err, refused)
	})

	// The registry sends the action as it held it with a refusal about its
	// state. That account is what is compared, and no read is made.
	account := func(change func(*review.Action)) func(review.Action) error {
		return func(held review.Action) error {
			if change != nil {
				change(&held)
			}
			return &review.TransportError{Status: http.StatusConflict, Code: "action_state", Message: "cannot settle uncertain action as uncertain", CurrentAction: &held}
		}
	}
	t.Run("a refusal that shows this attempt uncertain is its record", func(t *testing.T) {
		f := newFixture(t)
		f.effects.run = func(review.Action) (review.EffectResult, bool) {
			return review.EffectResult{Status: review.EffectUnknown, Detail: "action timed out"}, true
		}
		r := f.reviewer("reviewer-a")
		r.Registry = &settleFails{Registry: f.registry, refuse: account(func(a *review.Action) { a.State = review.ActionUncertain }), unreadable: errors.New("no read is made")}
		applied, err := r.Apply(context.Background(), f.prepare("reviewer-a"), notify)
		require.NoError(t, err)
		assert.Equal(t, review.ActionUncertain, applied.Executed[0].State)
		require.Len(t, f.state().Reviews[jobID], 1)
	})
	for name, change := range map[string]func(*review.Action){
		"still executing":         nil,
		"another attempt":         func(a *review.Action) { a.State = review.ActionUncertain; a.Attempt++ },
		"another grant":           func(a *review.Action) { a.State = review.ActionUncertain; a.GrantID = "grt_other" },
		"no grant":                func(a *review.Action) { a.State = review.ActionUncertain; a.GrantID = "" },
		"another job version":     func(a *review.Action) { a.State = review.ActionUncertain; a.JobVersion++ },
		"another target":          func(a *review.Action) { a.State = review.ActionUncertain; a.TargetID = "other" },
		"other parameters":        func(a *review.Action) { a.State = review.ActionUncertain; a.Params = map[string]string{"x": "y"} },
		"another action":          func(a *review.Action) { a.State = review.ActionUncertain; a.ID = "act_OTHER" },
		"failed, not uncertain":   func(a *review.Action) { a.State = review.ActionFailed },
		"an admitted execution":   func(a *review.Action) { a.State = review.ActionUncertain; a.AdmittedRef = "exec-other" },
		"escalated, not the same": func(a *review.Action) { a.State = review.ActionEscalated },
	} {
		t.Run("a refusal that shows the attempt "+name+" is an error", func(t *testing.T) {
			f := newFixture(t)
			f.effects.run = func(review.Action) (review.EffectResult, bool) {
				return review.EffectResult{Status: review.EffectUnknown, Detail: "action timed out"}, true
			}
			r := f.reviewer("reviewer-a")
			s := &settleFails{Registry: f.registry, refuse: account(change)}
			r.Registry = s
			_, err := r.Apply(context.Background(), f.prepare("reviewer-a"), notify)
			require.ErrorContains(t, err, "action_state")
			assert.Zero(t, s.reads, "the registry's own account decides; nothing is read to find another")
			assert.Empty(t, f.state().Reviews[jobID])
		})
	}

	// What the attempt was seen to admit is part of its outcome: the same
	// state without it is not the outcome being recorded.
	t.Run("the same state without the admitted execution is an error", func(t *testing.T) {
		f := newFixture(t)
		f.effects.run = func(review.Action) (review.EffectResult, bool) {
			return review.EffectResult{Status: review.EffectUnknown, Admitted: true, AdmittedRef: "exec-E"}, true
		}
		r := f.reviewer("reviewer-a")
		// The registry holds the attempt uncertain, with no execution.
		r.Registry = &settleFails{Registry: f.registry, err: refused, held: func(a *review.Action) { a.State = review.ActionUncertain }}
		_, err := r.Apply(context.Background(), f.prepare("reviewer-a"), notify)
		require.ErrorIs(t, err, refused)

		f = newFixture(t)
		f.effects.run = func(review.Action) (review.EffectResult, bool) {
			return review.EffectResult{Status: review.EffectUnknown, Admitted: true, AdmittedRef: "exec-E"}, true
		}
		r = f.reviewer("reviewer-a")
		r.Registry = &settleFails{Registry: f.registry, refuse: account(func(a *review.Action) { a.State = review.ActionUncertain })}
		_, err = r.Apply(context.Background(), f.prepare("reviewer-a"), notify)
		require.ErrorContains(t, err, "action_state")
	})

	// So is an admission the service gave without naming an execution.
	t.Run("the same state without an unnamed admission is an error", func(t *testing.T) {
		for name, fails := range map[string]func(f *fixture) *settleFails{
			"read back": func(f *fixture) *settleFails {
				return &settleFails{Registry: f.registry, err: errors.New("read tcp: connection reset by peer"), held: func(a *review.Action) { a.State = review.ActionUncertain }}
			},
			"in the refusal": func(f *fixture) *settleFails {
				return &settleFails{Registry: f.registry, refuse: account(func(a *review.Action) { a.State = review.ActionUncertain })}
			},
		} {
			f := newFixture(t)
			f.effects.run = func(review.Action) (review.EffectResult, bool) {
				return review.EffectResult{Status: review.EffectUnknown, Admitted: true}, true
			}
			r := f.reviewer("reviewer-a")
			r.Registry = fails(f)
			_, err := r.Apply(context.Background(), f.prepare("reviewer-a"), notify)
			require.Error(t, err, name)
			assert.Empty(t, f.state().Reviews[jobID], name)
		}
		// Held with the admission, it is the same outcome.
		f := newFixture(t)
		f.effects.run = func(review.Action) (review.EffectResult, bool) {
			return review.EffectResult{Status: review.EffectUnknown, Admitted: true}, true
		}
		r := f.reviewer("reviewer-a")
		r.Registry = &settleFails{Registry: f.registry, err: errors.New("read tcp: connection reset by peer"), written: true}
		_, err := r.Apply(context.Background(), f.prepare("reviewer-a"), notify)
		require.NoError(t, err)
	})

	// A conflict of another kind, and a record that is "not found" for a
	// reason that is not this action, say nothing about the attempt.
	t.Run("a conflict of another kind is an error even when the registry holds the outcome", func(t *testing.T) {
		f := newFixture(t)
		f.effects.run = func(review.Action) (review.EffectResult, bool) {
			return review.EffectResult{Status: review.EffectUnknown}, true
		}
		conflict := fmt.Errorf("%w: job is at version 2, not 1", review.ErrConflict)
		r := f.reviewer("reviewer-a")
		r.Registry = &settleFails{Registry: f.registry, err: conflict, written: true}
		_, err := r.Apply(context.Background(), f.prepare("reviewer-a"), notify)
		require.ErrorIs(t, err, conflict)
	})

	// Other answers of the registry are not about the action's state, and
	// are never read as "already recorded", whatever the registry holds.
	for name, said := range map[string]error{
		"a stale claim":   fmt.Errorf("%w: fence 1 is not the job's claim", review.ErrStaleFence),
		"a wrong grant":   &review.TransportError{Status: http.StatusConflict, Code: "grant_invalid", Message: "grant is not the action's current grant"},
		"an invalid body": &review.TransportError{Status: http.StatusBadRequest, Code: "invalid", Message: "succeeded needs a receipt"},
		"a server error":  &review.TransportError{Status: http.StatusInternalServerError, Message: "internal error"},
	} {
		t.Run(name+" is an error even when the registry holds the outcome", func(t *testing.T) {
			f := newFixture(t)
			f.effects.run = func(review.Action) (review.EffectResult, bool) {
				return review.EffectResult{Status: review.EffectUnknown}, true
			}
			r := f.reviewer("reviewer-a")
			// The outcome is written, and then this answer is given.
			r.Registry = &settleFails{Registry: f.registry, err: said, written: true}
			_, err := r.Apply(context.Background(), f.prepare("reviewer-a"), notify)
			require.ErrorIs(t, err, said)
		})
	}

	// The record is written and its answer never arrives: the registry
	// holds the outcome, receipt and all, and the review goes on.
	t.Run("a record whose answer was lost is found written", func(t *testing.T) {
		lost := errors.New("read tcp: connection reset by peer")
		f := newFixture(t)
		r := f.reviewer("reviewer-a")
		r.Registry = &settleFails{Registry: f.registry, err: lost, written: true}
		applied, err := r.Apply(context.Background(), f.prepare("reviewer-a"), notify)
		require.NoError(t, err)
		assert.Equal(t, review.ActionSucceeded, applied.Executed[0].State)
		s := f.state()
		assert.Equal(t, "receipt-notify", s.Actions[jobID][0].Receipt)
		require.Len(t, s.Reviews[jobID], 1)
		assert.Equal(t, 1, f.effects.count("notify"))
	})
	t.Run("a record that was lost and not written is an error", func(t *testing.T) {
		lost := errors.New("read tcp: connection reset by peer")
		f := newFixture(t)
		r := f.reviewer("reviewer-a")
		r.Registry = &settleFails{Registry: f.registry, err: lost}
		_, err := r.Apply(context.Background(), f.prepare("reviewer-a"), notify)
		require.ErrorIs(t, err, lost)
		assert.Equal(t, review.ActionExecuting, f.state().Actions[jobID][0].State, "left for the next review to reconcile")
	})
	t.Run("a success is not found written under another receipt", func(t *testing.T) {
		lost := errors.New("read tcp: connection reset by peer")
		f := newFixture(t)
		r := f.reviewer("reviewer-a")
		r.Registry = &settleFails{Registry: f.registry, err: lost, written: true, held: func(a *review.Action) { a.Receipt = "receipt-of-something-else" }}
		_, err := r.Apply(context.Background(), f.prepare("reviewer-a"), notify)
		require.ErrorIs(t, err, lost)
	})
}

// settleFails is a registry whose record of an outcome fails with err. With
// written, the outcome is written first, as when only the answer is lost.
// held changes what a read of the actions shows; unreadable fails that read.
type settleFails struct {
	review.Registry
	err        error
	written    bool
	held       func(*review.Action)
	unreadable error
	failed     bool
	// refuse, when set, makes the failure from the action as it is held.
	refuse func(review.Action) error
	// reads counts the reads of the actions made after the failure.
	reads int
}

func (s *settleFails) FinishAction(ctx context.Context, req review.FinishRequest) error {
	if s.written {
		if err := s.Registry.FinishAction(ctx, req); err != nil {
			return err
		}
	}
	s.failed = true
	if s.refuse != nil {
		actions, err := s.Registry.Actions(ctx, req.JobID)
		if err != nil {
			return err
		}
		for _, a := range actions {
			if a.ID == req.ActionID {
				return s.refuse(a)
			}
		}
	}
	return s.err
}

func (s *settleFails) Actions(ctx context.Context, jobID string) ([]review.Action, error) {
	actions, err := s.Registry.Actions(ctx, jobID)
	if err != nil || !s.failed {
		return actions, err
	}
	s.reads++
	if s.unreadable != nil {
		return nil, s.unreadable
	}
	if s.held != nil {
		for i := range actions {
			s.held(&actions[i])
		}
	}
	return actions, nil
}

// An interrupted attempt whose probe finds the effect is settled as done.
// A probe states that by its exit code and need print nothing, and the
// registry records no success without a receipt: the receipt then says that
// a probe found the effect of this attempt. Seen on the staging hub, where
// such a job could never be prepared again ("succeeded needs a receipt").
func TestAProbeThatFindsTheEffectSettlesTheAttempt(t *testing.T) {
	interrupted := func(t *testing.T) *fixture {
		t.Helper()
		f := newFixture(t)
		job := fixtureJob()
		job.Review.Actions[1].Reconcile = []string{"probe"}
		require.NoError(t, f.registry.PutJob(job))
		f.effects.run = func(review.Action) (review.EffectResult, bool) {
			f.clock.Advance(3 * time.Minute)
			return review.EffectResult{Status: review.EffectUnknown, Detail: "action timed out"}, true
		}
		f.apply("reviewer-a", f.prepare("reviewer-a"), review.AgentDecision{
			Outcome: review.OutcomeAct, Reasoning: "Notify.", Actions: []review.AgentAction{act("notify", nil)},
		})
		require.Equal(t, review.ActionUncertain, f.state().Actions[jobID][0].State)
		f.clock.Advance(2 * time.Hour)
		return f
	}

	t.Run("a probe that prints nothing", func(t *testing.T) {
		f := interrupted(t)
		probes := 0
		f.effects.probe = func(review.Action) review.EffectResult {
			probes++
			return review.EffectResult{Status: review.EffectApplied}
		}
		prepared := f.prepare("reviewer-b")
		action := f.state().Actions[jobID][0]
		assert.Equal(t, review.ActionSucceeded, action.State)
		assert.Equal(t, fmt.Sprintf("probe:%s:%d:reviewer-b", action.ID, action.Attempt), action.Receipt)
		assert.Equal(t, "reconciled: a probe found the effect present", action.Detail)
		assert.Empty(t, prepared.Packet.UnresolvedActions)
		assert.Equal(t, 1, probes)
		assert.Equal(t, 1, f.effects.count("notify"), "nothing ran again")
		assert.Empty(t, f.state().Proposals[jobID], "no person is asked")
	})
	// What a probe prints is not kept: it may print what it was given to
	// look with, and an outcome is stored and shown, unmasked.
	t.Run("nothing a probe prints is stored", func(t *testing.T) {
		f := interrupted(t)
		f.effects.probe = func(review.Action) review.EffectResult {
			return review.EffectResult{Status: review.EffectApplied, Receipt: "found with token s3cr3t-value"}
		}
		f.prepare("reviewer-b")
		action := f.state().Actions[jobID][0]
		assert.Equal(t, review.ActionSucceeded, action.State)
		assert.Equal(t, fmt.Sprintf("probe:%s:%d:reviewer-b", action.ID, action.Attempt), action.Receipt)
		stored, err := json.Marshal(f.state())
		require.NoError(t, err)
		assert.NotContains(t, string(stored), "s3cr3t-value")
	})
	t.Run("a probe that cannot tell settles nothing", func(t *testing.T) {
		f := interrupted(t)
		f.effects.probe = func(review.Action) review.EffectResult {
			return review.EffectResult{Status: review.EffectUnknown, Detail: "probe exited with code 1"}
		}
		f.prepare("reviewer-b")
		action := f.state().Actions[jobID][0]
		assert.NotEqual(t, review.ActionSucceeded, action.State, "not settled as done on a probe that could not tell")
		assert.NotEqual(t, review.ActionNotApplied, action.State)
		assert.Empty(t, action.Receipt)
		assert.Equal(t, 1, f.effects.count("notify"))
	})
	t.Run("a probe that finds nothing goes to the owner", func(t *testing.T) {
		f := interrupted(t)
		f.effects.probe = func(review.Action) review.EffectResult {
			return review.EffectResult{Status: review.EffectNotApplied}
		}
		f.prepare("reviewer-b")
		action := f.state().Actions[jobID][0]
		assert.Equal(t, review.ActionEscalated, action.State)
		assert.Empty(t, action.Receipt)
		assert.Equal(t, 1, f.effects.count("notify"))
	})
}

// The fake refuses what the registry refuses on these two points, so the
// tests above cannot pass against a fake that is kinder than the registry.
func TestTheFakeRegistrySettlesLikeTheRegistry(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	prepared := f.prepare("reviewer-a")
	action, err := f.registry.BeginAction(ctx, review.BeginRequest{
		Claim: prepared.Claim, JobVersion: 1, Name: "notify", TargetID: targetID, ReviewID: prepared.Packet.ReviewID, Timeout: 10 * time.Second,
	})
	require.NoError(t, err)
	finish := func(state review.ActionState, receipt string) error {
		return f.registry.FinishAction(ctx, review.FinishRequest{Claim: prepared.Claim, JobID: jobID, ActionID: action.ID, GrantID: action.GrantID, State: state, Receipt: receipt})
	}
	te := new(review.TransportError)
	require.ErrorAs(t, finish(review.ActionSucceeded, ""), &te)
	assert.Equal(t, "succeeded needs a receipt", te.Message)

	// Past the end of the grant the attempt is interrupted before the write
	// is looked at, so a record of "uncertain" is refused. The refused write
	// stores nothing: a read still shows the attempt executing.
	f.clock.Advance(11 * time.Second)
	require.ErrorIs(t, finish(review.ActionUncertain, ""), review.ErrConflict, "the expired attempt is uncertain already")
	state := func() (state review.ActionState) {
		f.registry.View(func(s *reviewtest.State) { state = s.Actions[jobID][0].State })
		return state
	}
	assert.Equal(t, review.ActionExecuting, state())
	// A write that is taken stores the interruption with it.
	require.NoError(t, f.registry.RecordReview(ctx, prepared.Claim, review.Review{ID: prepared.Packet.ReviewID, JobID: jobID}))
	assert.Equal(t, review.ActionUncertain, state())
	require.NoError(t, finish(review.ActionSucceeded, "found"))
	assert.Equal(t, review.ActionSucceeded, state())
}

// Against the real registry over its HTTP API, with its clock: an attempt
// that runs past its grant is recorded as the registry already holds it, and
// a probe that finds its effect settles it with a receipt the registry
// takes. The effect happens once.
// exportFixture is a job registered in the real registry with one routine
// keyed action that has a reconcile probe and a 10 second timeout, bound to
// this machine, and one attempt of it that applied its effect and ran past
// its grant: reviewed, and left uncertain.
type exportFixture struct {
	f        *remoteFixture
	id       string
	reviewer func(holder string) *review.Reviewer
}

func timedOutExport(t *testing.T) exportFixture {
	t.Helper()
	f := newRemoteFixture(t)
	ctx := context.Background()
	first := f.job()
	actor := &apigen.TxeActor{Kind: apigen.TxeActorKindCli, Id: "cc5-test"}
	id, err := registry.NewID(registry.PrefixJob, time.Now())
	require.NoError(t, err)
	digest, dir := fmt.Sprintf("sha256:%064x", 31), t.TempDir()
	keyed := apigen.TxePermittedActionIdempotency("keyed")
	registered := apigen.TxeJobVersionInput{
		Title: "Export", Purpose: "Pushes an export that may time out.",
		Package: apigen.TxePackage{Digest: digest, Path: dir, Entrypoint: "run.sh"},
		Dag:     apigen.TxeDAGRef{Spec: fmt.Sprintf("worker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/export.sh\n", first.MachineID)},
		Targets: &[]apigen.TxeTarget{{Kind: "fixture.export", StableId: map[string]string{"cluster_uid": "c-1", "uid": "export-1"}}},
		ReviewPolicy: &apigen.TxeReviewPolicy{
			Brief: new("Push a pending export."), Cadence: new("1h"), MaxAttempts: new(1),
			PermittedActions: &[]apigen.TxePermittedAction{
				{Name: "push_export", Routine: true, Command: new("./push.sh"), Reconcile: new("./probe.sh"), Idempotency: &keyed, TimeoutSec: 10},
			},
		},
	}
	require.NoError(t, f.remote.Transport.Do(ctx, http.MethodPost, "/txe/jobs", apigen.TxeRegisterRequest{
		JobId: id, RequestId: "timeout-1", OwnerId: first.OwnerID, ProjectId: first.ProjectID, MachineId: first.MachineID, JobKey: "export:1",
		Version: registered, Actor: actor,
	}, nil))
	require.NoError(t, f.remote.Transport.Do(ctx, http.MethodPost, "/txe/jobs/"+id+"/ready", apigen.TxeReadyRequest{
		Package: apigen.TxePackageEvidence{Digest: digest, Path: dir, MachineId: first.MachineID}, Actor: actor,
	}, nil))
	// This machine registered the job, so its commands are bound.
	f.remote.LocalVersion = func(jobID string, version int) (json.RawMessage, error) {
		if jobID != id || version != 1 {
			return nil, errors.New("not registered from this machine")
		}
		return json.Marshal(registered)
	}
	f.remote.LocalLatest = func(string) (int, string, error) { return 1, first.OwnerID, nil }
	stored := func() *registry.Action {
		t.Helper()
		job, err := f.store.GetJob(ctx, id)
		require.NoError(t, err)
		for _, a := range job.Actions {
			return a
		}
		archived, err := f.remote.Actions(ctx, id)
		require.NoError(t, err)
		require.Len(t, archived, 1)
		return &registry.Action{ActionID: archived[0].ID, State: registry.ActionState(archived[0].State)}
	}
	reviewer := func(holder string) *review.Reviewer {
		r := f.reviewer(holder)
		r.Now = func() time.Time { return time.Now().Add(*f.ahead) }
		return r
	}
	target := registry.TargetKey(registry.Target{Kind: "fixture.export", StableID: map[string]string{"cluster_uid": "c-1", "uid": "export-1"}})

	// The command applies its effect and hangs: the registry's clock passes
	// the end of the 10 second grant before the outcome is recorded.
	f.fx.run = func(review.Action) (review.EffectResult, bool) {
		*f.ahead += 30 * time.Second
		return review.EffectResult{Status: review.EffectUnknown, Detail: "action timed out"}, true
	}
	r := reviewer("tick-1")
	prepared, err := r.Prepare(ctx, id)
	require.NoError(t, err)
	require.Empty(t, prepared.Skipped)
	require.Empty(t, prepared.Packet.Job.CommandsRefused)
	applied, err := r.Apply(ctx, prepared, review.AgentDecision{
		Outcome: review.OutcomeAct, Reasoning: "Push.", Actions: []review.AgentAction{{Name: "push_export", TargetID: target, Reason: "pending"}},
	})
	require.NoError(t, err, "the review is not lost over a record the registry already holds")
	require.Len(t, applied.Executed, 1)
	assert.Equal(t, review.ActionUncertain, applied.Executed[0].State)
	assert.Equal(t, registry.ActionUncertain, stored().State)
	job, err := f.store.GetJob(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, 1, job.Checkpoint.Version, "the review was recorded")
	assert.Equal(t, 1, f.fx.count("push_export"))
	*f.ahead += 2 * time.Hour
	return exportFixture{f: f, id: id, reviewer: reviewer}
}

func TestRemoteATimedOutActionIsRecordedAndSettledByItsProbe(t *testing.T) {
	x := timedOutExport(t)
	f, id, reviewer, ctx := x.f, x.id, x.reviewer, context.Background()

	// The next review's probe finds the effect.
	probes := 0
	f.fx.probe = func(review.Action) review.EffectResult {
		probes++
		return review.EffectResult{Status: review.EffectApplied, Receipt: "found with token s3cr3t-value"}
	}
	r := reviewer("tick-2")
	prepared, err := r.Prepare(ctx, id)
	require.NoError(t, err, "the job can be prepared again")
	require.Empty(t, prepared.Skipped)
	assert.Empty(t, prepared.Packet.UnresolvedActions)
	assert.Equal(t, 1, probes)
	actions, err := f.remote.Actions(ctx, id)
	require.NoError(t, err)
	require.Len(t, actions, 1)
	assert.Equal(t, review.ActionSucceeded, actions[0].State)
	assert.Equal(t, fmt.Sprintf("probe:%s:1:tick-2", actions[0].ID), actions[0].Receipt)
	assert.Equal(t, 1, f.fx.count("push_export"), "the effect happened once")
	// The registry's own record: who confirmed it, and no text of the probe.
	type recorded struct {
		Receipt string         `json:"receipt"`
		Outcome map[string]any `json:"outcome"`
	}
	var record struct {
		Archived []recorded `json:"archived"`
		InFlight []recorded `json:"in_flight"`
	}
	require.NoError(t, f.remote.Transport.Do(ctx, http.MethodGet, "/txe/jobs/"+id+"/actions", nil, &record))
	record.Archived = append(record.Archived, record.InFlight...)
	require.Len(t, record.Archived, 1)
	sum := sha256.Sum256([]byte("found with token s3cr3t-value"))
	assert.Equal(t, map[string]any{
		"detail": "reconciled: a probe found the effect present", "confirmed_by": "probe",
		"probe_run": "tick-2", "probe_output_sha256": hex.EncodeToString(sum[:]),
	}, record.Archived[0].Outcome)
	whole, err := json.Marshal(record)
	require.NoError(t, err)
	assert.NotContains(t, string(whole), "s3cr3t-value")
	_, err = r.Apply(ctx, prepared, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "done"})
	require.NoError(t, err)
}

// A probe is given what the job's commands are given and may print any of
// it. Nothing it writes leaves the process: not its output, which is only
// counted into a digest, and not its error output, which an action's
// command writes to the step's log and a probe's does not.
func TestCommandEffectorKeepsWhatAProbePrints(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
	job := review.Job{ID: "job_A", OwnerID: "own_A", WorkingDir: t.TempDir()}
	action := review.Action{ID: "act_1", Name: "a", TargetID: "t1"}
	e := &review.CommandEffector{}

	// The step's log is this process's standard error.
	logged := func(t *testing.T, run func()) string {
		t.Helper()
		read, write, err := os.Pipe()
		require.NoError(t, err)
		saved := os.Stderr
		os.Stderr = write
		defer func() { os.Stderr = saved }()
		run()
		require.NoError(t, write.Close())
		data, err := io.ReadAll(read)
		require.NoError(t, err)
		return string(data)
	}
	for name, tc := range map[string]struct {
		script string
		status review.EffectStatus
		stdout string
	}{
		"found":         {`echo "token s3cr3t-out"; echo "token s3cr3t-err" >&2; exit 0`, review.EffectApplied, "token s3cr3t-out\n"},
		"found, silent": {`echo "token s3cr3t-err" >&2; exit 0`, review.EffectApplied, ""},
		"absent":        {`echo "token s3cr3t-out"; echo "token s3cr3t-err" >&2; exit 3`, review.EffectNotApplied, "token s3cr3t-out\n"},
		"cannot tell":   {`echo "token s3cr3t-out"; echo "token s3cr3t-err" >&2; exit 1`, review.EffectUnknown, "token s3cr3t-out\n"},
		"many lines":    {`echo "first s3cr3t-out"; echo; echo "last s3cr3t-out   "; exit 0`, review.EffectApplied, "first s3cr3t-out\n\nlast s3cr3t-out   \n"},
	} {
		t.Run(name, func(t *testing.T) {
			probe := shellAction("true", review.IdempotencyNone)
			probe.Reconcile = []string{"/bin/sh", "-c", tc.script}
			var res review.EffectResult
			log := logged(t, func() { res = e.Probe(context.Background(), job, probe, action) })
			assert.Equal(t, tc.status, res.Status)
			assert.NotContains(t, log, "s3cr3t", "nothing of the probe is in the step's log")
			assert.NotContains(t, fmt.Sprintf("%+v", res), "s3cr3t", "nothing of the probe is in its result")
			assert.Empty(t, res.Receipt)
			if tc.status == review.EffectApplied {
				want := ""
				if tc.stdout != "" {
					sum := sha256.Sum256([]byte(tc.stdout))
					want = hex.EncodeToString(sum[:])
				}
				assert.Equal(t, want, res.OutputSHA256, "the digest is of everything the probe wrote to its output")
			}
		})
	}

	// An action's own command still writes its error output to the log.
	log := logged(t, func() {
		e.Run(context.Background(), job, shellAction(`echo "from the action" >&2; echo receipt`, review.IdempotencyNone), action)
	})
	assert.Contains(t, log, "from the action")
}

// The remaining cases against the real registry over its HTTP API: the
// refusal it really sends, a record whose answer is lost, an account that is
// not of this attempt, a read-only attempt, and probes that find nothing or
// cannot tell. The effect count stays 1 throughout.
func TestRemoteSettlementAgainstTheRealRegistry(t *testing.T) {
	ctx := context.Background()
	type setup struct {
		f        *remoteFixture
		reviewer func(holder string) *review.Reviewer
		notify   review.AgentDecision
		collect  review.AgentDecision
	}
	start := func(t *testing.T) setup {
		t.Helper()
		f := newRemoteFixture(t)
		target := f.targetID()
		return setup{
			f: f,
			reviewer: func(holder string) *review.Reviewer {
				r := f.reviewer(holder)
				r.Now = func() time.Time { return time.Now().Add(*f.ahead) }
				return r
			},
			notify:  review.AgentDecision{Outcome: review.OutcomeAct, Reasoning: "Notify.", Actions: []review.AgentAction{{Name: "notify", TargetID: target, Reason: "r"}}},
			collect: review.AgentDecision{Outcome: review.OutcomeAct, Reasoning: "Collect.", Actions: []review.AgentAction{{Name: "collect_diagnostics", TargetID: target, Reason: "r"}}},
		}
	}
	timesOut := func(f *remoteFixture, status review.EffectStatus, happened bool) {
		f.fx.run = func(review.Action) (review.EffectResult, bool) {
			*f.ahead += 2 * time.Minute
			return review.EffectResult{Status: status, Detail: "action timed out"}, happened
		}
	}
	only := func(t *testing.T, f *remoteFixture) review.Action {
		t.Helper()
		actions, err := f.remote.Actions(ctx, f.jobID)
		require.NoError(t, err)
		require.Len(t, actions, 1)
		return actions[0]
	}

	t.Run("the refusal carries the interrupted attempt, and that is what is compared", func(t *testing.T) {
		s := start(t)
		timesOut(s.f, review.EffectUnknown, true)
		var refusal *review.TransportError
		r := s.reviewer("tick-1")
		r.Registry = &watchSettle{Registry: s.f.remote, seen: func(err error) error {
			refusal, _ = errors.AsType[*review.TransportError](err)
			return err
		}}
		prepared, err := r.Prepare(ctx, s.f.jobID)
		require.NoError(t, err)
		applied, err := r.Apply(ctx, prepared, s.notify)
		require.NoError(t, err)
		require.NotNil(t, refusal, "the registry refused the record")
		assert.Equal(t, http.StatusConflict, refusal.Status)
		assert.Equal(t, "action_state", refusal.Code)
		require.NotNil(t, refusal.CurrentAction, "and sent the action as it held it")
		assert.Equal(t, review.ActionUncertain, refusal.CurrentAction.State)
		assert.Equal(t, applied.Executed[0].ID, refusal.CurrentAction.ID)
		assert.Equal(t, 1, refusal.CurrentAction.Attempt)
		assert.NotEmpty(t, refusal.CurrentAction.GrantID)
		// The review's own writes stored the interruption.
		assert.Equal(t, review.ActionUncertain, only(t, s.f).State)
		assert.Equal(t, 1, s.f.job().Checkpoint.Version)
		assert.Equal(t, 1, s.f.fx.count("notify"))
	})

	for name, change := range map[string]func(*review.Action){
		"another attempt": func(a *review.Action) { a.Attempt++ },
		"another action":  func(a *review.Action) { a.ID = "act_OTHER" },
		"another grant":   func(a *review.Action) { a.GrantID = "grt_other" },
		"another state":   func(a *review.Action) { a.State = review.ActionEscalated },
	} {
		t.Run("an account of "+name+" is not this attempt's record", func(t *testing.T) {
			s := start(t)
			timesOut(s.f, review.EffectUnknown, true)
			r := s.reviewer("tick-1")
			r.Registry = &watchSettle{Registry: s.f.remote, seen: func(err error) error {
				if te, ok := errors.AsType[*review.TransportError](err); ok && te.CurrentAction != nil {
					change(te.CurrentAction)
				}
				return err
			}}
			prepared, err := r.Prepare(ctx, s.f.jobID)
			require.NoError(t, err)
			_, err = r.Apply(ctx, prepared, s.notify)
			require.ErrorContains(t, err, "action_state")
			assert.Zero(t, s.f.job().Checkpoint.Version, "the review is not recorded")
			assert.Equal(t, 1, s.f.fx.count("notify"))
		})
	}

	t.Run("a read-only attempt that ran past its grant is closed as failed and reviewed", func(t *testing.T) {
		s := start(t)
		timesOut(s.f, review.EffectNotApplied, false)
		r := s.reviewer("tick-1")
		prepared, err := r.Prepare(ctx, s.f.jobID)
		require.NoError(t, err)
		applied, err := r.Apply(ctx, prepared, s.collect)
		require.NoError(t, err)
		assert.Equal(t, review.ActionFailed, applied.Executed[0].State)
		assert.Equal(t, review.ActionFailed, only(t, s.f).State)
		assert.Equal(t, 1, s.f.job().Checkpoint.Version)
	})

	t.Run("a record whose answer is lost is found written, receipt and all", func(t *testing.T) {
		s := start(t)
		lost := errors.New("read tcp: connection reset by peer")
		r := s.reviewer("tick-1")
		r.Registry = &watchSettle{Registry: s.f.remote, seen: func(err error) error {
			require.NoError(t, err, "the registry took the record")
			return lost
		}}
		prepared, err := r.Prepare(ctx, s.f.jobID)
		require.NoError(t, err)
		applied, err := r.Apply(ctx, prepared, s.notify)
		require.NoError(t, err)
		assert.Equal(t, review.ActionSucceeded, applied.Executed[0].State)
		held := only(t, s.f)
		assert.Equal(t, review.ActionSucceeded, held.State)
		assert.Equal(t, "receipt-notify", held.Receipt)
		assert.Equal(t, 1, s.f.job().Checkpoint.Version)
		assert.Equal(t, 1, s.f.fx.count("notify"))
	})

	t.Run("a record that was lost before it was written is an error and nothing runs again", func(t *testing.T) {
		s := start(t)
		lost := errors.New("write tcp: broken pipe")
		r := s.reviewer("tick-1")
		r.Registry = &watchSettle{Registry: s.f.remote, before: lost}
		prepared, err := r.Prepare(ctx, s.f.jobID)
		require.NoError(t, err)
		_, err = r.Apply(ctx, prepared, s.notify)
		require.ErrorIs(t, err, lost)
		assert.Equal(t, review.ActionExecuting, only(t, s.f).State)
		assert.Zero(t, s.f.job().Checkpoint.Version)

		// The next review finds the attempt interrupted, has no probe for
		// it, and asks the owner. The effect is not made again.
		*s.f.ahead += 2 * time.Hour
		next := s.reviewer("tick-2")
		recovered, err := next.Prepare(ctx, s.f.jobID)
		require.NoError(t, err)
		require.Empty(t, recovered.Skipped)
		assert.Equal(t, review.ActionEscalated, only(t, s.f).State)
		_, err = next.Apply(ctx, recovered, s.notify)
		require.NoError(t, err)
		assert.Equal(t, 1, s.f.fx.count("notify"), "the effect happened once")
	})
}

// watchSettle is a registry that shows a test what the real one answered to
// a record of an outcome, and lets it change or replace that answer. With
// before, the record is not sent at all.
type watchSettle struct {
	review.Registry
	seen   func(error) error
	before error
}

func (w *watchSettle) FinishAction(ctx context.Context, req review.FinishRequest) error {
	if w.before != nil {
		return w.before
	}
	return w.seen(w.Registry.FinishAction(ctx, req))
}

// A probe that cannot tell settles nothing, and one that finds nothing sends
// the attempt to the owner: against the real registry neither is recorded as
// done or as not applied, neither gets a receipt, and the effect is not made
// again.
func TestRemoteAProbeThatDoesNotFindTheEffectSettlesNothing(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		probe review.EffectResult
		want  review.ActionState
	}{
		"cannot tell":   {review.EffectResult{Status: review.EffectUnknown, Detail: "probe exited with code 1"}, review.ActionEscalated},
		"finds nothing": {review.EffectResult{Status: review.EffectNotApplied, Detail: "probe found no effect"}, review.ActionEscalated},
	} {
		t.Run(name, func(t *testing.T) {
			x := timedOutExport(t)
			probes := 0
			x.f.fx.probe = func(review.Action) review.EffectResult {
				probes++
				return tc.probe
			}
			r := x.reviewer("tick-2")
			prepared, err := r.Prepare(ctx, x.id)
			require.NoError(t, err)
			require.Empty(t, prepared.Skipped)
			assert.Equal(t, 1, probes)
			actions, err := x.f.remote.Actions(ctx, x.id)
			require.NoError(t, err)
			require.Len(t, actions, 1)
			assert.Equal(t, tc.want, actions[0].State)
			assert.Empty(t, actions[0].Receipt)
			assert.Equal(t, 1, x.f.fx.count("push_export"), "the effect happened once")
			job, err := x.f.store.GetJob(ctx, x.id)
			require.NoError(t, err)
			open := 0
			for _, p := range job.Proposals {
				if p.State == registry.ProposalOpen {
					open++
				}
			}
			assert.Equal(t, 1, open, "the owner is asked")
		})
	}
}
