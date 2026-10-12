package review_test

import (
	"context"
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

// A job declares how often it is reviewed as a cron expression, read in the
// timezone of its own schedule. A duration is read as one, and anything
// else is said to be unreadable instead of being taken for something.
func TestReadCadence(t *testing.T) {
	for name, tc := range map[string]struct {
		declared, timezone string
		seconds            int
		cron               string
		reason             string
	}{
		"a daily cron in the schedule's zone":  {declared: "0 9 * * *", timezone: "Australia/Perth", cron: "CRON_TZ=Australia/Perth 0 9 * * *"},
		"an annual cron":                       {declared: "0 0 1 1 *", timezone: "UTC", cron: "CRON_TZ=UTC 0 0 1 1 *"},
		"no zone given is UTC":                 {declared: "*/10 * * * *", cron: "CRON_TZ=UTC */10 * * * *"},
		"a cron that names its own zone":       {declared: "CRON_TZ=Asia/Tokyo 0 9 * * *", timezone: "Australia/Perth", cron: "CRON_TZ=Asia/Tokyo 0 9 * * *"},
		"a descriptor":                         {declared: "@daily", timezone: "Australia/Perth", cron: "CRON_TZ=Australia/Perth @daily"},
		"an interval descriptor takes no zone": {declared: "@every 30m", timezone: "Australia/Perth", cron: "@every 30m"},
		"extra spaces":                         {declared: "  0  9 * * *  ", timezone: "UTC", cron: "CRON_TZ=UTC 0 9 * * *"},
		"a duration":                           {declared: "1h", timezone: "Australia/Perth", seconds: 3600},
		"a compound duration":                  {declared: "1h30m", seconds: 5400},
		"nothing declared":                     {},
		"words":                                {declared: "every morning", timezone: "UTC", reason: "neither a cron expression nor a duration"},
		"too few fields":                       {declared: "0 9 * *", timezone: "UTC", reason: "neither a cron expression nor a duration"},
		"a field out of range":                 {declared: "0 25 * * *", timezone: "UTC", reason: "neither a cron expression nor a duration"},
		"a zero duration":                      {declared: "0s", reason: "not a positive duration"},
		"a negative duration":                  {declared: "-1h", reason: "not a positive duration"},
		"a zone that does not exist":           {declared: "0 9 * * *", timezone: "Mars/Olympus", reason: "cannot be read in the schedule's timezone"},
	} {
		t.Run(name, func(t *testing.T) {
			seconds, cron, reason := review.ReadCadence(tc.declared, tc.timezone)
			assert.Equal(t, tc.seconds, seconds)
			assert.Equal(t, tc.cron, cron)
			if tc.reason == "" {
				assert.Empty(t, reason)
			} else {
				assert.Contains(t, reason, tc.reason)
				assert.Contains(t, reason, tc.declared, "the reason quotes what was declared")
			}
		})
	}
}

// cadenceFixture is a job reviewed at a known instant with a given policy.
func cadenceFixture(t *testing.T, at time.Time, policy func(*review.ReviewPolicy)) *fixture {
	t.Helper()
	f := newFixture(t)
	f.clock.Advance(at.Sub(f.clock.Now()))
	job := fixtureJob()
	job.Review.CadenceSec = 0
	policy(&job.Review)
	require.NoError(t, f.registry.PutJob(job))
	return f
}

func cronPolicy(declared, timezone string) func(*review.ReviewPolicy) {
	return func(p *review.ReviewPolicy) {
		p.CadenceSec, p.Cadence, p.CadenceInvalid = review.ReadCadence(declared, timezone)
	}
}

// The next review of a job is the next occurrence of its declared cron in
// its schedule's timezone, not an hour later. Seen on the staging hub: a job
// with "0 9 * * *" in Australia/Perth, reviewed at 11:55Z, was set to be
// reviewed again at 12:55Z.
func TestNextReviewFollowsTheDeclaredCron(t *testing.T) {
	reviewed := time.Date(2026, 10, 12, 11, 55, 57, 0, time.UTC)
	next := func(t *testing.T, f *fixture, d review.AgentDecision) time.Time {
		t.Helper()
		f.apply("reviewer-a", f.prepare("reviewer-a"), d)
		return f.state().Checkpoints[jobID].NextReviewAt
	}
	carryOn := review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "fine"}

	t.Run("a daily cron gives the next 09:00 in the job's zone", func(t *testing.T) {
		f := cadenceFixture(t, reviewed, cronPolicy("0 9 * * *", "Australia/Perth"))
		assert.True(t, next(t, f, carryOn).Equal(time.Date(2026, 10, 13, 1, 0, 0, 0, time.UTC)), "09:00 in Perth is 01:00Z")
	})
	t.Run("the same cron in another zone gives that zone's 09:00", func(t *testing.T) {
		f := cadenceFixture(t, reviewed, cronPolicy("0 9 * * *", "UTC"))
		assert.True(t, next(t, f, carryOn).Equal(time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)))
	})
	t.Run("an annual cron gives the next 1 January in the job's zone", func(t *testing.T) {
		f := cadenceFixture(t, reviewed, cronPolicy("0 0 1 1 *", "Australia/Perth"))
		assert.True(t, next(t, f, carryOn).Equal(time.Date(2026, 12, 31, 16, 0, 0, 0, time.UTC)))
	})
	t.Run("a cron more frequent than an hour is followed too", func(t *testing.T) {
		f := cadenceFixture(t, reviewed, cronPolicy("*/10 * * * *", "UTC"))
		assert.True(t, next(t, f, carryOn).Equal(time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)))
	})
	t.Run("a duration is counted from the review", func(t *testing.T) {
		f := cadenceFixture(t, reviewed, cronPolicy("6h", "Australia/Perth"))
		assert.True(t, next(t, f, carryOn).Equal(reviewed.Add(6*time.Hour)))
	})

	t.Run("the agent may ask to look again sooner, never later", func(t *testing.T) {
		f := cadenceFixture(t, reviewed, cronPolicy("0 9 * * *", "Australia/Perth"))
		sooner := carryOn
		sooner.NextReviewAfterSec = 300
		assert.True(t, next(t, f, sooner).Equal(reviewed.Add(5*time.Minute)))

		f = cadenceFixture(t, reviewed, cronPolicy("0 9 * * *", "Australia/Perth"))
		later := carryOn
		later.NextReviewAfterSec = 7 * 24 * 3600
		assert.True(t, next(t, f, later).Equal(time.Date(2026, 10, 13, 1, 0, 0, 0, time.UTC)), "the cadence bounds it")
	})
	t.Run("the next review is never sooner than a minute", func(t *testing.T) {
		// Reviewed 20 seconds before the cron's next occurrence.
		f := cadenceFixture(t, time.Date(2026, 10, 13, 0, 59, 40, 0, time.UTC), cronPolicy("0 9 * * *", "Australia/Perth"))
		assert.True(t, next(t, f, carryOn).Equal(time.Date(2026, 10, 13, 1, 0, 40, 0, time.UTC)))

		f = cadenceFixture(t, reviewed, cronPolicy("0 9 * * *", "Australia/Perth"))
		hurry := carryOn
		hurry.NextReviewAfterSec = 5
		assert.True(t, next(t, f, hurry).Equal(reviewed.Add(time.Minute)))
	})

	t.Run("a job that cannot be reviewed is put off to the cron's next occurrence", func(t *testing.T) {
		f := cadenceFixture(t, reviewed, func(p *review.ReviewPolicy) {
			cronPolicy("0 9 * * *", "Australia/Perth")(p)
		})
		prepared := f.prepare("reviewer-a")
		require.NoError(t, f.reviewer("reviewer-a").Fail(context.Background(), prepared, &review.AgentFailure{Kind: review.ExceptionReviewerAuth, Message: "login expired"}))
		assert.True(t, f.state().Checkpoints[jobID].NextReviewAt.Equal(time.Date(2026, 10, 13, 1, 0, 0, 0, time.UTC)))
	})
}

// A cadence that is neither a cron expression nor a duration is not taken
// for one. The job is reviewed at the default interval, and the owner is
// told so in the place exceptions are read: once for that version of the
// job, and no longer once the job has a cadence that can be read.
func TestAnUnreadableCadenceIsSaidNotAssumed(t *testing.T) {
	reviewed := time.Date(2026, 10, 12, 11, 55, 57, 0, time.UTC)
	f := cadenceFixture(t, reviewed, cronPolicy("every morning", "Australia/Perth"))
	carryOn := review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "fine"}
	raised := func() (open, resolved int, message string) {
		for _, e := range f.state().Exceptions {
			if e.Kind != review.ExceptionCadenceInvalid {
				continue
			}
			message = e.Message
			if e.ResolvedAt == nil {
				open++
			} else {
				resolved++
			}
		}
		return open, resolved, message
	}

	f.apply("reviewer-a", f.prepare("reviewer-a"), carryOn)
	assert.True(t, f.state().Checkpoints[jobID].NextReviewAt.Equal(reviewed.Add(time.Hour)), "the default interval")
	open, resolved, message := raised()
	assert.Equal(t, 1, open)
	assert.Zero(t, resolved)
	assert.Contains(t, message, `"every morning"`)
	assert.Contains(t, message, "neither a cron expression nor a duration")
	assert.Contains(t, message, "reviewed every 1h0m0s")

	// The next review says nothing new about the same version.
	f.clock.Advance(time.Hour)
	f.apply("reviewer-b", f.prepare("reviewer-b"), carryOn)
	open, resolved, _ = raised()
	assert.Equal(t, 1, open)
	assert.Zero(t, resolved)

	// The owner corrects the cadence: it is followed, and the exception ends.
	job := fixtureJob()
	job.Version = 2
	cronPolicy("0 9 * * *", "Australia/Perth")(&job.Review)
	require.NoError(t, f.registry.PutJob(job))
	f.clock.Advance(time.Hour)
	f.apply("reviewer-c", f.prepare("reviewer-c"), carryOn)
	assert.True(t, f.state().Checkpoints[jobID].NextReviewAt.Equal(time.Date(2026, 10, 13, 1, 0, 0, 0, time.UTC)))
	open, _, _ = raised()
	assert.Zero(t, open)

	// A job whose cadence can be read never has the exception at all.
	clean := cadenceFixture(t, reviewed, cronPolicy("0 9 * * *", "Australia/Perth"))
	clean.apply("reviewer-a", clean.prepare("reviewer-a"), carryOn)
	for _, e := range clean.state().Exceptions {
		assert.NotEqual(t, review.ExceptionCadenceInvalid, e.Kind)
	}
}

// Against the real registry over its HTTP API: a job registered with a cron
// cadence and a schedule timezone is read as that cron in that zone, and its
// checkpoint's next review is the cron's next occurrence. One registered
// with an unreadable cadence gets the registry's exception for that version.
func TestRemoteReviewCadenceIsTheRegisteredCron(t *testing.T) {
	f := newRemoteFixture(t)
	ctx := context.Background()
	first := f.job()
	actor := &apigen.TxeActor{Kind: apigen.TxeActorKindCli, Id: "cc5-test"}
	register := func(n int, cadence string) string {
		t.Helper()
		id, err := registry.NewID(registry.PrefixJob, time.Now())
		require.NoError(t, err)
		digest, dir := fmt.Sprintf("sha256:%064x", 20+n), t.TempDir()
		spec := fmt.Sprintf("worker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/job%d.sh\n", first.MachineID, n)
		require.NoError(t, f.remote.Transport.Do(ctx, http.MethodPost, "/txe/jobs", apigen.TxeRegisterRequest{
			JobId: id, RequestId: fmt.Sprintf("cadence-%d", n), OwnerId: first.OwnerID, ProjectId: first.ProjectID, MachineId: first.MachineID,
			JobKey: fmt.Sprintf("cadence:%d", n),
			Version: apigen.TxeJobVersionInput{
				Title: "Daily check", Purpose: "Reviewed once a day in Perth.",
				Package:      apigen.TxePackage{Digest: digest, Path: dir, Entrypoint: "run.sh"},
				Dag:          apigen.TxeDAGRef{Spec: spec},
				Schedule:     &apigen.TxeSchedule{Cron: new("*/5 * * * *"), Timezone: new("Australia/Perth")},
				Targets:      &[]apigen.TxeTarget{{Kind: "fixture.volume", StableId: map[string]string{"cluster_uid": "c-1", "uid": fmt.Sprintf("cadence-%d", n)}}},
				ReviewPolicy: &apigen.TxeReviewPolicy{Brief: new("Check it."), Cadence: new(cadence)},
			},
			Actor: actor,
		}, nil))
		require.NoError(t, f.remote.Transport.Do(ctx, http.MethodPost, "/txe/jobs/"+id+"/ready", apigen.TxeReadyRequest{
			Package: apigen.TxePackageEvidence{Digest: digest, Path: dir, MachineId: first.MachineID}, Actor: actor,
		}, nil))
		return id
	}
	review1 := func(id, holder string) {
		t.Helper()
		r := f.reviewer(holder)
		prepared, err := r.Prepare(ctx, id)
		require.NoError(t, err)
		require.Empty(t, prepared.Skipped)
		_, err = r.Apply(ctx, prepared, review.AgentDecision{Outcome: review.OutcomeContinue, Reasoning: "fine"})
		require.NoError(t, err)
	}

	daily := register(1, "0 9 * * *")
	job, err := f.remote.Job(ctx, daily)
	require.NoError(t, err)
	assert.Equal(t, "CRON_TZ=Australia/Perth 0 9 * * *", job.Review.Cadence)
	assert.Zero(t, job.Review.CadenceSec)
	assert.Empty(t, job.Review.CadenceInvalid)

	before := time.Now()
	review1(daily, "tick-1")
	perth, err := time.LoadLocation("Australia/Perth")
	require.NoError(t, err)
	local := before.In(perth)
	want := time.Date(local.Year(), local.Month(), local.Day(), 9, 0, 0, 0, perth)
	if !want.After(before) {
		want = want.AddDate(0, 0, 1)
	}
	stored, err := f.store.GetJob(ctx, daily)
	require.NoError(t, err)
	require.NotNil(t, stored.Checkpoint.NextReviewAt)
	if until := want.Sub(before); until > 2*time.Minute {
		assert.True(t, stored.Checkpoint.NextReviewAt.Equal(want), "next review %s, want %s", stored.Checkpoint.NextReviewAt, want)
	}
	for _, e := range stored.Exceptions {
		assert.NotEqual(t, string(review.ExceptionCadenceInvalid), e.Kind)
	}

	// The fixture's own job keeps its duration.
	kept, err := f.remote.Job(ctx, f.jobID)
	require.NoError(t, err)
	assert.Equal(t, 3600, kept.Review.CadenceSec)
	assert.Empty(t, kept.Review.Cadence)

	words := register(2, "every morning")
	job, err = f.remote.Job(ctx, words)
	require.NoError(t, err)
	assert.Contains(t, job.Review.CadenceInvalid, `"every morning"`)
	before = time.Now()
	review1(words, "tick-2")
	review1Again := func() int {
		stored, err := f.store.GetJob(ctx, words)
		require.NoError(t, err)
		open := 0
		for _, e := range stored.Exceptions {
			if e.Kind == string(review.ExceptionCadenceInvalid) && e.ResolvedAt == nil {
				assert.Equal(t, registry.ScopeBinding, e.Scope)
				assert.Equal(t, 1, e.JobVersion)
				assert.Contains(t, e.Detail, "neither a cron expression nor a duration")
				open++
			}
		}
		return open
	}
	assert.Equal(t, 1, review1Again(), "the registry holds one open exception about this version")
	stored, err = f.store.GetJob(ctx, words)
	require.NoError(t, err)
	require.NotNil(t, stored.Checkpoint.NextReviewAt)
	assert.WithinDuration(t, before.Add(time.Hour), *stored.Checkpoint.NextReviewAt, time.Minute, "the default interval")
}
