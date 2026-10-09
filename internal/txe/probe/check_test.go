// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
)

const (
	mch    = "mch_01JTXE0000000000000000F1X3"
	other  = "mch_01JTXE0000000000000000ZZZZ"
	jobA   = "job_01JTXE00000000000000000AAA"
	jobB   = "job_01JTXE00000000000000000BBB"
	kindCM = "kubernetes.configmap"
)

func cm(uid, name string, check string) txeclient.Target {
	return txeclient.Target{Kind: kindCM, Environment: "dev", DisplayName: "ns/" + name,
		StableID: map[string]string{KeyClusterUID: "c1", KeyUID: uid}, ExistenceCheck: check}
}

// fakeRegistry is the registry as a check sees it.
type fakeRegistry struct {
	jobs       map[string]*txeclient.Job
	versions   map[string]map[int]*txeclient.JobVersion
	recorded   []Event
	failRecord int // fail the next n RecordEvent calls
	incomplete []RecordedEvent
	// afterRecord changes a job once an event is recorded, as the registry's
	// rules would (for example retiring it).
	afterRecord func(Event)
}

func (f *fakeRegistry) Job(_ context.Context, id string) (*txeclient.Job, error) {
	j, ok := f.jobs[id]
	if !ok {
		return nil, errors.New("not found")
	}
	cp := *j
	return &cp, nil
}

func (f *fakeRegistry) JobVersion(_ context.Context, id string, v int) (*txeclient.JobVersion, error) {
	if ver, ok := f.versions[id][v]; ok {
		return ver, nil
	}
	return nil, errors.New("no such version")
}

func (f *fakeRegistry) ListJobs(_ context.Context, filter txeclient.JobFilter) ([]txeclient.Job, error) {
	var out []txeclient.Job
	for _, id := range []string{jobA, jobB} {
		if j, ok := f.jobs[id]; ok && (filter.MachineID == "" || j.MachineID == filter.MachineID) {
			out = append(out, *j)
		}
	}
	return out, nil
}

func (f *fakeRegistry) RecordEvent(_ context.Context, ev Event) (*RecordedEvent, error) {
	if f.failRecord > 0 {
		f.failRecord--
		return nil, errors.New("hub unreachable")
	}
	f.recorded = append(f.recorded, ev)
	if f.afterRecord != nil {
		f.afterRecord(ev)
	}
	return &RecordedEvent{EventID: ev.EventID, Target: ev.Target, Observation: ev.Observation, Complete: true}, nil
}

func (f *fakeRegistry) IncompleteEvents(_ context.Context, machine, _ string, _ int) ([]RecordedEvent, string, error) {
	if machine != mch {
		return nil, "", errors.New("wrong machine")
	}
	return f.incomplete, "", nil
}

// scripted answers each target's probe from a table keyed by uid, and can
// advance the clock to model a slow target.
type scripted struct {
	results map[string]Result
	clock   *time.Time
	cost    map[string]time.Duration
	probed  []string
}

func (s *scripted) Supports(kind string) bool { return kind == kindCM }
func (s *scripted) Probe(_ context.Context, t Target, _ Credentials) Result {
	uid := t.StableID[KeyUID]
	s.probed = append(s.probed, uid)
	if d := s.cost[uid]; d > 0 && s.clock != nil {
		*s.clock = s.clock.Add(d)
	}
	if r, ok := s.results[uid]; ok {
		return r
	}
	return Result{Outcome: Present}
}

type fixture struct {
	reg   *fakeRegistry
	probe *scripted
	check *Check
	out   *bytes.Buffer
	now   time.Time
	path  string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{now: time.Date(2026, 10, 10, 3, 0, 0, 0, time.UTC), out: &bytes.Buffer{}}
	f.path = filepath.Join(t.TempDir(), "journal.json")
	f.reg = &fakeRegistry{
		jobs: map[string]*txeclient.Job{
			jobA: {JobID: jobA, MachineID: mch, Version: 2, Lifecycle: "active"},
		},
		versions: map[string]map[int]*txeclient.JobVersion{jobA: {
			1: {Version: 1, Targets: []txeclient.Target{cm("old-1", "old", CheckPreRun)}},
			2: {Version: 2, Targets: []txeclient.Target{cm("u-1", "one", CheckPreRun), cm("u-2", "two", CheckReconcile), cm("u-3", "three", "event_only")}},
		}},
	}
	f.probe = &scripted{results: map[string]Result{}, clock: &f.now, cost: map[string]time.Duration{}}
	f.check = f.newCheck(t)
	return f
}

func (f *fixture) newCheck(t *testing.T) *Check {
	t.Helper()
	j, err := OpenJournal(f.path)
	if err != nil {
		t.Fatal(err)
	}
	return &Check{Registry: f.reg, Probes: Probes{f.probe}, Journal: j, MachineID: mch, Client: "test", Out: f.out,
		Now: func() time.Time { return f.now }}
}

func (f *fixture) preRun(t *testing.T, version int) int {
	t.Helper()
	code, err := f.check.PreRun(context.Background(), jobA, version, credMap{})
	if code == ExitOK && err != nil {
		t.Fatalf("exit 0 with error %v", err)
	}
	return code
}

// The pre-run check observes only the pre_run targets of the version the
// run was rendered for, reports each as the machine's reconciler, and lets
// the job run when all are present.
func TestPreRunPresentRuns(t *testing.T) {
	f := newFixture(t)
	if code := f.preRun(t, 2); code != ExitOK {
		t.Fatalf("exit = %d, want 0", code)
	}
	if strings.Join(f.probe.probed, ",") != "u-1" {
		t.Fatalf("probed %v, want only the pre_run target", f.probe.probed)
	}
	if len(f.reg.recorded) != 1 {
		t.Fatalf("recorded %d events", len(f.reg.recorded))
	}
	ev := f.reg.recorded[0]
	if ev.Observation != Present || ev.Actor.Kind != ActorKindReconciler || ev.Actor.MachineID != mch || !strings.HasPrefix(ev.EventID, "evt_") {
		t.Fatalf("event = %+v", ev)
	}
	var line Line
	if err := json.Unmarshal(bytes.TrimSpace(f.out.Bytes()), &line); err != nil || !line.Reported || line.JobID != jobA {
		t.Fatalf("output line %q: %v", f.out.String(), err)
	}
}

// An old run binds the version it was rendered for, not the job's current one.
func TestPreRunBindsTheRenderedVersion(t *testing.T) {
	f := newFixture(t)
	f.preRun(t, 1)
	if strings.Join(f.probe.probed, ",") != "old-1" {
		t.Fatalf("probed %v, want version 1's target", f.probe.probed)
	}
}

func TestPreRunRefusesAnotherMachine(t *testing.T) {
	f := newFixture(t)
	f.reg.jobs[jobA].MachineID = other
	if code := f.preRun(t, 2); code != ExitUsage || len(f.probe.probed) != 0 {
		t.Fatalf("exit = %d, probed %v", code, f.probe.probed)
	}
}

// A job waiting for a person still runs its ordinary checks; an ended job
// does not run.
func TestPreRunLifecycle(t *testing.T) {
	f := newFixture(t)
	f.reg.jobs[jobA].Lifecycle = "needs_human"
	if code := f.preRun(t, 2); code != ExitOK {
		t.Fatalf("needs_human: exit = %d, want 0", code)
	}
	// The gate is an allowlist: paused, ended or unknown states stop.
	for _, l := range []string{"retired", "completed", "paused", "", "some_future_state"} {
		f.reg.jobs[jobA].Lifecycle = l
		if code := f.preRun(t, 2); code != ExitStop {
			t.Fatalf("%s: exit = %d, want 3", l, code)
		}
	}
}

func TestPreRunOutcomes(t *testing.T) {
	for name, tc := range map[string]struct {
		result Result
		want   int
	}{
		"absent authoritative": {Result{Outcome: Absent, Authoritative: true}, ExitStop},
		"replacement":          {Result{Outcome: Present, Observed: &Target{Kind: kindCM, DisplayName: "ns/one", StableID: map[string]string{KeyClusterUID: "c1", KeyUID: "u-9"}}}, ExitStop},
		"unreachable":          {Result{Outcome: Unreachable}, ExitUnobserved},
		"auth denied":          {Result{Outcome: AuthDenied}, ExitUnobserved},
		"timeout":              {Result{Outcome: Timeout}, ExitUnobserved},
		"unknown":              {Result{Outcome: Unknown}, ExitUnobserved},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.probe.results["u-1"] = tc.result
			if code := f.preRun(t, 2); code != tc.want {
				t.Fatalf("exit = %d, want %d", code, tc.want)
			}
			ev := f.reg.recorded[0]
			if ev.Authoritative != (tc.result.Outcome == Absent) {
				t.Fatalf("authoritative = %v", ev.Authoritative)
			}
			// A replacement is reported as the new identity only.
			if tc.result.Observed != nil && (len(f.reg.recorded) != 1 || ev.Target.StableID[KeyUID] != "u-9" || ev.Observation != Present) {
				t.Fatalf("replacement reported as %+v", f.reg.recorded)
			}
		})
	}
}

// When the registry's rules end the job because of the report, the run
// stops even though the probe saw the target.
func TestPreRunStopsWhenTheReportEndsTheJob(t *testing.T) {
	f := newFixture(t)
	f.reg.afterRecord = func(Event) { f.reg.jobs[jobA].Lifecycle = "retired" }
	if code := f.preRun(t, 2); code != ExitStop {
		t.Fatalf("exit = %d, want 3", code)
	}
}

// A report the hub did not acknowledge stops the run, stays in the journal
// and is resent unchanged, under its event id, before the next report.
func TestUndeliveredReportIsResentUnchanged(t *testing.T) {
	f := newFixture(t)
	f.reg.failRecord = 1
	if code := f.preRun(t, 2); code != ExitUnobserved {
		t.Fatalf("exit = %d, want 75", code)
	}
	if len(f.reg.recorded) != 0 {
		t.Fatal("an unacknowledged report was counted")
	}
	j, _ := OpenJournal(f.path)
	held := j.Undelivered()
	if len(held) != 1 || !strings.HasPrefix(held[0].EventID, "evt_") {
		t.Fatalf("journal holds %+v", held)
	}
	f.check = f.newCheck(t)
	if code := f.preRun(t, 2); code != ExitOK {
		t.Fatalf("second run exit = %d", code)
	}
	if len(f.reg.recorded) != 2 || f.reg.recorded[0].EventID != held[0].EventID || f.reg.recorded[1].EventID == held[0].EventID {
		t.Fatalf("recorded %+v; want the held report first, then a new one", f.reg.recorded)
	}
	if j, _ := OpenJournal(f.path); len(j.Undelivered()) != 0 {
		t.Fatal("delivered report still held")
	}
}

// The periodic check covers the machine's reconcile targets and the targets
// of its incomplete events, and nothing of other machines or ended jobs.
func TestPeriodicScope(t *testing.T) {
	f := newFixture(t)
	f.reg.jobs[jobB] = &txeclient.Job{JobID: jobB, MachineID: other, Version: 1, Lifecycle: "active"}
	f.reg.versions[jobB] = map[int]*txeclient.JobVersion{1: {Targets: []txeclient.Target{cm("b-1", "b", CheckReconcile)}}}
	// An incomplete event about the pre_run target is observed again.
	pre := cm("u-1", "one", CheckPreRun)
	f.reg.incomplete = []RecordedEvent{{EventID: "evt_x", Target: toTarget(pre), Observation: Unreachable}}
	res, code, err := f.check.Periodic(context.Background(), f.now.Add(time.Hour), noCreds)
	if err != nil || code != ExitOK {
		t.Fatalf("exit = %d, %v", code, err)
	}
	got := strings.Join(f.probe.probed, ",")
	if got != "u-2,u-1" && got != "u-1,u-2" {
		t.Fatalf("probed %s, want the reconcile target and the incomplete event's target", got)
	}
	if res.Observed != 2 || res.Unfinished != 0 {
		t.Fatalf("result = %+v", res)
	}
	f.reg.jobs[jobA].Lifecycle = "retired"
	f.probe.probed = nil
	if _, _, err := f.check.Periodic(context.Background(), f.now.Add(time.Hour), noCreds); err != nil || len(f.probe.probed) != 0 {
		t.Fatalf("an ended job's targets were probed: %v %v", f.probe.probed, err)
	}
}

// A slow first target cannot starve the rest: what the deadline cut off is
// reported unfinished and goes first next time.
func TestPeriodicSlowTargetDoesNotStarveTheRest(t *testing.T) {
	f := newFixture(t)
	f.reg.versions[jobA][2].Targets = []txeclient.Target{cm("slow", "slow", CheckReconcile), cm("fast", "fast", CheckReconcile)}
	f.probe.cost["slow"] = 30 * time.Second
	f.probe.results["slow"] = Result{Outcome: Timeout}
	res, code, _ := f.check.Periodic(context.Background(), f.now.Add(45*time.Second), noCreds)
	if code != ExitUnobserved || res.Unfinished != 1 || strings.Join(f.probe.probed, ",") != "slow" {
		t.Fatalf("first run: exit %d, %+v, probed %v", code, res, f.probe.probed)
	}
	f.check = f.newCheck(t)
	f.probe.probed = nil
	res, code, _ = f.check.Periodic(context.Background(), f.now.Add(45*time.Second), noCreds)
	if len(f.probe.probed) == 0 || f.probe.probed[0] != "fast" {
		t.Fatalf("second run probed %v first, want the target the first run did not reach", f.probe.probed)
	}
	// With the slow target last, both fit in the second run's budget.
	if code != ExitOK || res.Unfinished != 0 || strings.Join(f.probe.probed, ",") != "fast,slow" {
		t.Fatalf("second run: exit %d, %+v, probed %v", code, res, f.probe.probed)
	}
}

// The pre-run check reads a reference the way the worker hands it to the
// step: a variable named after it.
func TestEnvCredentials(t *testing.T) {
	env := map[string]string{KubernetesCredential: "apiVersion: v1", LinearCredential: ""}
	creds := EnvCredentials{Env: func(k string) (string, bool) { v, ok := env[k]; return v, ok }}
	if c, ok := creds.Lookup(KubernetesCredential); !ok || c.Value != "apiVersion: v1" {
		t.Fatalf("kubernetes = %+v %v", c, ok)
	}
	if _, ok := creds.Lookup(LinearCredential); ok {
		t.Fatal("an empty variable counted as a credential")
	}
}

func noCreds(string, int) Credentials { return credMap{} }
