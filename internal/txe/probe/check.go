// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	"github.com/dagucloud/dagu/v2/internal/txe/target"
)

// Exit codes of `dagu txe resource check`. A non-zero exit of the pre-run
// check stops the job's run before the job's own command.
const (
	// ExitOK: the job may run (pre-run), or every observation was reported
	// (periodic).
	ExitOK = 0
	// ExitInternal: the check itself failed.
	ExitInternal = 1
	// ExitUsage: the arguments are wrong or do not bind (another machine).
	ExitUsage = 2
	// ExitStop: do not run: a target is gone or replaced, or the registry
	// would not admit the run.
	ExitStop = 3
	// ExitUnobserved: a target could not be observed, a report could not be
	// saved, or (periodic) some work was left for the next run.
	ExitUnobserved = 75
)

// Existence checks a target declares.
const (
	CheckPreRun    = target.CheckPreRun
	CheckReconcile = target.CheckReconcile
)

// ActorKindReconciler is the reporter kind of a check's resource events.
const ActorKindReconciler = "reconciler"

// Check observes targets and reports what it saw to the registry.
type Check struct {
	Registry Registry
	Probes   Probes
	Journal  *Journal
	// MachineID is the machine the check runs on and reports from.
	MachineID string
	// Client describes the CLI build, for the reporter actor.
	Client string
	// Out receives one JSON line per observed target.
	Out io.Writer
	// Evidence is added to every report, such as the run execution a
	// pre-run check belongs to.
	Evidence []string
	Now      func() time.Time
}

// Line is the JSON line a check prints for one target. It carries no
// credential value.
type Line struct {
	JobID         string   `json:"job_id,omitempty"`
	Target        Target   `json:"target"`
	Observation   Outcome  `json:"observation,omitempty"`
	Authoritative bool     `json:"authoritative,omitempty"`
	Replacement   *Target  `json:"replacement,omitempty"`
	Detail        string   `json:"detail,omitempty"`
	EventID       string   `json:"event_id,omitempty"`
	Reported      bool     `json:"reported"`
	ReportError   string   `json:"report_error,omitempty"`
	Dispositions  []string `json:"dispositions,omitempty"`
	// Resent marks a report delivered again from the journal.
	Resent bool `json:"resent,omitempty"`
	// Unfinished marks work this check did not do and the next one will.
	Unfinished bool `json:"unfinished,omitempty"`
}

func (c *Check) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Check) actor() *txeclient.Actor {
	return &txeclient.Actor{Kind: ActorKindReconciler, ID: "txe-probe", MachineID: c.MachineID, Client: c.Client}
}

// event turns one observation into the report the registry receives. A
// replacement is reported as the new identity being present; the old
// identity is not also reported absent, so the registry applies the job's
// replacement rule and not its deletion rule.
func (c *Check) event(t Target, r Result) Event {
	evidence := append(append([]string{}, r.Evidence...), c.Evidence...)
	ev := Event{Target: t, Observation: r.Outcome, Authoritative: r.Outcome == Absent && r.Authoritative,
		Detail: r.Detail, Evidence: evidence, ObservedAt: c.now().UTC(), Actor: c.actor()}
	if r.Observed != nil {
		ev.Target = *r.Observed
	}
	return ev
}

// report holds ev in the journal, sends it, and on acknowledgement drops it
// and records the requested target as observed.
func (c *Check) report(ctx context.Context, jobID string, requested Target, ev Event) (*RecordedEvent, error) {
	id, err := txeclient.NewID("evt")
	if err != nil {
		return nil, err
	}
	ev.EventID = id
	p := pendingReport{JobID: jobID, Key: TargetKey(requested), Event: ev}
	if err := c.Journal.hold(ctx, p); err != nil {
		return nil, err
	}
	rec, err := c.Registry.RecordEvent(ctx, ev)
	if err != nil {
		return nil, err
	}
	if err := c.Journal.delivered(ctx, p, c.now()); err != nil {
		return rec, err
	}
	return rec, nil
}

// replay resends the journal's unacknowledged reports unchanged, under
// their event ids; with a job id, only that job's. It reports how many could
// not be delivered.
func (c *Check) replay(ctx context.Context, jobID string) (int, error) {
	pending, err := c.Journal.pending(ctx, jobID)
	if err != nil {
		return 0, err
	}
	failed := 0
	for _, p := range pending {
		line := Line{JobID: p.JobID, Target: p.Event.Target, Observation: p.Event.Observation, EventID: p.Event.EventID, Resent: true}
		rec, err := c.Registry.RecordEvent(ctx, p.Event)
		if err == nil {
			err = c.Journal.delivered(ctx, p, c.now())
		}
		if err != nil {
			failed++
			line.ReportError = err.Error()
		} else {
			line.Reported = true
			for _, d := range rec.Dispositions {
				line.Dispositions = append(line.Dispositions, d.JobID+":"+d.Outcome)
			}
		}
		c.print(line)
	}
	return failed, nil
}

func (c *Check) observe(ctx context.Context, jobID string, t Target, creds Credentials) (Line, Result) {
	r := c.Probes.Probe(ctx, t, creds)
	line := Line{JobID: jobID, Target: t, Observation: r.Outcome, Authoritative: r.Outcome == Absent && r.Authoritative,
		Replacement: r.Observed, Detail: r.Detail}
	ev := c.event(t, r)
	rec, err := c.report(ctx, jobID, t, ev)
	if err != nil {
		line.ReportError = err.Error()
	} else {
		line.Reported, line.EventID = true, rec.EventID
		for _, d := range rec.Dispositions {
			line.Dispositions = append(line.Dispositions, d.JobID+":"+d.Outcome)
		}
	}
	c.print(line)
	return line, r
}

func (c *Check) print(line Line) {
	if c.Out == nil {
		return
	}
	b, _ := json.Marshal(line)
	_, _ = fmt.Fprintln(c.Out, string(b))
}

func terminal(lifecycle string) bool { return lifecycle == "completed" || lifecycle == "retired" }

// admits mirrors the registry's run admission for a run rendered for
// version: the lifecycle must be active or needs_human (an allowlist, so a
// paused or ended job, or a state this build does not know, stops); the
// job must not have expired, its registration must be ready, and the
// version the run was rendered for must still be the job's. A job waiting
// for a person, or a target's availability, never stops it here.
func admits(job *txeclient.Job, version int, now time.Time) error {
	switch {
	case job.Lifecycle != "active" && job.Lifecycle != "needs_human":
		return fmt.Errorf("job %s is %s", job.JobID, job.Lifecycle)
	case job.ExpiresAt != nil && !now.Before(*job.ExpiresAt):
		return fmt.Errorf("job %s expired at %s", job.JobID, job.ExpiresAt.UTC().Format(time.RFC3339))
	case job.Registration.State != "ready":
		return fmt.Errorf("job %s registration is %q, not ready", job.JobID, job.Registration.State)
	case job.Version != version:
		return fmt.Errorf("job %s is at version %d; this run was rendered for version %d", job.JobID, job.Version, version)
	}
	return nil
}

func toTarget(t txeclient.Target) Target {
	return Target{Kind: t.Kind, Environment: t.Environment, StableID: t.StableID, DisplayName: t.DisplayName}
}

// PreRun checks the pre_run targets of version of jobID before the job's
// command runs on machineID, and says whether it may run. It binds the
// version the run was rendered for, never a newer one. It first resends the
// job's unacknowledged reports, whatever its targets and state now. It stops
// (3) where the registry's run admission would refuse, and where a target is
// gone or replaced; it stops (75) when a target could not be observed or a
// report could not be saved. A job waiting for a person (needs_human) runs.
func (c *Check) PreRun(ctx context.Context, jobID string, version int, creds Credentials) (int, error) {
	job, err := c.Registry.Job(ctx, jobID)
	if err != nil {
		return ExitUnobserved, fmt.Errorf("read job %s: %w", jobID, err)
	}
	if job.MachineID != c.MachineID {
		return ExitUsage, fmt.Errorf("job %s runs on %s, not on %s", jobID, job.MachineID, c.MachineID)
	}
	failed, err := c.replay(ctx, jobID)
	if err != nil {
		return ExitUnobserved, err
	}
	if err := admits(job, version, c.now()); err != nil {
		return ExitStop, err
	}
	if failed > 0 {
		return ExitUnobserved, fmt.Errorf("%d earlier reports for job %s could not be delivered", failed, jobID)
	}
	v, err := c.Registry.JobVersion(ctx, jobID, version)
	if err != nil {
		return ExitUnobserved, fmt.Errorf("read version %d of job %s: %w", version, jobID, err)
	}
	code := ExitOK
	worse := func(n int) {
		if rank(n) > rank(code) {
			code = n
		}
	}
	for _, t := range v.Targets {
		if t.ExistenceCheck != CheckPreRun {
			continue
		}
		line, r := c.observe(ctx, jobID, toTarget(t), creds)
		switch {
		case !line.Reported:
			worse(ExitUnobserved)
		case r.Outcome == Absent && r.Authoritative, r.Observed != nil:
			worse(ExitStop)
		case r.Outcome != Present:
			worse(ExitUnobserved)
		}
	}
	if code != ExitOK {
		return code, nil
	}
	after, err := c.Registry.Job(ctx, jobID)
	if err != nil {
		return ExitUnobserved, fmt.Errorf("read job %s after the check: %w", jobID, err)
	}
	if err := admits(after, version, c.now()); err != nil {
		return ExitStop, err
	}
	return ExitOK, nil
}

// rank orders exit codes by how strongly they stop a run.
func rank(code int) int {
	switch code {
	case ExitOK:
		return 0
	case ExitUnobserved:
		return 1
	case ExitStop:
		return 2
	}
	return 3
}

// candidate is one target a periodic check may observe, with the job whose
// credentials it is observed with.
type candidate struct {
	jobID  string
	target Target
	creds  Credentials
}

// PeriodicResult summarises one periodic run.
type PeriodicResult struct {
	Observed   int `json:"observed"`
	Resent     int `json:"resent"`
	Unfinished int `json:"unfinished"`
	Failed     int `json:"failed"`
}

// Periodic resends every unacknowledged report, then observes the
// reconcile targets of the machine's jobs and the targets of the incomplete
// events this machine reported, until the deadline. Targets it has waited
// longest to see go first, so a run cut short by slow targets resumes with
// the rest next time. An incomplete event whose target no job of the
// machine names, by identity or as a replacement of a target's name, cannot
// be observed with any credential here and is reported unfinished, as is
// whatever the deadline cut off.
func (c *Check) Periodic(ctx context.Context, deadline time.Time, credsFor func(jobID string, version int) Credentials) (PeriodicResult, int, error) {
	var res PeriodicResult
	pendingBefore, err := c.Journal.pending(ctx, "")
	if err != nil {
		return res, ExitUnobserved, err
	}
	failed, err := c.replay(ctx, "")
	if err != nil {
		return res, ExitUnobserved, err
	}
	res.Resent, res.Failed = len(pendingBefore)-failed, failed
	jobs, err := c.Registry.ListJobs(ctx, txeclient.JobFilter{MachineID: c.MachineID})
	if err != nil {
		return res, ExitUnobserved, fmt.Errorf("list jobs of %s: %w", c.MachineID, err)
	}
	seen := map[string]bool{}
	var cands []candidate
	// byKey and byName find, for an incomplete event's target, a job of this
	// machine that names it, or names its place (a replacement), for its
	// credentials.
	byKey, byName := map[string]candidate{}, map[string]candidate{}
	for _, job := range jobs {
		if terminal(job.Lifecycle) || job.MachineID != c.MachineID {
			continue
		}
		v, err := c.Registry.JobVersion(ctx, job.JobID, job.Version)
		if err != nil {
			return res, ExitUnobserved, fmt.Errorf("read version %d of job %s: %w", job.Version, job.JobID, err)
		}
		creds := credsFor(job.JobID, job.Version)
		for _, t := range v.Targets {
			pt := toTarget(t)
			cand := candidate{jobID: job.JobID, target: pt, creds: creds}
			key := TargetKey(pt)
			if _, ok := byKey[key]; !ok {
				byKey[key] = cand
			}
			if _, ok := byName[nameKey(pt)]; !ok && pt.DisplayName != "" {
				byName[nameKey(pt)] = cand
			}
			if t.ExistenceCheck == CheckReconcile && !seen[key] {
				seen[key] = true
				cands = append(cands, cand)
			}
		}
	}
	after := ""
	for {
		events, next, err := c.Registry.IncompleteEvents(ctx, c.MachineID, after, 200)
		if err != nil {
			return res, ExitUnobserved, fmt.Errorf("list incomplete events of %s: %w", c.MachineID, err)
		}
		for _, ev := range events {
			key := TargetKey(ev.Target)
			if seen[key] {
				continue
			}
			seen[key] = true
			if cand, ok := byKey[key]; ok {
				cands = append(cands, cand)
				continue
			}
			if cand, ok := byName[nameKey(ev.Target)]; ok && ev.Target.DisplayName != "" {
				cands = append(cands, candidate{jobID: cand.jobID, target: ev.Target, creds: cand.creds})
				continue
			}
			res.Unfinished++
			c.print(Line{Target: ev.Target, EventID: ev.EventID, Unfinished: true,
				Detail: "incomplete event about a target no job of this machine names; nothing here can observe it"})
		}
		if next == "" || len(events) == 0 {
			break
		}
		after = next
	}
	checked, err := c.Journal.lastChecked(ctx)
	if err != nil {
		return res, ExitUnobserved, err
	}
	sort.SliceStable(cands, func(i, j int) bool {
		return checked[TargetKey(cands[i].target)].Before(checked[TargetKey(cands[j].target)])
	})
	for i, cand := range cands {
		if deadline.Sub(c.now()) < TargetTimeout {
			res.Unfinished += len(cands) - i
			for _, left := range cands[i:] {
				c.print(Line{JobID: left.jobID, Target: left.target, Unfinished: true, Detail: "not reached before the deadline; first next time"})
			}
			break
		}
		line, _ := c.observe(ctx, cand.jobID, cand.target, cand.creds)
		if line.Reported {
			res.Observed++
		} else {
			res.Failed++
		}
	}
	if res.Unfinished > 0 || res.Failed > 0 {
		return res, ExitUnobserved, nil
	}
	return res, ExitOK, nil
}

// EnvCredentials resolves credential references the way a job's run
// receives them: the worker resolves each declared reference and the step
// gets it as a variable named after the reference.
type EnvCredentials struct {
	// Env defaults to os.LookupEnv.
	Env func(string) (string, bool)
}

// Lookup returns the reference's resolved value.
func (e EnvCredentials) Lookup(name string) (Credential, bool) {
	lookup := e.Env
	if lookup == nil {
		lookup = os.LookupEnv
	}
	v, ok := lookup(name)
	if !ok || v == "" {
		return Credential{}, false
	}
	return Credential{Value: v}, true
}
