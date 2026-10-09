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
	// ExitStop: do not run: a target is gone or replaced, or the job ended.
	ExitStop = 3
	// ExitUnobserved: a target could not be observed, a report could not be
	// saved, or (periodic) some targets were left for the next run.
	ExitUnobserved = 75
)

// Existence checks a target declares.
const (
	CheckPreRun    = "pre_run"
	CheckReconcile = "reconcile"
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
	Now func() time.Time
}

// Line is the JSON line a check prints for one target. It carries no
// credential value.
type Line struct {
	JobID         string   `json:"job_id,omitempty"`
	Target        Target   `json:"target"`
	Observation   Outcome  `json:"observation"`
	Authoritative bool     `json:"authoritative,omitempty"`
	Replacement   *Target  `json:"replacement,omitempty"`
	Detail        string   `json:"detail,omitempty"`
	EventID       string   `json:"event_id,omitempty"`
	Reported      bool     `json:"reported"`
	ReportError   string   `json:"report_error,omitempty"`
	Dispositions  []string `json:"dispositions,omitempty"`
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
	ev := Event{Target: t, Observation: r.Outcome, Authoritative: r.Outcome == Absent && r.Authoritative,
		Detail: r.Detail, Evidence: r.Evidence, ObservedAt: c.now().UTC(), Actor: c.actor()}
	if r.Observed != nil {
		ev.Target = *r.Observed
	}
	return ev
}

// report delivers ev, resending an undelivered report about the same
// target first so a lost acknowledgement never leaves an orphan event.
func (c *Check) report(ctx context.Context, ev Event) (*RecordedEvent, error) {
	if old, ok := c.Journal.pending(ev.Target); ok {
		if _, err := c.Registry.RecordEvent(ctx, old); err != nil {
			return nil, fmt.Errorf("resend undelivered report %s: %w", old.EventID, err)
		}
		c.Journal.delivered(old)
	}
	id, err := txeclient.NewID("evt")
	if err != nil {
		return nil, err
	}
	ev.EventID = id
	c.Journal.hold(ev)
	if err := c.Journal.Save(); err != nil {
		return nil, err
	}
	rec, err := c.Registry.RecordEvent(ctx, ev)
	if err != nil {
		return nil, err
	}
	c.Journal.delivered(ev)
	c.Journal.checked(ev.Target, c.now())
	return rec, nil
}

func (c *Check) observe(ctx context.Context, jobID string, t Target, creds Credentials) (Line, Result) {
	r := c.Probes.Probe(ctx, t, creds)
	line := Line{JobID: jobID, Target: t, Observation: r.Outcome, Authoritative: r.Outcome == Absent && r.Authoritative,
		Replacement: r.Observed, Detail: r.Detail}
	ev := c.event(t, r)
	rec, err := c.report(ctx, ev)
	if err != nil {
		line.ReportError = err.Error()
	} else {
		line.Reported, line.EventID = true, rec.EventID
		for _, d := range rec.Dispositions {
			line.Dispositions = append(line.Dispositions, d.JobID+":"+d.Outcome)
		}
	}
	if !line.Reported {
		line.EventID = ev.EventID
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

func toTarget(t txeclient.Target) Target {
	return Target{Kind: t.Kind, Environment: t.Environment, StableID: t.StableID, DisplayName: t.DisplayName}
}

// PreRun checks the pre_run targets of version of jobID before the job's
// command runs on machineID, and says whether it may run. It binds the
// version the run was rendered for, never a newer one. A job waiting for a
// person (needs_human) may still run its ordinary checks; only an ended
// job, or a target this check found gone, replaced or unobservable, stops
// the run.
func (c *Check) PreRun(ctx context.Context, jobID string, version int, creds Credentials) (int, error) {
	job, err := c.Registry.Job(ctx, jobID)
	if err != nil {
		return ExitUnobserved, fmt.Errorf("read job %s: %w", jobID, err)
	}
	if job.MachineID != c.MachineID {
		return ExitUsage, fmt.Errorf("job %s runs on %s, not on %s", jobID, job.MachineID, c.MachineID)
	}
	if terminal(job.Lifecycle) {
		return ExitStop, fmt.Errorf("job %s is %s", jobID, job.Lifecycle)
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
	if err := c.Journal.Save(); err != nil {
		return ExitUnobserved, err
	}
	if code != ExitOK {
		return code, nil
	}
	after, err := c.Registry.Job(ctx, jobID)
	if err != nil {
		return ExitUnobserved, fmt.Errorf("read job %s after the check: %w", jobID, err)
	}
	if terminal(after.Lifecycle) {
		return ExitStop, fmt.Errorf("job %s is %s", jobID, after.Lifecycle)
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
	Unfinished int `json:"unfinished"`
	Failed     int `json:"failed"`
}

// Periodic observes the reconcile targets of the machine's jobs and the
// targets of events this machine reported that are not complete, until the
// deadline. Targets it has waited longest to see go first, so a run cut
// short by slow targets resumes with the rest next time; what it did not
// reach is reported as unfinished.
func (c *Check) Periodic(ctx context.Context, deadline time.Time, credsFor func(*txeclient.JobVersion) Credentials) (PeriodicResult, int, error) {
	var res PeriodicResult
	for _, ev := range c.Journal.Undelivered() {
		if _, err := c.Registry.RecordEvent(ctx, ev); err != nil {
			return res, ExitUnobserved, fmt.Errorf("resend undelivered report %s: %w", ev.EventID, err)
		}
		c.Journal.delivered(ev)
	}
	jobs, err := c.Registry.ListJobs(ctx, txeclient.JobFilter{MachineID: c.MachineID})
	if err != nil {
		return res, ExitUnobserved, fmt.Errorf("list jobs of %s: %w", c.MachineID, err)
	}
	seen := map[string]bool{}
	var cands []candidate
	// byKey finds, for an incomplete event's target, a job of this machine
	// whose current version names it, for its credentials.
	byKey := map[string]candidate{}
	for _, job := range jobs {
		if terminal(job.Lifecycle) || job.MachineID != c.MachineID {
			continue
		}
		v, err := c.Registry.JobVersion(ctx, job.JobID, job.Version)
		if err != nil {
			return res, ExitUnobserved, fmt.Errorf("read version %d of job %s: %w", job.Version, job.JobID, err)
		}
		creds := credsFor(v)
		for _, t := range v.Targets {
			pt := toTarget(t)
			cand := candidate{jobID: job.JobID, target: pt, creds: creds}
			key := TargetKey(pt)
			if _, ok := byKey[key]; !ok {
				byKey[key] = cand
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
			if cand, ok := byKey[key]; ok && !seen[key] {
				seen[key] = true
				cands = append(cands, cand)
			}
		}
		if next == "" || len(events) == 0 {
			break
		}
		after = next
	}
	sort.SliceStable(cands, func(i, j int) bool {
		return c.Journal.LastChecked(cands[i].target).Before(c.Journal.LastChecked(cands[j].target))
	})
	for i, cand := range cands {
		if deadline.Sub(c.now()) < TargetTimeout {
			res.Unfinished = len(cands) - i
			break
		}
		line, _ := c.observe(ctx, cand.jobID, cand.target, cand.creds)
		if line.Reported {
			res.Observed++
		} else {
			res.Failed++
		}
	}
	if err := c.Journal.Save(); err != nil {
		return res, ExitUnobserved, err
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

// FileCredentials resolves a version's file credential references from the
// worker's disk. Environment references are not available to the periodic
// check, which carries no secrets in its DAG.
type FileCredentials map[string]string

// FileCredentialsOf returns the file references of v.
func FileCredentialsOf(v *txeclient.JobVersion) Credentials {
	out := FileCredentials{}
	missing := map[string]string{}
	for _, ref := range v.Package.CredentialRefs {
		switch ref.Kind {
		case "file":
			out[ref.Name] = ref.Locator
		default:
			missing[ref.Name] = "credential reference " + ref.Name + " is an environment variable, which the periodic check does not receive"
		}
	}
	return explained{out, missing}
}

// Lookup returns the file reference's path.
func (f FileCredentials) Lookup(name string) (Credential, bool) {
	p, ok := f[name]
	return Credential{Path: p}, ok && p != ""
}

// explained adds why a reference is missing to a Credentials.
type explained struct {
	Credentials
	missing map[string]string
}

func (e explained) MissingReason(name string) string { return e.missing[name] }
