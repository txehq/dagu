// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/dagucloud/dagu/v2/internal/persis"
)

// Index layout, create-only. An entry only says "this job may depend on
// this resource"; evaluation always re-reads the job's current version.
//
//	resource_ids/<target key>/<job>     exact stable identity
//	resource_names/<name key>/<job>     same kind, environment and display name
//	resource_events/<evt>               every reported resource event
const (
	resourceIDsPrefix    = "resource_ids/"
	resourceNamesPrefix  = "resource_names/"
	resourceEventsPrefix = "resource_events/"
)

func targetKeyHex(t Target) string {
	return strings.TrimPrefix(TargetKey(t), "sha256:")
}

func nameKeyHex(kind, environment, displayName string) string {
	b, _ := CanonicalJSON([]string{kind, environment, displayName})
	return strings.TrimPrefix(sha256Hex(b), "sha256:")
}

type indexEntry struct {
	JobID string `json:"job_id"`
}

type indexReady struct {
	At time.Time `json:"at"`
}

// indexTargets records which resources a job version depends on.
func (s *Store) indexTargets(ctx context.Context, jobID string, targets []Target) error {
	for _, t := range targets {
		ids := []string{resourceIDsPrefix + targetKeyHex(t) + "/" + jobID}
		if t.DisplayName != "" {
			ids = append(ids, resourceNamesPrefix+nameKeyHex(t.Kind, t.Environment, t.DisplayName)+"/"+jobID)
		}
		for _, id := range ids {
			if err := s.createJSON(ctx, id, indexEntry{JobID: jobID}); err != nil && !errors.Is(err, persis.ErrConflict) {
				return fmt.Errorf("registry: index target of %s: %w", jobID, err)
			}
		}
	}
	return nil
}

func (s *Store) indexedJobs(ctx context.Context, prefix string) ([]string, error) {
	var out []string
	cursor := ""
	for {
		page, err := s.col.List(ctx, persis.ListQuery{Prefix: prefix, Cursor: cursor, Limit: 500})
		if err != nil {
			return nil, err
		}
		for _, rec := range page.Records {
			out = append(out, rec.ID[strings.LastIndex(rec.ID, "/")+1:])
		}
		if page.NextCursor == "" {
			sort.Strings(out)
			return out, nil
		}
		cursor = page.NextCursor
	}
}

// ResourceObservation is what a reporter saw of a resource.
type ResourceObservation string

const (
	ResourceDeleted     ResourceObservation = "deleted"
	ResourceAbsent      ResourceObservation = "absent"
	ResourcePresent     ResourceObservation = "present"
	ResourceUnreachable ResourceObservation = "unreachable"
	ResourceAuthDenied  ResourceObservation = "auth_denied"
	ResourceTimeout     ResourceObservation = "timeout"
	// ResourceUnknown is an answer that neither confirms nor denies the
	// resource (a lookup that returns nothing where absence cannot be
	// proven). It is recorded and changes nothing.
	ResourceUnknown ResourceObservation = "unknown"
)

// ResourceOutcome is what an event did to one job.
type ResourceOutcome string

const (
	OutcomeRetired      ResourceOutcome = "retired"
	OutcomeNeedsHuman   ResourceOutcome = "needs_human"
	OutcomeAvailability ResourceOutcome = "availability"
	OutcomeRecorded     ResourceOutcome = "recorded"
	OutcomeUnchanged    ResourceOutcome = "unchanged"
)

// ResourceDisposition is the effect of a resource event on one job.
type ResourceDisposition struct {
	JobID   string          `json:"job_id"`
	Match   string          `json:"match"` // identity | replacement
	Outcome ResourceOutcome `json:"outcome"`
	Detail  string          `json:"detail,omitempty"`
}

// ResourceEvent is a report about one external resource, identified by its
// kind and stable ID. A deletion retires dependents only when it is
// authoritative; anything ambiguous asks a person. Unreachable, denied or
// timed-out observations change availability and never retire.
//
// The event is saved before it is applied. Pending lists the dependents
// still to apply, Failures the last error for each, and Complete says
// whether every dependent was applied.
type ResourceEvent struct {
	Schema        int                   `json:"schema"`
	EventID       string                `json:"event_id"`
	Target        Target                `json:"target"`
	Observation   ResourceObservation   `json:"observation"`
	Authoritative bool                  `json:"authoritative"`
	Detail        string                `json:"detail,omitempty"`
	Evidence      []string              `json:"evidence,omitempty"`
	ObservedAt    time.Time             `json:"observed_at"`
	Reporter      Actor                 `json:"reporter"`
	Dispositions  []ResourceDisposition `json:"dispositions"`
	Pending       []ResourceDependent   `json:"pending,omitempty"`
	Failures      []ResourceFailure     `json:"failures,omitempty"`
	Complete      bool                  `json:"complete"`
}

// ResourceDependent is a job an event still has to be applied to.
type ResourceDependent struct {
	JobID string `json:"job_id"`
	Match string `json:"match"`
}

// ResourceFailure is the last error applying an event to one job.
type ResourceFailure struct {
	JobID string `json:"job_id"`
	Error string `json:"error"`
}

const (
	matchIdentity    = "identity"
	matchReplacement = "replacement"
	// resourcePendingPrefix marks events not yet completely applied; the
	// marker is operational state and is removed once the event completes.
	resourcePendingPrefix = "resource_events_pending/"
	// resourceIndexReady records that the index covers every job.
	resourceIndexReady = "resource_index_ready"
	maxReevaluations   = 3
)

// ResourceJobFilter decides whether a resource event may affect a job, for
// example whether the reporter may write it. Jobs it refuses are skipped and
// not reported.
type ResourceJobFilter func(ctx context.Context, job *Job) bool

// RecordResourceEvent evaluates a resource event against the jobs that
// depend on that resource and saves the event with what it did.
//
// Jobs whose target has the same stable identity are dependents. A present
// resource whose kind, environment and display name match a job's target but
// whose stable ID differs is a replacement: the job is never silently
// pointed at it; the job's replacement rule applies. Every other job is
// untouched. The filters decide which dependents the reporter may affect;
// they are checked when the dependents are listed and again inside each
// commit. Reporting the same event again is safe.
func (s *Store) RecordResourceEvent(ctx context.Context, ev ResourceEvent, by Actor, allow ...ResourceJobFilter) (*ResourceEvent, error) {
	permitted := func(ctx context.Context, job *Job) bool {
		for _, f := range allow {
			if f != nil && !f(ctx, job) {
				return false
			}
		}
		return true
	}
	t := ev.Target
	if t.Kind == "" || len(t.StableID) == 0 {
		return nil, refuse(CodeInvalid, "target needs kind and stable_id")
	}
	switch ev.Observation {
	case ResourceDeleted, ResourceAbsent, ResourcePresent, ResourceUnreachable, ResourceAuthDenied, ResourceTimeout:
	case ResourceUnknown:
		if ev.Authoritative {
			return nil, refuse(CodeInvalid, "an unknown observation cannot be authoritative")
		}
	default:
		return nil, refuse(CodeInvalid, "unknown observation %q", ev.Observation)
	}
	if err := s.requireIndexReady(ctx); err != nil {
		return nil, err
	}
	// A client-minted event ID makes the report resumable: sending it again
	// continues the saved event instead of starting another.
	if ev.EventID != "" {
		if err := ValidateID(PrefixEvent, ev.EventID); err != nil {
			return nil, err
		}
		saved, err := s.GetResourceEvent(ctx, ev.EventID)
		switch {
		case err == nil:
			return s.resumeResourceEvent(ctx, saved, ev, by, permitted)
		case ErrorCode(err) != CodeNotFound:
			return nil, err
		}
	} else {
		id, err := NewID(PrefixEvent, s.clock())
		if err != nil {
			return nil, err
		}
		ev.EventID = id
	}
	id := ev.EventID
	ev.Schema = SchemaVersion
	ev.Reporter = by
	if ev.ObservedAt.IsZero() {
		ev.ObservedAt = s.clock()
	}
	ev.Dispositions, ev.Failures, ev.Complete = nil, nil, false

	candidates, err := s.resourceCandidates(ctx, t, ev.Observation)
	if err != nil {
		return nil, err
	}
	ev.Pending = nil
	for _, c := range candidates {
		job, err := s.GetJob(ctx, c.JobID)
		if err != nil {
			if ErrorCode(err) == CodeNotFound {
				continue
			}
			return nil, err
		}
		if permitted(ctx, job) {
			ev.Pending = append(ev.Pending, c)
		}
	}
	if err := s.createJSON(ctx, resourceEventsPrefix+id, &ev); err != nil {
		if errors.Is(err, persis.ErrConflict) {
			return nil, refuse(CodeDuplicate, "resource event %s was created concurrently; send it again", id)
		}
		return nil, err
	}
	if err := s.createJSON(ctx, resourcePendingPrefix+id, indexEntry{}); err != nil && !errors.Is(err, persis.ErrConflict) {
		return nil, err
	}
	if err := s.applyPending(ctx, &ev, by, permitted); err != nil {
		return &ev, err
	}
	return &ev, nil
}

func (s *Store) resourceCandidates(ctx context.Context, t Target, obs ResourceObservation) ([]ResourceDependent, error) {
	exact, err := s.indexedJobs(ctx, resourceIDsPrefix+targetKeyHex(t)+"/")
	if err != nil {
		return nil, err
	}
	var out []ResourceDependent
	for _, id := range exact {
		out = append(out, ResourceDependent{JobID: id, Match: matchIdentity})
	}
	if obs == ResourcePresent && t.DisplayName != "" {
		named, err := s.indexedJobs(ctx, resourceNamesPrefix+nameKeyHex(t.Kind, t.Environment, t.DisplayName)+"/")
		if err != nil {
			return nil, err
		}
		for _, id := range named {
			out = append(out, ResourceDependent{JobID: id, Match: matchReplacement})
		}
	}
	return out, nil
}

// maxProgressRounds bounds how often an event's progress is re-read when
// another processor saved it first.
const maxProgressRounds = 5

// applyPending applies the event to each dependent still pending in its
// saved state, then saves the progress with a compare-and-swap against the
// state it read. Completion is final: a saved complete event is never
// processed or overwritten again, and a job commit refuses an event that is
// already complete, so a slower processor of the same event stops instead
// of applying it again. The caller's event changes only after progress is
// saved, so a failed save never reports progress that is not stored.
func (s *Store) applyPending(ctx context.Context, ev *ResourceEvent, by Actor, permitted ResourceJobFilter) error {
	incomplete := &Error{Code: CodeIncomplete, Message: "resource event " + ev.EventID + " progress could not be saved; send it again with this event_id", Current: ev.EventID}
	for range maxProgressRounds {
		rec, err := s.col.Get(ctx, resourceEventsPrefix+ev.EventID)
		if err != nil {
			return incomplete
		}
		var cur ResourceEvent
		if err := json.Unmarshal(rec.Data, &cur); err != nil {
			return fmt.Errorf("registry: decode event %s: %w", ev.EventID, err)
		}
		if cur.Complete {
			*ev = cur
			return s.dropPendingMarker(ctx, ev.EventID)
		}
		next := cur
		next.Dispositions = append([]ResourceDisposition(nil), cur.Dispositions...)
		var still []ResourceDependent
		var failures []ResourceFailure
		completedElsewhere := false
		for _, p := range cur.Pending {
			if completedElsewhere {
				still = append(still, p)
				continue
			}
			d, err := s.applyDependent(ctx, p, &cur, by, permitted)
			if ErrorCode(err) == CodeEventComplete {
				completedElsewhere = true
				still = append(still, p)
				continue
			}
			if err != nil {
				still = append(still, p)
				failures = append(failures, ResourceFailure{JobID: p.JobID, Error: err.Error()})
				continue
			}
			if d != nil {
				next.Dispositions = append(next.Dispositions, *d)
			}
		}
		if completedElsewhere {
			continue
		}
		next.Pending, next.Failures, next.Complete = still, failures, len(still) == 0
		data, err := json.Marshal(&next)
		if err != nil {
			return err
		}
		if err := s.col.CompareAndSwap(ctx, resourceEventsPrefix+ev.EventID, rec.Data, data); err != nil {
			if errors.Is(err, persis.ErrConflict) {
				continue
			}
			return incomplete
		}
		*ev = next
		if ev.Complete {
			return s.dropPendingMarker(ctx, ev.EventID)
		}
		return nil
	}
	return incomplete
}

func (s *Store) dropPendingMarker(ctx context.Context, eventID string) error {
	if err := s.col.Delete(ctx, resourcePendingPrefix+eventID); err != nil && !errors.Is(err, persis.ErrNotFound) {
		return err
	}
	return nil
}

// resumeResourceEvent continues a saved event re-sent under its own ID by
// the same reporter with the same report. The caller's current permission is
// checked again for every dependent still pending.
func (s *Store) resumeResourceEvent(ctx context.Context, saved *ResourceEvent, sent ResourceEvent, by Actor, permitted ResourceJobFilter) (*ResourceEvent, error) {
	if saved.Reporter.ID != by.ID || !sameReport(saved, &sent) {
		return nil, &Error{Code: CodeDuplicate, Message: "event " + saved.EventID + " was reported differently", Current: saved.EventID}
	}
	if saved.Complete {
		return saved, nil
	}
	if err := s.applyPending(ctx, saved, by, permitted); err != nil {
		return saved, err
	}
	return saved, nil
}

func sameReport(a, b *ResourceEvent) bool {
	digest := func(e *ResourceEvent) string {
		bs, _ := CanonicalJSON([]any{e.Target, e.Observation, e.Authoritative, e.Detail, e.Evidence})
		return sha256Hex(bs)
	}
	return digest(a) == digest(b)
}

// applyDependent applies the event to one job, evaluating it again from the
// job's current version when the version changes before the commit.
func (s *Store) applyDependent(ctx context.Context, p ResourceDependent, ev *ResourceEvent, by Actor, permitted ResourceJobFilter) (*ResourceDisposition, error) {
	for range maxReevaluations {
		job, err := s.GetJob(ctx, p.JobID)
		if err != nil {
			return nil, ignoreNotFound(err)
		}
		if d := job.appliedResourceEvent(appliedKey(p.Match, ev.Target), ev.EventID); d != nil {
			return d, nil
		}
		var d *ResourceDisposition
		if p.Match == matchReplacement {
			d, err = s.applyReplacement(ctx, p.JobID, ev, by, permitted)
		} else {
			d, err = s.applyIdentityEvent(ctx, p.JobID, ev, by, permitted)
		}
		if ErrorCode(err) != CodeVersionConflict {
			return d, err
		}
	}
	return nil, refuse(CodeVersionConflict, "job %s kept changing while the event was applied", p.JobID)
}

// ResourceReauthorizer decides, at reconciliation time, whether the
// reporter of an event may still affect a job.
type ResourceReauthorizer func(ctx context.Context, reporter Actor, job *Job) bool

// WithResourceReauthorizer lets ReconcileResourceEvents finish incomplete
// events by re-checking the reporter's current permission for each job.
func WithResourceReauthorizer(f ResourceReauthorizer) Option {
	return func(s *Store) { s.reauthorize = f }
}

// ReconcileResourceEvents completes events whose application was cut short,
// only for the dependents listed when they were reported, and only after
// re-checking the reporter's current permission for each. Without a
// reauthorizer it changes nothing: the event stays incomplete (complete is
// false and its pending dependents are listed) until the reporter sends it
// again, which is safe to repeat.
func (s *Store) ReconcileResourceEvents(ctx context.Context) error {
	if s.reauthorize == nil {
		return nil
	}
	ids, err := s.indexedJobs(ctx, resourcePendingPrefix)
	if err != nil {
		return err
	}
	var errs []error
	for _, id := range ids {
		ev, err := s.GetResourceEvent(ctx, id)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
			continue
		}
		reporter := ev.Reporter
		permitted := func(ctx context.Context, job *Job) bool { return s.reauthorize(ctx, reporter, job) }
		if err := s.applyPending(ctx, ev, ev.Reporter, permitted); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

// RebuildResourceIndex indexes the targets of every job's current version.
// Registration indexes before it commits; this covers jobs registered
// before resource events existed. It is idempotent.
func (s *Store) RebuildResourceIndex(ctx context.Context) error {
	jobs, err := s.ListJobs(ctx, JobFilter{})
	if err != nil {
		return err
	}
	var errs []error
	for _, job := range jobs {
		v, err := s.versionOf(ctx, job, job.Version)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", job.JobID, err))
			continue
		}
		if err := s.indexTargets(ctx, job.JobID, v.Targets); err != nil {
			errs = append(errs, err)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	return s.putJSON(ctx, resourceIndexReady, indexReady{At: s.clock()})
}

// requireIndexReady refuses resource events until every job registered
// before the index existed has been indexed, so an incomplete index is
// never taken as proof that a resource has no dependents.
func (s *Store) requireIndexReady(ctx context.Context) error {
	var ready indexReady
	if err := s.getJSON(ctx, resourceIndexReady, &ready); err != nil {
		if ErrorCode(err) == CodeNotFound {
			return refuse(CodeNotReady, "the resource index is being built; retry shortly")
		}
		return err
	}
	return nil
}

// currentTargets returns the targets of the job's current version that
// match, and the job.
func (s *Store) currentTargets(ctx context.Context, jobID string, match func(Target) bool) (*Job, []Target, error) {
	job, err := s.GetJob(ctx, jobID)
	if err != nil {
		return nil, nil, err
	}
	v, err := s.versionOf(ctx, job, job.Version)
	if err != nil {
		return nil, nil, err
	}
	var out []Target
	for _, t := range v.Targets {
		if match(t) {
			out = append(out, t)
		}
	}
	return job, out, nil
}

func (s *Store) applyIdentityEvent(ctx context.Context, jobID string, ev *ResourceEvent, by Actor, permitted ResourceJobFilter) (*ResourceDisposition, error) {
	key := TargetKey(ev.Target)
	job, hits, err := s.currentTargets(ctx, jobID, func(t Target) bool { return TargetKey(t) == key })
	if err != nil || len(hits) == 0 {
		// The index named a target the current version no longer has.
		return nil, ignoreNotFound(err)
	}
	if !permitted(ctx, job) {
		return nil, nil
	}
	d := &ResourceDisposition{JobID: jobID, Match: matchIdentity}
	c := eventCommit{s: s, check: atVersion(job.Version, permitted), eventID: ev.EventID, key: appliedKey(d.Match, ev.Target), d: d}
	evidence := append([]string{"resource_event:" + ev.EventID}, ev.Evidence...)
	if job.Lifecycle.Terminal() {
		d.Outcome, d.Detail = OutcomeUnchanged, "job is "+string(job.Lifecycle)
		return d, nil
	}
	switch ev.Observation {
	case ResourceDeleted, ResourceAbsent:
		if !ev.Authoritative {
			return s.askPerson(ctx, job, d, "target reported "+string(ev.Observation)+" without authoritative evidence", evidence, by, c)
		}
		v, err := s.versionOf(ctx, job, job.Version)
		if err != nil {
			return nil, err
		}
		switch v.RetirementRules.OnTargetDeleted {
		case RuleRetire:
			return s.retireFor(ctx, job, d, RetireTargetDeleted, "target "+describeTarget(ev.Target)+" deleted", evidence, by, c)
		case RuleReview:
			return s.askPerson(ctx, job, d, "target "+describeTarget(ev.Target)+" deleted", evidence, by, c)
		}
		return s.recordOnly(ctx, job, d, "target deleted; job rule keeps it", evidence, by, c)
	case ResourceUnreachable, ResourceTimeout:
		return s.observe(ctx, job, d, Observation{State: AvailabilityTargetUnreachable, Kind: "target_" + string(ev.Observation), Detail: ev.Detail, Evidence: evidence, Target: key}, by, c)
	case ResourceAuthDenied:
		return s.observe(ctx, job, d, Observation{State: AvailabilityAuthRequired, Kind: "target_auth_denied", Detail: ev.Detail, Evidence: evidence, Target: key}, by, c)
	case ResourceUnknown:
		// A target checked before each run that cannot be confirmed stops
		// those runs; availability makes that visible and actionable. It
		// never touches the lifecycle.
		if slices.ContainsFunc(hits, func(t Target) bool { return t.ExistenceCheck == CheckPreRun }) {
			return s.observe(ctx, job, d, Observation{State: AvailabilityTargetUnconfirmed, Kind: "target_unknown", Detail: ev.Detail, Evidence: evidence, Target: key}, by, c)
		}
		return s.recordOnly(ctx, job, d, "target could not be confirmed or denied; nothing changes", evidence, by, c)
	case ResourcePresent:
		// Only this target's open conditions are resolved; others stay.
		for _, e := range job.Exceptions {
			if e.ResolvedAt != nil || e.Scope != "" {
				continue
			}
			t, err := s.exceptionTarget(ctx, e)
			if err != nil {
				return nil, err
			}
			if t == key {
				return s.observe(ctx, job, d, Observation{State: AvailabilityReady, Detail: "target present", Evidence: evidence, Target: key}, by, c)
			}
		}
		d.Outcome = OutcomeUnchanged
		return d, nil
	}
	return nil, refuse(CodeInvalid, "unknown observation %q", ev.Observation)
}

func (s *Store) applyReplacement(ctx context.Context, jobID string, ev *ResourceEvent, by Actor, permitted ResourceJobFilter) (*ResourceDisposition, error) {
	key := TargetKey(ev.Target)
	job, hits, err := s.currentTargets(ctx, jobID, func(t Target) bool {
		return t.Kind == ev.Target.Kind && t.Environment == ev.Target.Environment &&
			t.DisplayName == ev.Target.DisplayName && TargetKey(t) != key
	})
	if err != nil || len(hits) == 0 {
		return nil, ignoreNotFound(err)
	}
	if !permitted(ctx, job) {
		return nil, nil
	}
	d := &ResourceDisposition{JobID: jobID, Match: matchReplacement}
	c := eventCommit{s: s, check: atVersion(job.Version, permitted), eventID: ev.EventID, key: appliedKey(d.Match, ev.Target), d: d}
	if job.Lifecycle.Terminal() {
		d.Outcome, d.Detail = OutcomeUnchanged, "job is "+string(job.Lifecycle)
		return d, nil
	}
	detail := fmt.Sprintf("%s now has a different stable identity; the job still targets %s", describeTarget(ev.Target), describeTarget(hits[0]))
	evidence := append([]string{"resource_event:" + ev.EventID}, ev.Evidence...)
	v, err := s.versionOf(ctx, job, job.Version)
	if err != nil {
		return nil, err
	}
	switch v.RetirementRules.OnReplacement {
	case RuleRetire:
		return s.retireFor(ctx, job, d, RetireReplaced, detail, evidence, by, c)
	case RuleKeep:
		return s.recordOnly(ctx, job, d, detail, evidence, by, c)
	}
	return s.askPerson(ctx, job, d, detail, evidence, by, c)
}

func (s *Store) retireFor(ctx context.Context, job *Job, d *ResourceDisposition, reason RetirementReason, detail string, evidence []string, by Actor, c eventCommit) (*ResourceDisposition, error) {
	d.Outcome, d.Detail = OutcomeRetired, detail
	_, err := s.ChangeLifecycle(ctx, job.JobID, Transition{Op: OpRetire, Reason: reason, Detail: detail, Evidence: evidence, Authorize: c.in(ctx)}, by)
	if ErrorCode(err) == CodeNotPermitted {
		return nil, nil
	}
	if ErrorCode(err) == CodeTransition {
		d.Outcome, d.Detail = OutcomeUnchanged, "already ended"
		return d, nil
	}
	if err != nil {
		return nil, err
	}
	d.Outcome, d.Detail = OutcomeRetired, detail
	return d, nil
}

func (s *Store) askPerson(ctx context.Context, job *Job, d *ResourceDisposition, detail string, evidence []string, by Actor, c eventCommit) (*ResourceDisposition, error) {
	if job.Lifecycle != LifecycleActive {
		return s.recordOnly(ctx, job, d, detail, evidence, by, c)
	}
	d.Outcome, d.Detail = OutcomeNeedsHuman, detail
	_, err := s.ChangeLifecycle(ctx, job.JobID, Transition{Op: OpNeedsHuman, Detail: detail, Evidence: evidence, Authorize: c.in(ctx)}, by)
	if ErrorCode(err) == CodeNotPermitted {
		return nil, nil
	}
	if ErrorCode(err) == CodeTransition {
		return s.recordOnly(ctx, job, d, detail, evidence, by, c)
	}
	if err != nil {
		return nil, err
	}
	d.Outcome, d.Detail = OutcomeNeedsHuman, detail
	return d, nil
}

func (s *Store) recordOnly(ctx context.Context, job *Job, d *ResourceDisposition, detail string, evidence []string, by Actor, c eventCommit) (*ResourceDisposition, error) {
	d.Outcome, d.Detail = OutcomeRecorded, detail
	inCommit := c.in(ctx)
	if _, err := s.WithJobTx(ctx, job.JobID, by, func(tx *JobTx) error {
		if err := inCommit(tx); err != nil {
			return err
		}
		return tx.event(Event{Kind: EventResource, Detail: detail, Evidence: evidence})
	}); err != nil {
		if ErrorCode(err) == CodeNotPermitted {
			return nil, nil
		}
		return nil, err
	}
	d.Outcome, d.Detail = OutcomeRecorded, detail
	return d, nil
}

func (s *Store) observe(ctx context.Context, job *Job, d *ResourceDisposition, o Observation, by Actor, c eventCommit) (*ResourceDisposition, error) {
	d.Outcome, d.Detail = OutcomeAvailability, string(o.State)
	inCommit := c.in(ctx)
	if _, err := s.WithJobTx(ctx, job.JobID, by, func(tx *JobTx) error {
		if err := inCommit(tx); err != nil {
			return err
		}
		if err := tx.Observe(o); err != nil {
			return err
		}
		// The result is the availability the job ended with (another
		// condition may still hold it), in the reply and in the record a
		// replay reads.
		d.Detail = string(tx.Job.Availability.State)
		if n := len(tx.Job.AppliedResourceEvents); n > 0 {
			if last := &tx.Job.AppliedResourceEvents[n-1]; last.EventID == c.eventID && last.Key == c.key {
				last.Disposition.Detail = d.Detail
			}
		}
		return nil
	}); err != nil {
		if ErrorCode(err) == CodeNotPermitted {
			return nil, nil
		}
		return nil, err
	}
	return d, nil
}

// exceptionTarget is the key of the target whose resource event opened e, or
// empty. Exceptions recorded before they carried their target are matched
// through the event that opened them, which is always the first evidence
// entry; later entries are the reporter's and are never used. A missing
// originating event matches nothing; any other read error is returned so the
// caller can be retried. Exceptions of other kinds (a worker, a login) never
// belong to a target.
func (s *Store) exceptionTarget(ctx context.Context, e *Exception) (string, error) {
	if e.Target != "" || !strings.HasPrefix(e.Kind, "target_") || len(e.Evidence) == 0 {
		return e.Target, nil
	}
	id, ok := strings.CutPrefix(e.Evidence[0], "resource_event:")
	if !ok {
		return "", nil
	}
	saved, err := s.GetResourceEvent(ctx, id)
	switch {
	case ErrorCode(err) == CodeNotFound:
		return "", nil
	case err != nil:
		return "", err
	}
	return TargetKey(saved.Target), nil
}

func describeTarget(t Target) string {
	keys := make([]string, 0, len(t.StableID))
	for k, v := range t.StableID {
		keys = append(keys, k+"="+v)
	}
	sort.Strings(keys)
	name := t.Kind
	if t.DisplayName != "" {
		name += " " + t.DisplayName
	}
	return name + " {" + strings.Join(keys, ", ") + "}"
}

func ignoreNotFound(err error) error {
	if ErrorCode(err) == CodeNotFound {
		return nil
	}
	return err
}

// IncompleteResourceEvents lists events not yet applied to every dependent,
// oldest first, after the event ID after; only those a reporter on machineID
// sent when machineID is set, and only those show accepts (it may also trim
// what the caller sees of an event). It returns at most limit events and the
// cursor for the next page, empty at the end; the cursor is always the ID of
// a returned event.
func (s *Store) IncompleteResourceEvents(ctx context.Context, machineID, after string, limit int, show func(*ResourceEvent) bool) ([]ResourceEvent, string, error) {
	if limit <= 0 {
		return nil, "", refuse(CodeInvalid, "limit must be positive")
	}
	ids, err := s.indexedJobs(ctx, resourcePendingPrefix)
	if err != nil {
		return nil, "", err
	}
	sort.Strings(ids)
	var out []ResourceEvent
	for _, id := range ids {
		if id <= after {
			continue
		}
		ev, err := s.GetResourceEvent(ctx, id)
		if err != nil {
			if ErrorCode(err) == CodeNotFound {
				continue
			}
			return nil, "", err
		}
		if ev.Complete || (machineID != "" && ev.Reporter.MachineID != machineID) || (show != nil && !show(ev)) {
			continue
		}
		if len(out) == limit {
			return out, out[len(out)-1].EventID, nil
		}
		out = append(out, *ev)
	}
	return out, "", nil
}

// GetResourceEvent returns a recorded resource event.
func (s *Store) GetResourceEvent(ctx context.Context, eventID string) (*ResourceEvent, error) {
	if err := ValidateID(PrefixEvent, eventID); err != nil {
		return nil, err
	}
	var ev ResourceEvent
	if err := s.getJSON(ctx, resourceEventsPrefix+eventID, &ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

// errEventComplete stops applying an event another processor completed.
var errEventComplete = refuse(CodeEventComplete, "resource event is already applied to this job")

// errVersionChanged marks a job that moved to another version after the
// event was evaluated against it; the caller evaluates it again.
var errVersionChanged = refuse(CodeVersionConflict, "job version changed while the event was applied")

// jobCheck is a check run inside the commit that changes a job.
type jobCheck func(ctx context.Context, job *Job) error

// atVersion builds the in-commit check for an event evaluated against
// version: the reporter must still be permitted and the job must still be at
// that version, or the decision is evaluated again.
func atVersion(version int, permitted ResourceJobFilter) jobCheck {
	return func(ctx context.Context, job *Job) error {
		if job.Version != version {
			return errVersionChanged
		}
		if !permitted(ctx, job) {
			return refuse(CodeNotPermitted, "reporter may not change job %s", job.JobID)
		}
		return nil
	}
}

// recheck runs check inside the commit, so authorization and the evaluated
// version hold for the state committed.
// A job keeps up to maxAppliedResourceEvents applied-event records, over all
// targets, before dropping the oldest whose event's saved progress already
// holds the job's result. A record whose event still lists the job is never
// dropped: it is what stops a replay applying the event twice, and only a
// lost progress write leaves one. When hardMaxAppliedResourceEvents records
// remain after compaction, new events other than a retirement are refused
// for the job until those are re-sent, so reports cannot grow a job record
// without bound.
const (
	maxAppliedResourceEvents     = 50
	hardMaxAppliedResourceEvents = 500
)

// eventCommit is the in-commit part of applying a resource event to a job:
// the authorization and version check, and the record that the event was
// applied, written in the same commit as the change so a replay of the
// event returns that result instead of applying it again.
type eventCommit struct {
	s       *Store
	check   jobCheck
	eventID string
	key     string
	d       *ResourceDisposition
}

func (c eventCommit) in(ctx context.Context) func(tx *JobTx) error {
	return func(tx *JobTx) error {
		if err := c.check(ctx, tx.Job); err != nil {
			return err
		}
		if tx.Job.appliedResourceEvent(c.key, c.eventID) != nil {
			// Applied by a concurrent replay; re-read its result.
			return errVersionChanged
		}
		// A processor holding a stale copy of the event stops here once the
		// saved event no longer lists this job as pending. The check shares
		// this job's commit with the compaction that drops such records, so
		// a dropped record is never reapplied.
		if saved, err := c.s.GetResourceEvent(ctx, c.eventID); err != nil {
			return err
		} else if !saved.pendingFor(tx.Job.JobID, c.d.Match) {
			return errEventComplete
		}
		list := c.s.compactApplied(ctx, tx.Job.JobID, tx.Job.AppliedResourceEvents)
		// Retirement always applies: it happens once, and a job that cannot
		// be retired by a confirmed deletion would be locked out of its
		// lifecycle.
		if len(list) >= hardMaxAppliedResourceEvents && c.d.Outcome != OutcomeRetired {
			return refuse(CodeNotReady, "job %s holds %d resource events whose progress was not saved; send them again with their event_id before new events apply",
				tx.Job.JobID, len(list))
		}
		tx.Job.AppliedResourceEvents = append(list, AppliedResourceEvent{Key: c.key, EventID: c.eventID, At: tx.now, Disposition: *c.d})
		tx.touch()
		return nil
	}
}

// compactApplied drops the oldest of jobID's records beyond
// maxAppliedResourceEvents whose event no longer lists the job as pending:
// its saved progress already holds the job's result, so a replay never
// reaches the job again. A record whose event still lists the job, or cannot
// be read, is kept; only a lost progress write leaves one behind.
func (s *Store) compactApplied(ctx context.Context, jobID string, list []AppliedResourceEvent) []AppliedResourceEvent {
	excess := len(list) - maxAppliedResourceEvents
	if excess <= 0 {
		return list
	}
	out := make([]AppliedResourceEvent, 0, len(list))
	for _, a := range list {
		if excess > 0 {
			if ev, err := s.GetResourceEvent(ctx, a.EventID); err == nil && !ev.pendingFor(jobID, a.Disposition.Match) {
				excess--
				continue
			}
		}
		out = append(out, a)
	}
	return out
}

// pendingFor reports whether the event's saved progress still owes jobID
// the given match.
func (e *ResourceEvent) pendingFor(jobID, match string) bool {
	if e.Complete {
		return false
	}
	for _, p := range e.Pending {
		if p.JobID == jobID && p.Match == match {
			return true
		}
	}
	return false
}

// appliedKey keys a job's applied-event records by how the event matched
// the job and by the event's target.
func appliedKey(match string, t Target) string {
	return match + "|" + TargetKey(t)
}

// appliedResourceEvent returns the recorded result of an event already
// applied to the job, or nil.
func (j *Job) appliedResourceEvent(key, eventID string) *ResourceDisposition {
	for _, a := range j.AppliedResourceEvents {
		if a.Key == key && a.EventID == eventID {
			d := a.Disposition
			return &d
		}
	}
	return nil
}
