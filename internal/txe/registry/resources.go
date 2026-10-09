// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"context"
	"errors"
	"fmt"
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
	maxReevaluations      = 3
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
	default:
		return nil, refuse(CodeInvalid, "unknown observation %q", ev.Observation)
	}
	id, err := NewID(PrefixEvent, s.clock())
	if err != nil {
		return nil, err
	}
	ev.Schema = SchemaVersion
	ev.EventID = id
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

// applyPending applies the event to each pending dependent, saves the
// event, and removes its pending marker once every dependent is applied.
func (s *Store) applyPending(ctx context.Context, ev *ResourceEvent, by Actor, permitted ResourceJobFilter) error {
	var still []ResourceDependent
	var failures []ResourceFailure
	for _, p := range ev.Pending {
		d, err := s.applyDependent(ctx, p, ev, by, permitted)
		if err != nil {
			still = append(still, p)
			failures = append(failures, ResourceFailure{JobID: p.JobID, Error: err.Error()})
			continue
		}
		if d != nil {
			ev.Dispositions = append(ev.Dispositions, *d)
		}
	}
	ev.Pending, ev.Failures, ev.Complete = still, failures, len(still) == 0
	if err := s.putJSON(ctx, resourceEventsPrefix+ev.EventID, ev); err != nil {
		return err
	}
	if ev.Complete {
		if err := s.col.Delete(ctx, resourcePendingPrefix+ev.EventID); err != nil {
			return err
		}
	}
	return nil
}

// applyDependent applies the event to one job, evaluating it again from the
// job's current version when the version changes before the commit.
func (s *Store) applyDependent(ctx context.Context, p ResourceDependent, ev *ResourceEvent, by Actor, permitted ResourceJobFilter) (*ResourceDisposition, error) {
	for range maxReevaluations {
		var d *ResourceDisposition
		var err error
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
	return errors.Join(errs...)
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
	check := atVersion(job.Version, permitted)
	d := &ResourceDisposition{JobID: jobID, Match: matchIdentity}
	evidence := append([]string{"resource_event:" + ev.EventID}, ev.Evidence...)
	if job.Lifecycle.Terminal() {
		d.Outcome, d.Detail = OutcomeUnchanged, "job is "+string(job.Lifecycle)
		return d, nil
	}
	switch ev.Observation {
	case ResourceDeleted, ResourceAbsent:
		if !ev.Authoritative {
			return s.askPerson(ctx, job, d, "target reported "+string(ev.Observation)+" without authoritative evidence", evidence, by, check)
		}
		v, err := s.versionOf(ctx, job, job.Version)
		if err != nil {
			return nil, err
		}
		switch v.RetirementRules.OnTargetDeleted {
		case RuleRetire:
			return s.retireFor(ctx, job, d, RetireTargetDeleted, "target "+describeTarget(ev.Target)+" deleted", evidence, by, check)
		case RuleReview:
			return s.askPerson(ctx, job, d, "target "+describeTarget(ev.Target)+" deleted", evidence, by, check)
		}
		return s.recordOnly(ctx, job, d, "target deleted; job rule keeps it", evidence, by, check)
	case ResourceUnreachable, ResourceTimeout:
		return s.observe(ctx, job, d, Observation{State: AvailabilityTargetUnreachable, Kind: "target_" + string(ev.Observation), Detail: ev.Detail, Evidence: evidence}, by, check)
	case ResourceAuthDenied:
		return s.observe(ctx, job, d, Observation{State: AvailabilityAuthRequired, Kind: "target_auth_denied", Detail: ev.Detail, Evidence: evidence}, by, check)
	case ResourcePresent:
		if job.Availability.State == AvailabilityTargetUnreachable || job.Availability.State == AvailabilityAuthRequired {
			return s.observe(ctx, job, d, Observation{State: AvailabilityReady, Detail: "target present", Evidence: evidence}, by, check)
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
	check := atVersion(job.Version, permitted)
	d := &ResourceDisposition{JobID: jobID, Match: matchReplacement}
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
		return s.retireFor(ctx, job, d, RetireReplaced, detail, evidence, by, check)
	case RuleKeep:
		return s.recordOnly(ctx, job, d, detail, evidence, by, check)
	}
	return s.askPerson(ctx, job, d, detail, evidence, by, check)
}

func (s *Store) retireFor(ctx context.Context, job *Job, d *ResourceDisposition, reason RetirementReason, detail string, evidence []string, by Actor, check jobCheck) (*ResourceDisposition, error) {
	_, err := s.ChangeLifecycle(ctx, job.JobID, Transition{Op: OpRetire, Reason: reason, Detail: detail, Evidence: evidence, Authorize: recheck(ctx, check)}, by)
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

func (s *Store) askPerson(ctx context.Context, job *Job, d *ResourceDisposition, detail string, evidence []string, by Actor, check jobCheck) (*ResourceDisposition, error) {
	if job.Lifecycle != LifecycleActive {
		return s.recordOnly(ctx, job, d, detail, evidence, by, check)
	}
	_, err := s.ChangeLifecycle(ctx, job.JobID, Transition{Op: OpNeedsHuman, Detail: detail, Evidence: evidence, Authorize: recheck(ctx, check)}, by)
	if ErrorCode(err) == CodeNotPermitted {
		return nil, nil
	}
	if ErrorCode(err) == CodeTransition {
		return s.recordOnly(ctx, job, d, detail, evidence, by, check)
	}
	if err != nil {
		return nil, err
	}
	d.Outcome, d.Detail = OutcomeNeedsHuman, detail
	return d, nil
}

func (s *Store) recordOnly(ctx context.Context, job *Job, d *ResourceDisposition, detail string, evidence []string, by Actor, check jobCheck) (*ResourceDisposition, error) {
	inCommit := recheck(ctx, check)
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

func (s *Store) observe(ctx context.Context, job *Job, d *ResourceDisposition, o Observation, by Actor, check jobCheck) (*ResourceDisposition, error) {
	inCommit := recheck(ctx, check)
	if _, err := s.WithJobTx(ctx, job.JobID, by, func(tx *JobTx) error {
		if err := inCommit(tx); err != nil {
			return err
		}
		return tx.Observe(o)
	}); err != nil {
		if ErrorCode(err) == CodeNotPermitted {
			return nil, nil
		}
		return nil, err
	}
	d.Outcome, d.Detail = OutcomeAvailability, string(o.State)
	return d, nil
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
func recheck(ctx context.Context, check jobCheck) func(tx *JobTx) error {
	return func(tx *JobTx) error { return check(ctx, tx.Job) }
}
