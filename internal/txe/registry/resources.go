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
}

// RecordResourceEvent evaluates a resource event against the jobs that
// depend on that resource and saves the event with what it did.
//
// Jobs whose target has the same stable identity are dependents. A present
// resource whose kind, environment and display name match a job's target but
// whose stable ID differs is a replacement: the job is never silently
// pointed at it; the job's replacement rule applies. Every other job is
// untouched. Reporting the same event again is safe: transitions that already
// happened are recorded as unchanged.
func (s *Store) RecordResourceEvent(ctx context.Context, ev ResourceEvent, by Actor) (*ResourceEvent, error) {
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
	ev.Dispositions = nil

	exact, err := s.indexedJobs(ctx, resourceIDsPrefix+targetKeyHex(t)+"/")
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, jobID := range exact {
		d, err := s.applyIdentityEvent(ctx, jobID, &ev, by)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", jobID, err))
			continue
		}
		if d != nil {
			ev.Dispositions = append(ev.Dispositions, *d)
		}
	}
	if ev.Observation == ResourcePresent && t.DisplayName != "" {
		named, err := s.indexedJobs(ctx, resourceNamesPrefix+nameKeyHex(t.Kind, t.Environment, t.DisplayName)+"/")
		if err != nil {
			return nil, err
		}
		for _, jobID := range named {
			d, err := s.applyReplacement(ctx, jobID, &ev, by)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", jobID, err))
				continue
			}
			if d != nil {
				ev.Dispositions = append(ev.Dispositions, *d)
			}
		}
	}
	if err := s.createJSON(ctx, resourceEventsPrefix+id, &ev); err != nil {
		return nil, err
	}
	return &ev, errors.Join(errs...)
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

func (s *Store) applyIdentityEvent(ctx context.Context, jobID string, ev *ResourceEvent, by Actor) (*ResourceDisposition, error) {
	key := TargetKey(ev.Target)
	job, hits, err := s.currentTargets(ctx, jobID, func(t Target) bool { return TargetKey(t) == key })
	if err != nil || len(hits) == 0 {
		// The index named a target the current version no longer has.
		return nil, ignoreNotFound(err)
	}
	d := &ResourceDisposition{JobID: jobID, Match: "identity"}
	evidence := append([]string{"resource_event:" + ev.EventID}, ev.Evidence...)
	if job.Lifecycle.Terminal() {
		d.Outcome, d.Detail = OutcomeUnchanged, "job is "+string(job.Lifecycle)
		return d, nil
	}
	switch ev.Observation {
	case ResourceDeleted, ResourceAbsent:
		if !ev.Authoritative {
			return s.askPerson(ctx, job, d, "target reported "+string(ev.Observation)+" without authoritative evidence", evidence, by)
		}
		v, err := s.versionOf(ctx, job, job.Version)
		if err != nil {
			return nil, err
		}
		switch v.RetirementRules.OnTargetDeleted {
		case RuleRetire:
			return s.retireFor(ctx, job, d, RetireTargetDeleted, "target "+describeTarget(ev.Target)+" deleted", evidence, by)
		case RuleReview:
			return s.askPerson(ctx, job, d, "target "+describeTarget(ev.Target)+" deleted", evidence, by)
		}
		return s.recordOnly(ctx, job, d, "target deleted; job rule keeps it", evidence, by)
	case ResourceUnreachable, ResourceTimeout:
		return s.observe(ctx, job, d, Observation{State: AvailabilityTargetUnreachable, Kind: "target_" + string(ev.Observation), Detail: ev.Detail, Evidence: evidence}, by)
	case ResourceAuthDenied:
		return s.observe(ctx, job, d, Observation{State: AvailabilityAuthRequired, Kind: "target_auth_denied", Detail: ev.Detail, Evidence: evidence}, by)
	case ResourcePresent:
		if job.Availability.State == AvailabilityTargetUnreachable || job.Availability.State == AvailabilityAuthRequired {
			return s.observe(ctx, job, d, Observation{State: AvailabilityReady, Detail: "target present", Evidence: evidence}, by)
		}
		d.Outcome = OutcomeUnchanged
		return d, nil
	}
	return nil, refuse(CodeInvalid, "unknown observation %q", ev.Observation)
}

func (s *Store) applyReplacement(ctx context.Context, jobID string, ev *ResourceEvent, by Actor) (*ResourceDisposition, error) {
	key := TargetKey(ev.Target)
	job, hits, err := s.currentTargets(ctx, jobID, func(t Target) bool {
		return t.Kind == ev.Target.Kind && t.Environment == ev.Target.Environment &&
			t.DisplayName == ev.Target.DisplayName && TargetKey(t) != key
	})
	if err != nil || len(hits) == 0 {
		return nil, ignoreNotFound(err)
	}
	d := &ResourceDisposition{JobID: jobID, Match: "replacement"}
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
		return s.retireFor(ctx, job, d, RetireReplaced, detail, evidence, by)
	case RuleKeep:
		return s.recordOnly(ctx, job, d, detail, evidence, by)
	}
	return s.askPerson(ctx, job, d, detail, evidence, by)
}

func (s *Store) retireFor(ctx context.Context, job *Job, d *ResourceDisposition, reason RetirementReason, detail string, evidence []string, by Actor) (*ResourceDisposition, error) {
	_, err := s.ChangeLifecycle(ctx, job.JobID, Transition{Op: OpRetire, Reason: reason, Detail: detail, Evidence: evidence}, by)
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

func (s *Store) askPerson(ctx context.Context, job *Job, d *ResourceDisposition, detail string, evidence []string, by Actor) (*ResourceDisposition, error) {
	if job.Lifecycle != LifecycleActive {
		return s.recordOnly(ctx, job, d, detail, evidence, by)
	}
	_, err := s.ChangeLifecycle(ctx, job.JobID, Transition{Op: OpNeedsHuman, Detail: detail, Evidence: evidence}, by)
	if ErrorCode(err) == CodeTransition {
		return s.recordOnly(ctx, job, d, detail, evidence, by)
	}
	if err != nil {
		return nil, err
	}
	d.Outcome, d.Detail = OutcomeNeedsHuman, detail
	return d, nil
}

func (s *Store) recordOnly(ctx context.Context, job *Job, d *ResourceDisposition, detail string, evidence []string, by Actor) (*ResourceDisposition, error) {
	if _, err := s.WithJobTx(ctx, job.JobID, by, func(tx *JobTx) error {
		return tx.event(Event{Kind: EventResource, Detail: detail, Evidence: evidence})
	}); err != nil {
		return nil, err
	}
	d.Outcome, d.Detail = OutcomeRecorded, detail
	return d, nil
}

func (s *Store) observe(ctx context.Context, job *Job, d *ResourceDisposition, o Observation, by Actor) (*ResourceDisposition, error) {
	if _, err := s.WithJobTx(ctx, job.JobID, by, func(tx *JobTx) error { return tx.Observe(o) }); err != nil {
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
