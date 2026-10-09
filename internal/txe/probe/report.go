// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
)

// Event is a resource event as the registry receives it.
type Event struct {
	EventID       string           `json:"event_id,omitempty"`
	Target        Target           `json:"target"`
	Observation   Outcome          `json:"observation"`
	Authoritative bool             `json:"authoritative"`
	Detail        string           `json:"detail,omitempty"`
	Evidence      []string         `json:"evidence,omitempty"`
	ObservedAt    time.Time        `json:"observed_at"`
	Actor         *txeclient.Actor `json:"actor,omitempty"`
}

// Disposition is what a recorded event did to one dependent job.
type Disposition struct {
	JobID   string `json:"job_id"`
	Match   string `json:"match"`
	Outcome string `json:"outcome"`
	Detail  string `json:"detail,omitempty"`
}

// RecordedEvent is the registry's record of an event.
type RecordedEvent struct {
	EventID      string          `json:"event_id"`
	Target       Target          `json:"target"`
	Observation  Outcome         `json:"observation"`
	Complete     bool            `json:"complete"`
	Dispositions []Disposition   `json:"dispositions"`
	Reporter     txeclient.Actor `json:"reporter"`
}

// Registry is what a check reads from and reports to.
type Registry interface {
	Job(ctx context.Context, jobID string) (*txeclient.Job, error)
	JobVersion(ctx context.Context, jobID string, version int) (*txeclient.JobVersion, error)
	ListJobs(ctx context.Context, filter txeclient.JobFilter) ([]txeclient.Job, error)
	RecordEvent(ctx context.Context, ev Event) (*RecordedEvent, error)
	// IncompleteEvents lists, oldest first, the events this machine
	// reported that are not yet applied to every dependent.
	IncompleteEvents(ctx context.Context, machineID, after string, limit int) ([]RecordedEvent, string, error)
}

// ClientRegistry adapts the CLI's registry client.
type ClientRegistry struct{ *txeclient.Client }

func (r ClientRegistry) RecordEvent(ctx context.Context, ev Event) (*RecordedEvent, error) {
	var out RecordedEvent
	if err := r.Do(ctx, http.MethodPost, "/txe/resource-events", nil, ev, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (r ClientRegistry) IncompleteEvents(ctx context.Context, machineID, after string, limit int) ([]RecordedEvent, string, error) {
	query := url.Values{"complete": {"false"}, "reporter_machine_id": {machineID}, "limit": {strconv.Itoa(limit)}}
	if after != "" {
		query.Set("after", after)
	}
	var out struct {
		Events     []RecordedEvent `json:"events"`
		NextCursor string          `json:"next_cursor"`
	}
	if err := r.Do(ctx, http.MethodGet, "/txe/resource-events", query, nil, &out); err != nil {
		return nil, "", err
	}
	return out.Events, out.NextCursor, nil
}
