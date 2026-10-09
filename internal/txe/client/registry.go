// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Health returns the hub's status and build.
func (c *Client) Health(ctx context.Context) (*Health, error) {
	var out Health
	if err := c.Do(ctx, http.MethodGet, "/health", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Installation returns the registry's schema and owners.
func (c *Client) Installation(ctx context.Context) (*Installation, error) {
	var out Installation
	if err := c.Do(ctx, http.MethodGet, "/txe/installation", nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Machine returns one machine the registry knows.
func (c *Client) Machine(ctx context.Context, machineID string) (*Machine, error) {
	var out Machine
	if err := c.Do(ctx, http.MethodGet, "/txe/machines/"+url.PathEscape(machineID), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EnsureProject returns the owner's project for key, creating it once.
// Concurrent first calls return the same project.
func (c *Client) EnsureProject(ctx context.Context, ownerID, key, name string, actor Actor) (*Project, error) {
	in := struct {
		OwnerID string `json:"owner_id"`
		Key     string `json:"key"`
		Name    string `json:"name,omitempty"`
		Actor   Actor  `json:"actor"`
	}{ownerID, key, name, actor}
	var out Project
	if err := c.Do(ctx, http.MethodPost, "/txe/projects", nil, in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// JobFilter narrows ListJobs. Empty fields are not applied.
type JobFilter struct {
	OwnerID   string
	ProjectID string
	MachineID string
	JobKey    string
	Lifecycle string
}

// ListJobs returns the jobs matching filter, oldest first.
func (c *Client) ListJobs(ctx context.Context, filter JobFilter) ([]Job, error) {
	query := url.Values{}
	for name, value := range map[string]string{
		"owner": filter.OwnerID, "project": filter.ProjectID, "machine": filter.MachineID,
		"job_key": filter.JobKey, "lifecycle": filter.Lifecycle,
	} {
		if value != "" {
			query.Set(name, value)
		}
	}
	var out struct {
		Jobs []Job `json:"jobs"`
	}
	if err := c.Do(ctx, http.MethodGet, "/txe/jobs", query, nil, &out); err != nil {
		return nil, err
	}
	return out.Jobs, nil
}

// Job returns one job's current record.
func (c *Client) Job(ctx context.Context, jobID string) (*Job, error) {
	var out Job
	if err := c.Do(ctx, http.MethodGet, "/txe/jobs/"+url.PathEscape(jobID), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// JobVersion returns one immutable version of a job.
func (c *Client) JobVersion(ctx context.Context, jobID string, version int) (*JobVersion, error) {
	var out JobVersion
	path := fmt.Sprintf("/txe/jobs/%s/versions/%d", url.PathEscape(jobID), version)
	if err := c.Do(ctx, http.MethodGet, path, nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RegisterJob saves a new job, its first version and its DAG. The job is
// incomplete until MarkReady. Sending the same request again returns the job
// that was stored the first time.
func (c *Client) RegisterJob(ctx context.Context, req RegisterRequest) (*Job, error) {
	var out Job
	if err := c.Do(ctx, http.MethodPost, "/txe/jobs", nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdateJobVersion records a new version when ExpectedVersion is current. The
// job is incomplete again until MarkReady.
func (c *Client) UpdateJobVersion(ctx context.Context, jobID string, req VersionRequest) (*Job, error) {
	var out Job
	if err := c.Do(ctx, http.MethodPost, "/txe/jobs/"+url.PathEscape(jobID)+"/versions", nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// MarkReady records that the package is in place on this machine and returns
// the receipt. It is the only way a job becomes runnable.
func (c *Client) MarkReady(ctx context.Context, jobID string, req ReadyRequest) (*Receipt, error) {
	var out Receipt
	if err := c.Do(ctx, http.MethodPost, "/txe/jobs/"+url.PathEscape(jobID)+"/ready", nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
