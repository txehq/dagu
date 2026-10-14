// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package txeauth connects the server to the TXE authentication and
// authorization libraries: it reads the owner of a resource from the
// registry, carries a verified provider token through a request, and says
// what kind of caller a request comes from.
package txeauth

import (
	"context"

	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// Registry answers the authorization library's questions about owners from
// the TXE registry, which is the only authority for who owns what.
type Registry struct {
	store *registry.Store
}

var _ authz.Registry = Registry{}

// NewRegistry returns the owner lookups of store.
func NewRegistry(store *registry.Store) Registry {
	return Registry{store: store}
}

// OwnerExists reports whether the owner is registered.
func (r Registry) OwnerExists(ctx context.Context, ownerID string) (bool, error) {
	if registry.ValidateID(registry.PrefixOwner, ownerID) != nil {
		return false, nil
	}
	_, err := r.store.GetOwner(ctx, ownerID)
	if err != nil {
		if registry.ErrorCode(err) == registry.CodeNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// JobFacts returns the owner, project and machine the registry records for a
// job.
func (r Registry) JobFacts(ctx context.Context, jobID string) (authz.JobFacts, error) {
	if registry.ValidateID(registry.PrefixJob, jobID) != nil {
		return authz.JobFacts{}, authz.ErrNotFound
	}
	job, err := r.store.GetJob(ctx, jobID)
	if err != nil {
		return authz.JobFacts{}, notFound(err)
	}
	return authz.JobFacts{OwnerID: job.OwnerID, ProjectID: job.ProjectID, MachineID: job.MachineID}, nil
}

// ProjectOwner returns the owner of a project.
func (r Registry) ProjectOwner(ctx context.Context, projectID string) (string, error) {
	if registry.ValidateID(registry.PrefixProject, projectID) != nil {
		return "", authz.ErrNotFound
	}
	p, err := r.store.GetProject(ctx, projectID)
	if err != nil {
		return "", notFound(err)
	}
	return p.OwnerID, nil
}

// MachineOwner returns the owner of a machine.
func (r Registry) MachineOwner(ctx context.Context, machineID string) (string, error) {
	if registry.ValidateID(registry.PrefixMachine, machineID) != nil {
		return "", authz.ErrNotFound
	}
	m, err := r.store.GetMachine(ctx, machineID)
	if err != nil {
		return "", notFound(err)
	}
	return m.OwnerID, nil
}

// OwnerDisplayName returns the display name the registry records for an
// owner, for a person to read. It is never used to match anything.
func (r Registry) OwnerDisplayName(ctx context.Context, ownerID string) (string, error) {
	o, err := r.store.GetOwner(ctx, ownerID)
	if err != nil {
		return "", notFound(err)
	}
	return o.DisplayName, nil
}

// notFound reports a registry miss as the library's ErrNotFound and passes
// every other error on, so a store that cannot be read is never taken for a
// record that does not exist.
func notFound(err error) error {
	if registry.ErrorCode(err) == registry.CodeNotFound {
		return authz.ErrNotFound
	}
	return err
}
