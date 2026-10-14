// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
)

// ShareGrant asks for a share. The resource's owner is not part of it: the
// registry says who owns the job or the project.
type ShareGrant struct {
	Resource       ResourceRef
	GranteeOwnerID string
	Permissions    []Permission
}

// GrantShare lets another owner use one job or one project.
//
// The caller must be a person acting for the owner the registry records for
// the resource. The grantee must be another registered owner. Granting again
// with the same permissions returns the share that stands; different
// permissions for a share that stands are refused with CodeConflict and
// change nothing, so a share is widened only by revoking it and granting
// anew.
func (s *Store) GrantShare(ctx context.Context, by Scope, grant ShareGrant) (*Share, error) {
	permissions, err := normalizePermissions(grant.Permissions)
	if err != nil {
		return nil, err
	}
	ownerID, err := s.administeredOwner(ctx, by, grant.Resource)
	if err != nil {
		return nil, err
	}
	if grant.GranteeOwnerID == "" || grant.GranteeOwnerID == ownerID {
		return nil, refuse(CodeInvalid, "a share names another owner")
	}
	exists, err := s.registry.OwnerExists(ctx, grant.GranteeOwnerID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, refuse(CodeNotFound, "owner %s is not registered", grant.GranteeOwnerID)
	}

	key := shareDigest(ownerID, grant.Resource, grant.GranteeOwnerID)
	for range attempts {
		var current Share
		raw, found, err := s.read(ctx, sharesPrefix+key, &current)
		if err != nil {
			return nil, err
		}
		if found && current.State == StateActive {
			if !slices.Equal(current.Permissions, permissions) {
				return nil, &Error{
					Code:    CodeConflict,
					Message: "the share stands with other permissions; revoke it and grant it again to change them",
					Current: &current,
				}
			}
			return &current, nil
		}
		next := Share{
			Schema: SchemaVersion, OwnerID: ownerID, Resource: grant.Resource, GranteeOwnerID: grant.GranteeOwnerID,
			Permissions: permissions, Generation: 1, State: StateActive, Granted: Stamp{At: s.clock(), By: by.actor()},
		}
		var applied bool
		if found {
			next.Generation = current.Generation + 1
			if err := s.archive(ctx, shareHistory, key, current.Generation, current); err != nil {
				return nil, err
			}
			applied, err = s.swap(ctx, sharesPrefix+key, raw, next)
		} else {
			applied, err = s.create(ctx, sharesPrefix+key, next)
		}
		if err != nil {
			return nil, err
		}
		if applied {
			return &next, nil
		}
	}
	return nil, errContended
}

// RevokeShare ends a share. Revoking one that is already revoked returns it
// unchanged.
func (s *Store) RevokeShare(ctx context.Context, by Scope, resource ResourceRef, granteeOwnerID, reason string) (*Share, error) {
	if reason == "" {
		return nil, refuse(CodeInvalid, "a reason is required")
	}
	ownerID, err := s.administeredOwner(ctx, by, resource)
	if err != nil {
		return nil, err
	}
	id := sharesPrefix + shareDigest(ownerID, resource, granteeOwnerID)
	for range attempts {
		var current Share
		raw, found, err := s.read(ctx, id, &current)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, refuse(CodeNotFound, "there is no such share")
		}
		if current.State == StateRevoked {
			return &current, nil
		}
		current.State = StateRevoked
		current.Revoked = &Revocation{At: s.clock(), By: by.actor(), Reason: reason}
		swapped, err := s.swap(ctx, id, raw, current)
		if err != nil {
			return nil, err
		}
		if swapped {
			return &current, nil
		}
	}
	return nil, errContended
}

// Shares returns the shares an owner has granted, revoked ones included,
// oldest first.
func (s *Store) Shares(ctx context.Context, ownerID string) ([]*Share, error) {
	var out []*Share
	err := s.each(ctx, sharesPrefix, func(data []byte) error {
		var share Share
		if err := json.Unmarshal(data, &share); err != nil {
			return err
		}
		if share.OwnerID == ownerID {
			out = append(out, &share)
		}
		return nil
	})
	return out, err
}

// administeredOwner returns the owner the registry records for a job or a
// project, after checking that the caller is a person who acts for that owner
// now. A caller acting for another owner is told the resource is not found,
// the same answer as for one that does not exist.
func (s *Store) administeredOwner(ctx context.Context, by Scope, ref ResourceRef) (string, error) {
	if err := s.requirePerson(ctx, by); err != nil {
		return "", err
	}
	var (
		resource Resource
		err      error
	)
	switch ref.Kind {
	case KindJob:
		resource, err = s.Job(ctx, ref.ID)
	case KindProject:
		resource, err = s.Project(ctx, ref.ID)
	case KindMachine, KindOwner, KindPlatform:
		return "", refuse(CodeInvalid, "only a job or a project can be shared")
	default:
		return "", refuse(CodeInvalid, "only a job or a project can be shared")
	}
	if err != nil {
		return "", err
	}
	if resource.ownerID != by.ownerID {
		return "", refuse(CodeNotFound, "%s %s is not registered", ref.Kind, ref.ID)
	}
	return resource.ownerID, nil
}

// requirePerson checks that the caller is a person whose binding to an owner
// still stands. Only such a caller administers an owner's shares and
// enrolments.
func (s *Store) requirePerson(ctx context.Context, by Scope) error {
	if by.Kind() != ScopeOwner || by.principal.Class != authn.ClassPerson {
		return refuse(CodeForbidden, "only a person acting for the owner may do this")
	}
	if expired(by.principal, s.clock()) {
		return refuse(CodeForbidden, "the sign-in has expired")
	}
	binding, _, err := s.activeBinding(ctx, by.principal.Identity)
	if err != nil {
		return err
	}
	if binding == nil || binding.OwnerID != by.ownerID || binding.Generation != by.bindingGeneration {
		return refuse(CodeForbidden, "the caller's binding no longer stands")
	}
	return nil
}

// activeShare returns the share of a resource to a grantee if it is in force.
func (s *Store) activeShare(ctx context.Context, ownerID string, ref ResourceRef, granteeOwnerID string) (*Share, error) {
	var share Share
	_, found, err := s.read(ctx, sharesPrefix+shareDigest(ownerID, ref, granteeOwnerID), &share)
	if err != nil || !found || share.State != StateActive {
		return nil, err
	}
	// The record is found by a digest. Its own fields are what is trusted.
	if share.OwnerID != ownerID || share.Resource != ref || share.GranteeOwnerID != granteeOwnerID {
		return nil, nil
	}
	return &share, nil
}

// ShareID is the opaque id a share is named by outside this package: the
// granting owner, the resource and the grantee, which name its one record.
func ShareID(share *Share) string {
	return shareDigest(share.OwnerID, share.Resource, share.GranteeOwnerID)
}

// SharesReceived returns the shares granted to an owner, revoked ones
// included.
func (s *Store) SharesReceived(ctx context.Context, granteeOwnerID string) ([]*Share, error) {
	var out []*Share
	err := s.each(ctx, sharesPrefix, func(data []byte) error {
		var share Share
		if err := json.Unmarshal(data, &share); err != nil {
			return err
		}
		if share.GranteeOwnerID == granteeOwnerID {
			out = append(out, &share)
		}
		return nil
	})
	return out, err
}
