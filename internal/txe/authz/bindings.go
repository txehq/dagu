// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"context"
	"encoding/json"

	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
)

// RequestBinding records that a person signed in and asks to be bound to an
// owner. It grants nothing: the identity stays unbound until the platform
// administrator approves the request for an owner.
//
// Only a person can ask. A token, whatever its class, cannot open a request,
// because a request is the proof that the subject signed in themselves.
// Asking again while a request is pending returns it unchanged; asking while
// bound returns the request that was approved.
func (s *Store) RequestBinding(ctx context.Context, p authn.Principal, shown Shown) (*BindingRequest, error) {
	if !p.IsPerson() {
		return nil, refuse(CodeForbidden, "only a person who signed in can ask to be bound")
	}
	if p.IsZero() {
		return nil, refuse(CodeInvalid, "the principal has no issuer or no subject")
	}
	if expired(p, s.clock()) {
		return nil, refuse(CodeForbidden, "the sign-in has expired")
	}
	id := requestsPrefix + identityDigest(p.Identity)

	for range attempts {
		var current BindingRequest
		raw, found, err := s.read(ctx, id, &current)
		if err != nil {
			return nil, err
		}
		if !found {
			request := BindingRequest{
				Schema: SchemaVersion, Issuer: p.Issuer, Subject: p.Subject, Shown: shown,
				State: RequestPending, RequestedAt: s.clock(), Generation: 1,
			}
			created, err := s.create(ctx, id, request)
			if err != nil {
				return nil, err
			}
			if created {
				return &request, nil
			}
			continue
		}
		if current.State == RequestPending {
			return &current, nil
		}
		// The last request was approved. A new one is wanted only if the
		// binding it led to has since been revoked.
		binding, _, err := s.binding(ctx, p.Identity)
		if err != nil {
			return nil, err
		}
		if binding != nil && binding.State == StateActive {
			return &current, nil
		}
		next := current
		next.Shown, next.State, next.RequestedAt = shown, RequestPending, s.clock()
		next.Generation = current.Generation + 1
		swapped, err := s.swap(ctx, id, raw, next)
		if err != nil {
			return nil, err
		}
		if swapped {
			return &next, nil
		}
	}
	return nil, errContended
}

// PendingRequest returns the identity's binding request if one is waiting,
// or nil.
func (s *Store) PendingRequest(ctx context.Context, id authn.Identity) (*BindingRequest, error) {
	var request BindingRequest
	_, found, err := s.read(ctx, requestsPrefix+identityDigest(id), &request)
	if err != nil || !found || request.State != RequestPending {
		return nil, err
	}
	return &request, nil
}

// ApproveBinding binds an identity to an owner.
//
// It takes two things that only different parties can supply: a pending
// request, which the subject made by signing in, and the platform
// administrator's approval naming the owner. The owner must already be
// registered; no owner is created here or anywhere in this package.
//
// Approving again with the same owner returns the binding that stands.
// Approving for a different owner while a binding stands is refused with
// CodeConflict and changes nothing.
func (s *Store) ApproveBinding(ctx context.Context, by Scope, id authn.Identity, ownerID string) (*Binding, error) {
	if by.Kind() != ScopePlatformAdmin {
		return nil, refuse(CodeForbidden, "only the platform administrator binds an identity to an owner")
	}
	if id.IsZero() || ownerID == "" {
		return nil, refuse(CodeInvalid, "an issuer, a subject and an owner are required")
	}
	exists, err := s.registry.OwnerExists(ctx, ownerID)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, refuse(CodeNotFound, "owner %s is not registered; a binding does not create one", ownerID)
	}

	bindingID := bindingsPrefix + identityDigest(id)
	for range attempts {
		var current Binding
		raw, found, err := s.read(ctx, bindingID, &current)
		if err != nil {
			return nil, err
		}
		if found && current.State == StateActive {
			if current.OwnerID != ownerID {
				return nil, &Error{
					Code:    CodeConflict,
					Message: "the identity is already bound to another owner; revoke that binding first",
					Current: &current,
				}
			}
			// A repeat. Finish marking the request in case an earlier
			// approval stopped between the two records.
			if err := s.markApproved(ctx, id); err != nil {
				return nil, err
			}
			return &current, nil
		}

		request, err := s.PendingRequest(ctx, id)
		if err != nil {
			return nil, err
		}
		if request == nil {
			return nil, refuse(CodeNotFound, "the identity has no pending binding request; it must sign in and ask first")
		}

		next := Binding{
			Schema: SchemaVersion, Issuer: id.Issuer, Subject: id.Subject, OwnerID: ownerID,
			Generation: 1, State: StateActive, Bound: Stamp{At: s.clock(), By: by.actor()}, Shown: request.Shown,
		}
		var applied bool
		if found {
			next.Generation = current.Generation + 1
			if err := s.archive(ctx, bindingHistory, identityDigest(id), current.Generation, current); err != nil {
				return nil, err
			}
			applied, err = s.swap(ctx, bindingID, raw, next)
		} else {
			applied, err = s.create(ctx, bindingID, next)
		}
		if err != nil {
			return nil, err
		}
		if !applied {
			continue
		}
		if err := s.markApproved(ctx, id); err != nil {
			return nil, err
		}
		return &next, nil
	}
	return nil, errContended
}

// markApproved moves a pending request to approved. A request that is not
// pending is left alone.
func (s *Store) markApproved(ctx context.Context, id authn.Identity) error {
	requestID := requestsPrefix + identityDigest(id)
	for range attempts {
		var request BindingRequest
		raw, found, err := s.read(ctx, requestID, &request)
		if err != nil {
			return err
		}
		if !found || request.State != RequestPending {
			return nil
		}
		request.State = RequestApproved
		swapped, err := s.swap(ctx, requestID, raw, request)
		if err != nil {
			return err
		}
		if swapped {
			return nil
		}
	}
	return errContended
}

// RevokeBinding ends an identity's binding. From the next decision on, the
// identity acts for nobody, and so does every machine enrolled under it.
// Revoking a binding that is already revoked returns it unchanged.
func (s *Store) RevokeBinding(ctx context.Context, by Scope, id authn.Identity, reason string) (*Binding, error) {
	if by.Kind() != ScopePlatformAdmin {
		return nil, refuse(CodeForbidden, "only the platform administrator revokes a binding")
	}
	if reason == "" {
		return nil, refuse(CodeInvalid, "a reason is required")
	}
	bindingID := bindingsPrefix + identityDigest(id)
	for range attempts {
		var current Binding
		raw, found, err := s.read(ctx, bindingID, &current)
		if err != nil {
			return nil, err
		}
		if !found {
			return nil, refuse(CodeNotFound, "the identity has no binding")
		}
		if current.State == StateRevoked {
			return &current, nil
		}
		current.State = StateRevoked
		current.Revoked = &Revocation{At: s.clock(), By: by.actor(), Reason: reason}
		swapped, err := s.swap(ctx, bindingID, raw, current)
		if err != nil {
			return nil, err
		}
		if swapped {
			return &current, nil
		}
	}
	return nil, errContended
}

// Bindings returns the bindings to an owner, revoked ones included, oldest
// first.
func (s *Store) Bindings(ctx context.Context, ownerID string) ([]*Binding, error) {
	var out []*Binding
	err := s.each(ctx, bindingsPrefix, func(data []byte) error {
		var binding Binding
		if err := json.Unmarshal(data, &binding); err != nil {
			return err
		}
		if binding.OwnerID == ownerID {
			out = append(out, &binding)
		}
		return nil
	})
	return out, err
}

// binding returns the identity's binding record, in force or not, and the
// bytes it was stored as.
func (s *Store) binding(ctx context.Context, id authn.Identity) (*Binding, []byte, error) {
	var binding Binding
	raw, found, err := s.read(ctx, bindingsPrefix+identityDigest(id), &binding)
	if err != nil || !found {
		return nil, nil, err
	}
	return &binding, raw, nil
}

// activeBinding returns the identity's binding if it is in force, or nil and
// the reason it is not.
func (s *Store) activeBinding(ctx context.Context, id authn.Identity) (*Binding, Reason, error) {
	binding, _, err := s.binding(ctx, id)
	if err != nil {
		return nil, ReasonEvaluationFailed, err
	}
	switch {
	case binding == nil:
		return nil, ReasonUnbound, nil
	case binding.State != StateActive:
		return nil, ReasonBindingRevoked, nil
	// The record is found by a digest of the identity. Checking the identity
	// itself costs nothing and does not depend on the digest.
	case binding.Issuer != id.Issuer || binding.Subject != id.Subject:
		return nil, ReasonUnbound, nil
	}
	return binding, "", nil
}

// each calls fn with the data of every record under prefix.
func (s *Store) each(ctx context.Context, prefix string, fn func(data []byte) error) error {
	cursor := ""
	for {
		page, err := s.col.List(ctx, persis.ListQuery{Prefix: prefix, Cursor: cursor})
		if err != nil {
			return err
		}
		for _, rec := range page.Records {
			if err := fn(rec.Data); err != nil {
				return err
			}
		}
		if page.NextCursor == "" {
			return nil
		}
		cursor = page.NextCursor
	}
}
