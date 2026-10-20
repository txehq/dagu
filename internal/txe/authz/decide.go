// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"context"
	"slices"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
)

// Reason says why a decision came out as it did, or why a principal acts for
// nobody.
type Reason string

const (
	// ReasonModeOff: nothing was evaluated.
	ReasonModeOff Reason = "mode_off"
	// ReasonOwner: the principal acts for the resource's owner.
	ReasonOwner Reason = "owner"
	// ReasonShare: a share from the resource's owner covers it.
	ReasonShare Reason = "share"
	// ReasonPlatformAdmin: the platform administrator, within what that
	// role may do.
	ReasonPlatformAdmin Reason = "platform_admin"

	// ReasonUnbound: the identity has no binding.
	ReasonUnbound Reason = "unbound"
	// ReasonNoIdentity: the principal has no issuer or no subject.
	ReasonNoIdentity Reason = "no_identity"
	// ReasonExpired: the principal is at or past the expiry of its token.
	ReasonExpired Reason = "expired"
	// ReasonBindingRevoked: the binding the scope came from no longer stands.
	ReasonBindingRevoked Reason = "binding_revoked"
	// ReasonNotEnrolled: the credential's key belongs to no enrolment, or to
	// one that no longer matches the credential.
	ReasonNotEnrolled Reason = "not_enrolled"
	// ReasonEnrolmentRevoked: the enrolment the scope came from no longer
	// stands.
	ReasonEnrolmentRevoked Reason = "enrolment_revoked"
	// ReasonClass: this class of principal may never do this.
	ReasonClass Reason = "class"
	// ReasonNotOwner: the resource belongs to another owner and no share
	// covers the request.
	ReasonNotOwner Reason = "not_owner"
	// ReasonOtherMachine: a machine asked about a resource of another
	// machine.
	ReasonOtherMachine Reason = "other_machine"
	// ReasonInvalid: the permission or the resource is not one.
	ReasonInvalid Reason = "invalid"
	// ReasonEvaluationFailed: the store or the registry could not be read.
	ReasonEvaluationFailed Reason = "evaluation_failed"
)

// Decision is the answer to one question: may this scope do this to this
// resource.
type Decision struct {
	// Allowed is the answer the caller must act on.
	Allowed bool
	// Mode is the mode the decision was made in.
	Mode Mode
	// Evaluated is false only in ModeOff.
	Evaluated bool
	// WouldDeny is true in ModeObserve when ModeEnforce would have denied.
	// It is what an observing service records.
	WouldDeny bool
	// Reason says why.
	Reason Reason
	// ShareOwnerID is the owner whose share allowed it, when a share did.
	ShareOwnerID string
	// BreakGlass is true when the platform administrator was allowed to see
	// an owner's data. The caller must record such an access.
	BreakGlass bool
}

// Decide answers whether scope may exercise permission on resource.
//
// In ModeOff it allows without looking at anything. In ModeObserve it
// evaluates, allows, and sets WouldDeny when ModeEnforce would have denied.
// In ModeEnforce it allows only what the evaluation allows.
//
// The scope is a snapshot. Decide reads the binding it came from again, the
// enrolment for a machine, and the share when one is needed, so that a
// revocation made after the scope was resolved is seen here. It also refuses
// a scope whose token has expired since.
//
// An error means the store or the registry could not be read. In ModeEnforce
// the decision is then a denial; in ModeObserve it is an allowance marked
// WouldDeny, because that is what enforcing would have done.
func (s *Store) Decide(ctx context.Context, mode Mode, scope Scope, permission Permission, resource Resource) (Decision, error) {
	switch mode {
	case ModeOff:
		return Decision{Allowed: true, Mode: ModeOff, Reason: ReasonModeOff}, nil
	case ModeObserve, ModeEnforce:
	default:
		// An unknown mode is not a reason to allow.
		return Decision{Mode: mode, Evaluated: true, Reason: ReasonInvalid}, refuse(CodeInvalid, "unknown mode %q", mode)
	}

	verdict, err := s.evaluate(ctx, scope, permission, resource)
	decision := Decision{
		Allowed:      verdict.allowed,
		Mode:         mode,
		Evaluated:    true,
		Reason:       verdict.reason,
		ShareOwnerID: verdict.shareOwnerID,
		BreakGlass:   verdict.breakGlass,
	}
	if err != nil {
		decision.Allowed, decision.Reason = false, ReasonEvaluationFailed
		decision.ShareOwnerID, decision.BreakGlass = "", false
	}
	if mode == ModeObserve {
		decision.WouldDeny = !decision.Allowed
		decision.Allowed = true
		// An observing service keeps running on a store it cannot read. The
		// failure is in the decision, where it is recorded.
		return decision, nil
	}
	return decision, err
}

type verdict struct {
	allowed      bool
	reason       Reason
	shareOwnerID string
	breakGlass   bool
}

func deny(reason Reason) (verdict, error) { return verdict{reason: reason}, nil }

func (s *Store) evaluate(ctx context.Context, scope Scope, permission Permission, resource Resource) (verdict, error) {
	if !permission.Valid() || resource.kind == "" || resource.id == "" {
		return deny(ReasonInvalid)
	}

	switch scope.Kind() {
	case ScopePlatformAdmin:
		// A bound administrator is also its owner's person: on its owner's
		// records, and what is shared to that owner, it may do what that
		// person may, and the administrator's own rights come on top. It
		// gains nothing else on another owner's records. The routes that
		// hold a person to more than the decision (writes only a machine
		// makes, writes closed to a person) hold it to the same.
		if person, ok := scope.OwnerPerson(); ok && resource.kind != KindPlatform {
			v, err := s.evaluate(ctx, person, permission, resource)
			if err != nil || v.allowed {
				return v, err
			}
		}
		return evaluateAdmin(permission, resource), nil

	case ScopeOwner:
		if reason, err := s.ownerStands(ctx, scope); reason != "" || err != nil {
			return verdict{reason: reason}, err
		}
		if !slices.Contains(classPermissions[scope.principal.Class], permission) {
			return deny(ReasonClass)
		}
		if resource.kind == KindPlatform {
			return deny(ReasonNotOwner)
		}
		if resource.ownerID == scope.ownerID {
			return verdict{allowed: true, reason: ReasonOwner}, nil
		}
		return s.evaluateShare(ctx, scope, permission, resource)

	case ScopeMachine:
		if reason, err := s.machineStands(ctx, scope); reason != "" || err != nil {
			return verdict{reason: reason}, err
		}
		if !slices.Contains(classPermissions[scope.principal.Class], permission) {
			return deny(ReasonClass)
		}
		// A machine acts on what is its owner's and on this machine. No
		// share reaches a machine.
		if resource.ownerID != scope.ownerID || resource.ownerID == "" {
			return deny(ReasonNotOwner)
		}
		if resource.machineID != scope.machineID {
			return deny(ReasonOtherMachine)
		}
		return verdict{allowed: true, reason: ReasonOwner}, nil

	case ScopeUnbound:
		return denyUnbound(scope)
	default:
		return denyUnbound(scope)
	}
}

// denyUnbound is the answer for a principal that acts for nobody.
func denyUnbound(scope Scope) (verdict, error) {
	if scope.reason == "" {
		return deny(ReasonUnbound)
	}
	return deny(scope.reason)
}

// evaluateAdmin is what the platform administrator may do. It administers the
// platform, which is how bindings are approved, and it may look at an
// owner's data, which the caller records. It is not an owner: it does not
// author, execute or approve anything of anyone's.
func evaluateAdmin(permission Permission, resource Resource) verdict {
	switch {
	case resource.kind == KindPlatform && (permission == PermissionAdminister || permission == PermissionView):
		return verdict{allowed: true, reason: ReasonPlatformAdmin}
	case resource.kind != KindPlatform && permission == PermissionView:
		return verdict{allowed: true, reason: ReasonPlatformAdmin, breakGlass: true}
	default:
		return verdict{reason: ReasonClass}
	}
}

// evaluateShare looks for a share that lets the scope's owner use a resource
// of another owner: one on the job itself, or one on the project it is in.
func (s *Store) evaluateShare(ctx context.Context, scope Scope, permission Permission, resource Resource) (verdict, error) {
	if !permission.Shareable() || resource.ownerID == "" {
		return deny(ReasonNotOwner)
	}
	var refs []ResourceRef
	switch resource.kind {
	case KindJob:
		refs = append(refs, ResourceRef{Kind: KindJob, ID: resource.id})
		if resource.projectID != "" {
			refs = append(refs, ResourceRef{Kind: KindProject, ID: resource.projectID})
		}
	case KindProject:
		refs = append(refs, ResourceRef{Kind: KindProject, ID: resource.id})
	case KindMachine, KindOwner, KindPlatform:
		// Machines and an owner's whole data are never shared.
		return deny(ReasonNotOwner)
	default:
		return deny(ReasonNotOwner)
	}
	for _, ref := range refs {
		share, err := s.activeShare(ctx, resource.ownerID, ref, scope.ownerID)
		if err != nil {
			return verdict{reason: ReasonEvaluationFailed}, err
		}
		if share != nil && slices.Contains(share.Permissions, permission) {
			return verdict{allowed: true, reason: ReasonShare, shareOwnerID: share.OwnerID}, nil
		}
	}
	return deny(ReasonNotOwner)
}

// ownerStands reads again the binding an owner scope came from. It returns a
// reason when the scope no longer stands.
func (s *Store) ownerStands(ctx context.Context, scope Scope) (Reason, error) {
	if expired(scope.principal, s.clock()) {
		return ReasonExpired, nil
	}
	binding, reason, err := s.activeBinding(ctx, scope.principal.Identity)
	if err != nil {
		return ReasonEvaluationFailed, err
	}
	if binding == nil {
		return reason, nil
	}
	// A binding revoked and made again, even for the same owner, is a new
	// one. The scope came from the old one.
	if binding.OwnerID != scope.ownerID || binding.Generation != scope.bindingGeneration {
		return ReasonBindingRevoked, nil
	}
	return "", nil
}

// machineStands reads again the enrolment and the binding a machine scope
// came from.
func (s *Store) machineStands(ctx context.Context, scope Scope) (Reason, error) {
	if expired(scope.principal, s.clock()) {
		return ReasonExpired, nil
	}
	found, err := s.activeEnrolment(ctx, scope.principal)
	if err != nil {
		return ReasonEvaluationFailed, err
	}
	enrolment := found.enrolment
	if enrolment == nil {
		return found.reason, nil
	}
	if enrolment.MachineID != scope.machineID || enrolment.OwnerID != scope.ownerID || enrolment.Generation != scope.enrolmentGeneration {
		return ReasonEnrolmentRevoked, nil
	}
	if found.binding.Generation != scope.bindingGeneration {
		return ReasonBindingRevoked, nil
	}
	return "", nil
}

// IsHuman reports whether a decision made by this scope counts as a person's
// own. Only someone signed in through the browser does, the platform
// administrator only as the person it is bound as. A token of any class is an
// agent, whoever it acts for.
func IsHuman(scope Scope) bool {
	if person, ok := scope.OwnerPerson(); ok {
		scope = person
	}
	return scope.Kind() == ScopeOwner && scope.principal.Class == authn.ClassPerson
}
