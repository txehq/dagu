// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"time"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
)

// State is whether a binding, share or enrolment is in force.
type State string

const (
	// StatePending is an enrolment that has been reserved and grants nothing
	// yet. Only enrolments are ever pending.
	StatePending State = "pending"
	StateActive  State = "active"
	StateRevoked State = "revoked"
)

// ActorKind says what kind of caller made a change.
type ActorKind string

const (
	ActorPlatformAdmin ActorKind = "platform_admin"
	ActorPerson        ActorKind = "person"
)

// Actor is who made a change, as recorded with it.
type Actor struct {
	Kind ActorKind `json:"kind"`
	// Name is the platform administrator's account name. It is recorded and
	// never matched.
	Name    string `json:"name,omitempty"`
	Issuer  string `json:"issuer,omitempty"`
	Subject string `json:"subject,omitempty"`
	OwnerID string `json:"owner_id,omitempty"`
}

// Stamp records when and by whom.
type Stamp struct {
	At time.Time `json:"at"`
	By Actor     `json:"by"`
}

// Revocation records the end of a binding, share or enrolment.
type Revocation struct {
	At     time.Time `json:"at"`
	By     Actor     `json:"by"`
	Reason string    `json:"reason"`
}

// Shown is what the identity provider said about an identity when it was
// recorded, for a human to read. Nothing ever matches on it.
type Shown struct {
	Username string `json:"username,omitempty"`
	Email    string `json:"email,omitempty"`
	Name     string `json:"name,omitempty"`
}

// RequestState is where a binding request stands, for a human to read.
// Whether a request can still be used is not read from it: that is decided by
// the binding, which records the request it consumed.
type RequestState string

const (
	RequestPending  RequestState = "pending"
	RequestApproved RequestState = "approved"
)

// BindingRequest records that an identity signed in and asked to be bound.
// It grants nothing.
type BindingRequest struct {
	Schema      int          `json:"schema"`
	Issuer      string       `json:"issuer"`
	Subject     string       `json:"subject"`
	Shown       Shown        `json:"shown"`
	State       RequestState `json:"state"`
	RequestedAt time.Time    `json:"requested_at"`
	// Generation counts the requests this identity has made. A new one is
	// needed after a binding is revoked.
	Generation int `json:"generation"`
}

// Binding links an identity to an owner. There is one record per identity, so
// an identity has at most one binding in force.
type Binding struct {
	Schema  int    `json:"schema"`
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
	OwnerID string `json:"owner_id"`
	// Generation counts the bindings this identity has had. A scope carries
	// the generation it was resolved from, and a later one does not satisfy it.
	Generation int `json:"generation"`
	// RequestGeneration is the binding request this binding consumed. It is
	// written with the binding, in one record, so a request is used exactly
	// once whatever happens to any other write: a request whose generation is
	// not above this one has been used and cannot make another binding.
	RequestGeneration int         `json:"request_generation"`
	State             State       `json:"state"`
	Bound             Stamp       `json:"bound"`
	Shown             Shown       `json:"shown"`
	Revoked           *Revocation `json:"revoked,omitempty"`
}

// Identity returns the identity the binding is for.
func (b *Binding) Identity() authn.Identity {
	return authn.Identity{Issuer: b.Issuer, Subject: b.Subject}
}

// ResourceKind names a kind of resource.
type ResourceKind string

const (
	KindJob     ResourceKind = "job"
	KindProject ResourceKind = "project"
	KindMachine ResourceKind = "machine"
	// KindOwner is everything an owner holds, for listing one's own data.
	KindOwner ResourceKind = "owner"
	// KindPlatform is the installation itself: bindings and their requests.
	KindPlatform ResourceKind = "platform"
)

// ResourceRef names a job or a project in a request to share it.
type ResourceRef struct {
	Kind ResourceKind `json:"kind"`
	ID   string       `json:"id"`
}

// Share grants another owner some permissions on one job or one project.
type Share struct {
	Schema         int          `json:"schema"`
	OwnerID        string       `json:"owner_id"`
	Resource       ResourceRef  `json:"resource"`
	GranteeOwnerID string       `json:"grantee_owner_id"`
	Permissions    []Permission `json:"permissions"`
	Generation     int          `json:"generation"`
	State          State        `json:"state"`
	Granted        Stamp        `json:"granted"`
	Revoked        *Revocation  `json:"revoked,omitempty"`
}

// EnrolmentKey is what an enrolment is found by: the identity provider's
// issuer and a provider client that exists for one machine and one class.
// The provider sets both, in every token it issues to that client; a caller
// can choose neither.
//
// Nothing else is a key. A provider session in particular is not: sign-ins
// made from one signed-in browser share a session, so it does not tell
// machines apart.
type EnrolmentKey struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
}

// KeyOf returns the key a verified principal carries.
func KeyOf(p authn.Principal) (EnrolmentKey, error) {
	if p.Issuer == "" || p.ClientID == "" {
		return EnrolmentKey{}, refuse(CodeInvalid, "the credential names no issuer or no client")
	}
	return EnrolmentKey{Issuer: p.Issuer, ClientID: p.ClientID}, nil
}

// Enrolment lets one machine act for its owner as one class. There is one
// record per machine and class.
type Enrolment struct {
	Schema    int         `json:"schema"`
	MachineID string      `json:"machine_id"`
	Class     authn.Class `json:"class"`
	OwnerID   string      `json:"owner_id"`
	// Issuer and Subject are the identity the machine signs in as. It must
	// be bound to OwnerID for as long as the enrolment is used.
	Issuer  string       `json:"issuer"`
	Subject string       `json:"subject"`
	Key     EnrolmentKey `json:"key"`
	// SessionID is the provider session of the credential the machine was
	// enrolled with. It is recorded so that the session can be ended at the
	// provider. It is never matched and never finds an enrolment.
	SessionID  string      `json:"session_id,omitempty"`
	Generation int         `json:"generation"`
	State      State       `json:"state"`
	Enrolled   Stamp       `json:"enrolled"`
	Revoked    *Revocation `json:"revoked,omitempty"`
}

// keyClaim is the index record that makes a key belong to one machine and
// class for good. It is created once and never changed or removed, so a key
// can never be pointed at another machine, even after its enrolment is
// revoked.
type keyClaim struct {
	Schema    int          `json:"schema"`
	Key       EnrolmentKey `json:"key"`
	MachineID string       `json:"machine_id"`
	Class     authn.Class  `json:"class"`
	ClaimedAt time.Time    `json:"claimed_at"`
}

// Record ids. Every free-text part is hashed, so nothing a provider or a
// caller chose becomes a path.
const (
	requestsPrefix   = "requests/"
	bindingsPrefix   = "bindings/"
	bindingHistory   = "binding_history/"
	sharesPrefix     = "shares/"
	shareHistory     = "share_history/"
	enrolmentsPrefix = "enrolments/"
	enrolmentHistory = "enrolment_history/"
	keysPrefix       = "enrolment_keys/"
)

// digest hashes parts so that no two different lists of parts collide: each
// part is preceded by its length.
func digest(parts ...string) string {
	h := sha256.New()
	var size [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		h.Write(size[:])
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func identityDigest(id authn.Identity) string {
	return digest("identity", id.Issuer, id.Subject)
}

func shareDigest(ownerID string, resource ResourceRef, granteeOwnerID string) string {
	return digest("share", ownerID, string(resource.Kind), resource.ID, granteeOwnerID)
}

func enrolmentDigest(machineID string, class authn.Class) string {
	return digest("enrolment", machineID, string(class))
}

func keyDigest(key EnrolmentKey) string {
	return digest("key", key.Issuer, key.ClientID)
}

// normalizePermissions returns the permissions sorted in their defined order
// and without repeats, or an error if one is not shareable.
func normalizePermissions(permissions []Permission) ([]Permission, error) {
	if len(permissions) == 0 {
		return nil, refuse(CodeInvalid, "a share grants at least one permission")
	}
	var out []Permission
	for _, p := range allPermissions {
		if slices.Contains(permissions, p) {
			out = append(out, p)
		}
	}
	for _, p := range permissions {
		if !p.Shareable() {
			return nil, refuse(CodeInvalid, "permission %q cannot be shared", p)
		}
	}
	return out, nil
}
