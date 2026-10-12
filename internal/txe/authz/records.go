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

// RequestState is where a binding request stands.
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
	Generation int         `json:"generation"`
	State      State       `json:"state"`
	Bound      Stamp       `json:"bound"`
	Shown      Shown       `json:"shown"`
	Revoked    *Revocation `json:"revoked,omitempty"`
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

// KeyKind says which provider-set value ties a credential to one machine.
type KeyKind string

const (
	// KeyClient ties a machine to a provider client that exists for that
	// machine alone. Every token issued to that client is the machine's.
	KeyClient KeyKind = "client"
	// KeySession ties a machine to one provider session of a client. It is
	// safe only when each machine signs in from a browser with no session
	// yet: sign-ins made in one signed-in browser share a session, and the
	// second machine to present it is refused.
	KeySession KeyKind = "session"
)

// EnrolmentKey is what an enrolment is found by. The provider sets every
// part of it; a caller can choose none.
type EnrolmentKey struct {
	Kind      KeyKind `json:"kind"`
	Issuer    string  `json:"issuer"`
	ClientID  string  `json:"client_id"`
	SessionID string  `json:"session_id,omitempty"`
}

// KeyOf returns the key of the given kind that a verified principal carries.
func KeyOf(kind KeyKind, p authn.Principal) (EnrolmentKey, error) {
	if p.Issuer == "" || p.ClientID == "" {
		return EnrolmentKey{}, refuse(CodeInvalid, "the credential names no issuer or no client")
	}
	switch kind {
	case KeyClient:
		return EnrolmentKey{Kind: KeyClient, Issuer: p.Issuer, ClientID: p.ClientID}, nil
	case KeySession:
		if p.SessionID == "" {
			return EnrolmentKey{}, refuse(CodeInvalid, "the credential names no session")
		}
		return EnrolmentKey{Kind: KeySession, Issuer: p.Issuer, ClientID: p.ClientID, SessionID: p.SessionID}, nil
	default:
		return EnrolmentKey{}, refuse(CodeInvalid, "unknown enrolment key kind %q", kind)
	}
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
	Issuer     string       `json:"issuer"`
	Subject    string       `json:"subject"`
	Key        EnrolmentKey `json:"key"`
	Generation int          `json:"generation"`
	State      State        `json:"state"`
	Enrolled   Stamp        `json:"enrolled"`
	Revoked    *Revocation  `json:"revoked,omitempty"`
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

// clientMode records which kind of key a provider client's machines are
// enrolled by. It is created once and never changed. Without it, a client
// whose machines are told apart by session could later be claimed whole by
// one machine as a client key, and that machine would then be every machine
// of that client.
type clientMode struct {
	Schema   int     `json:"schema"`
	Issuer   string  `json:"issuer"`
	ClientID string  `json:"client_id"`
	Kind     KeyKind `json:"kind"`
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
	modesPrefix      = "client_modes/"
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

func clientDigest(issuer, clientID string) string {
	return digest("client", issuer, clientID)
}

func keyDigest(key EnrolmentKey) string {
	return digest("key", string(key.Kind), key.Issuer, key.ClientID, key.SessionID)
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
