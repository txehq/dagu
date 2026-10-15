// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package continuity inventories a retained TXE installation and checks it,
// so that an upgrade or a storage move can show that nothing was lost,
// reassigned or broken.
//
// An inventory lists every record of the TXE registry and its authorization
// store with its digest, its owner and the records it refers to, and every
// retained native Dagu file and local package or output with its digest.
// Validate checks one inventory on its own: relationships resolve, every
// owner is the installation's stable owner, and nothing is of a kind this
// package does not understand. Compare checks a later inventory against an
// earlier one: nothing retained is missing and nothing immutable changed.
//
// Scanning only reads. It never follows a credential reference, and it does
// not read areas that hold credentials (users, API keys, webhooks, remote
// contexts, a CLI's client directory); those are listed as excluded. Owners
// are only ever taken from owner_id fields: never from a display name, an
// email address, an identity provider account or who logged in first.
package continuity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// FormatV1 names this inventory format. A reader refuses any other.
const FormatV1 = "txe.continuity.inventory/v1"

// Areas a root can be scanned as.
const (
	// AreaHubData is the hub's Dagu data directory; the TXE registry and
	// authorization store are under it.
	AreaHubData = "hub-data"
	// AreaDAGs is the hub's DAG definitions directory.
	AreaDAGs = "dags"
	// AreaLogs is the hub's run log directory.
	AreaLogs = "logs"
	// AreaArtifacts is the hub's native artifact directory, when it is not
	// under the data directory.
	AreaArtifacts = "artifacts"
	// AreaMachineHome is a machine's TXE home: its identity, packages,
	// receipts and outputs.
	AreaMachineHome = "machine-home"
)

// Record classes.
const (
	ClassOwner                = "owner"
	ClassProject              = "project"
	ClassMachine              = "machine"
	ClassJob                  = "job"
	ClassVersion              = "version"
	ClassEvent                = "event"
	ClassDecision             = "decision"
	ClassReview               = "review"
	ClassAction               = "action"
	ClassProposal             = "proposal"
	ClassClosure              = "closure"
	ClassDedupe               = "dedupe"
	ClassProjectKey           = "project_key"
	ClassResourceID           = "resource_id"
	ClassResourceName         = "resource_name"
	ClassResourceEvent        = "resource_event"
	ClassResourceEventPending = "resource_event_pending"
	ClassResourceIndexReady   = "resource_index_ready"
	ClassArtifactManifest     = "artifact_manifest"
	ClassExecutionEvidence    = "execution_evidence"
	ClassBindingRequest       = "binding_request"
	ClassBinding              = "binding"
	ClassBindingHistory       = "binding_history"
	ClassShare                = "share"
	ClassShareHistory         = "share_history"
	ClassEnrolment            = "enrolment"
	ClassEnrolmentHistory     = "enrolment_history"
	ClassEnrolmentKey         = "enrolment_key"
	ClassPackage              = "package"
	ClassMachineIdentity      = "machine_identity"
	// ClassUnknown is a record this package does not understand. It always
	// comes with a blocking issue.
	ClassUnknown = "unknown"
)

// Entity kinds a record can define or refer to. Kind "record" is a stored
// record by its storage ID; the others are logical IDs.
const (
	KindRecord    = "record"
	KindOwner     = "owner"
	KindProject   = "project"
	KindMachine   = "machine"
	KindJob       = "job"
	KindProposal  = "proposal"
	KindDecision  = "decision"
	KindReview    = "review"
	KindAction    = "action"
	KindEvent     = "resource_event"
	KindPackage   = "package"
	KindEnrolment = "enrolment"
	KindException = "exception"
)

// Inventory is everything retained at one point, with digests.
type Inventory struct {
	Format    string    `json:"format"`
	Label     string    `json:"label,omitempty"`
	ScannedAt time.Time `json:"scanned_at"`
	// Tool is the build of the tool that scanned, when known.
	Tool          string `json:"tool,omitempty"`
	ExpectedOwner string `json:"expected_owner"`
	// ModeBits says the scan recorded permission bits; on a system without
	// them every file's Mode is unknown, not zero.
	ModeBits bool              `json:"mode_bits,omitempty"`
	Roots    []RootInfo        `json:"roots"`
	Counts   map[string]int    `json:"counts"`
	Records  []Record          `json:"records"`
	Files    []File            `json:"files"`
	Excluded []Excluded        `json:"excluded,omitempty"`
	Issues   []Issue           `json:"issues,omitempty"`
	Machines map[string]string `json:"machines,omitempty"` // machine home root label -> machine ID
	// Kept are the entries a keep manifest kept, with the tree digest the
	// scan found, so a comparison sees a change no file shows.
	Kept []Kept `json:"kept,omitempty"`
	// Digest is the SHA-256 of the canonical JSON of the inventory without
	// this field.
	Digest string `json:"digest"`
}

// Kept is an entry no TXE writer owns, kept exactly as it is.
type Kept struct {
	Root string `json:"root"`
	Path string `json:"path"`
	// Digest is the tree digest the scan found (see KeepEntry).
	Digest     string `json:"digest"`
	Provenance string `json:"provenance"`
	// Refused is a credential-named path in the entry that the manifest did
	// not exclude. It was not read, so the entry is not evidence that the
	// tree was kept.
	Refused string `json:"refused,omitempty"`
}

// RootInfo is one scanned root.
type RootInfo struct {
	Area  string `json:"area"`
	Label string `json:"label"`
	Path  string `json:"path"`
	// Mount is where the service that wrote the root sees it, when that is
	// not Path: paths stored in records are resolved through it.
	Mount string `json:"mount,omitempty"`
}

// Record is one stored record.
type Record struct {
	Class string `json:"class"`
	// Store is the store the record is in: "registry", "authz" or a machine
	// home's label.
	Store string `json:"store"`
	// ID is the storage ID: the path under the store without ".json".
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
	// Raw is the SHA-256 of the record's exact bytes; SHA256 is of its
	// canonical JSON.
	Raw    string `json:"raw,omitempty"`
	Schema int    `json:"schema,omitempty"`
	// Owner is the owner_id the record states, if it states one.
	Owner string `json:"owner,omitempty"`
	// Job is the job the record belongs to, if any.
	Job     string   `json:"job,omitempty"`
	Defines []Entity `json:"defines,omitempty"`
	Refs    []Ref    `json:"refs,omitempty"`
	// Mutable says the record may change in place: a later inventory may
	// hold a different digest for it.
	Mutable bool `json:"mutable,omitempty"`
	// Attrs are the facts the checks compare, such as a job's revision.
	Attrs map[string]string `json:"attrs,omitempty"`
	// Artifacts are an artifact manifest's deliverables.
	Artifacts []ArtifactFact `json:"artifacts,omitempty"`
}

// ArtifactFact is one deliverable a run reported and where its bytes are.
type ArtifactFact struct {
	Deliverable string `json:"deliverable"`
	Path        string `json:"path"`
	Location    string `json:"location,omitempty"`
	Status      string `json:"status"`
	SHA256      string `json:"sha256,omitempty"`
	Bytes       int64  `json:"bytes,omitempty"`
	MachineID   string `json:"machine_id,omitempty"`
	// HubPath is where the hub copy is, as the hub sees it.
	HubPath string `json:"hub_path,omitempty"`
	// MachinePath is where a machine keeps it, relative to the machine's
	// TXE home.
	MachinePath string `json:"machine_path,omitempty"`
}

// Entity is a logical identity a record defines.
type Entity struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
}

// Ref is a reference from a record to an entity.
type Ref struct {
	Rel  string `json:"rel"`
	Kind string `json:"kind"`
	ID   string `json:"id"`
	// Optional refs may legitimately point at something that does not
	// exist, such as a review an action names before it is recorded.
	Optional bool `json:"optional,omitempty"`
}

// File is one retained file outside the record stores, or a package's file.
type File struct {
	Root string `json:"root"`
	// Path is slash-separated and relative to the root.
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
	// Link is a symbolic link's target; links are never followed.
	Link string `json:"link,omitempty"`
	// Mode is the file's permission bits, where the file system has them.
	Mode uint32 `json:"mode,omitempty"`
	// Policy says how a later inventory may differ: immutable, mutable or
	// operational.
	Policy string `json:"policy"`
}

// File policies.
const (
	// PolicyImmutable files must be present later with the same digest.
	PolicyImmutable = "immutable"
	// PolicyMutable files must be present later; their bytes may change.
	PolicyMutable = "mutable"
	// PolicyOperational files may change or go away; they are counted only.
	PolicyOperational = "operational"
)

// Excluded is a part of a root that was deliberately not read.
type Excluded struct {
	Root   string `json:"root"`
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Severity of an issue.
const (
	// SeverityBlock stops a transition: acceptance cannot be claimed.
	SeverityBlock = "block"
	// SeverityWarn is reported and does not stop a transition.
	SeverityWarn = "warn"
)

// Issue is one finding.
type Issue struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Class    string `json:"class,omitempty"`
	ID       string `json:"id,omitempty"`
	Detail   string `json:"detail"`
}

// Blocking returns the issues that block.
func Blocking(issues []Issue) []Issue {
	var out []Issue
	for _, i := range issues {
		if i.Severity == SeverityBlock {
			out = append(out, i)
		}
	}
	return out
}

// Seal sorts the inventory, recounts its classes and sets its digest.
func (inv *Inventory) Seal() error {
	sort.Slice(inv.Records, func(i, k int) bool {
		a, b := inv.Records[i], inv.Records[k]
		if a.Store != b.Store {
			return a.Store < b.Store
		}
		return a.ID < b.ID
	})
	sort.Slice(inv.Files, func(i, k int) bool {
		a, b := inv.Files[i], inv.Files[k]
		if a.Root != b.Root {
			return a.Root < b.Root
		}
		return a.Path < b.Path
	})
	sort.Slice(inv.Excluded, func(i, k int) bool {
		a, b := inv.Excluded[i], inv.Excluded[k]
		if a.Root != b.Root {
			return a.Root < b.Root
		}
		return a.Path < b.Path
	})
	sortIssues(inv.Issues)
	sort.Slice(inv.Kept, func(i, k int) bool {
		a, b := inv.Kept[i], inv.Kept[k]
		if a.Root != b.Root {
			return a.Root < b.Root
		}
		return a.Path < b.Path
	})
	inv.Counts = map[string]int{}
	for _, r := range inv.Records {
		inv.Counts[r.Class]++
	}
	for _, f := range inv.Files {
		inv.Counts["file:"+f.Root]++
	}
	d, err := inv.digest()
	if err != nil {
		return err
	}
	inv.Digest = d
	return nil
}

func (inv *Inventory) digest() (string, error) {
	c := *inv
	c.Digest = ""
	b, err := registry.CanonicalJSON(c)
	if err != nil {
		return "", fmt.Errorf("continuity: digest inventory: %w", err)
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Decode reads an inventory and checks its format and digest.
func Decode(data []byte) (*Inventory, error) {
	var inv Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("continuity: decode inventory: %w", err)
	}
	if inv.Format != FormatV1 {
		return nil, fmt.Errorf("continuity: inventory format %q is not %q", inv.Format, FormatV1)
	}
	d, err := inv.digest()
	if err != nil {
		return nil, err
	}
	if d != inv.Digest {
		return nil, fmt.Errorf("continuity: inventory digest %s does not match its content (%s)", inv.Digest, d)
	}
	return &inv, nil
}

func sortIssues(issues []Issue) {
	sort.SliceStable(issues, func(i, k int) bool {
		a, b := issues[i], issues[k]
		if a.Severity != b.Severity {
			return a.Severity == SeverityBlock
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		if a.Class != b.Class {
			return a.Class < b.Class
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Detail < b.Detail
	})
}
