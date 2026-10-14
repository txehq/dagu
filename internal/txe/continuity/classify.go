// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// supportedSchemas are the record schema versions this package understands.
var supportedSchemas = map[int]bool{registry.SchemaVersion: true}

// recordDigest is the SHA-256 of a record's canonical JSON, so that the
// digest does not depend on how the file was indented.
func recordDigest(data []byte) string {
	b, err := registry.CanonicalJSON(json.RawMessage(data))
	if err != nil {
		b = data
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// strict decodes data into v, refusing fields v does not have: a field this
// package does not know is a record shape it cannot vouch for.
func strict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("trailing data after the record")
	}
	return nil
}

type builder struct {
	rec    *Record
	issues []Issue
}

func newBuilder(class string) *builder {
	return &builder{rec: &Record{Class: class}}
}

func (b *builder) block(code, format string, args ...any) {
	b.issues = append(b.issues, Issue{Code: code, Severity: SeverityBlock, Class: b.rec.Class, Detail: fmt.Sprintf(format, args...)})
}

func (b *builder) define(kind, id string) {
	if id != "" {
		b.rec.Defines = append(b.rec.Defines, Entity{Kind: kind, ID: id})
	}
}

func (b *builder) ref(rel, kind, id string) {
	if id != "" {
		b.rec.Refs = append(b.rec.Refs, Ref{Rel: rel, Kind: kind, ID: id})
	}
}

func (b *builder) optRef(rel, kind, id string) {
	if id != "" {
		b.rec.Refs = append(b.rec.Refs, Ref{Rel: rel, Kind: kind, ID: id, Optional: true})
	}
}

// required refuses an empty field that the record cannot be without.
func (b *builder) required(rel, kind, id string) {
	if id == "" {
		b.block("missing_field", "the record has no %s", rel)
		return
	}
	b.ref(rel, kind, id)
}

func (b *builder) attr(k, v string) {
	if b.rec.Attrs == nil {
		b.rec.Attrs = map[string]string{}
	}
	b.rec.Attrs[k] = v
}

func (b *builder) schema(v int) {
	b.rec.Schema = v
	if !supportedSchemas[v] {
		b.block("unsupported_schema", "schema %d is not a supported schema version", v)
	}
}

func (b *builder) owner(id string) {
	b.rec.Owner = id
	b.required("owner", KindOwner, id)
}

func (b *builder) decode(data []byte, v any) bool {
	if err := strict(data, v); err != nil {
		b.block("undecodable", "the record does not decode as a %s: %v", b.rec.Class, err)
		return false
	}
	return true
}

func (b *builder) done() (*Record, []Issue) {
	sort.Slice(b.rec.Defines, func(i, k int) bool {
		x, y := b.rec.Defines[i], b.rec.Defines[k]
		if x.Kind != y.Kind {
			return x.Kind < y.Kind
		}
		return x.ID < y.ID
	})
	sort.Slice(b.rec.Refs, func(i, k int) bool {
		x, y := b.rec.Refs[i], b.rec.Refs[k]
		if x.Rel != y.Rel {
			return x.Rel < y.Rel
		}
		return x.ID < y.ID
	})
	return b.rec, b.issues
}

// unknown is a record of a kind this package does not understand.
func unknown(id string, data []byte) (*Record, []Issue) {
	b := newBuilder(ClassUnknown)
	if !json.Valid(data) {
		b.block("undecodable", "the record is not valid JSON")
	}
	b.block("unsupported_record", "%s is not a record kind this tool understands; it must be supported before a transition", id)
	return b.done()
}

// classifyRegistry decodes one registry record.
func classifyRegistry(id string, data []byte) (*Record, []Issue) {
	parts := strings.Split(id, "/")
	n := len(parts)
	switch {
	case n == 2 && parts[0] == "owners":
		return ownerRecord(parts[1], data)
	case n == 2 && parts[0] == "projects":
		return projectRecord(parts[1], data)
	case n == 2 && parts[0] == "machines":
		return machineRecord(parts[1], data)
	case n == 2 && parts[0] == "jobs":
		return jobRecord(parts[1], data)
	case n == 4 && parts[0] == "history":
		return historyRecord(id, parts[1], parts[2], data)
	case n == 4 && parts[0] == "dedupe":
		return dedupeRecord(parts[1], parts[2], data)
	case n == 3 && parts[0] == "project_keys":
		return projectKeyRecord(parts[1], data)
	case n == 3 && (parts[0] == "resource_ids" || parts[0] == "resource_names"):
		return resourceIndexRecord(parts[0], parts[2], data)
	case n == 2 && parts[0] == "resource_events":
		return resourceEventRecord(parts[1], data)
	case n == 2 && parts[0] == "resource_events_pending":
		return resourcePendingRecord(parts[1], data)
	case n == 1 && parts[0] == "resource_index_ready":
		b := newBuilder(ClassResourceIndexReady)
		var v struct {
			At json.RawMessage `json:"at"`
		}
		b.decode(data, &v)
		b.rec.Mutable = true
		return b.done()
	case n == 4 && parts[0] == "artifacts":
		return artifactRecord(parts[1], parts[2], parts[3], data)
	case n == 5 && parts[0] == "executions":
		return executionRecord(parts[1], data)
	}
	return unknown(id, data)
}

func checkID(b *builder, p registry.Prefix, id, what string) {
	if err := registry.ValidateID(p, id); err != nil {
		b.block("invalid_id", "%s %q is not a valid %s ID", what, id, p)
	}
}

func ownerRecord(key string, data []byte) (*Record, []Issue) {
	b := newBuilder(ClassOwner)
	var o registry.Owner
	if !b.decode(data, &o) {
		return b.done()
	}
	b.schema(o.Schema)
	checkID(b, registry.PrefixOwner, o.OwnerID, "owner_id")
	if o.OwnerID != key {
		b.block("id_mismatch", "owner %s is stored as %s", o.OwnerID, key)
	}
	b.rec.Owner = o.OwnerID
	b.define(KindOwner, o.OwnerID)
	return b.done()
}

func projectRecord(key string, data []byte) (*Record, []Issue) {
	b := newBuilder(ClassProject)
	var p registry.Project
	if !b.decode(data, &p) {
		return b.done()
	}
	b.schema(p.Schema)
	checkID(b, registry.PrefixProject, p.ProjectID, "project_id")
	if p.ProjectID != key {
		b.block("id_mismatch", "project %s is stored as %s", p.ProjectID, key)
	}
	b.owner(p.OwnerID)
	b.define(KindProject, p.ProjectID)
	return b.done()
}

func machineRecord(key string, data []byte) (*Record, []Issue) {
	b := newBuilder(ClassMachine)
	var m registry.Machine
	if !b.decode(data, &m) {
		return b.done()
	}
	b.schema(m.Schema)
	checkID(b, registry.PrefixMachine, m.MachineID, "machine_id")
	if m.MachineID != key {
		b.block("id_mismatch", "machine %s is stored as %s", m.MachineID, key)
	}
	b.owner(m.OwnerID)
	b.define(KindMachine, m.MachineID)
	return b.done()
}

func jobRecord(key string, data []byte) (*Record, []Issue) {
	b := newBuilder(ClassJob)
	var j registry.Job
	if !b.decode(data, &j) {
		return b.done()
	}
	b.schema(j.Schema)
	checkID(b, registry.PrefixJob, j.JobID, "job_id")
	if j.JobID != key {
		b.block("id_mismatch", "job %s is stored as %s", j.JobID, key)
	}
	b.rec.Job = j.JobID
	b.rec.Mutable = true
	b.owner(j.OwnerID)
	b.required("project", KindProject, j.ProjectID)
	b.required("machine", KindMachine, j.MachineID)
	b.define(KindJob, j.JobID)
	b.attr("revision", strconv.FormatInt(j.Revision, 10))
	b.attr("version", strconv.Itoa(j.Version))
	b.attr("project", j.ProjectID)
	b.attr("machine", j.MachineID)
	b.attr("package_digest", j.PackageDigest)
	b.attr("dag_spec_sha256", j.DAGSpecSHA256)
	b.attr("registration", string(j.Registration.State))
	b.attr("lifecycle", string(j.Lifecycle))
	b.attr("version_refs", strings.Join(j.VersionRefs, ","))
	b.attr("checkpoint", strconv.Itoa(j.Checkpoint.Version))
	if j.Version != len(j.VersionRefs) {
		b.block("version_refs", "job is at version %d but has %d version references", j.Version, len(j.VersionRefs))
	}
	for i, ref := range j.VersionRefs {
		b.ref("version_"+strconv.Itoa(i+1), KindRecord, ref)
	}
	if j.Registration.DuplicateOf != "" {
		b.ref("duplicate_of", KindJob, j.Registration.DuplicateOf)
	}
	if pe := j.Registration.Package; pe != nil {
		b.ref("package_evidence_machine", KindMachine, pe.MachineID)
	}
	if j.Lifecycle == registry.LifecycleRetired && j.Retirement == nil {
		b.block("retirement_missing", "job is retired with no retirement record")
	}
	for kind, head := range map[string]string{
		"events": j.Chains.Events, "decisions": j.Chains.Decisions, "reviews": j.Chains.Reviews,
		"actions": j.Chains.Actions, "proposals": j.Chains.Proposals, "closures": j.Chains.Closures,
	} {
		if head != "" {
			b.ref("chain_"+kind, KindRecord, head)
			b.attr("chain_"+kind, head)
			if !strings.HasPrefix(head, "history/"+j.JobID+"/"+kind+"/") {
				b.block("chain_foreign", "the %s chain head %s is not a %s record of this job", kind, head, kind)
			}
		}
	}
	for id, p := range j.Proposals {
		if p == nil {
			b.block("corrupt_entry", "proposal %s is null", id)
			continue
		}
		if p.ProposalID != id {
			b.block("id_mismatch", "proposal %s is held as %s", p.ProposalID, id)
		}
		b.define(KindProposal, id)
		proposalRefs(b, p)
	}
	for id, a := range j.Actions {
		if a == nil {
			b.block("corrupt_entry", "action %s is null", id)
			continue
		}
		if a.ActionID != id {
			b.block("id_mismatch", "action %s is held as %s", a.ActionID, id)
		}
		b.define(KindAction, id)
		b.attr("action_state:"+id, string(a.State))
		actionRefs(b, a)
	}
	for id, e := range j.Exceptions {
		if e == nil {
			b.block("corrupt_entry", "exception %s is null", id)
			continue
		}
		b.define(KindException, id)
	}
	if c := j.Claim; c != nil {
		b.ref("claim_machine", KindMachine, c.Reviewer.MachineID)
		b.attr("claim", string(c.State)+":"+string(c.Kind))
	}
	for key, d := range j.DecisionKeys {
		b.ref("decision_key:"+key, KindDecision, d)
	}
	for id, r := range j.NativeResumes {
		if r == nil {
			b.block("corrupt_entry", "native resume %s is null", id)
			continue
		}
		b.ref("native_resume_decision", KindDecision, r.DecisionID)
		b.ref("native_resume_proposal", KindProposal, r.ProposalID)
	}
	for id, r := range j.UncertainResolutions {
		if r == nil {
			b.block("corrupt_entry", "uncertain resolution %s is null", id)
			continue
		}
		b.ref("uncertain_action", KindAction, r.ActionID)
		b.ref("uncertain_decision", KindDecision, r.DecisionID)
	}
	for id, c := range j.PendingClosures {
		if c == nil {
			b.block("corrupt_entry", "pending closure %s is null", id)
			continue
		}
		b.ref("pending_closure", KindProposal, c.ProposalID)
		b.ref("pending_closure_machine", KindMachine, c.MachineID)
		if c.JobID != j.JobID {
			b.block("foreign_job", "pending closure of proposal %s names job %s", c.ProposalID, c.JobID)
		}
	}
	for key, in := range j.Intents {
		if in == nil {
			b.block("corrupt_entry", "intent %s is null", key)
			continue
		}
		b.ref("intent:"+key, KindAction, in.ActionID)
	}
	if j.Checkpoint.LastReviewID != "" {
		b.ref("checkpoint_review", KindReview, j.Checkpoint.LastReviewID)
	}
	return b.done()
}

func proposalRefs(b *builder, p *registry.Proposal) {
	b.optRef("proposal_review", KindReview, p.ReviewID)
	if p.Decision != nil {
		b.ref("proposal_decision", KindDecision, p.Decision.DecisionID)
	}
}

func actionRefs(b *builder, a *registry.Action) {
	b.optRef("action_review", KindReview, a.ReviewID)
	if a.Kind == registry.ActionApproved {
		b.required("action_proposal", KindProposal, a.ProposalID)
		b.required("action_decision", KindDecision, a.DecisionID)
	} else {
		b.ref("action_proposal", KindProposal, a.ProposalID)
		b.ref("action_decision", KindDecision, a.DecisionID)
	}
}

// historyRecord decodes an immutable history record of a job.
func historyRecord(id, jobID, kind string, data []byte) (*Record, []Issue) {
	var b *builder
	prev := ""
	switch kind {
	case "versions":
		b = newBuilder(ClassVersion)
		var v registry.JobVersion
		if b.decode(data, &v) {
			b.schema(v.Schema)
			b.owner(v.OwnerID)
			if v.JobID != jobID {
				b.block("foreign_job", "version of job %s is stored under job %s", v.JobID, jobID)
			}
			b.attr("version", strconv.Itoa(v.Version))
			b.attr("package_digest", v.Package.Digest)
			b.attr("dag_spec_sha256", v.DAG.SpecSHA256)
			b.attr("schedule", v.Schedule.Cron+"|"+v.Schedule.Timezone)
		}
	case "events":
		b = newBuilder(ClassEvent)
		var e registry.Event
		if b.decode(data, &e) {
			if e.JobID != jobID {
				b.block("foreign_job", "event of job %s is stored under job %s", e.JobID, jobID)
			}
			prev = e.Prev
		}
	case "decisions":
		b = newBuilder(ClassDecision)
		var d registry.Decision
		if b.decode(data, &d) {
			b.define(KindDecision, d.DecisionID)
			b.required("decision_proposal", KindProposal, d.ProposalID)
			prev = d.Prev
		}
	case "reviews":
		b = newBuilder(ClassReview)
		var r registry.Review
		if b.decode(data, &r) {
			b.define(KindReview, r.ReviewID)
			for _, d := range r.EvidenceDecisions {
				b.ref("review_evidence_decision", KindDecision, d)
			}
			prev = r.Prev
		}
	case "actions":
		b = newBuilder(ClassAction)
		var a registry.Action
		if b.decode(data, &a) {
			b.define(KindAction, a.ActionID)
			actionRefs(b, &a)
			prev = a.Prev
		}
	case "proposals":
		b = newBuilder(ClassProposal)
		var p registry.Proposal
		if b.decode(data, &p) {
			b.define(KindProposal, p.ProposalID)
			proposalRefs(b, &p)
			prev = p.Prev
		}
	case "closures":
		b = newBuilder(ClassClosure)
		var c registry.Closure
		if b.decode(data, &c) {
			b.required("closure_proposal", KindProposal, c.ProposalID)
			prev = c.Prev
		}
	default:
		return unknown(id, data)
	}
	checkID(b, registry.PrefixJob, jobID, "job")
	b.rec.Job = jobID
	b.ref("job", KindJob, jobID)
	b.attr("kind", kind)
	if prev != "" {
		b.ref("prev", KindRecord, prev)
		b.attr("prev", prev)
		if !strings.HasPrefix(prev, "history/"+jobID+"/"+kind+"/") {
			b.block("chain_foreign", "the previous record %s is not a %s record of job %s", prev, kind, jobID)
		}
	}
	return b.done()
}

func dedupeRecord(ownerID, projectID string, data []byte) (*Record, []Issue) {
	b := newBuilder(ClassDedupe)
	var v struct {
		JobID string `json:"job_id"`
	}
	if b.decode(data, &v) {
		b.rec.Job = v.JobID
		b.required("job", KindJob, v.JobID)
	}
	b.owner(ownerID)
	b.ref("project", KindProject, projectID)
	return b.done()
}

func projectKeyRecord(ownerID string, data []byte) (*Record, []Issue) {
	b := newBuilder(ClassProjectKey)
	var v struct {
		ProjectID string `json:"project_id"`
	}
	if b.decode(data, &v) {
		b.required("project", KindProject, v.ProjectID)
	}
	b.owner(ownerID)
	return b.done()
}

func resourceIndexRecord(prefix, jobID string, data []byte) (*Record, []Issue) {
	class := ClassResourceID
	if prefix == "resource_names" {
		class = ClassResourceName
	}
	b := newBuilder(class)
	var v struct {
		JobID string `json:"job_id"`
	}
	if b.decode(data, &v) && v.JobID != jobID {
		b.block("foreign_job", "index entry names job %s under job %s", v.JobID, jobID)
	}
	b.rec.Job = jobID
	// The registry indexes a job's targets before the job commits, and an
	// entry for a job that never committed is ignored by it.
	b.optRef("job", KindJob, jobID)
	return b.done()
}

func resourceEventRecord(key string, data []byte) (*Record, []Issue) {
	b := newBuilder(ClassResourceEvent)
	b.rec.Mutable = true
	var ev registry.ResourceEvent
	if !b.decode(data, &ev) {
		return b.done()
	}
	b.schema(ev.Schema)
	if ev.EventID != key {
		b.block("id_mismatch", "resource event %s is stored as %s", ev.EventID, key)
	}
	b.define(KindEvent, ev.EventID)
	for _, d := range ev.Dispositions {
		b.ref("disposition_job", KindJob, d.JobID)
	}
	for _, d := range ev.Pending {
		b.ref("pending_job", KindJob, d.JobID)
	}
	return b.done()
}

func resourcePendingRecord(key string, data []byte) (*Record, []Issue) {
	b := newBuilder(ClassResourceEventPending)
	// The marker is removed once its event is completely applied.
	b.rec.Mutable = true
	if !json.Valid(data) {
		b.block("undecodable", "the record is not valid JSON")
	}
	b.ref("event", KindEvent, key)
	return b.done()
}

func artifactRecord(jobID, runID, execution string, data []byte) (*Record, []Issue) {
	b := newBuilder(ClassArtifactManifest)
	// Hub copies are checked after the manifest is written.
	b.rec.Mutable = true
	var m registry.ArtifactManifest
	if b.decode(data, &m) {
		b.schema(m.Schema)
		if m.JobID != jobID || m.RunID != runID || m.Execution != execution {
			b.block("id_mismatch", "manifest of job %s run %s execution %s is stored as %s/%s/%s", m.JobID, m.RunID, m.Execution, jobID, runID, execution)
		}
		produced := m.ProducedIn.Execution
		if produced == "" {
			produced = m.Execution
		}
		for _, a := range m.Artifacts {
			b.ref("artifact_machine", KindMachine, a.MachineID)
			f := ArtifactFact{Deliverable: a.Deliverable, Path: a.Path, Location: a.Location, Status: string(a.Status),
				SHA256: a.SHA256, Bytes: a.Bytes, MachineID: a.MachineID}
			if a.Location == registry.DeliveryHub && m.ArchiveDir != "" {
				// Joined without cleaning, so a UNC prefix (//server/share)
				// survives as it does in the mount it is matched against.
				f.HubPath = strings.TrimSuffix(slashPath(m.ArchiveDir), "/") + "/" + registry.HubCopyPath(m.Execution, a.Path)
			}
			if a.Location == registry.DeliveryMachine {
				f.MachinePath = path.Join("outputs", jobID, "runs", runID, "executions", produced, a.Path)
			}
			b.rec.Artifacts = append(b.rec.Artifacts, f)
		}
		b.attr("job_version", strconv.Itoa(m.JobVersion))
	}
	b.rec.Job = jobID
	b.ref("job", KindJob, jobID)
	return b.done()
}

func executionRecord(jobID string, data []byte) (*Record, []Issue) {
	b := newBuilder(ClassExecutionEvidence)
	// The content is a Dagu run status kept verbatim; only its validity is
	// checked, its fields are Dagu's.
	if !json.Valid(data) {
		b.block("undecodable", "the record is not valid JSON")
	}
	b.rec.Job = jobID
	b.ref("job", KindJob, jobID)
	return b.done()
}

// classifyAuthz decodes one authorization store record.
func classifyAuthz(id string, data []byte) (*Record, []Issue) {
	parts := strings.Split(id, "/")
	if len(parts) < 2 {
		return unknown(id, data)
	}
	switch parts[0] {
	case "requests":
		b := newBuilder(ClassBindingRequest)
		b.rec.Mutable = true
		var r authz.BindingRequest
		if b.decode(data, &r) {
			b.schema(r.Schema)
			identity(b, r.Issuer, r.Subject)
		}
		return b.done()
	case "bindings", "binding_history":
		class := ClassBinding
		if parts[0] == "binding_history" {
			class = ClassBindingHistory
		}
		b := newBuilder(class)
		b.rec.Mutable = class == ClassBinding
		var r authz.Binding
		if b.decode(data, &r) {
			b.schema(r.Schema)
			identity(b, r.Issuer, r.Subject)
			b.owner(r.OwnerID)
			b.attr("state", string(r.State))
			b.attr("identity", r.Issuer+"|"+r.Subject)
		}
		return b.done()
	case "shares", "share_history":
		class := ClassShare
		if parts[0] == "share_history" {
			class = ClassShareHistory
		}
		b := newBuilder(class)
		b.rec.Mutable = class == ClassShare
		var r authz.Share
		if b.decode(data, &r) {
			b.schema(r.Schema)
			b.owner(r.OwnerID)
			b.required("grantee", KindOwner, r.GranteeOwnerID)
			switch r.Resource.Kind {
			case authz.KindJob:
				b.required("resource", KindJob, r.Resource.ID)
			case authz.KindProject:
				b.required("resource", KindProject, r.Resource.ID)
			default:
				b.block("unsupported_share", "a share of %q is not supported", r.Resource.Kind)
			}
			b.attr("state", string(r.State))
		}
		return b.done()
	case "enrolments", "enrolment_history":
		class := ClassEnrolment
		if parts[0] == "enrolment_history" {
			class = ClassEnrolmentHistory
		}
		b := newBuilder(class)
		b.rec.Mutable = class == ClassEnrolment
		var r authz.Enrolment
		if b.decode(data, &r) {
			b.schema(r.Schema)
			b.owner(r.OwnerID)
			b.required("machine", KindMachine, r.MachineID)
			identity(b, r.Issuer, r.Subject)
			if r.Key.Issuer == "" || r.Key.ClientID == "" {
				b.block("missing_field", "the enrolment has no provider client key")
			}
			if class == ClassEnrolment {
				b.define(KindEnrolment, r.MachineID+"|"+string(r.Class))
			}
			b.attr("state", string(r.State))
		}
		return b.done()
	case "enrolment_keys":
		// A key is claimed once, for good, by one machine and class.
		b := newBuilder(ClassEnrolmentKey)
		var r struct {
			Schema    int                `json:"schema"`
			Key       authz.EnrolmentKey `json:"key"`
			MachineID string             `json:"machine_id"`
			Class     string             `json:"class"`
			ClaimedAt json.RawMessage    `json:"claimed_at"`
		}
		if b.decode(data, &r) {
			b.schema(r.Schema)
			b.required("machine", KindMachine, r.MachineID)
			b.ref("enrolment", KindEnrolment, r.MachineID+"|"+r.Class)
		}
		return b.done()
	}
	return unknown(id, data)
}

// identity checks that an identity binding names both the provider and its
// subject: an identity is never an email address or a display name alone.
func identity(b *builder, issuer, subject string) {
	if issuer == "" || subject == "" {
		b.block("missing_field", "the record does not name both an issuer and a subject")
	}
}

// slashPath writes a stored path with forward slashes, whichever system
// stored it: a store written on Windows is checked on any system.
func slashPath(p string) string {
	return strings.ReplaceAll(p, `\`, "/")
}
