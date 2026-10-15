// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity

import (
	"fmt"
	"path"
	"strconv"
	"strings"

	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// Policy is what Validate holds an inventory to.
type Policy struct {
	// AllowedOwners are owners other than the expected owner that may hold
	// records. Empty for a single-owner installation: then any other owner
	// blocks.
	AllowedOwners []string
}

// Validate checks one inventory on its own and returns its scan issues with
// everything it finds. It reads nothing but the inventory.
func Validate(inv *Inventory, pol Policy) []Issue {
	v := &validator{inv: inv, pol: pol, issues: append([]Issue(nil), inv.Issues...)}
	v.index()
	v.owners()
	v.refs()
	v.jobs()
	v.chains()
	v.packages()
	v.dags()
	v.artifacts()
	sortIssues(v.issues)
	return v.issues
}

type validator struct {
	inv          *Inventory
	pol          Policy
	issues       []Issue
	defined      map[string]map[string]bool // kind -> id
	records      map[string]*Record         // registry storage ID -> record
	ownerOf      map[string]map[string]string
	allowed      map[string]bool
	verifiedPkgs map[string]bool // home|job|digest verified in a scanned machine home
}

func (v *validator) add(sev, code string, r *Record, format string, args ...any) {
	i := Issue{Code: code, Severity: sev, Detail: fmt.Sprintf(format, args...)}
	if r != nil {
		i.Class = r.Class
		i.ID = r.Store + "/" + r.ID
	}
	v.issues = append(v.issues, i)
}

func (v *validator) index() {
	v.defined = map[string]map[string]bool{}
	v.records = map[string]*Record{}
	v.ownerOf = map[string]map[string]string{KindProject: {}, KindMachine: {}, KindJob: {}}
	v.verifiedPkgs = map[string]bool{}
	v.allowed = map[string]bool{v.inv.ExpectedOwner: true}
	for _, o := range v.pol.AllowedOwners {
		v.allowed[o] = true
	}
	for i := range v.inv.Records {
		r := &v.inv.Records[i]
		if r.Store == "registry" {
			v.records[r.ID] = r
			v.define(KindRecord, r.ID)
		}
		for _, e := range r.Defines {
			v.define(e.Kind, e.ID)
			if _, ok := v.ownerOf[e.Kind]; ok {
				v.ownerOf[e.Kind][e.ID] = r.Owner
			}
			if e.Kind == KindPackage {
				v.verifiedPkgs[e.ID] = true
			}
		}
	}
}

func (v *validator) define(kind, id string) {
	if v.defined[kind] == nil {
		v.defined[kind] = map[string]bool{}
	}
	v.defined[kind][id] = true
}

// owners checks that every owner is the installation's stable owner, or one
// the policy names. Nothing else is consulted: an owner is never inferred
// from a display name, an email address or an identity binding.
func (v *validator) owners() {
	if !v.defined[KindOwner][v.inv.ExpectedOwner] {
		if v.registryScanned() {
			v.add(SeverityBlock, "owner_missing", nil, "the expected owner %s has no owner record", v.inv.ExpectedOwner)
		} else {
			v.add(SeverityWarn, "not_checked", nil, "the expected owner's record is in the registry, which this inventory did not scan")
		}
	}
	for i := range v.inv.Records {
		r := &v.inv.Records[i]
		if r.Class == ClassOwner && !v.allowed[r.Owner] {
			v.add(SeverityBlock, "unexpected_owner", r, "owner %s is not the installation's owner %s", r.Owner, v.inv.ExpectedOwner)
			continue
		}
		if r.Owner != "" && !v.allowed[r.Owner] {
			v.add(SeverityBlock, "owner_mismatch", r, "the record is owned by %s, not %s", r.Owner, v.inv.ExpectedOwner)
		}
		for _, ref := range r.Refs {
			if ref.Kind == KindOwner && ref.Rel != "owner" && !v.allowed[ref.ID] {
				v.add(SeverityBlock, "owner_mismatch", r, "%s names owner %s, not %s", ref.Rel, ref.ID, v.inv.ExpectedOwner)
			}
		}
	}
}

// registryScanned reports whether the inventory holds a hub data
// directory, and so the registry. A machine home is inventoried on its
// machine, apart from the hub; what only the registry can answer is then
// reported as not checked, while every owner it names is still checked.
func (v *validator) registryScanned() bool {
	for _, root := range v.inv.Roots {
		if root.Area == AreaHubData {
			return true
		}
	}
	return false
}

// refs checks that every required reference resolves.
func (v *validator) refs() {
	for i := range v.inv.Records {
		r := &v.inv.Records[i]
		for _, ref := range r.Refs {
			optional := ref.Optional
			if r.Class == ClassJob && ref.Rel == "checkpoint_review" && !v.checkpointReview(r, ref.ID) {
				optional = true
			}
			if v.defined[ref.Kind][ref.ID] {
				continue
			}
			if optional {
				// It may never have existed; one that did and is gone is
				// found by Compare as a missing record.
				continue
			}
			if ref.Kind != KindPackage && !v.registryScanned() {
				// Only a machine home's packages are outside the registry.
				v.add(SeverityWarn, "not_checked", r, "%s refers to %s %s, which is in the registry; this inventory did not scan it", ref.Rel, ref.Kind, ref.ID)
				continue
			}
			v.add(SeverityBlock, "dangling_ref", r, "%s refers to %s %s, which is not present", ref.Rel, ref.Kind, ref.ID)
		}
	}
}

// maxCheckpointEpisodes bounds the episodes checkpointReview enumerates.
// A checkpoint further along than this is not judged, and its review is
// required as it always was.
const maxCheckpointEpisodes = 1 << 20

// checkpointReview reports whether the review a job's checkpoint names
// must be present, by the registry's contract. The registry records a
// review of a job only under ReviewID(job, k) for an episode k it has
// reached, and the reviewer records the review of episode v-1 before it
// names it in checkpoint v. AdvanceCheckpoint stores whatever ID its caller
// sends, so another client can leave a checkpoint naming a review the job
// could not have recorded in any episode up to that checkpoint. Such an ID
// is reported by name and not required to be present. Any ID the job could
// have recorded stays required, and a checkpoint this cannot decide, with a
// version the registry never writes, is held as it always was. A review
// that is present is checked as every reference is, whatever it is named;
// one that is lost later is a missing record to Compare, and a recorded
// review of the job's own is also lost from its reviews chain.
func (v *validator) checkpointReview(r *Record, id string) bool {
	version, err := strconv.Atoi(r.Attrs["checkpoint"])
	if err != nil || version < 1 || version > maxCheckpointEpisodes || r.Job == "" {
		return true
	}
	ended, err := registry.ReviewID(r.Job, version-1)
	if err != nil || id == ended {
		return true
	}
	if registry.ValidateID(registry.PrefixReview, id) == nil {
		for k := 0; k <= version; k++ {
			if k == version-1 {
				continue
			}
			other, err := registry.ReviewID(r.Job, k)
			if err != nil {
				return true
			}
			if id == other {
				v.add(SeverityWarn, "checkpoint_review_noncanonical", r, "checkpoint %d names review %s of episode %d, not %s of the episode it ended; it is still required", version, id, k, ended)
				return true
			}
		}
	}
	v.add(SeverityWarn, "checkpoint_review_unrecordable", r, "checkpoint %d names review %s, which this job could not have recorded in any episode up to its checkpoint (the episode it ended has %s); it is reported, not required", version, id, ended)
	return false
}

// jobs checks that a job, its project and its machine have one owner, and
// that the job's current facts are its latest version's.
func (v *validator) jobs() {
	for i := range v.inv.Records {
		r := &v.inv.Records[i]
		if r.Class != ClassJob {
			continue
		}
		for _, k := range []string{KindProject, KindMachine} {
			id := r.Attrs[k]
			if o, ok := v.ownerOf[k][id]; ok && o != r.Owner {
				v.add(SeverityBlock, "owner_inconsistent", r, "the job is owned by %s but its %s %s by %s", r.Owner, k, id, o)
			}
		}
		refs := splitList(r.Attrs["version_refs"])
		for n, ref := range refs {
			ver := v.records[ref]
			if ver == nil {
				continue // reported as a dangling reference
			}
			if ver.Class != ClassVersion || ver.Job != r.Job {
				v.add(SeverityBlock, "version_foreign", r, "version reference %s is not a version of this job", ref)
				continue
			}
			if ver.Attrs["version"] != strconv.Itoa(n+1) {
				v.add(SeverityBlock, "version_order", r, "version reference %d holds version %s", n+1, ver.Attrs["version"])
			}
			if ver.Owner != r.Owner {
				v.add(SeverityBlock, "owner_inconsistent", r, "version %d is owned by %s, the job by %s", n+1, ver.Owner, r.Owner)
			}
			if n == len(refs)-1 {
				if ver.Attrs["package_digest"] != r.Attrs["package_digest"] {
					v.add(SeverityBlock, "version_mismatch", r, "the job's package digest %s is not its latest version's %s", r.Attrs["package_digest"], ver.Attrs["package_digest"])
				}
				if ver.Attrs["dag_spec_sha256"] != r.Attrs["dag_spec_sha256"] {
					v.add(SeverityBlock, "version_mismatch", r, "the job's DAG digest %s is not its latest version's %s", r.Attrs["dag_spec_sha256"], ver.Attrs["dag_spec_sha256"])
				}
			}
		}
	}
	// A version or history record of a job that is not present is an orphan
	// of the job; versions are referenced by the job, so an unreferenced
	// version is reported with the chains.
}

// chains walks every job's history chains from their heads. A history record
// that no committed head reaches was written by a commit that did not
// happen: the registry never shows it, and it is retained as it is.
func (v *validator) chains() {
	reached := map[string]bool{}
	for i := range v.inv.Records {
		r := &v.inv.Records[i]
		if r.Class != ClassJob {
			continue
		}
		for _, ref := range splitList(r.Attrs["version_refs"]) {
			reached[ref] = true
		}
		for _, kind := range chainKinds {
			id := r.Attrs["chain_"+kind]
			seen := map[string]bool{}
			for id != "" {
				if seen[id] {
					v.add(SeverityBlock, "chain_cycle", r, "the %s chain loops at %s", kind, id)
					break
				}
				seen[id] = true
				reached[id] = true
				rec := v.records[id]
				if rec == nil {
					break // reported as a dangling reference
				}
				if rec.Job != r.Job || rec.Attrs["kind"] != kind {
					v.add(SeverityBlock, "chain_foreign", r, "%s in the %s chain is not a %s record of this job", id, kind, kind)
					break
				}
				id = rec.Attrs["prev"]
			}
		}
	}
	for i := range v.inv.Records {
		r := &v.inv.Records[i]
		if r.Store != "registry" || !strings.HasPrefix(r.ID, "history/") || reached[r.ID] {
			continue
		}
		v.add(SeverityWarn, "uncommitted_history", r, "no committed chain reaches this record; it is from a commit that did not happen and is retained unchanged")
	}
}

// packages checks that each machine home holds a verified package for every
// version of every job assigned to that machine. Versions of jobs on a
// machine that was not scanned are counted, not judged.
func (v *validator) packages() {
	for i := range v.inv.Records {
		r := &v.inv.Records[i]
		if r.Class == ClassPackage && !v.defined[KindJob][r.Job] {
			v.add(SeverityWarn, "package_without_job", r, "the registry holds no job %s; the package is retained as it is", r.Job)
		}
	}
	if len(v.inv.Machines) == 0 {
		return
	}
	homes := map[string][]string{} // machine ID -> labels of its scanned homes
	for label, m := range v.inv.Machines {
		homes[m] = append(homes[m], label)
	}
	for i := range v.inv.Records {
		r := &v.inv.Records[i]
		if r.Class != ClassVersion {
			continue
		}
		job := v.records["jobs/"+r.Job]
		if job == nil || len(homes[job.Attrs["machine"]]) == 0 {
			continue
		}
		if job.Attrs["registration"] == "incomplete" && r.Attrs["version"] == job.Attrs["version"] {
			// An incomplete registration has no package yet by definition.
			continue
		}
		// The package must be on the machine that runs the job: a worker
		// resolves packages only under its own home.
		found := false
		for _, label := range homes[job.Attrs["machine"]] {
			found = found || v.verifiedPkgs[label+"|"+r.Job+"|"+r.Attrs["package_digest"]]
		}
		if !found {
			v.add(SeverityBlock, "package_missing", r, "machine %s holds no verified package %s for version %s of job %s", job.Attrs["machine"], r.Attrs["package_digest"], r.Attrs["version"], r.Job)
		}
	}
}

// dags checks each job's saved DAG against the digest the job records, when
// the DAG directory was scanned. The registry rewrites a missing or edited
// DAG from the version, so a difference is reported, not blocking.
func (v *validator) dags() {
	files := map[string]string{}
	scanned := false
	for _, root := range v.inv.Roots {
		if root.Area == AreaDAGs {
			scanned = true
		}
	}
	if !scanned {
		return
	}
	areas := map[string]string{}
	for _, root := range v.inv.Roots {
		areas[root.Label] = root.Area
	}
	for _, f := range v.inv.Files {
		if areas[f.Root] == AreaDAGs && path.Ext(f.Path) == ".yaml" {
			files[strings.TrimSuffix(f.Path, ".yaml")] = f.SHA256
		}
	}
	for i := range v.inv.Records {
		r := &v.inv.Records[i]
		if r.Class != ClassJob || r.Attrs["registration"] == "duplicate" {
			// A duplicate registration never runs; its DAG is the winner's.
			continue
		}
		got, ok := files[r.Job]
		switch {
		case !ok:
			v.add(SeverityWarn, "dag_missing", r, "the DAG of job %s is not in the DAG directory", r.Job)
		case got != r.Attrs["dag_spec_sha256"]:
			v.add(SeverityWarn, "dag_changed", r, "the saved DAG digest %s is not the job's %s", got, r.Attrs["dag_spec_sha256"])
		}
	}
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	out := strings.Split(s, ",")
	return out
}

// artifacts checks the bytes of every deliverable whose location was
// scanned: a verified hub copy must be in the hub's artifact files with its
// recorded digest, and a machine copy in that machine's outputs. A location
// that was not scanned is reported as unverified, never as present.
func (v *validator) artifacts() {
	files := map[string]File{}
	for _, f := range v.inv.Files {
		files[f.Root+"\x00"+f.Path] = f
	}
	homes := map[string]string{} // machine ID -> root label
	for label, m := range v.inv.Machines {
		homes[m] = label
	}
	for i := range v.inv.Records {
		r := &v.inv.Records[i]
		for _, a := range r.Artifacts {
			switch {
			case a.Status == "missing":
				continue
			case a.HubPath != "" && a.Status == "verified":
				label, rel, ok := v.resolveHub(a.HubPath)
				if !ok {
					v.add(SeverityWarn, "artifact_unverified", r, "the hub copy of %s at %s is in no scanned root", a.Deliverable, a.HubPath)
					continue
				}
				v.checkBytes(r, a, files, label, rel)
			case a.MachinePath != "":
				label, ok := homes[a.MachineID]
				if !ok {
					v.add(SeverityWarn, "artifact_unverified", r, "%s is kept on machine %s, whose home was not scanned", a.Deliverable, a.MachineID)
					continue
				}
				v.checkBytes(r, a, files, label, a.MachinePath)
			}
		}
	}
}

func (v *validator) checkBytes(r *Record, a ArtifactFact, files map[string]File, label, rel string) {
	f, ok := files[label+"\x00"+rel]
	switch {
	case !ok:
		v.add(SeverityBlock, "artifact_missing", r, "%s is recorded at %s/%s, which is not there", a.Deliverable, label, rel)
	case a.SHA256 != "" && f.SHA256 != a.SHA256:
		v.add(SeverityBlock, "artifact_digest", r, "%s at %s/%s has digest %s, not the recorded %s", a.Deliverable, label, rel, f.SHA256, a.SHA256)
	}
}

// resolveHub maps a path as the hub sees it to a scanned root and a path
// relative to it.
func (v *validator) resolveHub(p string) (string, string, bool) {
	for _, root := range v.inv.Roots {
		if root.Area != AreaHubData && root.Area != AreaArtifacts {
			continue
		}
		base := root.Mount
		if base == "" {
			base = root.Path
		}
		base = strings.TrimSuffix(slashPath(base), "/")
		if after, ok := strings.CutPrefix(p, base+"/"); ok {
			return root.Label, after, true
		}
	}
	return "", "", false
}

// chainKinds are the job history chains, by their names in a job's chains.
var chainKinds = []string{"events", "decisions", "reviews", "actions", "proposals", "closures"}
