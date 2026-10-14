// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Report is the comparison of a later inventory with an earlier one.
type Report struct {
	Before string `json:"before"`
	After  string `json:"after"`
	// Counts are per class: before, after.
	Counts map[string][2]int `json:"counts"`
	// Added are records and files present only after: what happened since
	// the earlier inventory, to be reconciled at the freeze point.
	Added   []string `json:"added,omitempty"`
	Changed []string `json:"changed,omitempty"`
	Issues  []Issue  `json:"issues,omitempty"`
}

// Compare checks that everything the earlier inventory holds is still held
// later: no record or retained file is missing, nothing immutable changed,
// and a job aggregate changed only by moving forward with its identity
// intact.
func Compare(before, after *Inventory) *Report {
	rep := &Report{Before: before.Digest, After: after.Digest, Counts: map[string][2]int{}}
	add := func(code, class, id, detail string) {
		rep.Issues = append(rep.Issues, Issue{Code: code, Severity: SeverityBlock, Class: class, ID: id, Detail: detail})
	}
	for k, n := range before.Counts {
		c := rep.Counts[k]
		c[0] = n
		rep.Counts[k] = c
	}
	for k, n := range after.Counts {
		c := rep.Counts[k]
		c[1] = n
		rep.Counts[k] = c
	}
	if before.ExpectedOwner != after.ExpectedOwner {
		add("owner_changed", "", "", "the expected owner changed from "+before.ExpectedOwner+" to "+after.ExpectedOwner)
	}

	later := map[string]*Record{}
	laterRegistry := map[string]*Record{}
	for i := range after.Records {
		r := &after.Records[i]
		later[r.Store+"/"+r.ID] = r
		if r.Store == "registry" {
			laterRegistry[r.ID] = r
		}
	}
	laterJobEntities := committedEntities(laterRegistry)
	earlier := map[string]bool{}
	for i := range before.Records {
		b := &before.Records[i]
		key := b.Store + "/" + b.ID
		earlier[key] = true
		a := later[key]
		switch {
		case a == nil && b.Class == ClassResourceEventPending:
			// The marker is removed once its event is completely applied.
			continue
		case a == nil:
			add("record_missing", b.Class, key, "the record is no longer present")
			continue
		case a.SHA256 == b.SHA256:
			continue
		}
		rep.Changed = append(rep.Changed, key)
		if a.Class != b.Class {
			add("class_changed", b.Class, key, "the record changed from a "+b.Class+" to a "+a.Class)
			continue
		}
		if !b.Mutable {
			add("immutable_changed", b.Class, key, "an immutable record changed from "+b.SHA256+" to "+a.SHA256)
			continue
		}
		if a.Owner != b.Owner {
			add("owner_changed", b.Class, key, "the record's owner changed from "+b.Owner+" to "+a.Owner)
		}
		if b.Class == ClassJob {
			compareJob(b, a, key, add)
			compareChains(b, a, key, laterRegistry, add)
			compareLive(b, a, key, laterJobEntities, add)
		}
	}
	for i := range after.Records {
		r := &after.Records[i]
		if key := r.Store + "/" + r.ID; !earlier[key] {
			rep.Added = append(rep.Added, key)
		}
	}

	// Modes are compared only when both scans had permission bits.
	modes := before.ModeBits && after.ModeBits
	laterFiles := map[string]File{}
	for _, f := range after.Files {
		laterFiles[f.Root+"/"+f.Path] = f
	}
	earlierFiles := map[string]bool{}
	for _, b := range before.Files {
		key := b.Root + "/" + b.Path
		earlierFiles[key] = true
		a, ok := laterFiles[key]
		switch {
		case b.Policy == PolicyOperational:
			continue
		case !ok:
			add("file_missing", "file", key, "the retained file is no longer present")
		case a.SHA256 == b.SHA256 && a.Link == b.Link && (b.Policy != PolicyImmutable || !modes || a.Mode == b.Mode):
		case b.Policy == PolicyImmutable:
			rep.Changed = append(rep.Changed, key)
			add("immutable_changed", "file", key, fmt.Sprintf("an immutable file changed from %s mode %o to %s mode %o", b.SHA256, b.Mode, a.SHA256, a.Mode))
		default:
			rep.Changed = append(rep.Changed, key)
		}
	}
	for _, f := range after.Files {
		if key := f.Root + "/" + f.Path; !earlierFiles[key] {
			rep.Added = append(rep.Added, key)
		}
	}
	sort.Strings(rep.Added)
	sort.Strings(rep.Changed)
	sortIssues(rep.Issues)
	return rep
}

// compareJob checks that a job aggregate kept its identity and moved
// forward: a higher revision, the same versions as a prefix, the same
// project and machine.
func compareJob(b, a *Record, key string, add func(code, class, id, detail string)) {
	for _, k := range []string{"project", "machine"} {
		if a.Attrs[k] != b.Attrs[k] {
			add("identity_changed", ClassJob, key, "the job's "+k+" changed from "+b.Attrs[k]+" to "+a.Attrs[k])
		}
	}
	rb, _ := strconv.ParseInt(b.Attrs["revision"], 10, 64)
	ra, _ := strconv.ParseInt(a.Attrs["revision"], 10, 64)
	if ra <= rb {
		add("aggregate_rewritten", ClassJob, key, "the job changed without a later revision ("+b.Attrs["revision"]+" then "+a.Attrs["revision"]+")")
	}
	bv, av := b.Attrs["version_refs"], a.Attrs["version_refs"]
	if bv != "" && av != bv && !strings.HasPrefix(av, bv+",") {
		add("versions_rewritten", ClassJob, key, "the job's earlier versions are not kept as they were")
	}
}

// compareChains checks that every history record the job had committed is
// still in its history: each earlier chain head must be reachable from the
// later head. A record left on disk but no longer reachable is gone from
// the registry's history.
func compareChains(b, a *Record, key string, records map[string]*Record, add func(code, class, id, detail string)) {
	for _, kind := range chainKinds {
		head := b.Attrs["chain_"+kind]
		if head == "" {
			continue
		}
		found := false
		seen := map[string]bool{}
		for id := a.Attrs["chain_"+kind]; id != "" && !seen[id]; {
			if id == head {
				found = true
				break
			}
			seen[id] = true
			r := records[id]
			if r == nil {
				break
			}
			id = r.Attrs["prev"]
		}
		if !found {
			add("history_unreachable", ClassJob, key, "the job's "+kind+" history no longer reaches "+head+", which it had committed")
		}
	}
}

// compareLive checks that nothing the job held live was dropped. The
// registry removes a proposal or an action from a job only by archiving it
// into the job's history, and never removes an exception or a decision key,
// so each must still be defined by the job later.
func compareLive(b, a *Record, key string, entities map[string]bool, add func(code, class, id, detail string)) {
	for _, e := range b.Defines {
		switch e.Kind {
		case KindProposal, KindAction, KindException:
			if !entities[b.Job+"|"+e.Kind+"|"+e.ID] {
				add("live_entry_lost", ClassJob, key, "the job's "+e.Kind+" "+e.ID+" is neither held nor archived any more")
			}
		}
	}
	keys := map[string]string{}
	for _, r := range a.Refs {
		if strings.HasPrefix(r.Rel, "decision_key:") {
			keys[r.Rel] = r.ID
		}
	}
	for _, r := range b.Refs {
		if !strings.HasPrefix(r.Rel, "decision_key:") {
			continue
		}
		switch got, ok := keys[r.Rel]; {
		case !ok:
			add("live_entry_lost", ClassJob, key, "the job's "+r.Rel+" is no longer held, so a replayed decision would not be recognized")
		case got != r.ID:
			add("live_entry_lost", ClassJob, key, "the job's "+r.Rel+" now names "+got+" instead of "+r.ID+", so a replay would resolve to another decision")
		}
	}
}

// committedEntities are the entities each job defines, live in its aggregate
// or in history its chains reach, keyed "job|kind|id". A history record no
// chain reaches is from a commit that did not happen and counts for nothing.
func committedEntities(records map[string]*Record) map[string]bool {
	out := map[string]bool{}
	define := func(r *Record) {
		for _, e := range r.Defines {
			out[r.Job+"|"+e.Kind+"|"+e.ID] = true
		}
	}
	for _, j := range records {
		if j.Class != ClassJob {
			continue
		}
		define(j)
		for _, kind := range chainKinds {
			seen := map[string]bool{}
			for id := j.Attrs["chain_"+kind]; id != "" && !seen[id]; {
				seen[id] = true
				r := records[id]
				if r == nil || r.Job != j.Job {
					break
				}
				define(r)
				id = r.Attrs["prev"]
			}
		}
	}
	return out
}
