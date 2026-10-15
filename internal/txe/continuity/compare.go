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

// CompareOptions configure Compare.
type CompareOptions struct {
	// Reconciled are the records ("<store>/<id>") and files ("<root>/<path>")
	// that may be changed or added between the two inventories, because a
	// recorded step changed them (a transition's journal). Nothing else
	// may. A missing record or file is never reconciled: a transition does
	// not delete retained data.
	Reconciled map[string]bool
}

// Compare is the transition gate. It compares the inventory taken at the
// freeze point with the one taken after the transition, before dispatch
// resumes: nothing may be missing, added or changed. Every retained record
// must keep its canonical digest, and every file that is not operational
// its bytes, link and permission bits (where both scans have them), unless
// opts.Reconciled names it; even a reconciled record keeps its class and
// owner. Nothing about which changes are harmless is inferred.
func Compare(before, after *Inventory, opts CompareOptions) *Report {
	rep, add := newReport(before, after)
	later := map[string]*Record{}
	for i := range after.Records {
		r := &after.Records[i]
		later[r.Store+"/"+r.ID] = r
	}
	earlier := map[string]bool{}
	for i := range before.Records {
		b := &before.Records[i]
		key := b.Store + "/" + b.ID
		earlier[key] = true
		a := later[key]
		switch {
		case a == nil:
			add("record_missing", b.Class, key, "the record is no longer present")
			continue
		case a.SHA256 == b.SHA256:
			continue
		}
		rep.Changed = append(rep.Changed, key)
		switch {
		case a.Class != b.Class:
			add("class_changed", b.Class, key, "the record changed from a "+b.Class+" to a "+a.Class)
		case a.Owner != b.Owner:
			add("owner_changed", b.Class, key, "the record's owner changed from "+b.Owner+" to "+a.Owner)
		case !opts.Reconciled[key]:
			add("record_changed", b.Class, key, "the record changed from "+b.SHA256+" to "+a.SHA256+" and no recorded step changed it")
		}
	}
	for i := range after.Records {
		r := &after.Records[i]
		if key := r.Store + "/" + r.ID; !earlier[key] {
			rep.Added = append(rep.Added, key)
			if !opts.Reconciled[key] {
				add("record_added", r.Class, key, "the record was added and no recorded step added it")
			}
		}
	}
	compareFiles(before, after, rep, add, func(b, a File, key string) {
		if !opts.Reconciled[key] {
			add("file_changed", "file", key, fmt.Sprintf("the file changed from %s mode %o to %s mode %o and no recorded step changed it", b.SHA256, b.Mode, a.SHA256, a.Mode))
		}
	}, func(f File, key string) {
		if !opts.Reconciled[key] {
			add("file_added", "file", key, "the file was added and no recorded step added it")
		}
	})
	compareKept(before, after, add, true)
	sortReport(rep)
	return rep
}

// CompareProgress reports what changed between an earlier inventory and a
// later one while the installation was in use, such as a test snapshot and
// the latest freeze point, so the additions can be reconciled. It blocks
// only what it can tell is a loss: a missing record or retained file, a
// changed immutable record or file, a shrunken run or log file, a job that
// lost its identity, versions, committed history, live entries, decision
// keys or unresolved intents, or went backward. It is not a preservation
// proof for mutable state; Compare at the freeze point is.
func CompareProgress(before, after *Inventory) *Report {
	rep, add := newReport(before, after)
	appendOnly := appendOnlyFiles(before)
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
			compareIntents(b, a, key, add)
		}
	}
	for i := range after.Records {
		r := &after.Records[i]
		if key := r.Store + "/" + r.ID; !earlier[key] {
			rep.Added = append(rep.Added, key)
		}
	}
	compareFiles(before, after, rep, add, func(b, a File, key string) {
		switch {
		case b.Policy == PolicyImmutable:
			add("immutable_changed", "file", key, fmt.Sprintf("an immutable file changed from %s mode %o to %s mode %o", b.SHA256, b.Mode, a.SHA256, a.Mode))
		case a.Size < b.Size && appendOnly[b.Root+"\x00"+b.Path]:
			// A log only grows; a shorter one lost content.
			add("file_truncated", "file", key, fmt.Sprintf("the retained file shrank from %d to %d bytes", b.Size, a.Size))
		}
	}, func(File, string) {})
	compareKept(before, after, add, false)
	sortReport(rep)
	return rep
}

func newReport(before, after *Inventory) (*Report, func(code, class, id, detail string)) {
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
	return rep, add
}

// compareFiles reports missing retained files, and hands each changed and
// each added file that is not operational to changed and added.
// compareKept checks the entries kept exactly as they are: each must still
// be kept, with the same tree digest, which also covers what no file
// shows (a directory, permission bits, an excluded path's type). The
// strict comparison also refuses a newly kept entry.
func compareKept(before, after *Inventory, add func(code, class, id, detail string), strict bool) {
	later := map[string]Kept{}
	for _, k := range after.Kept {
		later[k.Root+"/"+k.Path] = k
	}
	earlier := map[string]bool{}
	for _, b := range before.Kept {
		key := b.Root + "/" + b.Path
		earlier[key] = true
		a, ok := later[key]
		switch {
		case !ok:
			add("kept_missing", "", key, "the entry kept as it was is no longer kept")
		case a.Refused != "" || b.Refused != "":
			add("kept_credential", "", key, "the kept entry holds a credential-named path the manifest does not exclude, which was not read")
		case a.Digest != b.Digest:
			add("kept_changed", "", key, fmt.Sprintf("the kept entry's tree changed from %s to %s", b.Digest, a.Digest))
		}
	}
	if !strict {
		return
	}
	for _, a := range after.Kept {
		if key := a.Root + "/" + a.Path; !earlier[key] {
			add("kept_added", "", key, "the entry is kept now but was not before")
		}
	}
}

func compareFiles(before, after *Inventory, rep *Report, add func(code, class, id, detail string), changed func(b, a File, key string), added func(f File, key string)) {
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
		if b.Policy == PolicyOperational {
			continue
		}
		a, ok := laterFiles[key]
		switch {
		case !ok:
			add("file_missing", "file", key, "the retained file is no longer present")
		case a.SHA256 == b.SHA256 && a.Link == b.Link && (!modes || a.Mode == b.Mode):
		default:
			rep.Changed = append(rep.Changed, key)
			changed(b, a, key)
		}
	}
	for _, f := range after.Files {
		if key := f.Root + "/" + f.Path; !earlierFiles[key] && f.Policy != PolicyOperational {
			rep.Added = append(rep.Added, key)
			added(f, key)
		}
	}
}

func sortReport(rep *Report) {
	sort.Strings(rep.Added)
	sort.Strings(rep.Changed)
	sortIssues(rep.Issues)
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

// compareIntents checks that an intent whose action was unresolved is not
// dropped while that action is still held unresolved: the intent is what
// stops a later episode from starting the same effect again.
func compareIntents(b, a *Record, key string, add func(code, class, id, detail string)) {
	held := map[string]bool{}
	for _, r := range a.Refs {
		if strings.HasPrefix(r.Rel, "intent:") {
			held[r.Rel] = true
		}
	}
	for _, r := range b.Refs {
		if !strings.HasPrefix(r.Rel, "intent:") || held[r.Rel] {
			continue
		}
		if st := a.Attrs["action_state:"+r.ID]; st == "executing" || st == "uncertain" {
			add("live_entry_lost", ClassJob, key, "the job's "+r.Rel+" was dropped while its action "+r.ID+" is still "+st)
		}
	}
}

// appendOnlyFiles are the files that only ever grow: those in a log root.
// A run's status file is compacted to its latest status when the run ends,
// and a DAG, view or workspace file may get shorter, so those are not.
func appendOnlyFiles(inv *Inventory) map[string]bool {
	areas := map[string]string{}
	for _, r := range inv.Roots {
		areas[r.Label] = r.Area
	}
	out := map[string]bool{}
	for _, f := range inv.Files {
		if areas[f.Root] == AreaLogs {
			out[f.Root+"\x00"+f.Path] = true
		}
	}
	return out
}
