// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity

import (
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
		}
	}
	for i := range after.Records {
		r := &after.Records[i]
		if key := r.Store + "/" + r.ID; !earlier[key] {
			rep.Added = append(rep.Added, key)
		}
	}

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
		case a.SHA256 == b.SHA256 && a.Link == b.Link:
		case b.Policy == PolicyImmutable:
			rep.Changed = append(rep.Changed, key)
			add("immutable_changed", "file", key, "an immutable file changed from "+b.SHA256+" to "+a.SHA256)
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
