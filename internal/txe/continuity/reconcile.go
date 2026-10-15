// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity

import (
	"errors"
	"fmt"
	"sort"
)

// ErrIncompatible reports inventories that cannot be reconciled into one.
var ErrIncompatible = errors.New("continuity: the inventories cannot be reconciled")

// Reconcile joins inventories taken apart (the hub's data directory in one
// place, each machine's home on its machine) into one joint inventory, so
// that validation sees the registry and every machine together: owners,
// references and packages are checked across them, as in one scan.
//
// The parts must belong to one installation and one point in time: the
// same format, expected owner, label and permission-bit capability. Each
// root, record, file and kept entry must come from exactly one part, there
// must be exactly one hub data directory and at least one machine home, and
// a part must not itself be a joint inventory. Anything else is refused;
// nothing is merged on a guess. The joint inventory names its parts'
// digests and is sealed like a scanned one, so Validate and Compare apply
// to it unchanged.
func Reconcile(parts ...*Inventory) (*Inventory, error) {
	if len(parts) < 2 {
		return nil, fmt.Errorf("%w: reconcile needs the hub's inventory and at least one machine's", ErrIncompatible)
	}
	first := parts[0]
	joint := &Inventory{
		Format:        FormatV1,
		Label:         first.Label,
		Tool:          "dagu txe continuity reconcile",
		ExpectedOwner: first.ExpectedOwner,
		ModeBits:      first.ModeBits,
		Machines:      map[string]string{},
	}
	roots := map[string]bool{}
	records := map[string]bool{}
	files := map[string]bool{}
	kept := map[string]bool{}
	parents := map[string]bool{}
	hubs, homes := 0, 0
	for i, p := range parts {
		if p == nil {
			return nil, fmt.Errorf("%w: part %d is missing", ErrIncompatible, i+1)
		}
		switch {
		case p.Format != FormatV1:
			return nil, fmt.Errorf("%w: %s has format %q", ErrIncompatible, p.Digest, p.Format)
		case p.ExpectedOwner != first.ExpectedOwner:
			return nil, fmt.Errorf("%w: %s expects owner %s, %s expects %s", ErrIncompatible, p.Digest, p.ExpectedOwner, first.Digest, first.ExpectedOwner)
		case p.Label != first.Label:
			return nil, fmt.Errorf("%w: %s is labelled %q, %s %q; parts of one inventory share its label", ErrIncompatible, p.Digest, p.Label, first.Digest, first.Label)
		case p.ModeBits != first.ModeBits:
			return nil, fmt.Errorf("%w: %s and %s differ in whether they recorded permission bits", ErrIncompatible, p.Digest, first.Digest)
		case len(p.Parts) > 0:
			return nil, fmt.Errorf("%w: %s is already a joint inventory; reconcile the inventories it was made from", ErrIncompatible, p.Digest)
		case parents[p.Digest]:
			return nil, fmt.Errorf("%w: %s is given twice", ErrIncompatible, p.Digest)
		}
		parents[p.Digest] = true
		joint.Parts = append(joint.Parts, p.Digest)
		if p.ScannedAt.After(joint.ScannedAt) {
			joint.ScannedAt = p.ScannedAt
		}
		for _, r := range p.Roots {
			if roots[r.Label] {
				return nil, fmt.Errorf("%w: root %q is in more than one part", ErrIncompatible, r.Label)
			}
			roots[r.Label] = true
			switch r.Area {
			case AreaHubData:
				hubs++
			case AreaMachineHome:
				homes++
			}
			joint.Roots = append(joint.Roots, r)
		}
		for _, r := range p.Records {
			key := r.Store + "/" + r.ID
			if records[key] {
				return nil, fmt.Errorf("%w: record %s is in more than one part", ErrIncompatible, key)
			}
			records[key] = true
			joint.Records = append(joint.Records, r)
		}
		for _, f := range p.Files {
			key := f.Root + "/" + f.Path
			if files[key] {
				return nil, fmt.Errorf("%w: file %s is in more than one part", ErrIncompatible, key)
			}
			files[key] = true
			joint.Files = append(joint.Files, f)
		}
		for _, k := range p.Kept {
			key := k.Root + "/" + k.Path
			if kept[key] {
				return nil, fmt.Errorf("%w: kept entry %s is in more than one part", ErrIncompatible, key)
			}
			kept[key] = true
			joint.Kept = append(joint.Kept, k)
		}
		for label, machine := range p.Machines {
			if have, ok := joint.Machines[label]; ok && have != machine {
				return nil, fmt.Errorf("%w: machine home %q names machines %s and %s", ErrIncompatible, label, have, machine)
			}
			joint.Machines[label] = machine
		}
		joint.Excluded = append(joint.Excluded, p.Excluded...)
		joint.Issues = append(joint.Issues, p.Issues...)
	}
	if hubs != 1 {
		return nil, fmt.Errorf("%w: the parts hold %d hub data directories; exactly one holds the registry", ErrIncompatible, hubs)
	}
	if homes == 0 {
		return nil, fmt.Errorf("%w: no part holds a machine home", ErrIncompatible)
	}
	// Every record and file belongs to a root of its own part: a root
	// label used for records of another part would make a machine's
	// packages or files look like someone else's.
	for _, f := range joint.Files {
		if !roots[f.Root] {
			return nil, fmt.Errorf("%w: file %s/%s names a root no part scanned", ErrIncompatible, f.Root, f.Path)
		}
	}
	for label := range joint.Machines {
		if !roots[label] {
			return nil, fmt.Errorf("%w: machine home %q is not a scanned root", ErrIncompatible, label)
		}
	}
	sort.Strings(joint.Parts)
	sort.Slice(joint.Roots, func(i, k int) bool { return joint.Roots[i].Label < joint.Roots[k].Label })
	if err := joint.Seal(); err != nil {
		return nil, err
	}
	return joint, nil
}
