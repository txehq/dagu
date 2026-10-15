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
	given := map[string]bool{}
	for i, p := range parts {
		if p == nil {
			return nil, fmt.Errorf("%w: part %d is missing", ErrIncompatible, i+1)
		}
		if given[p.Digest] {
			return nil, fmt.Errorf("%w: %s is given twice", ErrIncompatible, p.Digest)
		}
		given[p.Digest] = true
	}
	// A root label names the part that scanned it, and only that part
	// may hold records, files, kept entries, exclusions or a machine
	// identity under it.
	owner := map[string]int{}
	for i, p := range parts {
		for _, r := range p.Roots {
			if hubStores[r.Label] {
				return nil, fmt.Errorf("%w: root label %q of %s names a hub store", ErrIncompatible, r.Label, p.Digest)
			}
			if _, ok := owner[r.Label]; ok {
				return nil, fmt.Errorf("%w: root %q is in more than one part", ErrIncompatible, r.Label)
			}
			owner[r.Label] = i
		}
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
	records := map[string]bool{}
	files := map[string]bool{}
	kept := map[string]bool{}
	hubs, homes := 0, 0
	for i, p := range parts {
		own := func(label, what string) error {
			if j, ok := owner[label]; !ok || j != i {
				return fmt.Errorf("%w: %s of %s names root %q, which that inventory did not scan", ErrIncompatible, what, p.Digest, label)
			}
			return nil
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
		}
		joint.Parts = append(joint.Parts, p.Digest)
		if p.ScannedAt.After(joint.ScannedAt) {
			joint.ScannedAt = p.ScannedAt
		}
		for _, r := range p.Roots {
			switch r.Area {
			case AreaHubData:
				hubs++
			case AreaMachineHome:
				homes++
			}
			joint.Roots = append(joint.Roots, r)
		}
		hasHub := false
		for _, r := range p.Roots {
			hasHub = hasHub || r.Area == AreaHubData
		}
		for _, r := range p.Records {
			// The registry's and the authorization store's records come
			// from the hub's data directory; a machine home's are stored
			// under its root label. Nothing else is a record's store.
			switch {
			case hubStores[r.Store]:
				if !hasHub {
					return nil, fmt.Errorf("%w: record %s/%s of %s is a hub record, but that inventory did not scan the hub's data directory", ErrIncompatible, r.Store, r.ID, p.Digest)
				}
			default:
				if err := own(r.Store, "record "+r.Store+"/"+r.ID); err != nil {
					return nil, err
				}
			}
			key := r.Store + "/" + r.ID
			if records[key] {
				return nil, fmt.Errorf("%w: record %s is in more than one part", ErrIncompatible, key)
			}
			records[key] = true
			joint.Records = append(joint.Records, r)
		}
		for _, f := range p.Files {
			if err := own(f.Root, "file "+f.Path); err != nil {
				return nil, err
			}
			key := f.Root + "/" + f.Path
			if files[key] {
				return nil, fmt.Errorf("%w: file %s is in more than one part", ErrIncompatible, key)
			}
			files[key] = true
			joint.Files = append(joint.Files, f)
		}
		for _, k := range p.Kept {
			if err := own(k.Root, "kept entry "+k.Path); err != nil {
				return nil, err
			}
			key := k.Root + "/" + k.Path
			if kept[key] {
				return nil, fmt.Errorf("%w: kept entry %s is in more than one part", ErrIncompatible, key)
			}
			kept[key] = true
			joint.Kept = append(joint.Kept, k)
		}
		for label, machine := range p.Machines {
			if err := own(label, "machine "+machine); err != nil {
				return nil, err
			}
			if have, ok := joint.Machines[label]; ok && have != machine {
				return nil, fmt.Errorf("%w: machine home %q names machines %s and %s", ErrIncompatible, label, have, machine)
			}
			joint.Machines[label] = machine
		}
		for _, e := range p.Excluded {
			if err := own(e.Root, "exclusion "+e.Path); err != nil {
				return nil, err
			}
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
	sort.Strings(joint.Parts)
	sort.Slice(joint.Roots, func(i, k int) bool { return joint.Roots[i].Label < joint.Roots[k].Label })
	if err := joint.Seal(); err != nil {
		return nil, err
	}
	return joint, nil
}
