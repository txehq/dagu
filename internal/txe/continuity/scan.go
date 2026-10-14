// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// Root is a directory to scan, as one area.
type Root struct {
	Area string
	Path string
	// Label names the root in the inventory. It must be the same in every
	// inventory that is compared, wherever the root is mounted.
	Label string
	// Mount is where the service that wrote the root sees it, when the scan
	// reads a copy or another mount: for a hub data directory, the hub's
	// data directory path. Paths stored in records are resolved through it.
	Mount string
}

// Options configure a scan.
type Options struct {
	Roots []Root
	// ExpectedOwner is the installation's stable owner. Required.
	ExpectedOwner string
	Label         string
	Tool          string
	Now           func() time.Time
}

// Hub data directory areas. Each top-level entry of the data directory is
// one of these, or the scan reports it as unclassified and blocks.
var hubDataAreas = map[string]string{
	// Retained execution history and state: present later, may change.
	"dag-runs":   PolicyMutable,
	"dag-state":  PolicyMutable,
	"artifacts":  PolicyImmutable,
	"suspend":    PolicyMutable,
	"workspaces": PolicyMutable,
	"views":      PolicyMutable,
	"gitsync":    PolicyMutable,
	// Operational state that is rebuilt or consumed.
	"queue":            PolicyOperational,
	"proc":             PolicyOperational,
	"service-registry": PolicyOperational,
}

// Areas of the data directory that are never read.
var hubDataExcluded = map[string]string{
	"users":            "holds login credentials; not read",
	"apikeys":          "holds API key material; not read",
	"webhooks":         "holds webhook secrets; not read",
	"contexts":         "holds remote context credentials; not read",
	"remote-nodes":     "holds remote node credentials; not read",
	"dag-run-work":     "per-run scratch working directories; operational, not retained",
	"tools":            "downloaded tool binaries; reinstalled, not retained data",
	"materializations": "derived caches; rebuilt",
}

// Areas of a machine's TXE home.
var machineHomeAreas = map[string]string{
	"receipts": PolicyMutable,
	"outputs":  PolicyImmutable,
}

var machineHomeExcluded = map[string]string{
	"client": "the CLI's Dagu home holds its hub credential; not read",
	"skill":  "unpacked skill revisions; reinstalled, not retained data",
}

// Scan inventories the roots. It only reads; a root that cannot be read is
// an error, and anything it does not understand is a blocking issue.
func Scan(ctx context.Context, opts Options) (*Inventory, error) {
	if opts.ExpectedOwner == "" {
		return nil, errors.New("continuity: an expected owner is required")
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	inv := &Inventory{
		Format:        FormatV1,
		Label:         opts.Label,
		ScannedAt:     now().UTC(),
		Tool:          opts.Tool,
		ExpectedOwner: opts.ExpectedOwner,
		Machines:      map[string]string{},
	}
	labels := map[string]bool{}
	for _, r := range opts.Roots {
		if r.Label == "" {
			return nil, fmt.Errorf("continuity: root %s needs a label", r.Path)
		}
		if labels[r.Label] {
			return nil, fmt.Errorf("continuity: root label %q is used twice", r.Label)
		}
		labels[r.Label] = true
		info, err := os.Stat(r.Path)
		if err != nil {
			return nil, fmt.Errorf("continuity: root %s: %w", r.Label, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("continuity: root %s is not a directory", r.Label)
		}
		inv.Roots = append(inv.Roots, RootInfo{Area: r.Area, Label: r.Label, Path: r.Path, Mount: r.Mount})
		s := &scanner{ctx: ctx, inv: inv, root: r}
		switch r.Area {
		case AreaHubData:
			err = s.hubData()
		case AreaDAGs, AreaLogs, AreaArtifacts:
			policy := PolicyMutable
			if r.Area == AreaArtifacts {
				policy = PolicyImmutable
			}
			err = s.files("", policy)
		case AreaMachineHome:
			err = s.machineHome()
		default:
			return nil, fmt.Errorf("continuity: root %s has unknown area %q", r.Label, r.Area)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := inv.Seal(); err != nil {
		return nil, err
	}
	return inv, nil
}

type scanner struct {
	ctx  context.Context
	inv  *Inventory
	root Root
}

func (s *scanner) issue(code, class, id, format string, args ...any) {
	s.inv.Issues = append(s.inv.Issues, Issue{Code: code, Severity: SeverityBlock, Class: class, ID: id, Detail: fmt.Sprintf(format, args...)})
}

func (s *scanner) exclude(rel, reason string) {
	s.inv.Excluded = append(s.inv.Excluded, Excluded{Root: s.root.Label, Path: rel, Reason: reason})
}

func (s *scanner) hubData() error {
	entries, err := os.ReadDir(s.root.Path)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		switch {
		case name == "txe":
			if err := s.txe(); err != nil {
				return err
			}
		case hubDataExcluded[name] != "":
			s.exclude(name, hubDataExcluded[name])
		case hubDataAreas[name] != "":
			if err := s.files(name, hubDataAreas[name]); err != nil {
				return err
			}
		default:
			s.issue("unclassified_area", "", name, "%s/%s is not a known area of the data directory; classify it before a transition, it was not read", s.root.Label, name)
		}
	}
	return nil
}

func (s *scanner) txe() error {
	dir := filepath.Join(s.root.Path, "txe")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		switch name := e.Name(); name {
		case "v1":
			if err := s.store("registry", filepath.Join(dir, "v1"), classifyRegistry); err != nil {
				return err
			}
		case "authz":
			sub, err := os.ReadDir(filepath.Join(dir, "authz"))
			if err != nil {
				return err
			}
			for _, a := range sub {
				if a.Name() == "v1" {
					if err := s.store("authz", filepath.Join(dir, "authz", "v1"), classifyAuthz); err != nil {
						return err
					}
					continue
				}
				s.issue("unclassified_area", "", "txe/authz/"+a.Name(), "txe/authz/%s is not a known authorization store version; it was not read", a.Name())
			}
		case "locks":
			s.exclude("txe/locks", "lock files; operational")
		default:
			s.issue("unclassified_area", "", "txe/"+name, "txe/%s is not a known TXE store; it was not read", name)
		}
	}
	return nil
}

// store reads every record of a file collection rooted at dir.
func (s *scanner) store(store, dir string, classify func(id string, data []byte) (*Record, []Issue)) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := s.ctx.Err(); err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			// The file collection keeps per-record lock directories here.
			if strings.HasPrefix(d.Name(), ".") && rel != "." {
				s.exclude(store+"/"+rel, "collection lock directory; operational")
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 || !d.Type().IsRegular() {
			s.issue("unsupported_record", ClassUnknown, store+"/"+rel, "%s/%s is not a regular file", store, rel)
			return nil
		}
		if !strings.HasSuffix(rel, ".json") {
			if strings.Contains(path.Base(rel), ".tmp") {
				s.exclude(store+"/"+rel, "interrupted atomic write; not a record")
				return nil
			}
			s.issue("unsupported_record", ClassUnknown, store+"/"+rel, "%s/%s is not a JSON record", store, rel)
			return nil
		}
		data, err := os.ReadFile(p) //nolint:gosec // a path under the scanned root
		if err != nil {
			return err
		}
		id := strings.TrimSuffix(rel, ".json")
		rec, issues := classify(id, data)
		rec.Store = store
		rec.ID = id
		if rec.SHA256 == "" {
			rec.SHA256 = recordDigest(data)
		}
		for i := range issues {
			if issues[i].ID == "" {
				issues[i].ID = store + "/" + id
			}
		}
		s.inv.Records = append(s.inv.Records, *rec)
		s.inv.Issues = append(s.inv.Issues, issues...)
		return nil
	})
}

// files digests every file under rel as one area.
func (s *scanner) files(rel, policy string) error {
	base := filepath.Join(s.root.Path, filepath.FromSlash(rel))
	return filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := s.ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		r, err := filepath.Rel(s.root.Path, p)
		if err != nil {
			return err
		}
		f := File{Root: s.root.Label, Path: filepath.ToSlash(r), Policy: policy}
		if d.Type()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			f.Link = target
			s.inv.Files = append(s.inv.Files, f)
			return nil
		}
		if !d.Type().IsRegular() {
			s.issue("unsupported_file", "", s.root.Label+"/"+f.Path, "%s is not a regular file", f.Path)
			return nil
		}
		f.Size, f.SHA256, err = fileDigest(p)
		if err != nil {
			return err
		}
		s.inv.Files = append(s.inv.Files, f)
		return nil
	})
}

func (s *scanner) machineHome() error {
	entries, err := os.ReadDir(s.root.Path)
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		switch {
		case name == "machine.json":
			if err := s.machineIdentity(); err != nil {
				return err
			}
		case name == "packages":
			if err := s.packages(); err != nil {
				return err
			}
		case machineHomeExcluded[name] != "":
			s.exclude(name, machineHomeExcluded[name])
		case machineHomeAreas[name] != "":
			if err := s.files(name, machineHomeAreas[name]); err != nil {
				return err
			}
		default:
			s.issue("unclassified_area", "", s.root.Label+"/"+name, "%s/%s is not a known part of a machine's TXE home; classify it before a transition, it was not read", s.root.Label, name)
		}
	}
	return nil
}

func fileDigest(p string) (int64, string, error) {
	f, err := os.Open(p) //nolint:gosec // a path under the scanned root
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
