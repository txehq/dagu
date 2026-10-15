// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// KeepFormatV1 is the format of a keep manifest.
const KeepFormatV1 = "txe.continuity.keep/v1"

// KeepManifest names entries that no TXE writer owns but that are kept
// exactly as they are: each one is attributed, and pinned by the digest of
// its whole tree.
type KeepManifest struct {
	Format  string      `json:"format"`
	Entries []KeepEntry `json:"entries"`
}

// KeepEntry is one kept entry. It applies only where the scan would
// otherwise block because nothing classifies the entry: it never overrides
// a classified or excluded area.
type KeepEntry struct {
	// Root is the label of the scanned root that holds the entry.
	Root string `json:"root"`
	// Path is the entry's slash-separated path under the root.
	Path string `json:"path"`
	// Digest pins the entry's tree (TreeDigest). An entry without one
	// blocks and reports the digest it found, for review.
	Digest string `json:"digest,omitempty"`
	// Provenance says who wrote the entry, when and how.
	Provenance string `json:"provenance"`
	// Exclude names paths under the entry that are never opened, such as a
	// key. Only their names and types are pinned.
	Exclude []string `json:"exclude,omitempty"`
	// Credential says the entry itself is a credential kept at a path no
	// rule names, such as a worker credential file given to dagu txe enrol
	// inside the TXE home. It is never opened: only its type and permission
	// bits are pinned, so a rotation that rewrites it in place is not a
	// change.
	Credential bool `json:"credential,omitempty"`
}

var keepDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// keepCredentialNames are names under which writers keep credentials. A
// kept entry that holds one must exclude it.
var keepCredentialNames = map[string]bool{
	"auth": true, "users": true, "apikeys": true, "webhooks": true, "contexts": true, "remote-nodes": true,
	"tailscale": true, "license": true, "secrets": true, "oidc_sessions": true, "client": true, "tunnel": true,
	"encryption_key": true, "kubeconfig": true,
}

// DecodeKeep reads a keep manifest strictly.
func DecodeKeep(data []byte) (*KeepManifest, error) {
	var m KeepManifest
	if err := strict(data, &m); err != nil {
		return nil, fmt.Errorf("keep manifest: %w", err)
	}
	if m.Format != KeepFormatV1 {
		return nil, fmt.Errorf("keep manifest: format %q is not %s", m.Format, KeepFormatV1)
	}
	seen := map[string]bool{}
	for i, e := range m.Entries {
		if e.Root == "" || strings.ContainsAny(e.Root, "/\\") {
			return nil, fmt.Errorf("keep manifest: entry %d: root %q is not a root label", i, e.Root)
		}
		if !cleanRel(e.Path) {
			return nil, fmt.Errorf("keep manifest: entry %d: path %q is not a clean relative path", i, e.Path)
		}
		if strings.TrimSpace(e.Provenance) == "" {
			return nil, fmt.Errorf("keep manifest: entry %d (%s/%s) has no provenance", i, e.Root, e.Path)
		}
		if e.Digest != "" && !keepDigestPattern.MatchString(e.Digest) {
			return nil, fmt.Errorf("keep manifest: entry %d (%s/%s): digest %q is not sha256:<64 hex>", i, e.Root, e.Path, e.Digest)
		}
		key := e.Root + "/" + e.Path
		if e.Credential && len(e.Exclude) > 0 {
			return nil, fmt.Errorf("keep manifest: %s is a credential, which is never read; it has nothing to exclude", key)
		}
		if seen[key] {
			return nil, fmt.Errorf("keep manifest: %s is kept twice", key)
		}
		seen[key] = true
		ex := map[string]bool{}
		for _, x := range e.Exclude {
			if !cleanRel(x) || ex[x] {
				return nil, fmt.Errorf("keep manifest: %s: exclude %q is not a clean relative path, or is repeated", key, x)
			}
			ex[x] = true
		}
	}
	return &m, nil
}

func cleanRel(p string) bool {
	return p != "" && p != "." && !strings.Contains(p, "\\") && !path.IsAbs(p) && path.Clean(p) == p &&
		p != ".." && !strings.HasPrefix(p, "../")
}

// kept takes over an entry the scan cannot classify, when the manifest
// keeps it. It reports whether it did.
func (s *scanner) kept(rel string) (bool, error) {
	e := s.keep[s.root.Label+"/"+rel]
	if e == nil {
		return false, nil
	}
	s.keepSeen[s.root.Label+"/"+rel] = true
	id := s.root.Label + "/" + rel
	var digest, refused string
	var err error
	if e.Credential {
		digest, err = s.keepCredential(rel)
	} else {
		digest, refused, err = s.keepTree(rel, e)
	}
	if err != nil {
		return true, err
	}
	k := Kept{Root: s.root.Label, Path: rel, Digest: digest, Provenance: e.Provenance}
	if refused != "" {
		k.Refused = path.Join(rel, refused)
	}
	s.inv.Kept = append(s.inv.Kept, k)
	switch {
	case refused != "":
		s.issue("kept_credential", "", id, "%s is or holds %s, whose name is where credentials are kept; exclude it in the keep manifest, it was not read", id, path.Join(rel, refused))
	case e.Digest == "":
		s.issue("kept_unpinned", "", id, "%s is kept but not pinned; its tree digest is %s, pin it after review", id, digest)
	case e.Digest != digest:
		s.issue("kept_changed", "", id, "%s is pinned at %s but its tree digest is now %s", id, e.Digest, digest)
	default:
		s.inv.Issues = append(s.inv.Issues, Issue{Code: "kept_unclassified", Severity: SeverityWarn, ID: id,
			Detail: fmt.Sprintf("%s is no TXE writer's; kept exactly as it is (%s): %s", id, digest, e.Provenance)})
	}
	return true, nil
}

// keepTree inventories every file under a kept entry as immutable, without
// following links or opening an excluded path, and returns the digest of
// the tree: each path's type, permission bits, and its content digest or
// link target. It refuses, without reading it, a credential-named path that
// the entry does not exclude.
func (s *scanner) keepTree(rel string, e *KeepEntry) (digest, refused string, err error) {
	exclude := map[string]bool{}
	for _, x := range e.Exclude {
		exclude[x] = true
	}
	var lines []string
	base := filepath.Join(s.root.Path, filepath.FromSlash(rel))
	err = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := s.ctx.Err(); err != nil {
			return err
		}
		r, err := filepath.Rel(base, p)
		if err != nil {
			return err
		}
		r = filepath.ToSlash(r)
		info, err := d.Info()
		if err != nil {
			return err
		}
		perm := uint32(0)
		if hasModeBits {
			perm = uint32(info.Mode().Perm())
		}
		kind := "f"
		switch {
		case d.IsDir():
			kind = "d"
		case d.Type()&fs.ModeSymlink != 0:
			kind = "l"
		case !d.Type().IsRegular():
			// A device, socket or pipe: its exact type is pinned.
			kind = "o:" + info.Mode().Type().String()
		}
		if r != "." && exclude[r] {
			lines = append(lines, fmt.Sprintf("x\x00%s\x00%s", r, kind))
			s.exclude(rel+"/"+r, "kept entry; excluded by the keep manifest and not read")
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if keepCredentialNames[d.Name()] {
			// Pinned by its name and type, never opened.
			lines = append(lines, fmt.Sprintf("c\x00%s\x00%s", r, kind))
			if refused == "" {
				refused = r
			}
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		f := File{Root: s.root.Label, Path: path.Join(rel, r), Policy: PolicyImmutable, Mode: perm}
		switch kind {
		case "d":
			lines = append(lines, fmt.Sprintf("d\x00%s\x00%o", r, perm))
			return nil
		case "l":
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			f.Link = target
			lines = append(lines, fmt.Sprintf("l\x00%s\x00%s", r, target))
		case "f":
			f.Size, f.SHA256, err = fileDigest(p)
			if err != nil {
				return err
			}
			lines = append(lines, fmt.Sprintf("f\x00%s\x00%o\x00%s", r, perm, f.SHA256))
		default:
			// A device, socket or pipe is pinned by its type and
			// permission bits, and never opened.
			lines = append(lines, fmt.Sprintf("%s\x00%s\x00%o", kind, r, perm))
			return nil
		}
		s.inv.Files = append(s.inv.Files, f)
		return nil
	})
	if err != nil {
		return "", "", err
	}
	for x := range exclude {
		found := false
		for _, l := range lines {
			if strings.HasPrefix(l, "x\x00"+x+"\x00") {
				found = true
			}
		}
		if !found {
			// A declared exclusion that is not there is part of the tree.
			lines = append(lines, "x\x00"+x+"\x00absent")
		}
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return "sha256:" + hex.EncodeToString(sum[:]), refused, nil
}

// keepCredential pins a kept credential by its type and permission bits,
// from its directory entry, without opening it or anything under it.
func (s *scanner) keepCredential(rel string) (string, error) {
	info, err := os.Lstat(filepath.Join(s.root.Path, filepath.FromSlash(rel)))
	if err != nil {
		return "", err
	}
	perm := uint32(0)
	if hasModeBits {
		perm = uint32(info.Mode().Perm())
	}
	s.exclude(rel, "a credential kept by the keep manifest; not read")
	sum := sha256.Sum256([]byte(fmt.Sprintf("k\x00%s\x00%o", info.Mode().Type().String(), perm)))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// keptMissing blocks for every entry of the manifest that the scan did not
// find, whichever root it names: a manifest names exactly what one
// inventory keeps.
func keptMissing(inv *Inventory, keep map[string]*KeepEntry, seen map[string]bool) {
	var missing []string
	for key := range keep {
		if !seen[key] {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	for _, key := range missing {
		inv.Issues = append(inv.Issues, Issue{Code: "kept_missing", Severity: SeverityBlock, ID: key,
			Detail: fmt.Sprintf("%s is kept by the keep manifest but was not found: it is gone, now classified, or its root was not scanned", key)})
	}
}

// keepIndex indexes a manifest's entries by root label and path.
func keepIndex(m *KeepManifest) (map[string]*KeepEntry, error) {
	out := map[string]*KeepEntry{}
	if m == nil {
		return out, nil
	}
	if m.Format != KeepFormatV1 {
		return nil, errors.New("continuity: the keep manifest was not decoded with DecodeKeep")
	}
	for i := range m.Entries {
		e := &m.Entries[i]
		out[e.Root+"/"+e.Path] = e
	}
	return out, nil
}
