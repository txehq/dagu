// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// machineIdentity reads the machine's machine.json. It names the machine
// whose packages and outputs the home holds.
func (s *scanner) machineIdentity() error {
	p := filepath.Join(s.root.Path, "machine.json")
	if ok, err := regular(p); err != nil || !ok {
		if err != nil {
			return err
		}
		s.issue("unsupported_file", ClassMachineIdentity, s.root.Label+"/machine.json", "machine.json is not a regular file; it was not read")
		return nil
	}
	data, err := os.ReadFile(p) //nolint:gosec // a fixed name under the scanned root
	if err != nil {
		return err
	}
	b := newBuilder(ClassMachineIdentity)
	var m txepkg.Machine
	if b.decode(data, &m) {
		b.schema(m.Schema)
		b.owner(m.OwnerID)
		b.required("machine", KindMachine, m.MachineID)
		checkID(b, registry.PrefixMachine, m.MachineID, "machine_id")
		s.inv.Machines[s.root.Label] = m.MachineID
	}
	rec, issues := b.done()
	rec.Store = s.root.Label
	rec.ID = "machine.json"
	rec.SHA256 = recordDigest(data)
	for i := range issues {
		issues[i].ID = s.root.Label + "/machine.json"
	}
	s.inv.Records = append(s.inv.Records, *rec)
	s.inv.Issues = append(s.inv.Issues, issues...)
	return nil
}

// packages verifies every stored package against its digest and lists its
// files. The staging area is retained as it is: a staged build may belong to
// a registration journal that still refers to it.
func (s *scanner) packages() error {
	dir := filepath.Join(s.root.Path, "packages")
	jobs, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, j := range jobs {
		name := j.Name()
		if s.symlink("packages/"+name, j) {
			continue
		}
		switch {
		case name == ".staging":
			if err := s.files("packages/.staging", PolicyMutable); err != nil {
				return err
			}
			continue
		case name == ".staging.lock":
			s.exclude("packages/.staging.lock", "lock file; operational")
			continue
		case !j.IsDir():
			s.issue("unsupported_file", ClassPackage, s.root.Label+"/packages/"+name, "packages/%s is not a job's package directory", name)
			continue
		}
		if err := registry.ValidateID(registry.PrefixJob, name); err != nil {
			s.issue("unsupported_file", ClassPackage, s.root.Label+"/packages/"+name, "packages/%s is not named by a job ID", name)
			continue
		}
		digests, err := os.ReadDir(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		for _, d := range digests {
			if s.symlink("packages/"+name+"/"+d.Name(), d) {
				continue
			}
			if !d.IsDir() {
				s.issue("unsupported_file", ClassPackage, s.root.Label+"/packages/"+name+"/"+d.Name(), "packages/%s/%s is not a package directory", name, d.Name())
				continue
			}
			if err := s.pkg(name, d.Name()); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *scanner) pkg(jobID, dirName string) error {
	rel := "packages/" + jobID + "/" + dirName
	dir := filepath.Join(s.root.Path, filepath.FromSlash(rel))
	b := newBuilder(ClassPackage)
	b.rec.Store = s.root.Label
	b.rec.ID = rel
	b.rec.Job = jobID
	// A package can be committed before its registration is: one whose job
	// the registry does not hold is retained and reported, not refused.
	b.optRef("job", KindJob, jobID)
	digest := strings.Replace(dirName, "-", ":", 1)
	if _, err := txepkg.DigestDirName(digest); err != nil {
		b.block("invalid_id", "%s is not named by a package digest", rel)
	}
	b.attr("digest", digest)
	manifestPath := filepath.Join(dir, txepkg.ManifestName)
	var manifest []byte
	isRegular, err := regular(manifestPath)
	if err == nil && !isRegular {
		err = errors.New("it is not a regular file")
	}
	if err == nil {
		manifest, err = os.ReadFile(manifestPath) //nolint:gosec // a path under the scanned root
	}
	switch {
	case err != nil:
		b.block("package_corrupt", "%s has no readable manifest: %v", rel, err)
		b.rec.SHA256 = digest
	default:
		found := txepkg.Digest(manifest)
		b.rec.SHA256 = found
		if found != digest {
			b.block("package_corrupt", "%s holds a manifest with digest %s", rel, found)
		}
		var m txepkg.Manifest
		if b.decode(manifest, &m) {
			if m.Schema != txepkg.ManifestSchema {
				b.block("unsupported_schema", "package manifest schema %d is not supported", m.Schema)
			}
			s.checkPayload(b, dir, rel, m.Files)
			checkSealed(b, rel, dir, manifestPath)
		}
	}
	// The package's own bytes are inventoried too, so a later inventory
	// detects a changed file even if its manifest stayed.
	if err := s.files(rel, PolicyImmutable); err != nil {
		return err
	}
	if len(b.issues) == 0 {
		// Only a package that verified counts as the version's package.
		b.define(KindPackage, jobID+"|"+digest)
	}
	rec, issues := b.done()
	for i := range issues {
		issues[i].ID = s.root.Label + "/" + rel
	}
	s.inv.Records = append(s.inv.Records, *rec)
	s.inv.Issues = append(s.inv.Issues, issues...)
	return nil
}

// checkPayload compares the payload with the manifest's file list.
func (s *scanner) checkPayload(b *builder, dir, rel string, files []txepkg.File) {
	listed := map[string]txepkg.File{}
	for _, f := range files {
		listed[f.Path] = f
	}
	payload := filepath.Join(dir, txepkg.FilesDir)
	if info, err := os.Lstat(payload); err != nil || !info.IsDir() {
		b.block("package_corrupt", "%s has no payload directory", rel)
		return
	}
	err := filepath.WalkDir(payload, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		r, _ := filepath.Rel(payload, p)
		r = filepath.ToSlash(r)
		want, ok := listed[r]
		if !ok {
			b.block("package_corrupt", "%s/files/%s is not in the manifest", rel, r)
			return nil
		}
		delete(listed, r)
		if !d.Type().IsRegular() {
			b.block("package_corrupt", "%s/files/%s is not a regular file", rel, r)
			return nil
		}
		size, sum, err := fileDigest(p)
		if err != nil {
			return err
		}
		// The package store records a payload hash as bare hex.
		if size != want.Size || strings.TrimPrefix(sum, "sha256:") != strings.TrimPrefix(want.SHA256, "sha256:") {
			b.block("package_corrupt", "%s/files/%s does not match its manifest entry", rel, r)
		}
		if hasModeBits {
			info, err := d.Info()
			if err != nil {
				return err
			}
			if (info.Mode().Perm()&0o111 != 0) != want.Executable {
				b.block("package_corrupt", "the executable bit of %s/files/%s is not as packaged", rel, r)
			}
		}
		return nil
	})
	if err != nil {
		b.block("package_corrupt", "%s payload could not be read: %v", rel, err)
	}
	var missing []string
	for p := range listed {
		missing = append(missing, p)
	}
	sort.Strings(missing)
	for _, p := range missing {
		b.block("package_corrupt", "%s/files/%s is in the manifest but missing", rel, p)
	}
}

// checkSealed refuses a package that is writable, as the package store's
// own verification does: a package is sealed when it is committed.
func checkSealed(b *builder, rel, dir, manifest string) {
	if !hasModeBits {
		return
	}
	writable := false
	for _, p := range []string{dir, manifest} {
		if info, err := os.Lstat(p); err != nil || info.Mode().Perm()&0o222 != 0 {
			writable = true
		}
	}
	_ = filepath.WalkDir(filepath.Join(dir, txepkg.FilesDir), func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // a read failure is reported by checkPayload
		}
		if info, err := d.Info(); err == nil && info.Mode().Perm()&0o222 != 0 {
			writable = true
		}
		return nil
	})
	if writable {
		b.block("package_corrupt", "%s is writable; a committed package is sealed", rel)
	}
}
