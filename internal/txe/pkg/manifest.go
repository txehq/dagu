// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// ManifestSchema is the version of the manifest format written by this package.
const ManifestSchema = 1

// ManifestName is the manifest's file name inside a package directory.
const ManifestName = "manifest.json"

// FilesDir is the payload directory inside a package. It is the working
// directory of the job's steps.
const FilesDir = "files"

const digestPrefix = "sha256:"

// Manifest describes one immutable package. Its exact bytes on disk are what
// the package digest covers, and it lists the hash of every payload file.
type Manifest struct {
	Schema int `json:"schema"`
	// Entrypoint is the command the job runs, relative to the payload
	// directory when its first element names a packaged file.
	Entrypoint []string `json:"entrypoint"`
	Files      []File   `json:"files"`
	// ContentSHA256 covers the payload alone, so two packages with the same
	// files compare equal whatever their provenance.
	ContentSHA256  string          `json:"content_sha256"`
	Runtimes       []string        `json:"runtimes,omitempty"`
	CredentialRefs []CredentialRef `json:"credential_refs,omitempty"`
	Provenance     Provenance      `json:"provenance"`
}

// File is one payload file, by its slash-separated path under FilesDir.
type File struct {
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Executable bool   `json:"executable,omitempty"`
}

// Provenance records where a package's files came from. It is evidence for a
// reader, not an identity: ownership never derives from it.
type Provenance struct {
	Repository string `json:"repository,omitempty"`
	Commit     string `json:"commit,omitempty"`
	// SourceRoot is the directory the files were copied from. The package
	// does not depend on it after creation.
	SourceRoot string `json:"source_root"`
	// Uncommitted lists packaged files that differed from Commit or were
	// untracked, so a reader knows the commit alone does not reproduce them.
	Uncommitted []string `json:"uncommitted,omitempty"`
	Session     string   `json:"session,omitempty"`
}

// Credential reference kinds.
const (
	// CredentialFile names a file on the machine whose content is the value.
	CredentialFile = "file"
	// CredentialEnv names a variable in the worker's own environment.
	CredentialEnv = "env"
)

// CredentialRef names a credential the job needs at run time. Locator says
// where the worker finds it on the machine; the value is never read here.
type CredentialRef struct {
	// Name is the environment variable the job's script receives.
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Locator string `json:"locator"`
}

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Validate checks the reference's shape without touching the credential.
func (r CredentialRef) Validate(policy PathPolicy) error {
	if !envNamePattern.MatchString(r.Name) {
		return fmt.Errorf("credential reference name %q is not a valid variable name", r.Name)
	}
	switch r.Kind {
	case CredentialFile:
		if !filepath.IsAbs(r.Locator) {
			return fmt.Errorf("credential reference %s: file locator %q must be an absolute path", r.Name, r.Locator)
		}
		if err := policy.CheckDurable(r.Locator); err != nil {
			return fmt.Errorf("credential reference %s: %w", r.Name, err)
		}
	case CredentialEnv:
		if !envNamePattern.MatchString(r.Locator) {
			return fmt.Errorf("credential reference %s: env locator %q is not a valid variable name", r.Name, r.Locator)
		}
	default:
		return fmt.Errorf("credential reference %s: kind must be %q or %q, got %q", r.Name, CredentialFile, CredentialEnv, r.Kind)
	}
	return nil
}

// encode renders the manifest in the form that is written to disk and hashed.
func (m *Manifest) encode() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	return buf.Bytes(), nil
}

// Digest returns the package digest of a manifest's bytes as "sha256:<hex>".
func Digest(manifest []byte) string {
	sum := sha256.Sum256(manifest)
	return digestPrefix + hex.EncodeToString(sum[:])
}

// contentDigest hashes the payload listing: path, executable bit and file hash.
func contentDigest(files []File) string {
	h := sha256.New()
	for _, f := range files {
		mode := "-"
		if f.Executable {
			mode = "x"
		}
		fmt.Fprintf(h, "%s\x00%s\x00%s\n", f.Path, mode, f.SHA256)
	}
	return hex.EncodeToString(h.Sum(nil))
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// DigestDirName is the directory name for a digest: the colon is replaced so
// the path can appear in colon-separated variables.
func DigestDirName(digest string) (string, error) {
	if !digestPattern.MatchString(digest) {
		return "", fmt.Errorf("invalid package digest %q", digest)
	}
	return strings.Replace(digest, ":", "-", 1), nil
}
