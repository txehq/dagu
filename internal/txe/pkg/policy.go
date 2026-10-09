// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrNotDurable reports a path that a cleanup could remove: one inside a git
// working tree or a temporary directory.
var ErrNotDurable = errors.New("path is not durable")

// ErrCredentialFile reports a file that looks like a credential. Packages
// carry references to credentials, never the credentials themselves.
var ErrCredentialFile = errors.New("file looks like a credential")

// PathPolicy decides which paths a registered job may depend on.
type PathPolicy struct {
	// TempRoots are directories whose contents are treated as disposable.
	TempRoots []string
	// HomeDir bounds the search for an enclosing git working tree: a
	// repository rooted at the home directory or above it is ignored.
	HomeDir string
}

// DefaultPathPolicy treats the system temporary directories as disposable.
func DefaultPathPolicy() PathPolicy {
	roots := []string{os.TempDir(), "/tmp", "/var/tmp", "/var/folders"}
	home, _ := os.UserHomeDir()
	return PathPolicy{TempRoots: roots, HomeDir: home}
}

// CheckDurable returns ErrNotDurable when path lies in a temporary directory
// or inside a git working tree.
func (p PathPolicy) CheckDurable(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%w: %s is not absolute", ErrNotDurable, path)
	}
	resolved := resolveExisting(path)
	for _, root := range p.TempRoots {
		if root == "" {
			continue
		}
		if within(resolveExisting(root), resolved) {
			return fmt.Errorf("%w: %s is under the temporary directory %s", ErrNotDurable, path, root)
		}
	}
	if tree := p.enclosingWorktree(resolved); tree != "" {
		return fmt.Errorf("%w: %s is inside the git working tree %s", ErrNotDurable, path, tree)
	}
	return nil
}

// enclosingWorktree returns the nearest ancestor of path that holds a .git
// entry. The home directory and its ancestors are not considered.
func (p PathPolicy) enclosingWorktree(path string) string {
	home := ""
	if p.HomeDir != "" {
		home = resolveExisting(p.HomeDir)
	}
	for dir := path; ; dir = filepath.Dir(dir) {
		if home != "" && within(dir, home) {
			return ""
		}
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		if dir == filepath.Dir(dir) {
			return ""
		}
	}
}

// resolveExisting resolves symlinks in the longest existing prefix of path, so
// that /tmp and /private/tmp compare equal on macOS.
func resolveExisting(path string) string {
	path = filepath.Clean(path)
	rest := ""
	for dir := path; ; dir = filepath.Dir(dir) {
		if real, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(real, rest)
		}
		if dir == filepath.Dir(dir) {
			return path
		}
		rest = filepath.Join(filepath.Base(dir), rest)
	}
}

// within reports whether path is root or lies beneath it.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

var credentialNames = map[string]bool{
	".env": true, ".netrc": true, ".npmrc": true, ".pypirc": true,
	"kubeconfig": true, "credentials": true, "credentials.json": true,
	"id_rsa": true, "id_dsa": true, "id_ecdsa": true, "id_ed25519": true,
	"token": true,
}

var credentialSuffixes = []string{
	".pem", ".key", ".p12", ".pfx", ".kubeconfig", ".token",
}

// looksLikeCredentialName reports whether a file name is one conventionally
// used for a credential.
func looksLikeCredentialName(base string) bool {
	lower := strings.ToLower(base)
	if credentialNames[lower] || strings.HasPrefix(lower, ".env.") {
		return true
	}
	for _, suffix := range credentialSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// looksLikeCredentialContent recognises a private key or a kubeconfig from
// the start of a file.
func looksLikeCredentialContent(head []byte) bool {
	if bytes.Contains(head, []byte("-----BEGIN")) && bytes.Contains(head, []byte("PRIVATE KEY-----")) {
		return true
	}
	return bytes.Contains(head, []byte("kind: Config")) &&
		bytes.Contains(head, []byte("clusters:")) &&
		bytes.Contains(head, []byte("users:"))
}
