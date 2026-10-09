// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"bytes"
	"context"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// DetectProvenance reads the git state of the directory a package is built
// from: the repository, the commit, and which of the given paths differ from
// that commit or are untracked. A directory outside git yields only the
// source root. It never fails: provenance is a record for readers, and a
// package is valid without it.
func DetectProvenance(ctx context.Context, sourceRoot string, include []string) Provenance {
	p := Provenance{SourceRoot: sourceRoot}
	top, ok := gitOutput(ctx, sourceRoot, "rev-parse", "--show-toplevel")
	if !ok {
		return p
	}
	if commit, ok := gitOutput(ctx, sourceRoot, "rev-parse", "HEAD"); ok {
		p.Commit = commit
	}
	if remote, ok := gitOutput(ctx, sourceRoot, "remote", "get-url", "origin"); ok {
		p.Repository = NormalizeRepository(remote)
	}

	args := append([]string{"status", "--porcelain", "--untracked-files=all", "--"}, include...)
	status, ok := gitOutput(ctx, sourceRoot, args...)
	if !ok || status == "" {
		return p
	}
	for line := range strings.SplitSeq(status, "\n") {
		if len(line) < 4 {
			continue
		}
		// Porcelain paths are relative to the repository root; a rename is
		// reported as "old -> new".
		path := line[3:]
		if _, renamed, ok := strings.Cut(path, " -> "); ok {
			path = renamed
		}
		path = strings.Trim(path, `"`)
		if rel, err := filepath.Rel(sourceRoot, filepath.Join(top, path)); err == nil {
			p.Uncommitted = append(p.Uncommitted, filepath.ToSlash(rel))
		}
	}
	sort.Strings(p.Uncommitted)
	return p
}

func gitOutput(ctx context.Context, dir string, args ...string) (string, bool) {
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", dir}, args...)...) //nolint:gosec // fixed binary; arguments are paths the caller already reads
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", false
	}
	return strings.TrimRight(out.String(), "\n"), true
}

var scpRemote = regexp.MustCompile(`^[^@/]+@([^:/]+):(.+)$`)

// NormalizeRepository turns a git remote URL into a stable key such as
// github.com/txehq/txe: no scheme, credentials, port or ".git", and lower
// case. Two clones of one repository give the same key whichever protocol
// they use.
func NormalizeRepository(remote string) string {
	remote = strings.TrimSpace(remote)
	if _, rest, ok := strings.Cut(remote, "://"); ok {
		host, path, _ := strings.Cut(rest, "/")
		if i := strings.LastIndex(host, "@"); i >= 0 {
			host = host[i+1:]
		}
		host, _, _ = strings.Cut(host, ":")
		remote = host + "/" + path
	} else if m := scpRemote.FindStringSubmatch(remote); m != nil {
		remote = m[1] + "/" + m[2]
	}
	remote = strings.TrimSuffix(strings.TrimSuffix(remote, "/"), ".git")
	return strings.ToLower(remote)
}
