// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// installerSources are the scripts that write a machine's TXE home, or name a
// place in it: the worker kit for both service managers and the developer
// install (TXE-7312). A new script there is read without a change here.
var installerSources = []string{"txe/worker/*.sh", "txe/worker/*.py", "txe/developer/*.sh"}

var (
	// "$TXE_DAGU_HOME/a/b", "${TXE_DAGU_HOME}/a/b" or "$TXE_DAGU_HOME"/a.
	shellHomePath = regexp.MustCompile(`\$\{?TXE_DAGU_HOME\}?"?/([^"'\s,;)|<>]+)`)
	// mkdir -p "$TXE_DAGU_HOME"/{bin,packages,...}
	shellHomeBraces = regexp.MustCompile(`\$\{?TXE_DAGU_HOME\}?"?/\{([^}]+)\}`)
	// f"{home}/a/b" in the Python helpers.
	pythonHomePath = regexp.MustCompile(`\{home\}/([^"'\s,;)]+)`)
	// os.path.join(home, "a", "b")
	pythonHomeJoin = regexp.MustCompile(`os\.path\.join\(home((?:\s*,\s*"[^"]+")+)\s*\)`)
	quoted         = regexp.MustCompile(`"([^"]+)"`)
)

// installerPathValues are the values a variable in an installer's path takes.
// A path with a variable not listed here fails the check, so a new one is
// named here before it can pass.
var installerPathValues = map[string][]string{
	"$version": {"2.18.2-txe.6"},
	"{stem}":   {"tunnel", "worker"},
	// A glob over logpipe's rotated logs (status.sh).
	"*": {logpipeStamp},
}

// logpipeStamp is a stamp in logpipe.py's format (STAMP, _STAMP_RE).
const logpipeStamp = "20261113T080000123456Z"

// logpipeOwned matches a log an installer gives logpipe.py as --path; its
// own diagnostics and launchd's files are not logs logpipe rotates.
var logpipeOwned = regexp.MustCompile(`^logs/[a-z-]+\.log$`)

// homePathsInInstallers returns every machine-home path the installer
// sources name, by source, with its variables replaced.
func homePathsInInstallers(t *testing.T) map[string][]string {
	t.Helper()
	root := filepath.Join("..", "..", "..")
	found := map[string][]string{}
	add := func(src, rel string) {
		rel = strings.TrimRight(rel, ".:")
		for _, p := range expandInstallerPath(t, src, rel) {
			found[p] = append(found[p], src)
		}
	}
	for _, glob := range installerSources {
		files, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(glob)))
		require.NoError(t, err)
		require.NotEmpty(t, files, glob)
		for _, file := range files {
			data, err := os.ReadFile(file) //nolint:gosec // a source file of this repository
			require.NoError(t, err)
			src, err := filepath.Rel(root, file)
			require.NoError(t, err)
			src = filepath.ToSlash(src)
			text := string(data)
			for _, m := range shellHomeBraces.FindAllStringSubmatch(text, -1) {
				for name := range strings.SplitSeq(m[1], ",") {
					add(src, strings.TrimSpace(name))
				}
			}
			for _, m := range shellHomePath.FindAllStringSubmatch(text, -1) {
				if !strings.HasPrefix(m[1], "{") {
					add(src, m[1])
				}
			}
			for _, m := range pythonHomePath.FindAllStringSubmatch(text, -1) {
				add(src, m[1])
			}
			for _, m := range pythonHomeJoin.FindAllStringSubmatch(text, -1) {
				var parts []string
				for _, q := range quoted.FindAllStringSubmatch(m[1], -1) {
					parts = append(parts, q[1])
				}
				add(src, strings.Join(parts, "/"))
			}
		}
	}
	return found
}

func expandInstallerPath(t *testing.T, src, rel string) []string {
	out := []string{rel}
	vars := make([]string, 0, len(installerPathValues))
	for v := range installerPathValues {
		vars = append(vars, v)
	}
	sort.Strings(vars)
	for _, v := range vars {
		values := installerPathValues[v]
		var next []string
		for _, p := range out {
			if !strings.Contains(p, v) {
				next = append(next, p)
				continue
			}
			for _, value := range values {
				next = append(next, strings.ReplaceAll(p, v, value))
			}
		}
		out = next
	}
	for _, p := range out {
		assert.NotRegexp(t, `[$\{\}*?\[]`, p, "%s names the home path %q with a variable this check does not know; add its values to installerPathValues", src, rel)
	}
	return out
}

// logpipeNames are the names logpipe.py (txe/worker/logpipe.py) writes beside
// a log it owns: rotated, compressed, being compressed, the archive of a log
// it took over, and its diagnostics with their one previous copy.
func logpipeNames(log string) []string {
	dir, base := path.Split(log)
	stem := strings.TrimSuffix(base, ".log")
	const stamp = logpipeStamp
	return []string{
		dir + base + "." + stamp, dir + base + "." + stamp + "-1",
		dir + base + "." + stamp + ".gz", dir + base + "." + stamp + ".gz.tmp",
		dir + stem + ".legacy-" + stamp + ".log",
		dir + stem + ".logpipe.log", dir + stem + ".logpipe.log.1",
	}
}

// classifiedPath reports whether the machine home rules classify rel: every
// directory on the way is a classified directory, and a rule matches the
// last name or a directory above it that is classified as a whole.
func classifiedPath(rel string) bool {
	if rel == "machine.json" || rel == "packages" || strings.HasPrefix(rel, "packages/") {
		return true // read by the scan itself (machine.go)
	}
	rules := machineHomeRules
	names := strings.Split(rel, "/")
	for i, name := range names {
		r := ruleFor(rules, name)
		if r == nil {
			return false
		}
		if i == len(names)-1 || r.dir == nil {
			return r.dir != nil || r.policy != "" || r.exclude != ""
		}
		rules = r.dir
	}
	return false
}

// Every path in a machine home that an installer writes or names, and every
// name logpipe.py writes beside a log an installer gives it, is classified
// by the continuity rules: a script that adds a file the rules do not
// classify fails here, before an installed machine fails continuity
// validation (TXE-7312).
func TestInstallerHomePathsAreClassified(t *testing.T) {
	t.Parallel()
	found := homePathsInInstallers(t)
	// The extraction finds what is known to be there, so a change that
	// breaks it cannot pass by finding nothing.
	for _, known := range []string{
		"bin/dagu", "bin/logpipe.py", "bin/credential-watch.py", "credential-watch/state.json",
		"alert-webhook.url", "logs/credential-watch.log", "logs/worker.log", "tunnel/kubeconfig",
		"worker-credential.json", "machine.json",
	} {
		assert.Contains(t, found, known)
	}
	paths := make([]string, 0, len(found))
	for p := range found {
		paths = append(paths, p)
		if logpipeOwned.MatchString(p) && !strings.HasSuffix(p, ".logpipe.log") && !strings.HasSuffix(p, ".launchd.log") {
			for _, n := range logpipeNames(p) {
				if _, ok := found[n]; !ok {
					found[n] = []string{"logpipe.py beside " + p}
					paths = append(paths, n)
				}
			}
		}
	}
	sort.Strings(paths)
	for _, p := range paths {
		assert.True(t, classifiedPath(p), "%s is not classified by machineHomeRules (internal/txe/continuity/scan.go); named by %v", p, found[p])
	}
}

// The check itself fails for a path the rules do not classify.
func TestClassifiedPathRefusesUnknownPaths(t *testing.T) {
	t.Parallel()
	for _, p := range []string{"bin/agents.py", "logs/reviewer.log", "credential-watch/other.json", "webhook.url", "worker-home/data/dags"} {
		assert.False(t, classifiedPath(p), p)
	}
	for _, p := range []string{"tunnel/anything", "worker-home/data/auth/key", "bin/credential-watch.py", "alert-webhook.url"} {
		assert.True(t, classifiedPath(p), p)
	}
}
