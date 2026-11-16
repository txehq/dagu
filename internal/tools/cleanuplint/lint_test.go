// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// markerRe is an expectation written at the end of a fixture line:
// "// want:<rule>" for a reported finding, "// allowed:<rule>" for one a
// directive keeps. The test removes markers before linting, so they are
// never part of a directive's reason.
var markerRe = regexp.MustCompile(`\s*(?://|#)\s*(want|allowed):([a-z-]+)\s*$`)

// The fixtures live under testdata with a .txt suffix, which the lint never
// reads, so the hazards they plant cannot fail the repository's own run. Each
// is linted as if it sat at rel, which decides its language and whether it is
// harness code.
func TestFixtures(t *testing.T) {
	t.Parallel()
	cases := []struct{ fixture, rel string }{
		{"harness_bad_test.go.txt", "internal/fixture/bad_test.go"},
		{"harness_good_test.go.txt", "internal/fixture/good_test.go"},
		{"directives_test.go.txt", "internal/fixture/directives_test.go"},
		{"product.go.txt", "internal/service/server/cleanup.go"},
		{"harness_bad.sh.txt", "scripts/ci/bad.sh"},
		{"harness_good.sh.txt", "scripts/e2e/good.sh"},
		{"product.sh.txt", "scripts/installer.sh"},
		{"Makefile.txt", "Makefile"},
		{"harness.ps1.txt", "scripts/ci/harness.ps1"},
		{"harness_test.py.txt", "txe/tests/harness_test.py"},
		{"workflow.yml.txt", ".github/workflows/x.yaml"},
		{"workflow_steps.yml.txt", ".github/workflows/steps.yaml"},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("testdata", tc.fixture))
			require.NoError(t, err)
			src, want, allowed := stripMarkers(data)
			l := classify(tc.rel, src)
			require.NotEqual(t, langNone, l, "fixture %s is not linted as %s", tc.fixture, tc.rel)
			res := lintSources([]source{{rel: tc.rel, lang: l, data: src}})
			assert.Equal(t, want, keys(res.Findings), "findings (line:rule)\n%s", strings.Join(lineStrings(res.Findings), "\n"))
			assert.Equal(t, allowed, keys(res.Allowed), "allowed (line:rule)")
		})
	}
}

func stripMarkers(data []byte) (src []byte, want, allowed []string) {
	var out [][]byte
	for i, line := range bytes.Split(data, []byte("\n")) {
		if m := markerRe.FindSubmatchIndex(line); m != nil {
			key := fmt.Sprintf("%d:%s", i+1, line[m[4]:m[5]])
			if string(line[m[2]:m[3]]) == "want" {
				want = append(want, key)
			} else {
				allowed = append(allowed, key)
			}
			line = line[:m[0]]
		}
		out = append(out, line)
	}
	sort.Strings(want)
	sort.Strings(allowed)
	return bytes.Join(out, []byte("\n")), want, allowed
}

func keys(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		k := fmt.Sprintf("%d:%s", f.Line, f.Rule)
		if !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func lineStrings(fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.String())
	}
	return out
}

// A logical line continued with a backslash is reported where it starts.
func TestContinuedCommandReportsItsFirstLine(t *testing.T) {
	t.Parallel()
	src := []byte("#!/bin/sh\nrm -rf \\\n  \"$GOCACHE\"\n")
	res := lintSources([]source{{rel: "scripts/ci/x.sh", lang: langShell, data: src}})
	assert.Equal(t, []string{"2:" + ruleEnvDelete}, keys(res.Findings))
}

// A package function's parameter is tainted by a call from another file of
// the same package.
func TestTaintCrossesFilesOfAPackage(t *testing.T) {
	t.Parallel()
	helper := []byte("package p\n\nimport \"os\"\n\nfunc wipe(dir string) {\n\t_ = os.RemoveAll(dir)\n}\n")
	caller := []byte("package p\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestX(t *testing.T) {\n\twipe(os.Getenv(\"GOCACHE\"))\n\twipe(t.TempDir())\n}\n")
	res := lintSources([]source{
		{rel: "internal/test/p/helper.go", lang: langGo, data: helper},
		{rel: "internal/test/p/x_test.go", lang: langGo, data: caller},
	})
	require.Len(t, res.Findings, 1, "%v", res.Findings)
	assert.Equal(t, "internal/test/p/helper.go", res.Findings[0].Path)
	assert.Equal(t, 6, res.Findings[0].Line)
}

func TestIsHarness(t *testing.T) {
	t.Parallel()
	for rel, want := range map[string]bool{
		"internal/cmd/x_test.go":                    true,
		"internal/test/helper.go":                   true,
		"internal/test/intgharness/rig.go":          true,
		"internal/test/chrometest/chrome.go":        true,
		"internal/intg/machineauth/provenance.go":   true,
		"scripts/ci/trim-go-cache.sh":               true,
		"scripts/e2e/start-stack.sh":                true,
		".github/codex-review/test-merge.sh":        true,
		"txe/i5harness/rig.sh":                      true,
		"deploy/docker/smoke/signal-shutdown.sh":    true,
		"Makefile":                                  true,
		"internal/service/worker/remote_handler.go": false,
		"scripts/installer.sh":                      false,
		"txe/worker/install.sh":                     false,
		"internal/latest/x.go":                      true, // a directory named *test is treated as harness
	} {
		assert.Equal(t, want, isHarness(rel), rel)
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()
	assert.Equal(t, langShell, classify("txe/bin/run", []byte("#!/usr/bin/env bash\n")))
	assert.Equal(t, langPython, classify("txe/bin/tool", []byte("#!/usr/bin/env python3\n")))
	assert.Equal(t, langNone, classify("txe/bin/data", []byte("plain text\n")))
	assert.Equal(t, langNone, classify("charts/dagu/values.yaml", nil))
	assert.Equal(t, langShell, classify(".github/workflows/ci.yaml", nil))
	assert.Equal(t, langMake, classify("Makefile", nil))
	assert.Equal(t, langNone, classify("internal/tools/cleanuplint/testdata/x.go.txt", nil))
}

// The command fails on a repository with a planted go clean -modcache in a
// _test.go file, and passes once it is gone.
func TestRunFailsOnAPlantedModcacheClean(t *testing.T) {
	t.Parallel()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	repo := t.TempDir()
	gitIn(t, repo, "init", "-q")
	planted, err := os.ReadFile(filepath.Join("testdata", "planted_test.go.txt"))
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(filepath.Join(repo, "internal", "x"), 0o750))
	file := filepath.Join(repo, "internal", "x", "planted_test.go")
	require.NoError(t, os.WriteFile(file, planted, 0o600))

	var out, errOut bytes.Buffer
	assert.Equal(t, 1, run([]string{repo}, &out, &errOut), "stderr: %s", errOut.String())
	assert.Contains(t, out.String(), "internal/x/planted_test.go:9: "+ruleGoClean)

	require.NoError(t, os.Remove(file))
	out.Reset()
	assert.Equal(t, 0, run([]string{repo}, &out, &errOut), "stdout: %s stderr: %s", out.String(), errOut.String())
}

func TestRunRefusesBadArguments(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	assert.Equal(t, 2, run([]string{"a", "b"}, &out, &errOut))
	assert.Equal(t, 2, run([]string{filepath.Join(t.TempDir(), "not-a-repo")}, &out, &errOut))
}

func gitIn(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v: %s", args, out)
}
