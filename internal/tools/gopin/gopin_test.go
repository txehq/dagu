// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package gopin

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A pin is one place that names the Go version.
type pin struct {
	where string // file:line, or file and step
	value string
}

var (
	goDirective        = regexp.MustCompile(`^go\s+(\S+)\s*$`)
	toolchainDirective = regexp.MustCompile(`^toolchain\s+go(\S+)\s*$`)
	// FROM [--platform=...] golang:<version>[-variant] [AS name]
	fromGolang = regexp.MustCompile(`(?i)^\s*FROM\s+(?:--\S+\s+)*(?:\S+/)?golang:([0-9][0-9A-Za-z.]*)`)
)

// expressions a setup-go step may name instead of a literal version.
var allowedExpressions = []string{"${{ env.GO_VERSION }}", "${{ inputs.go-version }}"}

func TestGoVersionPinsMatchGoMod(t *testing.T) {
	root := repoRoot(t)
	want := goModVersion(t, filepath.Join(root, "go.mod"))

	dockerPins := dockerfilePins(t, root)
	workflowPins := workflowPins(t, root)
	// A pin list that came back empty means the scan broke, not that all is well.
	if len(dockerPins) == 0 {
		t.Fatal("found no golang: image in any Dockerfile; the scan no longer matches this repository")
	}
	if len(workflowPins) == 0 {
		t.Fatal("found no Go version in any workflow; the scan no longer matches this repository")
	}

	for _, p := range slices.Concat(dockerPins, workflowPins) {
		if p.value != want {
			t.Errorf("%s pins Go %q; go.mod says %q. Change it to %q (go.mod is the one source).", p.where, p.value, want, want)
		}
	}
}

// The scan itself: each kind of pin is found, and each wrong one reported.
func TestScanFindsEachKindOfPin(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/x\n\ngo 1.2.3\n\ntoolchain go1.2.4\n")
	write("Dockerfile", "FROM --platform=$TARGETPLATFORM golang:1.2.4 AS b\nFROM alpine\n")
	write("build/Dockerfile.alpine", "FROM docker.io/library/golang:1.2.3-alpine\n")
	write("node_modules/x/Dockerfile", "FROM golang:0.0.1\n")
	write(".github/workflows/a.yaml", `
env:
  GO_VERSION: "1.2.4"
jobs:
  j:
    env:
      GO_VERSION: "1.2.3"
    steps:
      - uses: actions/setup-go@abc # v6
        with:
          go-version: ${{ env.GO_VERSION }}
      - uses: actions/setup-go@abc
        with:
          go-version-file: go.mod
      - uses: actions/setup-go@abc
        with:
          go-version-file: other/go.mod
      - uses: ./.github/actions/setup-go-cache
        with:
          go-version: "1.2.2"
      - uses: actions/setup-go@abc
      - uses: actions/setup-go@abc
        with:
          go-version: stable
`)
	write(".github/actions/setup-go-cache/action.yml", `
runs:
  using: composite
  steps:
    - uses: actions/setup-go@abc
      with:
        go-version: ${{ inputs.go-version }}
`)

	if got := goModVersion(t, filepath.Join(root, "go.mod")); got != "1.2.4" {
		t.Fatalf("go.mod version = %q, want the toolchain's 1.2.4", got)
	}
	var docker []string
	for _, p := range dockerfilePins(t, root) {
		docker = append(docker, p.where+"="+p.value)
	}
	if want := []string{"Dockerfile:1=1.2.4", "build/Dockerfile.alpine:1=1.2.3"}; !slices.Equal(docker, want) {
		t.Errorf("Dockerfile pins = %q, want %q", docker, want)
	}
	var wf []string
	for _, p := range workflowPins(t, root) {
		wf = append(wf, p.value)
	}
	// env x2, file go.mod (kept as the go.mod value), a wrong file, a wrong literal,
	// a missing version, a channel name. The two allowed expressions add nothing.
	want := []string{"1.2.4", "1.2.3", "1.2.4", "go-version-file other/go.mod", "1.2.2", "no go-version", "stable"}
	if !slices.Equal(wf, want) {
		t.Errorf("workflow pins = %q, want %q", wf, want)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".github", "workflows")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no repository root (go.mod beside .github/workflows) above the test's directory")
		}
		dir = parent
	}
}

// goModVersion is the Go the module builds with: toolchain if set, else go.
func goModVersion(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // the test's own repository file
	if err != nil {
		t.Fatal(err)
	}
	var goV, toolchainV string
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if m := goDirective.FindStringSubmatch(line); m != nil {
			goV = m[1]
		}
		if m := toolchainDirective.FindStringSubmatch(line); m != nil {
			toolchainV = m[1]
		}
	}
	if toolchainV != "" {
		return toolchainV
	}
	if goV == "" {
		t.Fatalf("%s has no go directive", path)
	}
	return goV
}

var skipDirs = map[string]bool{".git": true, "node_modules": true, "testdata": true, "dist": true}

func dockerfilePins(t *testing.T, root string) []pin {
	t.Helper()
	var pins []pin
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasPrefix(d.Name(), "Dockerfile") {
			return nil
		}
		data, err := os.ReadFile(path) //nolint:gosec // a file of the repository under test
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		sc := bufio.NewScanner(bytes.NewReader(data))
		for n := 1; sc.Scan(); n++ {
			if m := fromGolang.FindStringSubmatch(sc.Text()); m != nil {
				pins = append(pins, pin{where: fmt.Sprintf("%s:%d", filepath.ToSlash(rel), n), value: m[1]})
			}
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return pins
}

// workflowPins reads every workflow and local action. Each GO_VERSION in an env
// map is a pin, and each setup-go step yields the version it installs; a step
// that names an allowed expression yields nothing (the env pin it reads is
// checked on its own). A step whose version cannot be checked yields a value
// that never equals a version, so the test reports it.
func workflowPins(t *testing.T, root string) []pin {
	t.Helper()
	var files []string
	for _, pattern := range []string{".github/workflows/*.y*ml", ".github/actions/*/action.y*ml"} {
		m, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	goModPin := goModVersion(t, filepath.Join(root, "go.mod"))

	var pins []pin
	for _, file := range files {
		data, err := os.ReadFile(file) //nolint:gosec // a file of the repository under test
		if err != nil {
			t.Fatal(err)
		}
		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		rel, _ := filepath.Rel(root, file)
		rel = filepath.ToSlash(rel)
		walk(&doc, func(n *yaml.Node) {
			if v := mapValue(n, "env"); v != nil {
				if gv := mapValue(v, "GO_VERSION"); gv != nil {
					pins = append(pins, pin{where: fmt.Sprintf("%s:%d GO_VERSION", rel, gv.Line), value: gv.Value})
				}
			}
			uses := mapValue(n, "uses")
			if uses == nil || !isSetupGo(uses.Value) {
				return
			}
			where := fmt.Sprintf("%s:%d %s", rel, uses.Line, strings.Fields(uses.Value)[0])
			with := mapValue(n, "with")
			var version, file *yaml.Node
			if with != nil {
				version, file = mapValue(with, "go-version"), mapValue(with, "go-version-file")
			}
			switch {
			case file != nil && file.Value == "go.mod":
				pins = append(pins, pin{where: where, value: goModPin})
			case file != nil:
				pins = append(pins, pin{where: where, value: "go-version-file " + file.Value})
			case version == nil:
				pins = append(pins, pin{where: where, value: "no go-version"})
			case slices.Contains(allowedExpressions, strings.TrimSpace(version.Value)):
			default:
				pins = append(pins, pin{where: where, value: version.Value})
			}
		})
	}
	return pins
}

func isSetupGo(uses string) bool {
	return strings.HasPrefix(uses, "actions/setup-go@") || uses == "./.github/actions/setup-go-cache"
}

func walk(n *yaml.Node, visit func(*yaml.Node)) {
	if n.Kind == yaml.MappingNode {
		visit(n)
	}
	for _, c := range n.Content {
		walk(c, visit)
	}
}

func mapValue(n *yaml.Node, key string) *yaml.Node {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
