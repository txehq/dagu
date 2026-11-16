// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	ruleGoClean   = "go-clean-cache"
	ruleEnvDelete = "env-path-delete"
	ruleDirective = "allow-directive"
	ruleParse     = "parse"

	directive       = "cleanuplint:allow"
	minReasonWords  = 3
	directiveFormat = "write the reason after it: cleanuplint:allow <why this delete cannot reach a tree it did not create>"
)

// Finding is one report at a file and line.
type Finding struct {
	Path   string
	Line   int
	Rule   string
	Msg    string
	Reason string // the directive's reason, for an allowed finding
}

func (f Finding) String() string {
	return fmt.Sprintf("%s:%d: %s: %s", f.Path, f.Line, f.Rule, f.Msg)
}

// Result is the outcome of a lint run.
type Result struct {
	Files    int
	Findings []Finding
	Allowed  []Finding
}

type lang int

const (
	langNone lang = iota
	langGo
	langShell
	langMake
	langPowerShell
	langPython
)

// classify names the language a repository path is linted as, from its name
// and, for a file with no extension, its #! line.
func classify(rel string, head []byte) lang {
	rel = filepath.ToSlash(rel)
	base := path.Base(rel)
	switch ext := path.Ext(base); ext {
	case ".go":
		return langGo
	case ".sh", ".bash", ".zsh", ".ksh":
		return langShell
	case ".mk":
		return langMake
	case ".ps1", ".psm1":
		return langPowerShell
	case ".py":
		return langPython
	case ".yml", ".yaml":
		// Workflow and action steps carry shell in their run: blocks.
		if strings.HasPrefix(rel, ".github/") {
			return langShell
		}
		return langNone
	case "":
		if base == "Makefile" || base == "GNUmakefile" || base == "makefile" {
			return langMake
		}
		return shebang(head)
	default:
		return langNone
	}
}

func shebang(head []byte) lang {
	if !bytes.HasPrefix(head, []byte("#!")) {
		return langNone
	}
	line, _, _ := bytes.Cut(head, []byte("\n"))
	s := string(line)
	switch {
	case strings.Contains(s, "python"):
		return langPython
	case strings.Contains(s, "pwsh"):
		return langPowerShell
	case regexp.MustCompile(`\b(sh|bash|zsh|ksh|dash)\b`).MatchString(s):
		return langShell
	}
	return langNone
}

// listFiles lists the files git tracks under root, plus untracked files git
// does not ignore, so a new file is linted before its first commit.
func listFiles(root string) ([]string, error) {
	cmd := exec.Command("git", "-C", root, "ls-files", "-z", "--cached", "--others", "--exclude-standard") //nolint:gosec // root is the repository this lint was asked to read
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files in %s: %w: %s", root, err, strings.TrimSpace(stderr.String()))
	}
	seen := map[string]bool{}
	var files []string
	for name := range strings.SplitSeq(string(out), "\x00") {
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		files = append(files, name)
	}
	sort.Strings(files)
	return files, nil
}

// skipped reports whether a repository path is outside what the lint reads:
// third-party trees.
func skipped(rel string) bool {
	for part := range strings.SplitSeq(filepath.ToSlash(rel), "/") {
		switch part {
		case "node_modules", "vendor", ".git":
			return true
		}
	}
	return false
}

type source struct {
	rel  string
	lang lang
	data []byte
}

// lintFiles lints the named files, relative to root.
func lintFiles(root string, files []string) (Result, error) {
	var srcs []source
	for _, rel := range files {
		if skipped(rel) {
			continue
		}
		full := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Lstat(full)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // deleted in the work tree but still in the index
			}
			return Result{}, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		data, err := os.ReadFile(full) //nolint:gosec // the path comes from git's own file list
		if err != nil {
			return Result{}, err
		}
		head := data
		if len(head) > 256 {
			head = head[:256]
		}
		l := classify(rel, head)
		if l == langNone {
			continue
		}
		srcs = append(srcs, source{rel: filepath.ToSlash(rel), lang: l, data: data})
	}
	return lintSources(srcs), nil
}

// lintSources lints sources already read; tests call it with fixtures.
func lintSources(srcs []source) Result {
	var res Result
	goPkgs := map[string][]source{}
	var raw []Finding
	dirs := map[string][]directiveAt{}
	for _, s := range srcs {
		res.Files++
		if s.lang == langGo {
			goPkgs[path.Dir(s.rel)] = append(goPkgs[path.Dir(s.rel)], s)
			continue
		}
		fs, ds := lintScript(s)
		raw = append(raw, fs...)
		dirs[s.rel] = ds
	}
	pkgDirs := make([]string, 0, len(goPkgs))
	for d := range goPkgs {
		pkgDirs = append(pkgDirs, d)
	}
	sort.Strings(pkgDirs)
	for _, d := range pkgDirs {
		fs, ds := lintGoDir(goPkgs[d])
		raw = append(raw, fs...)
		for rel, list := range ds {
			dirs[rel] = append(dirs[rel], list...)
		}
	}
	res.Findings, res.Allowed = applyDirectives(raw, dirs)
	return res
}

type directiveAt struct {
	line   int
	reason string
	used   bool
}

// directiveRe matches a directive at the start of a comment: //, /* or #,
// then optional space. Text that only mentions the directive, such as this
// package's documentation, is not one.
var directiveRe = regexp.MustCompile(`^(?://|/\*|#)\s*cleanuplint:allow\b(.*?)(?:\*/)?$`)

// parseDirective reads a directive from a comment's text.
func parseDirective(comment string) (string, bool) {
	m := directiveRe.FindStringSubmatch(strings.TrimSpace(comment))
	if m == nil {
		return "", false
	}
	return strings.TrimSpace(m[1]), true
}

// harnessElems are path elements that mark test and harness code.
var harnessElems = map[string]bool{
	"test": true, "tests": true, "testutil": true, "testdata": true, "testing": true,
	"intg": true, "e2e": true, "smoke": true, "fixtures": true,
}

// isHarness reports whether a repository path is test or harness code, where
// env-path-delete applies: Go _test.go files, test scripts, CI scripts and
// workflows, the Makefile, and anything under a test or harness directory.
// Product code (the server, the installers) is out of its scope; go clean of a
// whole cache is reported everywhere.
func isHarness(rel string) bool {
	rel = filepath.ToSlash(rel)
	base := path.Base(rel)
	switch {
	case strings.HasSuffix(base, "_test.go"),
		strings.HasPrefix(rel, ".github/"), strings.HasPrefix(rel, "scripts/ci/"),
		base == "Makefile", strings.HasSuffix(base, ".mk"):
		return true
	}
	stem := strings.TrimSuffix(base, path.Ext(base))
	if strings.HasPrefix(stem, "test-") || strings.HasPrefix(stem, "test_") ||
		strings.HasSuffix(stem, "_test") || strings.HasSuffix(stem, "-test") {
		return true
	}
	for el := range strings.SplitSeq(path.Dir(rel), "/") {
		if harnessElems[el] || strings.Contains(el, "harness") || strings.HasSuffix(el, "test") {
			return true
		}
	}
	return false
}

// applyDirectives splits findings into reported and allowed. A finding is
// allowed by a directive with a reason on its own line or the line above. A
// directive without a reason, or one that allows nothing, is reported.
func applyDirectives(raw []Finding, dirs map[string][]directiveAt) (findings, allowed []Finding) {
	for _, f := range raw {
		list := dirs[f.Path]
		idx := -1
		for i := range list {
			if list[i].line == f.Line || list[i].line == f.Line-1 {
				idx = i
				if list[i].line == f.Line {
					break
				}
			}
		}
		if idx >= 0 && len(strings.Fields(list[idx].reason)) >= minReasonWords {
			list[idx].used = true
			f.Reason = list[idx].reason
			allowed = append(allowed, f)
			continue
		}
		if idx >= 0 {
			list[idx].used = true // reported below for its missing reason
		}
		findings = append(findings, f)
	}
	for rel, list := range dirs {
		for _, d := range list {
			switch {
			case len(strings.Fields(d.reason)) < minReasonWords:
				findings = append(findings, Finding{Path: rel, Line: d.line, Rule: ruleDirective,
					Msg: fmt.Sprintf("%s needs a reason of at least %d words; %s", directive, minReasonWords, directiveFormat)})
			case !d.used:
				findings = append(findings, Finding{Path: rel, Line: d.line, Rule: ruleDirective,
					Msg: directive + " allows nothing on this line or the next; remove it"})
			}
		}
	}
	sortFindings(findings)
	sortFindings(allowed)
	return findings, allowed
}

func sortFindings(fs []Finding) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Path != fs[j].Path {
			return fs[i].Path < fs[j].Path
		}
		if fs[i].Line != fs[j].Line {
			return fs[i].Line < fs[j].Line
		}
		return fs[i].Rule < fs[j].Rule
	})
}

// goCleanRe matches `go clean` with a flag that empties a whole Go cache,
// in text whose quotes, commas and brackets have been turned into spaces.
var goCleanRe = regexp.MustCompile(`(^|[^\w.-])go\s+clean(\s+-{1,2}[\w=.-]+)*\s+-{1,2}(modcache|cache|fuzzcache)\b`)

// argvPunct turns an argv written as a list ("go", "clean") into words.
var argvPunct = strings.NewReplacer(`"`, " ", `'`, " ", ",", " ", "[", " ", "]", " ", "(", " ", ")", " ", "{", " ", "}", " ", "`", " ")

// goVarRe is a go binary held in a variable: $GO, ${GO}, $(GO), $(GO_BIN).
var goVarRe = regexp.MustCompile(`\$[({]?GO[A-Z0-9_]*[)}]?`)

// normArgv turns text into words for the go clean and go env patterns.
func normArgv(text string) string {
	return argvPunct.Replace(goVarRe.ReplaceAllString(text, " go "))
}

func goCleanIn(text string) bool {
	return goCleanRe.MatchString(normArgv(text))
}

const goCleanMsg = "go clean with -modcache, -cache or -fuzzcache removes whatever GOMODCACHE/GOCACHE names when it runs; remove the directory your code created instead"

// lines splits text into lines, tolerating a missing final newline.
func lines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		out = append(out, strings.TrimSuffix(sc.Text(), "\r"))
	}
	return out
}
