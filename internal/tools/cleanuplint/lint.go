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
	"slices"
	"sort"
	"strconv"
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
		if isYAML(s.rel) {
			fs, ds := lintWorkflow(s)
			raw = append(raw, fs...)
			dirs[s.rel] = ds
			continue
		}
		fs, ds := lintScript(s)
		raw = append(raw, fs...)
		dirs[s.rel] = ds
	}
	trapRaw, trapAllowed := lintTrapSources(srcs)
	raw = append(raw, trapRaw...)
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
	res.Allowed = append(res.Allowed, trapAllowed...)
	sortFindings(res.Allowed)
	return res
}

func isYAML(rel string) bool {
	ext := path.Ext(rel)
	return ext == ".yml" || ext == ".yaml"
}

// mergeFindings adds to a the findings of b on a line and rule a lacks.
func mergeFindings(a, b []Finding) []Finding {
	for _, f := range b {
		if !slices.ContainsFunc(a, func(g Finding) bool { return g.Line == f.Line && g.Rule == f.Rule }) {
			a = append(a, f)
		}
	}
	return a
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

// goCleanCmdRe finds `go clean` in text whose quotes, commas and brackets
// have been turned into spaces, including after go's leading -C dir flag
// (go -C dir clean, go -C=dir clean), which changes directory first and
// leaves the cache flags meaning what they always do.
var goCleanCmdRe = regexp.MustCompile(`(^|[^\w.-])go(?:\s+-{1,2}C(?:\s*=\s*\S*|\s+\S+))?\s+clean\b`)

// cmdEndRe ends a command's arguments: a shell separator or redirection.
var cmdEndRe = regexp.MustCompile(`[;&|<>\n]`)

// quotedFlagValueRe is a flag value quoted on its own, -modcache="false", so
// that it stays one word with its flag.
var quotedFlagValueRe = regexp.MustCompile(`=(?:"([^"\s]*)"|'([^'\s]*)')`)

// argvPunct turns an argv written as a list ("go", "clean") into words.
var argvPunct = strings.NewReplacer(`"`, " ", `'`, " ", "[", " ", "]", " ", "(", " ", ")", " ", "{", " ", "}", " ", "`", " ")

// listCommaRe is a comma that separates list elements: one with space or a
// line's edge beside it once quotes are spaces ("go", "clean"). A comma
// inside a word is part of the argument, as in -tags integration,e2e.
var listCommaRe = regexp.MustCompile(`(^|\s),|,(\s|$)`)

// goVarRe is a go binary held in a variable: $GO, ${GO}, $(GO), $(GO_BIN).
var goVarRe = regexp.MustCompile(`\$[({]?GO[A-Z0-9_]*[)}]?`)

// normArgv turns text into words for the go clean and go env patterns.
func normArgv(text string) string {
	t := argvPunct.Replace(goVarRe.ReplaceAllString(text, " go "))
	for listCommaRe.MatchString(t) {
		t = listCommaRe.ReplaceAllString(t, "$1 $2")
	}
	return t
}

// goCleanIn reports text that runs go clean with a flag that empties a whole
// Go cache. It reads the text twice: once with every quote a word break, so
// an argv written as a list ("go", "clean") and a command inside a quoted
// string (sh -c "go clean -modcache") are read, and once with each quoted
// string one word, as the shell reads it, so a quoted flag value with spaces
// (-tags "a b") stays one argument and the scan reaches the flags after it.
func goCleanIn(text string) bool {
	return goCleanInWords(text) || goCleanInWords(joinQuoted(text))
}

// quotedSpace stands for a space inside a quoted string that joinQuoted
// keeps in one word. It is not a space to strings.Fields or to \s.
const quotedSpace = "\x1f"

// joinQuoted replaces the spaces and tabs inside each '...' or "..." string
// with quotedSpace, so the string is one word once its quotes are removed.
func joinQuoted(text string) string {
	var b strings.Builder
	var z quoter
	for i := 0; i < len(text); {
		next, _ := z.step(text, i)
		for j := i; j < next && j < len(text); j++ {
			c := text[j]
			if (c == ' ' || c == '\t') && (z.q == '"' || z.q == '\'') {
				b.WriteString(quotedSpace)
				continue
			}
			b.WriteByte(c)
		}
		i = next
	}
	return b.String()
}

func goCleanInWords(text string) bool {
	norm := normArgv(quotedFlagValueRe.ReplaceAllString(text, "=$1$2"))
	for _, loc := range goCleanCmdRe.FindAllStringIndex(norm, -1) {
		args := norm[loc[1]:]
		if end := cmdEndRe.FindStringIndex(args); end != nil {
			args = args[:end[0]]
		}
		if cleanFlagsCache(strings.Fields(args)) {
			return true
		}
	}
	return false
}

// goValueFlags are go clean's flags (its own and the build flags) that take
// the next argument as their value when written without =.
var goValueFlags = map[string]bool{
	"C": true, "p": true, "o": true, "asmflags": true, "buildmode": true, "compiler": true,
	"covermode": true, "coverpkg": true, "gccgoflags": true, "gcflags": true,
	"installsuffix": true, "ldflags": true, "mod": true, "modfile": true, "overlay": true,
	"pgo": true, "pkgdir": true, "tags": true, "toolexec": true, "exec": true,
	"debug-actiongraph": true, "debug-runtime-trace": true, "debug-trace": true,
}

// cleanFlagsCache reads go clean's arguments as Go's flag package does: flags
// end at the first argument that is not one, or at --, and a flag in
// goValueFlags written without = takes the next argument, unless that is a
// cache flag. A word holding an unexpanded variable ($EXTRA) may be any
// number of flags, so the scan reads past it; a cache flag set from a
// variable (-modcache=$v) is reported.
func cleanFlagsCache(args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return false
		case cleansCache(a):
			return true
		case strings.Contains(a, "$"):
			continue
		case !strings.HasPrefix(a, "-") || a == "-":
			return false
		}
		name := strings.TrimLeft(a, "-")
		if !strings.Contains(name, "=") && goValueFlags[name] {
			// The next word is this flag's value, unless it is a cache
			// flag: an empty argument ('', or a variable that expands to
			// nothing) leaves no word behind, so -tags '' -modcache reads
			// as -tags -modcache here.
			if i+1 < len(args) && cleansCache(args[i+1]) {
				return true
			}
			i++
		}
	}
	return false
}

// cleansCache reports a go clean argument that turns on -modcache, -cache or
// -fuzzcache, with one dash or two: the bare flag, or the flag given a value
// Go's flag package reads as true (-modcache=true, =1, =T). A value it reads
// as false (-modcache=false, =0, =F) turns the flag off. Any other value is
// reported too: go refuses it, but the lint cannot tell it from a variable
// that expands to true.
func cleansCache(arg string) bool {
	name, ok := strings.CutPrefix(arg, "-")
	if !ok {
		return false
	}
	name, val, hasVal := strings.Cut(strings.TrimPrefix(name, "-"), "=")
	switch name {
	case "modcache", "cache", "fuzzcache":
	default:
		return false
	}
	if !hasVal {
		return true
	}
	on, err := strconv.ParseBool(val)
	return on || err != nil
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
