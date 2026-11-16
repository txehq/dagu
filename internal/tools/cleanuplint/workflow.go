package main

import (
	"regexp"
	"strings"
)

// A workflow or action file is not one shell script. Each run: block runs
// in its own shell, so a variable one step assigns is not defined in another
// step or job: it reaches a later step only through the environment (an
// env: map, or $GITHUB_ENV), which the step did not choose. The lint
// therefore reads each run: block as its own script, with its own
// assignments. Lines outside every run: block are read together as one more
// script, as the whole file was before, so nothing outside a run: block goes
// unread. Line numbers stay the file's.

var (
	// yamlRunKeyRe is a run: key, as a step's first key (- run:) or a later
	// one. Group 2 is the text before the key name, whose length is the
	// key's column.
	yamlRunKeyRe = regexp.MustCompile(`^((\s*)(?:-\s+)?)run\s*:(?:\s|$)`)
	// yamlEnvKeyRe is an env: key at the workflow, job or step level; group
	// 2 is its value on the same line, if any.
	yamlEnvKeyRe = regexp.MustCompile(`^(\s*(?:-\s+)?)env\s*:(.*)$`)
	// yamlEnvNameRe is one key of an env: map in block style.
	yamlEnvNameRe = regexp.MustCompile(`^\s*["']?([A-Za-z_]\w*)["']?\s*:`)
	// yamlFlowNameRe is one key of an env: map written in flow style,
	// env: { A: x, B: y }.
	yamlFlowNameRe = regexp.MustCompile(`[{,]\s*["']?([A-Za-z_]\w*)["']?\s*:`)
)

// indentOf is the number of leading spaces and tabs.
func indentOf(s string) int {
	return len(s) - len(strings.TrimLeft(s, " \t"))
}

// blank reports a line with nothing but whitespace on it.
func blank(s string) bool {
	return strings.TrimSpace(s) == ""
}

// childEnd returns the index just past the lines after phys[key] that belong
// to a key at column col: blank lines and lines indented past col. A block
// scalar (run: |) and a plain or quoted value continued onto later lines
// both end at the first line indented no further than the key.
func childEnd(phys []string, key, col int) int {
	end := key + 1
	for i := key + 1; i < len(phys); i++ {
		if blank(phys[i]) {
			continue
		}
		if indentOf(phys[i]) <= col {
			break
		}
		end = i + 1
	}
	return end
}

// workflowSegments splits a workflow file's lines into the scripts the lint
// reads: one per run: block, then one of every line outside a run: block.
// Each segment is as long as the file, with the lines of other segments
// blanked, so a finding's line is the file's.
func workflowSegments(phys []string) [][]string {
	inRun := make([]bool, len(phys))
	var segs [][]string
	for i := 0; i < len(phys); i++ {
		m := yamlRunKeyRe.FindStringSubmatch(phys[i])
		if m == nil {
			continue
		}
		end := childEnd(phys, i, len(m[1]))
		seg := make([]string, len(phys))
		for j := i; j < end; j++ {
			seg[j] = phys[j]
			inRun[j] = true
		}
		segs = append(segs, seg)
		i = end - 1
	}
	rest := make([]string, len(phys))
	for i, p := range phys {
		if !inRun[i] {
			rest[i] = p
		}
	}
	return append(segs, rest)
}

// workflowEnvNames returns every name a workflow, job or step env: map in
// the file sets. Each is a source in every run: block that does not assign
// it itself: the runner, not the step's script, chose its value. The lint
// does not track which job or step a map belongs to; a name set anywhere in
// the file counts everywhere, which can only report more.
func workflowEnvNames(phys []string) map[string]bool {
	names := map[string]bool{}
	for i := 0; i < len(phys); i++ {
		m := yamlEnvKeyRe.FindStringSubmatch(phys[i])
		if m == nil {
			continue
		}
		if v := strings.TrimSpace(m[2]); strings.HasPrefix(v, "{") {
			for _, f := range yamlFlowNameRe.FindAllStringSubmatch(v, -1) {
				names[f[1]] = true
			}
			continue
		}
		col := len(m[1])
		end := childEnd(phys, i, col)
		child := -1
		for j := i + 1; j < end; j++ {
			if blank(phys[j]) || isCommentLine(phys[j]) {
				continue
			}
			ind := indentOf(phys[j])
			if child < 0 {
				child = ind
			}
			if ind != child {
				continue // a continued value, not a key
			}
			if n := yamlEnvNameRe.FindStringSubmatch(phys[j]); n != nil {
				names[n[1]] = true
			}
		}
		i = end - 1
	}
	return names
}

// githubEnvNameRe is a name written as name=value: in a step that writes
// $GITHUB_ENV, any such text may be what it exports (echo "x=$v" >>
// "$GITHUB_ENV", a heredoc, printf), and it cannot tell which.
var githubEnvNameRe = regexp.MustCompile(`(?:^|[^\w$-])([A-Za-z_]\w*)=`)

// githubEnvNames returns every name a run: block that writes $GITHUB_ENV
// may export to the steps after it: each name=value text in that block.
// It over-collects, which can only report more: a name the reading step
// assigns itself is still defined there.
func githubEnvNames(segs [][]string) map[string]bool {
	names := map[string]bool{}
	for _, seg := range segs {
		text := strings.Join(seg, "\n")
		if !strings.Contains(text, "GITHUB_ENV") {
			continue
		}
		for _, m := range githubEnvNameRe.FindAllStringSubmatch(text, -1) {
			names[m[1]] = true
		}
	}
	return names
}

// lintWorkflow lints a workflow or action file one run: block at a time. A
// step may run under shell: pwsh, so each block is read as PowerShell as
// well as shell.
func lintWorkflow(s source) ([]Finding, []directiveAt) {
	phys := lines(s.data)
	envNames := workflowEnvNames(phys)
	segs := workflowSegments(phys)
	for n := range githubEnvNames(segs[:len(segs)-1]) {
		envNames[n] = true
	}
	var out []Finding
	for _, seg := range segs {
		out = mergeFindings(out, scanScript(s, seg, envNames))
		ps := s
		ps.lang = langPowerShell
		out = mergeFindings(out, scanScript(ps, seg, nil))
	}
	return out, scriptDirectives(phys)
}
