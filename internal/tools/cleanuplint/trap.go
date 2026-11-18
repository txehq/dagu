// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// The trap rule (TXE-7857, the port of txehq/txe's TXE-7835) reads the shell
// traps of CI code: workflow and action run: blocks, everything else under
// .github, and every script those name. Under set -e, which every GitHub run:
// step has (bash -e -o pipefail), the first command of an EXIT trap that fails
// ends the script with that command's status, whatever the main command's
// was, and skips the rest of the cleanup:
//
//	bash -e -c 'trap "false >/dev/null 2>&1" EXIT; true'     # exit=1, nothing printed
//	bash -e -c 'trap "false >/dev/null 2>&1" EXIT; exit 3'   # exit=1, not 3
//
// Without set -e bash keeps the main command's status, but a script that turns
// errexit on later, or a trap copied into a run: step, gets the first. In txe
// it hit PR 5184: a step went red with an empty log because its trap's docker
// rm -f failed into /dev/null. The rule, for every trap on EXIT or ERR, inline
// or through a function the same script defines:
//
//   - its first statement keeps the main command's status (RC=$?) and its last
//     returns it (exit "$RC"), so the cleanup neither fails a passing step nor
//     hides a failing one; a cleanup whose leftover is itself a defect sets RC
//     itself, after saying so;
//   - between them, set +e comes first, or every command is guarded with
//     || (cmd || echo "::warning::..."): under set -e a failing command ends
//     the handler before its exit, with the cleanup's status;
//   - it never sends stderr to /dev/null (2>/dev/null, &>/dev/null,
//     >/dev/null 2>&1, 2>&-), so a cleanup that fails says why.
//
// The variable is any name; RC is the house form because shellcheck, which CI
// runs on these scripts, reports a lower-case name assigned inside a trap
// string as never assigned (SC2154).
//
// A trap on any other signal (TERM, INT) is held to the last rule only: it
// ends with its own exit status, chosen by the author.

const ruleTrap = "trap-status"

// trapScope reports a path whose traps are always read: workflows, actions
// and every script under .github. Scripts outside it are read when an
// in-scope file names them (trapReach).
func trapScope(rel string) bool {
	return strings.HasPrefix(rel, ".github/")
}

// scriptPathRe is a repository-relative path a CI file may run.
var scriptPathRe = regexp.MustCompile(`[A-Za-z0-9_.][A-Za-z0-9_./-]*/[A-Za-z0-9_.-]+`)

// trapReach returns the shell sources the trap rule reads: every one in
// trapScope, and, transitively, every shell source whose path one of those
// names, written from the repository root (bash scripts/foo.sh,
// ./scripts/foo.sh).
func trapReach(srcs []source) map[string]bool {
	byRel := map[string]source{}
	for _, s := range srcs {
		if s.lang == langShell {
			byRel[s.rel] = s
		}
	}
	reach := map[string]bool{}
	var work []string
	for rel := range byRel {
		if trapScope(rel) {
			reach[rel] = true
			work = append(work, rel)
		}
	}
	sort.Strings(work)
	for len(work) > 0 {
		rel := work[0]
		work = work[1:]
		for _, m := range scriptPathRe.FindAllString(string(byRel[rel].data), -1) {
			m = strings.TrimPrefix(m, "./")
			if _, ok := byRel[m]; ok && !reach[m] {
				reach[m] = true
				work = append(work, m)
			}
		}
	}
	return reach
}

// trapAllowedFiles allows the trap-status findings of a file from here, with
// the reason, where a cleanuplint:allow comment in the file would itself be a
// change the file cannot take. An entry that allows nothing is a finding, so
// it goes when the file is fixed.
var trapAllowedFiles = map[string]string{
	// The codex-review gate runs this file from CODEX_REVIEW_GATE_SHA on a
	// maintenance base, and test-gate-pin.sh fails main once main's copy
	// differs from the pin's; moving the pin changes codex-review.yml, which
	// every live maint/txe-v* base must then take (TXE-7556). It has no
	// errexit (set -uo pipefail), and without errexit bash ends a script with
	// its own status whatever its EXIT trap does (measured, TXE-7857).
	".github/codex-review/test-codex-review-check.sh": "a gate file pinned by CODEX_REVIEW_GATE_SHA (TXE-7556); it has no errexit, so bash keeps its status whatever the trap does; fix it with the next pin move",
}

// lintTrapSources runs the trap rule over every source it reaches. The
// findings of a file in trapAllowedFiles come back allowed, with its reason.
func lintTrapSources(srcs []source) (findings, allowed []Finding) {
	reach := trapReach(srcs)
	for _, s := range srcs {
		if !reach[s.rel] || !isShellTrapSource(s) {
			continue
		}
		fs := lintTraps(s)
		reason, ok := trapAllowedFiles[s.rel]
		switch {
		case !ok:
			findings = append(findings, fs...)
		case len(fs) == 0:
			findings = append(findings, Finding{Path: s.rel, Line: 1, Rule: ruleDirective,
				Msg: "trapAllowedFiles in internal/tools/cleanuplint/trap.go allows trap-status here, and this file has no such finding; remove its entry"})
		default:
			for _, f := range fs {
				f.Reason = reason
				allowed = append(allowed, f)
			}
		}
	}
	return findings, allowed
}

// isShellTrapSource reports a source the trap rule can read: shell other than
// zsh, whose traps differ.
func isShellTrapSource(s source) bool {
	return s.lang == langShell && path.Ext(s.rel) != ".zsh"
}

// lintTraps reports the traps in one shell source or workflow that break the
// rule. A workflow's run: blocks are each read as their own script.
func lintTraps(s source) []Finding {
	phys := lines(s.data)
	segs := [][]string{phys}
	if isYAML(s.rel) {
		segs = workflowSegments(phys)
		segs = segs[:len(segs)-1] // only run: blocks hold shell
	}
	var out []Finding
	for _, seg := range segs {
		if key, script, ok := quotedRun(seg); ok {
			// The runner runs the decoded scalar; its findings are
			// reported at the run: key.
			for _, f := range trapFindings(s.rel, script) {
				f.Line = key + 1
				out = mergeFindings(out, []Finding{f})
			}
			continue
		}
		out = mergeFindings(out, trapFindings(s.rel, strings.Join(runValue(seg), "\n")))
	}
	return out
}

// runValue returns a run: block with its key blanked, so that a plain value
// (run: trap ... EXIT) starts a command where the shell starts one: the
// script begins after the key, not at the key (TXE-7864). Columns are kept.
func runValue(seg []string) []string {
	for i, l := range seg {
		if m := yamlRunKeyRe.FindStringIndex(l); m != nil {
			out := slices.Clone(seg)
			out[i] = strings.Repeat(" ", m[1]) + l[m[1]:]
			return out
		}
	}
	return seg
}

// quotedRun decodes a run: block whose value is a YAML quoted scalar,
// run: "..." or run: '...', which GitHub unquotes before the shell reads it
// (connector review of PR 292). It returns the key's index and the script.
// A block scalar (run: |) or a plain value is read as written.
func quotedRun(seg []string) (int, string, bool) {
	for i, l := range seg {
		m := yamlRunKeyRe.FindStringSubmatchIndex(l)
		if m == nil {
			continue
		}
		v := strings.TrimSpace(l[m[1]:])
		if v == "" || (v[0] != '"' && v[0] != '\'') {
			return 0, "", false
		}
		// A flow scalar folds its line breaks: each one is a space, and an
		// empty line is a newline.
		var b strings.Builder
		b.WriteString(v)
		for _, cont := range seg[i+1:] {
			t := strings.TrimSpace(cont)
			if t == "" {
				b.WriteString("\n")
				continue
			}
			b.WriteString(" ")
			b.WriteString(t)
		}
		return i, decodeFlowScalar(b.String()), true
	}
	return 0, "", false
}

// decodeFlowScalar decodes a YAML single- or double-quoted scalar, up to its
// closing quote: in single quotes a doubled quote is one, and in double
// quotes a backslash escapes the next character.
func decodeFlowScalar(v string) string {
	q := v[0]
	var b strings.Builder
	for i := 1; i < len(v); i++ {
		c := v[i]
		switch {
		case q == '\'' && c == '\'':
			if i+1 < len(v) && v[i+1] == '\'' {
				b.WriteByte('\'')
				i++
				continue
			}
			return b.String()
		case q == '"' && c == '"':
			return b.String()
		case q == '"' && c == '\\' && i+1 < len(v):
			i++
			switch v[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			case ' ':
				// an escaped line break was folded to a space: it joins
			default:
				b.WriteByte(v[i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// trapCmd is one trap command found in a script.
type trapCmd struct {
	line    int
	action  string // the handler as the shell runs it, quotes removed
	early   bool   // the handler has a $ the shell expands when trap runs, not when the handler does
	signals []string
}

const keepStatusMsg = "%s on %s must keep the main command's status: start with RC=$?; set +e (or guard each command with ||) and end with exit \"$RC\" (under set -e, which every run: step has, a failing cleanup ends the script with its own status and skips the rest)"

func trapFindings(rel, text string) []Finding {
	var out []Finding
	for _, t := range findTraps(text) {
		status := false
		for _, sig := range t.signals {
			switch strings.TrimPrefix(strings.ToUpper(sig), "SIG") {
			case "EXIT", "0", "ERR":
				status = true
			}
		}
		body := strings.TrimSpace(t.action)
		if body == "" || body == "-" || body == ":" {
			continue // ignore or reset the signal: no handler
		}
		where := "the trap"
		if fn, ok := funcBody(text, body); ok {
			where = "function " + body
			body = fn
		} else if t.early && status {
			// Only a status-keeping handler must read $? when it runs; a
			// TERM or INT handler may fix a value when it is set (connector
			// review of PR 292).
			out = append(out, Finding{Path: rel, Line: t.line, Rule: ruleTrap,
				Msg: "the trap's handler is double-quoted or unquoted, so its $ expands when trap runs, not when the handler does; single-quote it"})
			continue
		}
		// The handler, and each function it calls that the script defines.
		checked := map[string]string{where: body}
		for _, st := range statements(body) {
			if f := strings.Fields(st); len(f) > 0 {
				if fn, ok := funcBody(text, f[0]); ok {
					checked["function "+f[0]] = fn
				}
			}
		}
		names := make([]string, 0, len(checked))
		for n := range checked {
			names = append(names, n)
		}
		sort.Strings(names)
		var msgs []string
		if status && !keepsStatus(body) {
			msgs = append(msgs, fmt.Sprintf(keepStatusMsg, where, strings.Join(t.signals, " ")))
		}
		for _, n := range names {
			if silencedRe.MatchString(shellCode(checked[n])) {
				msgs = append(msgs, n+" sends stderr to /dev/null: a cleanup that fails must say why; let its stderr through, or print a ::warning:: on failure")
				break
			}
		}
		if len(msgs) > 0 {
			out = append(out, Finding{Path: rel, Line: t.line, Rule: ruleTrap, Msg: strings.Join(msgs, "; and ")})
		}
	}
	return out
}

// shellCode returns body with its comments removed and the text inside
// quotes blanked, so a redirection mentioned in a message or a comment is not
// read as one (connector review of PR 292). Line breaks are kept, except a
// backslash-newline, which the shell removes (TXE-7864).
func shellCode(body string) string {
	body = joinContinuations(body)
	// A quoted redirection target is still a target: 2>"/dev/null".
	body = quotedTargetRe.ReplaceAllString(body, "$1/dev/null")
	var out strings.Builder
	for i, l := range strings.Split(body, "\n") {
		if i > 0 {
			out.WriteByte('\n')
		}
		l = stripComment(l)
		var z quoter
		for j := 0; j < len(l); {
			next, plain := z.step(l, j)
			for k := j; k < next && k < len(l); k++ {
				if plain {
					out.WriteByte(l[k])
				} else {
					out.WriteByte(' ')
				}
			}
			j = next
		}
	}
	return out.String()
}

// quotedTargetRe is a redirection to a quoted /dev/null or &- target.
var quotedTargetRe = regexp.MustCompile(`(>&?\s*)["']/dev/null["']`)

// silencedRe is a redirection that discards stderr.
var silencedRe = regexp.MustCompile(`(?:^|[^0-9>&])(?:2|&)>>?\s*/dev/null|>\s*/dev/null\s*2>&1|2>&-`)

var (
	captureRe = regexp.MustCompile(`^(?:local\s+)?([A-Za-z_]\w*)="?\$\?"?$`)
	exitRe    = regexp.MustCompile(`^exit\s+"?\$\{?([A-Za-z_]\w*)\}?"?$`)
	funcName  = regexp.MustCompile(`^[A-Za-z_][\w-]*$`)
)

// keepsStatus reports a handler whose first statement saves $? in a variable
// and whose last exits with it.
func keepsStatus(body string) bool {
	stmts := statements(body)
	if len(stmts) < 2 {
		return false
	}
	c := captureRe.FindStringSubmatch(stmts[0])
	e := exitRe.FindStringSubmatch(stmts[len(stmts)-1])
	if c == nil || e == nil || c[1] != e[1] {
		return false
	}
	// Under set -e (every run: step) a failing command ends the handler
	// before its exit, with its own status: the handler turns errexit off
	// first, or guards each command between with ||.
	middle := stmts[1 : len(stmts)-1]
	if len(middle) > 0 && middle[0] == "set +e" {
		return true
	}
	for _, st := range middle {
		if !orGuarded(st) {
			return false
		}
	}
	return true
}

// orGuarded reports a statement whose last list operator, outside quotes and
// $( ), is ||: cmd || echo "::warning::...". Its status is the guard's.
func orGuarded(st string) bool {
	var z quoter
	depth, last := 0, ""
	for i := 0; i < len(st); {
		c := st[i]
		next, plain := z.step(st, i)
		if plain {
			switch {
			case c == '(' || c == '{':
				depth++
			case (c == ')' || c == '}') && depth > 0:
				depth--
			case depth == 0 && strings.HasPrefix(st[i:], "||"):
				last = "||"
				next = i + 2
			case depth == 0 && strings.HasPrefix(st[i:], "&&"):
				last = "&&"
				next = i + 2
			case depth == 0 && c == '|':
				last = "|"
			}
		}
		i = next
	}
	return last == "||"
}

// joinContinuations removes each backslash-newline outside single quotes and
// comments, as the shell does when it reads the text: a handler single-quoted
// when the trap is set keeps those bytes, and the shell joins its lines only
// when the handler runs (connector review of PR 292, TXE-7864). A comment
// ends at its newline whatever precedes it, so a backslash there joins
// nothing, and the next line stays code.
func joinContinuations(s string) string {
	if !strings.Contains(s, "\\\n") {
		return s
	}
	var b strings.Builder
	var z quoter
	for i := 0; i < len(s); {
		if z.q == 0 && s[i] == '#' && (i == 0 || strings.IndexByte(" \t\n;&|()", s[i-1]) >= 0) {
			end := strings.IndexByte(s[i:], '\n')
			if end < 0 {
				end = len(s) - i
			}
			b.WriteString(s[i : i+end])
			i += end
			continue
		}
		if z.q != '\'' && s[i] == '\\' && i+1 < len(s) && s[i+1] == '\n' {
			i += 2
			continue
		}
		next, _ := z.step(s, i)
		b.WriteString(s[i:min(next, len(s))])
		i = next
	}
	return b.String()
}

// statements splits a handler at ; and newlines outside quotes, $( ), ${ }
// and braces, dropping comments and blank statements.
func statements(body string) []string {
	body = joinContinuations(body)
	var out []string
	var z quoter
	depth, last := 0, 0
	flush := func(end int) {
		st := strings.TrimSpace(stripComment(body[last:end]))
		if st != "" {
			out = append(out, st)
		}
	}
	for i := 0; i < len(body); {
		c := body[i]
		next, plain := z.step(body, i)
		if plain {
			switch c {
			case '(', '{':
				depth++
			case ')', '}':
				if depth > 0 {
					depth--
				}
			case '#':
				if i == 0 || strings.IndexByte(" \t\n;", body[i-1]) >= 0 {
					for next < len(body) && body[next] != '\n' {
						next++
					}
				}
			case ';', '\n':
				if depth == 0 {
					flush(i)
					last = i + 1
				}
			}
		}
		i = next
	}
	flush(len(body))
	return out
}

// findTraps returns every trap command in a script, read outside quotes,
// comments and here-documents. A handler may span lines inside its quotes.
func findTraps(text string) []trapCmd {
	var out []trapCmd
	var z quoter
	// cmd: the next word is where the shell reads a command name; target:
	// the next word is a redirection's target, so cmd is unchanged.
	cmd, target := true, false
	// bodyEnd: where the here-documents started on this line end. The rest
	// of the line is still shell (cat <<EOF; trap ...), so the bodies are
	// skipped at its newline (connector review of PR 293).
	bodyEnd := -1
	// wordEnd: the end of the last word read. Its inside is not read again
	// (FOO=a\ b, 2>&1), except after a ( that starts a command in it,
	// x=$(trap ...).
	wordEnd := 0
	for i := 0; i < len(text); {
		c := text[i]
		if z.q == 0 {
			if c == '\n' && bodyEnd > i {
				i, bodyEnd = bodyEnd, -1
				continue
			}
			if strings.HasPrefix(text[i:], "<<<") {
				// A here-string: its word is a redirection's target, so the
				// command position is unchanged (<<< in trap ...).
				i += 3
				for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
					i++
				}
				if i < len(text) {
					_, i = wordAt(text, i)
				}
				continue
			}
			if strings.HasPrefix(text[i:], "<<") {
				if end, n := heredocAt(text, i); n > 0 {
					bodyEnd = max(bodyEnd, end)
					i += n // the delimiter, like any target, keeps the position
				} else {
					i += 2 // a shift, $((1<<n)), or a here-document no line ends
				}
				continue
			}
			if strings.HasPrefix(text[i:], "\\\n") {
				i += 2 // a line continuation is a blank: it starts no word
				continue
			}
			wordStart := i == 0 || (i >= wordEnd && strings.IndexByte(" \t\n;&|(", text[i-1]) >= 0) || text[i-1] == '('
			if wordStart && c == '#' {
				for i < len(text) && text[i] != '\n' {
					i++
				}
				continue
			}
			if wordStart && strings.IndexByte(" \t\n;&|()", c) < 0 {
				w, wend := wordAt(text, i)
				wordEnd = wend
				switch {
				case target:
					// The target may run into the next operator: > a> b.
					_, _, target = wordRedir(w)
				case w == "{":
					// A group or a function body starts a command, also
					// after function name (function f { trap ...; }).
					cmd = true
				case !cmd:
				case w == "trap" && wend < len(text) && (text[wend] == ' ' || text[wend] == '\t'):
					words, end := commandWords(text, wend)
					if t, ok := parseTrap(words); ok {
						t.line = strings.Count(text[:i], "\n") + 1
						out = append(out, t)
					}
					i, cmd = end, false
					continue
				default:
					// A redirection in the word (>/dev/null, FOO=1> f, 2>&1)
					// keeps the position when what comes before it does; an
					// operator at the word's end takes the next word.
					if before, ok, needs := wordRedir(w); ok && (before == "" || redirFDRe.MatchString(before) || keepsCommand(before)) {
						target = needs
					} else if !keepsCommand(w) {
						cmd = false
					}
				}
			}
		}
		next, plain := z.step(text, i)
		// Inside a word read whole, only a ( starts a command ($( ), <( )).
		if plain && (c == '(' || i >= wordEnd && strings.IndexByte("\n;&|)", c) >= 0) {
			cmd, target = true, false
		}
		i = next
	}
	return out
}

// The trap rule reads trap only where the shell reads a command name, not
// an argument: echo trap false EXIT sets no trap (connector review of PR 292,
// TXE-7864). A command starts at the start of the script and after a newline,
// ;, &, | or a parenthesis (a subshell, $( ), or a case pattern); a reserved
// word or command prefix (if, then, !, builtin, command, ...), an option, an
// assignment (FOO="a b") and a redirection with its target (>/dev/null,
// 2> err) keep the next word in command position. Where the text is
// ambiguous, a & or a parenthesis inside a word, or a { after any word, the
// next word is read as a command, so the rule reads a trap it is unsure of
// rather than miss one. A backslash-newline is a blank, as it is to the
// shell (connector review of PR 293).

// keepsCommand reports a word after which the next word is still a command.
func keepsCommand(w string) bool {
	return commandPrefixes[w] || assignmentRe.MatchString(w) || strings.HasPrefix(w, "-")
}

// commandPrefixes are the words after which the next word is still a
// command: reserved words, and builtins that run their arguments as one.
var commandPrefixes = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "do": true,
	"while": true, "until": true, "!": true, "time": true, "{": true,
	"builtin": true, "command": true, "coproc": true,
	// eval runs its arguments as a command in this shell: eval trap ...
	// sets a trap (connector security review of PR 293).
	"eval": true,
}

var (
	// assignmentRe is a variable assignment written before a command.
	assignmentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(?:\[[^]]*\])?\+?=`)
	// redirFDRe is what may stand before a redirection operator in its own
	// word: a descriptor (2>), a {varname} (exec {fd}>), or the & of &>.
	redirFDRe = regexp.MustCompile(`^(?:[0-9]+|\{[A-Za-z_]\w*\}|&)$`)
)

// wordRedir finds the redirections of a word, outside quotes and $( ): it
// returns the text before the first operator, whether there is one, and
// whether the last one ends the word, so that its operand is the next word
// (FOO=1> /dev/null, >/dev/null< /dev/null; connector review of PR 293).
func wordRedir(w string) (before string, found, needsTarget bool) {
	var z quoter
	depth, first, opEnd := 0, -1, -1
	for i := 0; i < len(w); {
		next, plain := z.step(w, i)
		if plain {
			switch c := w[i]; {
			case c == '(':
				depth++
			case c == ')' && depth > 0:
				depth--
			case depth == 0 && (c == '<' || c == '>'):
				if first < 0 {
					first = i
				}
				for next < len(w) && strings.IndexByte("<>&|", w[next]) >= 0 {
					next++
				}
				opEnd = next
			}
		}
		i = next
	}
	if first < 0 {
		return w, false, false
	}
	return w[:first], true, opEnd >= len(w)
}

// wordAt returns the shell word that starts at i and the index past it. A
// & or | of a redirection operator (>&, <&, >|) is part of the word.
func wordAt(text string, i int) (string, int) {
	var z quoter
	j := i
	for j < len(text) {
		next, plain := z.step(text, j)
		if plain && strings.IndexByte(" \t\n;&|)", text[j]) >= 0 &&
			(j == i || strings.IndexByte("&|", text[j]) < 0 || strings.IndexByte("<>", text[j-1]) < 0) {
			break
		}
		j = next
	}
	j = min(j, len(text))
	return text[i:j], j
}

// commandWords reads the words of one simple command starting at i, up to a
// newline, ;, &, | or ) outside quotes. A backslash-newline is a space.
func commandWords(text string, i int) ([]string, int) {
	var words []string
	for i < len(text) {
		for i < len(text) && (text[i] == ' ' || text[i] == '\t' || strings.HasPrefix(text[i:], "\\\n")) {
			if text[i] == '\\' {
				i++
			}
			i++
		}
		if i >= len(text) || strings.IndexByte("\n;&|)#", text[i]) >= 0 {
			return words, i
		}
		start := i
		var z quoter
		for i < len(text) {
			c := text[i]
			next, plain := z.step(text, i)
			if plain && strings.IndexByte(" \t\n;&|)", c) >= 0 {
				break
			}
			i = next
		}
		i = min(i, len(text))
		words = append(words, text[start:i])
	}
	return words, i
}

// parseTrap reads trap's arguments: [--] action signal..., or a signal list
// alone (-p, -l print and set nothing).
func parseTrap(words []string) (trapCmd, bool) {
	if len(words) > 0 && words[0] == "--" {
		words = words[1:]
	}
	if len(words) < 2 || strings.HasPrefix(words[0], "-") && words[0] != "-" {
		return trapCmd{}, false
	}
	action, early := unquote(words[0])
	// A quoted signal ("EXIT", 'ERR') names the same signal to the shell.
	signals := make([]string, 0, len(words)-1)
	for _, w := range words[1:] {
		sig, _ := unquote(w)
		signals = append(signals, sig)
	}
	return trapCmd{action: action, early: early, signals: signals}, true
}

// unquote removes shell quoting from a word, and reports whether it holds a $
// the shell expands while reading it (outside single quotes).
func unquote(w string) (string, bool) {
	var b strings.Builder
	early := false
	for i := 0; i < len(w); i++ {
		c := w[i]
		switch c {
		case '\'':
			end := strings.IndexByte(w[i+1:], '\'')
			if end < 0 {
				end = len(w) - i - 1
			}
			b.WriteString(w[i+1 : i+1+end])
			i += end + 1
		case '"':
			for i++; i < len(w) && w[i] != '"'; i++ {
				if w[i] == '\\' && i+1 < len(w) && w[i+1] == '\n' {
					i++ // a line continuation: the shell removes both
					continue
				}
				if w[i] == '\\' && i+1 < len(w) && strings.IndexByte("\"\\$`", w[i+1]) >= 0 {
					i++
				} else if w[i] == '$' {
					early = true
				}
				b.WriteByte(w[i])
			}
		case '\\':
			if i+1 < len(w) {
				i++
				if w[i] != '\n' { // a line continuation: the shell removes both
					b.WriteByte(w[i])
				}
			}
		case '$':
			early = true
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), early
}

var heredocRe = regexp.MustCompile(`^<<(-?)[ \t]*(?:'([^']*)'|"([^"]*)"|\\?([A-Za-z_][\w]*))`)

// heredocAt reads a here-document operator at i: n is the length of the
// operator with its delimiter word, and end the index of the newline that
// ends its body. n is 0 when << starts none or no line ends it (an
// arithmetic shift, $((1<<n)), reads the same), so a skip never hides the
// rest of a script. Its body is data: an apostrophe or the word trap in it is
// not shell.
func heredocAt(text string, i int) (end, n int) {
	m := heredocRe.FindStringSubmatch(text[i:])
	if m == nil {
		return 0, 0
	}
	delim := m[2] + m[3] + m[4]
	nl := strings.IndexByte(text[i:], '\n')
	if nl < 0 {
		return len(text), len(m[0])
	}
	j := i + nl + 1
	for j < len(text) {
		end := strings.IndexByte(text[j:], '\n')
		if end < 0 {
			end = len(text) - j
		}
		if strings.TrimSpace(text[j:j+end]) == delim {
			return j + end, len(m[0])
		}
		j += end + 1
	}
	return 0, 0
}

// funcBody returns the body of the shell function name, if the script
// defines one: name() { ... } or function name { ... }.
func funcBody(text, name string) (string, bool) {
	if !funcName.MatchString(name) {
		return "", false
	}
	defRe := regexp.MustCompile(`(?m)^[ \t]*(?:function[ \t]+` + regexp.QuoteMeta(name) + `[ \t]*(?:\(\s*\))?|` + regexp.QuoteMeta(name) + `[ \t]*\(\s*\))\s*\{`)
	loc := defRe.FindStringIndex(text)
	if loc == nil {
		return "", false
	}
	var z quoter
	depth := 1
	for i := loc[1]; i < len(text); {
		c := text[i]
		next, plain := z.step(text, i)
		if plain && c == '#' && strings.IndexByte(" \t\n;", text[i-1]) >= 0 {
			for next < len(text) && text[next] != '\n' {
				next++
			}
		}
		if plain {
			switch c {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					return text[loc[1]:i], true
				}
			}
		}
		i = next
	}
	return "", false
}
