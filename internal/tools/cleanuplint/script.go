// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"regexp"
	"slices"
	"strings"
)

// The script half reads shell (with workflow run: blocks), Makefiles,
// PowerShell and Python a logical line at a time. It knows which variables a
// file assigns, so `tmp=$(mktemp -d); rm -rf "$tmp"` passes and
// `rm -rf "$HOME/.cache"` or `rm -rf "$CACHE_DIR"` (CACHE_DIR set by whoever
// runs the script) does not.

type logical struct {
	line int // first physical line, 1-based
	text string
}

// joinLines joins continued lines: a trailing backslash (shell, Make, Python),
// a trailing backtick (PowerShell), or an open bracket (Python).
func joinLines(l lang, phys []string) []logical {
	var out []logical
	var cur strings.Builder
	start := 0
	depth := 0
	var py pyScanner
	for i, p := range phys {
		if cur.Len() == 0 {
			start = i + 1
		}
		text := p
		if l != langPython && isCommentLine(text) {
			// A comment line never continues; flush what came before it.
			if cur.Len() > 0 {
				out = append(out, logical{line: start, text: cur.String()})
				cur.Reset()
			}
			out = append(out, logical{line: i + 1, text: text})
			continue
		}
		cont := false
		if l == langPowerShell {
			if before, ok := strings.CutSuffix(strings.TrimRight(text, " \t"), "`"); ok {
				text = before
				cont = true
			}
		} else if strings.HasSuffix(text, `\`) && !strings.HasSuffix(text, `\\`) {
			text = strings.TrimSuffix(text, `\`)
			cont = true
		}
		if l == langPython {
			depth += py.depth(text)
			if depth > 0 || py.inTriple() {
				cont = true
			} else {
				depth = 0
			}
		}
		cur.WriteString(text)
		cur.WriteString(" ")
		if !cont {
			out = append(out, logical{line: start, text: cur.String()})
			cur.Reset()
		}
	}
	if cur.Len() > 0 {
		out = append(out, logical{line: start, text: cur.String()})
	}
	return out
}

// pyScanner tracks Python string state across physical lines, so a bracket
// or apostrophe inside a string or docstring ("bazel.yml's (") neither opens
// a quote nor continues a line. Shell quoting rules do not apply to Python: a
// backtick is an ordinary character, and a triple-quoted string spans lines.
type pyScanner struct {
	quote  byte // the open string's quote character, or 0
	triple bool // the open string is triple-quoted
}

func (p *pyScanner) inTriple() bool { return p.quote != 0 && p.triple }

// depth returns the net count of opening brackets outside strings and
// comments on one physical line, carrying an open triple-quoted string to
// the next line. A single-quoted string ends at the end of its line.
func (p *pyScanner) depth(s string) int {
	d := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if p.quote != 0 {
			switch {
			case c == '\\':
				i++
			case c == p.quote && !p.triple:
				p.quote = 0
			case c == p.quote && strings.HasPrefix(s[i:], strings.Repeat(string(c), 3)):
				p.quote, p.triple = 0, false
				i += 2
			}
			continue
		}
		switch c {
		case '#':
			return d
		case '\'', '"':
			p.quote = c
			p.triple = strings.HasPrefix(s[i:], strings.Repeat(string(c), 3))
			if p.triple {
				i += 2
			}
		case '(', '[', '{':
			d++
		case ')', ']', '}':
			d--
		}
	}
	if !p.triple {
		p.quote = 0
	}
	return d
}

func isCommentLine(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), "#")
}

// quoter tracks shell-style quotes while a scanner walks a line.
type quoter struct{ q byte }

// step consumes the byte at i and returns the next index, and whether that
// byte was outside quotes and unescaped, for the caller to act on.
func (z *quoter) step(s string, i int) (int, bool) {
	c := s[i]
	switch z.q {
	case '\'', '`':
		if c == z.q {
			z.q = 0
		}
		return i + 1, false
	case '"':
		switch c {
		case '\\':
			return i + 2, false
		case '"':
			z.q = 0
		}
		return i + 1, false
	}
	switch c {
	case '\\':
		return i + 2, false
	case '\'', '"', '`':
		z.q = c
		return i + 1, false
	}
	return i + 1, true
}

// stripComment drops a # comment that starts outside quotes, at the start of
// the text or after whitespace (so ${#x} and $# stay).
func stripComment(s string) string {
	var z quoter
	for i := 0; i < len(s); {
		next, plain := z.step(s, i)
		if plain && s[i] == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
			return s[:i]
		}
		i = next
	}
	return s
}

// splitCommands splits a logical line at ;, &&, || and | outside quotes,
// $(...) and backticks.
func splitCommands(s string) []string {
	var out []string
	var z quoter
	paren, last := 0, 0
	for i := 0; i < len(s); {
		c := s[i]
		next, plain := z.step(s, i)
		if plain {
			switch c {
			case '(':
				paren++
			case ')':
				if paren > 0 {
					paren--
				}
			case ';', '|', '&':
				if paren == 0 {
					out = append(out, s[last:i])
					last = i + 1
				}
			}
		}
		i = next
	}
	return append(out, s[min(last, len(s)):])
}

// shellWordEnd is the end of the shell word that starts at i: quotes,
// $(...), ${...} and backticks are part of the word.
func shellWordEnd(s string, i int) int {
	var z quoter
	paren, brace := 0, 0
	for i < len(s) {
		c := s[i]
		next, plain := z.step(s, i)
		if plain {
			switch c {
			case '(':
				paren++
			case ')':
				if paren == 0 {
					return i
				}
				paren--
			case '{':
				brace++
			case '}':
				if brace > 0 {
					brace--
				}
			case ' ', '\t', ';', '&', '|':
				if paren == 0 && brace == 0 {
					return i
				}
			}
		}
		i = next
	}
	return min(i, len(s))
}

type assignment struct {
	name       string
	rhs        string
	overridden bool // the caller's environment can set the value (${X:-...}, make ?=)
}

var (
	shellAssignRe = regexp.MustCompile(`(?:^|[\s;&|(])(?:(?:export|local|readonly|declare|typeset)\s+(?:-\w+\s+)*)?([A-Za-z_]\w*)=`)
	shellForRe    = regexp.MustCompile(`\bfor\s+([A-Za-z_]\w*)\s+in\s+([^;]*)`)
	makeAssignRe  = regexp.MustCompile(`^(?:override\s+|export\s+)?([A-Za-z_][\w.-]*)\s*(\?=|::=|:=|\+=|!=|=)\s*(.*)$`)
	// The value's first character is part of the capture: x=os.environ[...]
	// with no space after = must keep its "o".
	psAssignRe = regexp.MustCompile(`(?:^|[\s;(])\$([A-Za-z_]\w*)\s*=([^=].*)$`)
	pyAssignRe = regexp.MustCompile(`^\s*([A-Za-z_][\w, ]*?)\s*(?::[^=]+)?=([^=].*)$`)
	pyForRe    = regexp.MustCompile(`^\s*(?:async\s+)?for\s+([A-Za-z_][\w, ]*?)\s+in\s+(.*):`)
	pyWithRe   = regexp.MustCompile(`\bas\s+([A-Za-z_]\w*)`)

	shellRefRe = regexp.MustCompile(`\$\{?([A-Za-z_]\w*)`)
	makeRefRe  = regexp.MustCompile(`\$[({]([A-Za-z_][\w.-]*)[)}]`)
	psRefRe    = regexp.MustCompile(`\$([A-Za-z_]\w*)\b(?::)?`)
	pyRefRe    = regexp.MustCompile(`\b([A-Za-z_]\w*)\b`)

	goEnvRe     = regexp.MustCompile(`(^|[^\w.-])go(?:\s+-{1,2}C(?:\s*=\s*\S*|\s+\S+))?\s+env\b`)
	tildeRe     = regexp.MustCompile(`(^|[\s=:"'(])~(/|\\|[\s"')]|$)`)
	psSourceRe  = regexp.MustCompile(`(?i)\$env:\w+|\[(system\.)?environment\]::(GetEnvironmentVariable|GetFolderPath|ExpandEnvironmentVariables)|GetTempPath|\$HOME\b`)
	pySourceRe  = regexp.MustCompile(`\bos\.environ\b|\bgetenv\s*\(|\benviron\.get\b|\bexpanduser\s*\(|\bexpandvars\s*\(|\bPath\.home\s*\(|\bgettempdir\s*\(|\btempfile\.tempdir\b`)
	envNameRe   = regexp.MustCompile(`^(HOME|TMPDIR|TMP|TEMP|USERPROFILE|LOCALAPPDATA|APPDATA|XDG_\w+|GO\w*)$`)
	upperNameRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

	rmRe     = regexp.MustCompile(`(?:^|[\s'"(` + "`" + `])rm\s+(.*)$`)
	rmRecRe  = regexp.MustCompile(`(?:^|\s)(-[a-zA-Z]*[rR][a-zA-Z]*|--recursive)\b`)
	findRe   = regexp.MustCompile(`(?:^|[\s'"(` + "`" + `])find\s+(.*)$`)
	findDel  = regexp.MustCompile(`\s-delete\b|\s-exec(dir)?\s+rm\b`)
	psDelRe  = regexp.MustCompile(`(?i)(?:^|[\s(|;])(?:Remove-Item|ri|rmdir|rd|del|erase)\s+(.*)$`)
	psRecRe  = regexp.MustCompile(`(?i)\s-r(ecurse)?\b|\s/s\b`)
	psDirDel = regexp.MustCompile(`(?i)\[(System\.)?IO\.Directory\]::Delete\s*\((.*)$`)
	pyDelRe  = regexp.MustCompile(`\brmtree\s*\((.*)$`)

	// createsTemp starts an expression whose value is a directory or file
	// just created under a unique name: its identity is known, wherever its
	// parent came from.
	createsTemp = regexp.MustCompile(`(?i)\bmktemp\b|\bmkdtemp\s*\(|\bmkstemp\s*\(|\bTemporaryDirectory\s*\(|\bNew-TemporaryFile\b`)

	// targetEnd cuts a delete's arguments where the command ends, including
	// inside a quoted trap string: trap 'rm -rf "$tmp"; rmdir "$lock"' EXIT.
	targetEnd = regexp.MustCompile(`;|&&|\|\|?`)
)

// stripCreated removes each expression in s that creates a fresh temporary
// path: a $(...) or `...` substitution that runs mktemp, or a call such as
// tempfile.mkdtemp(...) or New-TemporaryFile. What is left still counts, so
// ${GOCACHE:-$(mktemp -d)} is still the caller's GOCACHE.
func stripCreated(s string) string {
	for {
		loc := createsTemp.FindStringIndex(s)
		if loc == nil {
			return s
		}
		start, end := createdSpan(s, loc[0], loc[1])
		s = s[:start] + " " + s[end:]
	}
}

// createdSpan widens a createsTemp match to the expression it belongs to: the
// enclosing $( ) or backticks for a shell command, or the call's parentheses.
func createdSpan(s string, mStart, mEnd int) (int, int) {
	// The enclosing command substitution, if any.
	depth := 0
	for i := mStart - 1; i >= 0; i-- {
		switch s[i] {
		case ')':
			depth++
		case '(':
			if depth > 0 {
				depth--
				continue
			}
			if i > 0 && s[i-1] == '$' {
				return i - 1, closeParen(s, i)
			}
		case '`':
			if end := strings.IndexByte(s[mEnd:], '`'); end >= 0 {
				return i, mEnd + end + 1
			}
		}
	}
	// A call: extend over its argument list when the match ends at "(".
	if mEnd > 0 && s[mEnd-1] == '(' {
		return mStart, closeParen(s, mEnd-1)
	}
	return mStart, mEnd
}

// closeParen returns the index just past the parenthesis that closes s[open].
func closeParen(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(s)
}

func cutTarget(s string) string {
	if loc := targetEnd.FindStringIndex(s); loc != nil {
		return s[:loc[0]]
	}
	return s
}

// shellSpecial are upper-case names the shell or make sets itself.
var shellSpecial = map[string]bool{
	"BASH_SOURCE": true, "LINENO": true, "RANDOM": true, "SECONDS": true, "BASHPID": true,
	"PPID": true, "UID": true, "EUID": true, "FUNCNAME": true, "PIPESTATUS": true,
	"OPTARG": true, "OPTIND": true, "REPLY": true, "IFS": true, "BASH_REMATCH": true,
	"CURDIR": true, "MAKE": true, "MAKEFILE_LIST": true, "MAKEFLAGS": true,
}

type scriptScan struct {
	l       lang
	logical []logical
	assigns []assignment
	tainted map[string]bool
	defined map[string]bool
	// envNames are names the environment sets: in a workflow, the keys of
	// its env: maps. Nil outside a workflow.
	envNames map[string]bool
	// argAssigns are assignments from outside the script that expansions
	// also reads. They define nothing: they only add go clean readings.
	argAssigns []assignment
}

func lintScript(s source) ([]Finding, []directiveAt) {
	phys := lines(s.data)
	return scanScript(s, phys, nil, nil), scriptDirectives(phys)
}

// scriptDirectives finds the cleanuplint:allow directives in a file's lines.
func scriptDirectives(phys []string) []directiveAt {
	var dirs []directiveAt
	for i, p := range phys {
		for idx := strings.Index(p, "#"); idx >= 0; {
			if reason, ok := parseDirective(p[idx:]); ok {
				dirs = append(dirs, directiveAt{line: i + 1, reason: reason})
				break
			}
			next := strings.Index(p[idx+1:], "#")
			if next < 0 {
				break
			}
			idx += 1 + next
		}
	}
	return dirs
}

// scanScript reports the findings in one script's lines. envNames are
// names the environment sets for this script beyond the ones the lint
// already treats as sources: a workflow's env: maps. argAssigns are
// assignments made outside this script whose values may still reach its
// go clean arguments: in a workflow, every step's, since a step can export
// a value through $GITHUB_ENV to the steps after it.
func scanScript(s source, phys []string, envNames map[string]bool, argAssigns []assignment) []Finding {
	logicals := joinLines(s.lang, phys)
	if s.lang != langPython {
		for i := range logicals {
			logicals[i].text = maskWorkflowExprs(logicals[i].text)
		}
	}
	sc := &scriptScan{l: s.lang, logical: logicals, tainted: map[string]bool{}, defined: map[string]bool{}, envNames: envNames, argAssigns: argAssigns}
	sc.collectAssignments()
	sc.propagate()

	var out []Finding
	for _, lg := range sc.logical {
		if isCommentLine(lg.text) {
			continue
		}
		text := stripComment(lg.text)
		if s.lang == langPython {
			text = lg.text // Python # inside strings is common; full-line comments were skipped
		}
		if goCleanIn(text) || slices.ContainsFunc(sc.expansions(text), goCleanIn) {
			out = append(out, Finding{Path: s.rel, Line: lg.line, Rule: ruleGoClean, Msg: goCleanMsg})
		}
		if !isHarness(s.rel) {
			continue
		}
		if target, ok := sc.envDelete(text); ok {
			out = append(out, Finding{Path: s.rel, Line: lg.line, Rule: ruleEnvDelete,
				Msg: "recursive delete of a path the environment chooses (" + strings.TrimSpace(target) + "); delete only a directory this code created, such as mktemp -d"})
		}
	}
	return out
}

// Expansion bounds: rounds of substitution (a value can reference another
// variable, or its own old value: flags="$flags -x"), and readings in all.
const (
	maxExpandRounds = 3
	maxExpansions   = 256
)

// expansions returns readings of text with its shell or make variable
// references replaced by values assigned to them, so an argument array is
// read whole (args=(clean -modcache); go "${args[@]}"). A variable can hold
// any of the values assigned to it: the script may assign it on a branch
// that does not run, or keep a value another step exported through
// $GITHUB_ENV (argAssigns). So each combination of values is its own
// reading, as is all of a variable's values joined, and a go clean is
// reported when any reading clears a cache. It can only report more.
func (sc *scriptScan) expansions(text string) []string {
	if sc.l != langShell && sc.l != langMake {
		return nil
	}
	var out []string
	cur := []string{text}
	for range maxExpandRounds {
		var next []string
		for _, t := range cur {
			for _, e := range sc.expandOnce(t) {
				if len(out)+len(next) >= maxExpansions {
					break
				}
				if !slices.Contains(out, e) && !slices.Contains(next, e) {
					next = append(next, e)
				}
			}
		}
		if len(next) == 0 {
			break
		}
		out = append(out, next...)
		cur = next
	}
	return out
}

// expandOnce returns text with its references substituted once: one
// reading per combination of the referenced variables' values, then one
// with each variable's values joined. It returns nil when no reference has
// a value.
func (sc *scriptScan) expandOnce(text string) []string {
	vals := map[string][]string{}
	var names []string
	for _, m := range argRefRe.FindAllStringSubmatch(text, -1) {
		if _, seen := vals[m[1]]; seen {
			continue
		}
		v := assignedValues(append(slices.Clip(sc.assigns), sc.argAssigns...), m[1])
		vals[m[1]] = v
		if len(v) > 0 {
			names = append(names, m[1])
		}
	}
	if len(names) == 0 {
		return nil
	}
	subst := func(pick map[string]string) string {
		return argRefRe.ReplaceAllStringFunc(text, func(ref string) string {
			if v, ok := pick[argRefRe.FindStringSubmatch(ref)[1]]; ok {
				return " " + v + " "
			}
			return ref
		})
	}
	var out []string
	pick := map[string]string{}
	var walk func(i int)
	walk = func(i int) {
		if len(out) >= maxExpansions {
			return
		}
		if i == len(names) {
			out = append(out, subst(pick))
			return
		}
		for _, v := range vals[names[i]] {
			pick[names[i]] = v
			walk(i + 1)
		}
	}
	walk(0)
	joined := map[string]string{}
	for _, n := range names {
		joined[n] = strings.Join(vals[n], " ")
	}
	return append(out, subst(joined))
}

// assignedValues returns the distinct values assigns gives name, in order.
// A value assigned twice is read once: subcmd=clean in two places must
// expand go $subcmd to go clean, not go clean clean.
func assignedValues(assigns []assignment, name string) []string {
	var vals []string
	for _, a := range assigns {
		if a.name == name && !slices.Contains(vals, a.rhs) {
			vals = append(vals, a.rhs)
		}
	}
	return vals
}

// argRefRe is a variable reference: $x, ${x}, ${x[@]}, ${x[*]}, $(x).
var argRefRe = regexp.MustCompile(`\$[({]?([A-Za-z_]\w*)(?:\[[@*]\])?[)}]?`)

func (sc *scriptScan) collectAssignments() {
	for _, lg := range sc.logical {
		if isCommentLine(lg.text) {
			continue
		}
		text := stripComment(lg.text)
		switch sc.l {
		case langShell, langMake:
			if sc.l == langMake && !strings.HasPrefix(lg.text, "\t") {
				if m := makeAssignRe.FindStringSubmatch(text); m != nil {
					sc.assigns = append(sc.assigns, assignment{name: m[1], rhs: m[3], overridden: m[2] == "?="})
					continue
				}
			}
			for _, m := range shellAssignRe.FindAllStringSubmatchIndex(text, -1) {
				name := text[m[2]:m[3]]
				end := shellWordEnd(text, m[1])
				rhs := text[m[1]:end]
				over := regexp.MustCompile(`\$\{` + regexp.QuoteMeta(name) + `:?[-=]`).MatchString(rhs)
				sc.assigns = append(sc.assigns, assignment{name: name, rhs: rhs, overridden: over})
			}
			for _, m := range shellForRe.FindAllStringSubmatch(text, -1) {
				sc.assigns = append(sc.assigns, assignment{name: m[1], rhs: m[2]})
			}
		case langPowerShell:
			for _, m := range psAssignRe.FindAllStringSubmatch(text, -1) {
				sc.assigns = append(sc.assigns, assignment{name: strings.ToLower(m[1]), rhs: m[2]})
			}
		case langPython:
			if m := pyForRe.FindStringSubmatch(lg.text); m != nil {
				for n := range strings.SplitSeq(m[1], ",") {
					sc.assigns = append(sc.assigns, assignment{name: strings.TrimSpace(n), rhs: m[2]})
				}
				continue
			}
			if m := pyAssignRe.FindStringSubmatch(lg.text); m != nil {
				for n := range strings.SplitSeq(m[1], ",") {
					sc.assigns = append(sc.assigns, assignment{name: strings.TrimSpace(n), rhs: m[2]})
				}
			}
			for _, m := range pyWithRe.FindAllStringSubmatch(lg.text, -1) {
				sc.assigns = append(sc.assigns, assignment{name: m[1], rhs: lg.text})
			}
		case langNone, langGo:
		}
	}
	for _, a := range sc.assigns {
		sc.defined[a.name] = true
	}
}

// propagate marks every variable whose value can come from the environment.
func (sc *scriptScan) propagate() {
	for _, a := range sc.assigns {
		if a.overridden {
			sc.tainted[a.name] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for _, a := range sc.assigns {
			if sc.tainted[a.name] {
				continue
			}
			if sc.textTainted(stripCreated(a.rhs)) {
				sc.tainted[a.name] = true
				changed = true
			}
		}
	}
}

// varTainted reports whether a referenced variable can name a path the
// environment chose.
func (sc *scriptScan) varTainted(name string) bool {
	if sc.l == langPowerShell {
		name = strings.ToLower(name)
	}
	if sc.tainted[name] {
		return true
	}
	if sc.defined[name] {
		return false
	}
	switch sc.l {
	case langShell, langMake:
		if sc.envNames[name] {
			return true
		}
		if shellSpecial[name] {
			return false
		}
		return envNameRe.MatchString(name) || upperNameRe.MatchString(name)
	case langPowerShell:
		return name == "home"
	case langNone, langGo, langPython:
	}
	return false
}

// workflowExprRe is a GitHub Actions expression, ${{ ... }}. The runner
// substitutes it into a run: block before the shell starts, from env, vars,
// inputs, a step's outputs or the runner's own context, so the script never
// chose the value: every context is a source, as an upper-case variable the
// script never assigns is.
var workflowExprRe = regexp.MustCompile(`\$\{\{.*?\}\}`)

// maskWorkflowExprs replaces the inside of each ${{ }} expression, so that
// its operators and quotes (${{ inputs.dir || vars.DIR }}, env['X']) are not
// read as shell: they would otherwise end a command or a delete's target in
// the middle of the expression. The masked expression is still a source.
func maskWorkflowExprs(text string) string {
	return workflowExprRe.ReplaceAllString(text, "${{expr}}")
}

// textTainted reports whether text reads the environment directly or through
// a tainted variable.
func (sc *scriptScan) textTainted(text string) bool {
	if goEnvRe.MatchString(normArgv(text)) {
		return true
	}
	if sc.l != langPython && workflowExprRe.MatchString(text) {
		return true
	}
	switch sc.l {
	case langShell, langMake:
		if tildeRe.MatchString(text) {
			return true
		}
		for _, m := range shellRefRe.FindAllStringSubmatch(text, -1) {
			if sc.varTainted(m[1]) {
				return true
			}
		}
		if sc.l == langMake {
			for _, m := range makeRefRe.FindAllStringSubmatch(text, -1) {
				if sc.varTainted(m[1]) {
					return true
				}
			}
		}
	case langPowerShell:
		if psSourceRe.MatchString(text) || tildeRe.MatchString(text) {
			return true
		}
		for _, m := range psRefRe.FindAllStringSubmatch(text, -1) {
			if strings.EqualFold(m[1], "env") {
				continue
			}
			if sc.varTainted(m[1]) {
				return true
			}
		}
	case langPython:
		if pySourceRe.MatchString(text) {
			return true
		}
		for _, m := range pyRefRe.FindAllStringSubmatch(text, -1) {
			if sc.tainted[m[1]] {
				return true
			}
		}
	case langNone, langGo:
	}
	return false
}

// envDelete finds a recursive delete in a logical line whose target the
// environment chooses, and returns that target text.
func (sc *scriptScan) envDelete(text string) (string, bool) {
	for _, target := range recursiveDeleteTargets(sc.l, text) {
		if sc.textTainted(target) {
			return target, true
		}
	}
	return "", false
}

// recursiveDeleteTargets returns the argument text of each recursive delete
// in a logical line.
func recursiveDeleteTargets(l lang, text string) []string {
	var out []string
	cmds := splitCommands(text)
	if l == langPython {
		cmds = []string{argvPunct.Replace(text)}
		if m := pyDelRe.FindStringSubmatch(text); m != nil {
			out = append(out, m[1])
		}
	}
	for _, c := range cmds {
		if l == langPowerShell {
			if m := psDelRe.FindStringSubmatch(c); m != nil && psRecRe.MatchString(" "+cutTarget(m[1])) {
				out = append(out, cutTarget(m[1]))
			}
			if m := psDirDel.FindStringSubmatch(c); m != nil {
				out = append(out, m[2])
			}
		}
		if m := rmRe.FindStringSubmatch(c); m != nil && rmRecRe.MatchString(cutTarget(m[1])) {
			out = append(out, cutTarget(m[1]))
		}
		if m := findRe.FindStringSubmatch(c); m != nil && findDel.MatchString(" "+cutTarget(m[1])) {
			out = append(out, cutTarget(m[1]))
		}
	}
	return out
}
