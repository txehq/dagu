#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""PreToolUse hook (TXE-8055): refuse shell-evaluated text before the shell parses it.

Agents write prose (message bodies, comments, PR bodies) into shell commands. In a double-quoted
string or an unquoted here-document, a backtick or $( ) in that prose is a command substitution:
the shell runs it before the target program starts. On 2026-11-22 this ran a merge script (an
unquoted heredoc) and `flux suspend` against the production context (a double-quoted --body).
A check after the shell (a CLI wrapper) is too late, so this hook reads the command TEXT first.

Rules, keyed on the shell construct and never on a CLI name. An ACTIVE command substitution is a
`$(` that is not `$((`, or an unescaped backtick, where the shell would run it. Its nearest
quoting context decides:
  D1  a backtick inside a double-quoted string                      -> refuse
  T2  a $( ) inside a double-quoted string (any CLI, flag, length)    -> refuse
  H1  either one inside the body of an unquoted heredoc (<<EOF)       -> refuse
  U1  a backtick in unquoted code (write $( ) instead)                -> refuse
      a $( ) in unquoted code (V=$(cmd), cmd $(other))                -> allowed: code, not prose
${ } and arithmetic take the enclosing context. Inert forms are allowed: '...', $'...', "\\$(x)",
<<'EOF' (any quoted delimiter), comments, and a plain "$V" (expanded once, never re-parsed).
Rewrite for an intended substitution: V=$(cmd), then pass "$V". Prose goes in a file, passed with
--body-file, -F or git commit -F.

Refused because the scanner cannot follow the input, visibly:
  X1  a construct still open at end of input (quote, $(, backtick, ${, heredoc without delimiter)
  B1  input larger than MAX_BYTES        B2  nesting deeper than MAX_DEPTH
Every size bound counts BYTES (UTF-8), never characters.
Payload routes (tool_input read as data; argv is never joined into a synthetic shell string):
  no command/cmd key                          -> allowed (not command-bearing; non-shell tools pass)
  command/cmd is a string                     -> scanned as a shell command string
  a list whose argv[0] is a POSIX shell and whose options, parsed by that shell's grammar,
  include -c                                  -> only the script operand is scanned
  any other list of strings                   -> a direct exec; every element is an inert argument
                                                 (so `echo bash -c TEXT` is inert)
Refused visibly, never assumed safe:
  P0 hook input not UTF-8 JSON, or over the byte bound (detected while reading, before decoding)
  P1 an unsupported command shape     P2 an option outside the shell's modelled grammar, or -c
  with no script     P3 a non-POSIX shell (fish, csh, ...)     P4 a shell run through a wrapper
  (env, timeout, sudo, xargs, ...), whose own grammar this guard does not model
Known limits (pinned by tests): text a SECOND parser runs (sh -c '...', eval "$x", bash <<'EOF',
ssh host '...', python3 -c '...'), a script file a later call runs, command text built at run
time, and `case ... in a)` inside $( ), where an early ')' fails toward refusing. This guard
does not make a shell command safe; it removes one class of accident.

Protocol: hook input JSON on stdin. A refusal exits 2 with the reason on stderr; anything else
prints nothing and exits 0. An exception inside the guard refuses (fail closed) and names it.
This module imports only json and sys and calls no process, exec or eval facility. The
structural tests (an import list, and allowlists of every called name and attribute) DETECT a
regression; they are not a proof of zero execution. README.md gives the reviewed call graph.
"""
import json
import sys

MAX_BYTES = 256 * 1024
MAX_DEPTH = 64
MAX_FINDINGS = 20
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
NON_POSIX_SHELLS = frozenset({"fish", "csh", "tcsh", "nu", "pwsh", "xonsh", "elvish"})

CODE, DQ, CMDSUB, BQ, PARAM, ARITH, HDOC = "code", "dq", "cmdsub", "bq", "param", "arith", "hdoc"
CODE_LIKE = (CODE, CMDSUB, BQ)
WORD_BREAK = " \t\n;&|()<>"
CMD_START_PREV = "\n;&|({!"

RULES = {
    "D1": "a backtick inside a double-quoted string runs as a command",
    "T2": "a $( ) inside a double-quoted string runs as a command",
    "H1": "a backtick or $( ) inside an unquoted heredoc (<<EOF) runs as a command",
    "U1": "an unquoted backtick runs as a command",
    "X1": "a quote, substitution or heredoc is still open at the end of the command",
    "B1": "the command is larger than the guard's bound",
    "B2": "the command nests deeper than the guard's bound",
}


class _Frame:
    __slots__ = ("kind", "depth")

    def __init__(self, kind):
        self.kind = kind
        self.depth = 0


class _Stop(Exception):
    pass


class Scanner:
    """One forward pass over shell text. Records (rule, offset) findings; never evaluates."""

    def __init__(self, s, start_kind=CODE, base=0, depth_budget=MAX_DEPTH):
        self.s = s
        self.n = len(s)
        self.i = 0
        self.base = base
        self.budget = depth_budget
        self.stack = [_Frame(start_kind)]
        self.findings = []
        self.pending = []  # heredocs waiting for the end of the current line: (delim, quoted, strip_tabs)
        self.ws = True  # at a word start in unquoted code (see step_code)

    # -- bookkeeping -------------------------------------------------------------------------
    def find(self, rule, at):
        self.findings.append((rule, self.base + at))
        if len(self.findings) >= MAX_FINDINGS:
            raise _Stop()

    def push(self, kind):
        if len(self.stack) >= self.budget:
            self.find("B2", self.i)
            raise _Stop()
        self.stack.append(_Frame(kind))

    def pop(self):
        if len(self.stack) > 1:
            self.stack.pop()

    def top(self):
        return self.stack[-1]

    def has_dq_ancestor(self):
        return any(f.kind == DQ for f in self.stack)

    def substitution(self, backtick, at):
        """An active substitution at `at`: its nearest quoting context decides the rule."""
        for f in reversed(self.stack):
            if f.kind in (PARAM, ARITH):
                continue
            if f.kind == DQ:
                self.find("D1" if backtick else "T2", at)
            elif f.kind == HDOC:
                self.find("H1", at)
            elif backtick:
                self.find("U1", at)
            return

    # -- driver ------------------------------------------------------------------------------
    def scan(self):
        try:
            while self.i < self.n:
                k = self.top().kind
                if k in CODE_LIKE:
                    self.step_code()
                elif k == DQ:
                    self.step_dq()
                elif k == HDOC:
                    self.step_hdoc()
                elif k == PARAM:
                    self.step_param()
                else:
                    self.step_arith()
            if len(self.stack) > 1 or self.pending:
                self.find("X1", self.n)
        except _Stop:
            pass
        return self.findings

    # -- shared openers ($..., backtick, quotes) ---------------------------------------------
    def dollar(self):
        """At a '$'. Returns True when it opened something."""
        s, i = self.s, self.i
        if s.startswith("$((", i):
            self.ws = False
            self.push(ARITH)
            self.i = i + 3
            return True
        if s.startswith("$(", i):
            self.substitution(False, i)
            self.push(CMDSUB)
            self.ws = True  # a new command starts inside $( )
            self.i = i + 2
            return True
        if s.startswith("${", i):
            self.ws = False
            self.push(PARAM)
            self.i = i + 2
            return True
        return False

    def open_backtick(self):
        """Enter a backtick substitution: a new command starts inside it."""
        self.push(BQ)
        self.ws = True

    def skip_single(self):
        j = self.s.find("'", self.i + 1)
        if j < 0:
            self.find("X1", self.i)
            self.i = self.n
        else:
            self.i = j + 1

    def skip_ansi_c(self):
        j = self.i + 2
        while j < self.n:
            if self.s[j] == "\\":
                j += 2
            elif self.s[j] == "'":
                break
            else:
                j += 1
        if j >= self.n:
            self.find("X1", self.i)
            self.i = self.n
        else:
            self.i = j + 1

    def at_command_start(self):
        j = self.i - 1
        while j >= 0 and self.s[j] in " \t":
            j -= 1
        return j < 0 or self.s[j] in CMD_START_PREV

    # -- contexts ----------------------------------------------------------------------------
    def step_code(self):
        """Unquoted code. self.ws is True when the next character would start a shell word: only
        there does '#' begin a comment. An escaped character (`\\ `) continues the word; a
        backslash-newline is removed by the shell, so it leaves self.ws as it was."""
        s, i, f = self.s, self.i, self.top()
        c = s[i]
        if c == "\\":
            if not s.startswith("\\\n", i):
                self.ws = False
            self.i = i + 2
        elif c == "'":
            self.ws = False
            self.skip_single()
        elif c == "$" and s.startswith("$'", i):
            self.ws = False
            self.skip_ansi_c()
        elif c == "$" and s.startswith('$"', i):
            self.ws = False
            self.push(DQ)
            self.i = i + 2
        elif c == '"':
            self.ws = False
            self.push(DQ)
            self.i = i + 1
        elif c == "`":
            if f.kind == BQ:
                self.pop()
                self.ws = False
            else:
                self.substitution(True, i)
                self.open_backtick()
            self.i = i + 1
        elif c == "$" and self.dollar():
            pass
        elif c == "(" and f.kind != BQ and s.startswith("((", i) and self.at_command_start():
            self.ws = False
            self.push(ARITH)  # closes on '))' at depth 0, as $(( does
            self.i = i + 2
        elif c == "(":
            if f.kind == CMDSUB:
                f.depth += 1
            self.ws = True
            self.i = i + 1
        elif c == ")":
            if f.kind == CMDSUB and not f.depth:
                self.pop()
                self.ws = False  # `$(x)#y` is one word: the '#' does not start a comment
            else:
                if f.kind == CMDSUB:
                    f.depth -= 1
                self.ws = True
            self.i = i + 1
        elif c == "#" and self.ws:
            j = s.find("\n", i)
            self.i = self.n if j < 0 else j
        elif c == "<" and s.startswith("<<<", i):
            self.ws = True
            self.i = i + 3
        elif c == "<" and s.startswith("<<", i):
            self.ws = False
            self.heredoc_operator()
        elif c == "\n":
            self.ws = True
            self.i = i + 1
            if self.pending:
                self.read_heredoc_bodies()
        else:
            self.ws = c in WORD_BREAK
            self.i = i + 1

    def step_dq(self):
        s, i = self.s, self.i
        c = s[i]
        if c == "\\":
            self.i = i + (2 if i + 1 < self.n and s[i + 1] in '$`"\\\n' else 1)
        elif c == '"':
            self.pop()
            self.i = i + 1
        elif c == "`":
            self.substitution(True, i)
            self.open_backtick()
            self.i = i + 1
        elif c == "$" and self.dollar():
            pass
        else:
            self.i = i + 1

    def step_hdoc(self):
        """Body of an unquoted heredoc: like double quotes, but '"' is literal."""
        s, i = self.s, self.i
        c = s[i]
        if c == "\\":
            self.i = i + (2 if i + 1 < self.n and s[i + 1] in "$`\\\n" else 1)
        elif c == "`":
            self.substitution(True, i)
            self.open_backtick()
            self.i = i + 1
        elif c == "$" and self.dollar():
            pass
        else:
            self.i = i + 1

    def step_param(self):
        s, i, f = self.s, self.i, self.top()
        c = s[i]
        if c == "\\":
            self.i = i + 2
        elif c == "'" and not self.has_dq_ancestor():
            self.skip_single()
        elif c == '"':
            self.push(DQ)
            self.i = i + 1
        elif c == "`":
            self.substitution(True, i)
            self.open_backtick()
            self.i = i + 1
        elif c == "$" and self.dollar():
            pass
        elif c == "{":
            f.depth += 1
            self.i = i + 1
        elif c == "}":
            if f.depth:
                f.depth -= 1
            else:
                self.pop()
            self.i = i + 1
        else:
            self.i = i + 1

    def step_arith(self):
        s, i, f = self.s, self.i, self.top()
        c = s[i]
        if c == "`":
            self.substitution(True, i)
            self.open_backtick()
            self.i = i + 1
        elif c == '"':
            self.push(DQ)
            self.i = i + 1
        elif c == "$" and self.dollar():
            pass
        elif c == "(":
            f.depth += 1
            self.i = i + 1
        elif c == ")":
            if f.depth > 0:
                f.depth -= 1
                self.i = i + 1
            else:
                self.pop()
                self.i = i + (2 if s.startswith("))", i) else 1)
        else:
            self.i = i + 1

    # -- heredocs ----------------------------------------------------------------------------
    def heredoc_operator(self):
        s = self.s
        j = self.i + 2
        strip = j < self.n and s[j] == "-"
        if strip:
            j += 1
        while j < self.n and s[j] in " \t":
            j += 1
        delim, quoted = [], False
        while j < self.n and s[j] not in WORD_BREAK:
            c = s[j]
            if c == "$" and s.startswith(("$'", '$"'), j):
                # $'...' (ANSI-C) or $"..." (locale): quote removal leaves the inner text, and the
                # delimiter counts as quoted. A backslash escape inside is not modelled: refuse.
                quoted = True
                k = s.find(s[j + 1], j + 2)
                if k < 0 or "\\" in s[j + 2:k]:
                    self.find("X1", j)
                    self.i = self.n
                    return
                delim.append(s[j + 2:k])
                j = k + 1
            elif c in "'\"":
                quoted = True
                k = s.find(c, j + 1)
                if k < 0:
                    self.find("X1", j)
                    self.i = self.n
                    return
                delim.append(s[j + 1:k])
                j = k + 1
            elif c == "\\":
                quoted = True
                delim.append(s[j + 1:j + 2])
                j += 2
            else:
                delim.append(c)
                j += 1
        word = "".join(delim)
        if not word:
            self.find("X1", self.i)
            self.i = self.n
            return
        self.pending.append((word, quoted, strip))
        self.i = j

    def read_heredoc_bodies(self):
        """At the start of the line after a heredoc operator: consume each pending body in order."""
        s = self.s
        pending, self.pending = self.pending, []
        for word, quoted, strip in pending:
            start, pos = self.i, self.i
            while True:
                if pos >= self.n:
                    self.find("X1", start)
                    self.i = self.n
                    return
                e = s.find("\n", pos)
                line = s[pos:] if e < 0 else s[pos:e]
                if (line.lstrip("\t") if strip else line) == word:
                    body_end = pos
                    self.i = self.n if e < 0 else e + 1
                    break
                pos = self.n if e < 0 else e + 1
            if not quoted:
                sub = Scanner(s[start:body_end], HDOC, self.base + start, self.budget - len(self.stack))
                sub.scan()
                for rule, at in sub.findings:
                    self.find(rule, at - self.base)


def check(text):
    """Findings for one shell command string: a list of (rule, offset). Empty means allowed."""
    if not isinstance(text, str):
        raise TypeError("check() takes a string")
    if len(text.encode("utf-8", "surrogatepass")) > MAX_BYTES:
        return [("B1", 0)]
    return Scanner(text).scan()


# -- payload routes ------------------------------------------------------------------------------
class Refusal(Exception):
    def __init__(self, rule, detail):
        super().__init__(detail)
        self.rule = rule
        self.detail = detail


def _basename(word):
    return word.rstrip("/").rsplit("/", 1)[-1]


# Option grammar per shell, as each shell's manual states it (bash(1) INVOCATION, zsh(1)
# INVOCATION / zshoptions, dash(1), ksh(1)): which long options take no argument, which take one,
# and which single-letter options consume the next word (-o NAME, bash's -O SHOPT).
_LONG_NOARG = {
    "bash": frozenset({"--login", "--noprofile", "--norc", "--posix", "--noediting", "--restricted",
                       "--verbose", "--debugger", "--dump-strings", "--dump-po-strings", "--protected"}),
    "zsh": frozenset(),  # zsh accepts --<option-name> for any option: see _zsh_long
    "sh": frozenset(), "dash": frozenset(), "ksh": frozenset(),
}
_LONG_ARG = {"bash": frozenset({"--rcfile", "--init-file"}), "zsh": frozenset({"--emulate"})}
_ARG_LETTERS = {"bash": "oO", "zsh": "o", "sh": "o", "dash": "o", "ksh": "o"}
# Programs that run another program from their own argv. A shell named inside one is NOT parsed:
# the wrapper's own grammar decides where its command starts, so it is classified and refused.
WRAPPERS = frozenset({"env", "timeout", "gtimeout", "nice", "nohup", "command", "exec", "sudo", "doas",
                      "xargs", "time", "stdbuf", "caffeinate", "arch", "chroot", "setsid", "unbuffer"})


def _zsh_long(token):
    name = token[2:]
    return bool(name) and all(ch.isalnum() or ch in "_-" for ch in name)


def classify_argv(argv):
    """How a direct-exec argv list would run, decided by argv[0] and its real option grammar.

    Returns None for a direct exec (every element is an inert argument, even `echo bash -c TEXT`),
    or the script operand of `<shell> [options] -c SCRIPT [arg0 args...]`, which alone is scanned.
    Elements are never joined into a synthetic shell string. A form this guard does not model is
    refused visibly (P2 unknown shell option or -c without a script, P3 non-POSIX shell, P4 a shell
    run through a wrapper); it is never assumed safe."""
    exe = _basename(argv[0])
    if exe in NON_POSIX_SHELLS:
        raise Refusal("P3", f"{exe} is not a shell this guard can read")
    if exe in WRAPPERS:
        named = [w for w in argv[1:] if _basename(w) in SHELLS or _basename(w) in NON_POSIX_SHELLS]
        if named:
            raise Refusal("P4", f"{exe} runs {_basename(named[0])}; a shell inside a wrapper is not parsed")
        return None
    if exe not in SHELLS:
        return None
    j, has_c, n = 1, False, len(argv)
    while j < n:
        t = argv[j]
        if t in ("--", "-"):
            j += 1
            break
        if t.startswith("--"):
            if t in _LONG_NOARG[exe] or (exe == "zsh" and t not in _LONG_ARG["zsh"] and _zsh_long(t)):
                j += 1
                continue
            if t in _LONG_ARG.get(exe, ()):
                j += 2
                continue
            raise Refusal("P2", f"{exe} option {t!r} is not in this guard's grammar")
        if len(t) > 1 and t[0] in "-+":
            letters = t[1:]
            if not letters.isalpha():
                raise Refusal("P2", f"{exe} option {t!r} is not in this guard's grammar")
            if t[0] == "-" and "c" in letters:
                has_c = True
            j += 1 + sum(letters.count(ch) for ch in _ARG_LETTERS[exe])
            continue
        break
    if has_c:
        if j >= n:
            raise Refusal("P2", f"{exe} -c with no script operand")
        return argv[j]
    return None  # a shell reading a script FILE or stdin: not visible here (a known limit)


def command_texts(payload):
    """The shell command strings a hook payload would run, as a list (possibly empty).
    Raises Refusal for a shape this guard cannot read."""
    if not isinstance(payload, dict):
        raise Refusal("P0", "hook input is not a JSON object")
    ti = payload.get("tool_input")
    if not isinstance(ti, dict):
        return []
    texts = []
    for key in ("command", "cmd"):
        if key not in ti:
            continue
        v = ti[key]
        if isinstance(v, str):
            texts.append(v)
        elif isinstance(v, list) and v and all(isinstance(x, str) for x in v):
            script = classify_argv(v)
            if script is not None:
                texts.append(script)
        else:
            raise Refusal("P1", f"tool_input.{key} has a shape this guard does not support ({type(v).__name__})")
    return texts


REWRITE = ("Write prose to a file with the Write tool and pass the file (--body-file, -F, git commit -F); "
           "for a computed value, run V=$(cmd) first and pass \"$V\". Use single quotes for short fixed text. "
           "Do not move the text into sh -c, eval or another parser to get past this check; "
           "if you believe this is a false positive, ask your coordinator.")


def _reason(findings):
    parts = [f"{rule} at offset {at}: {RULES.get(rule, rule)}" for rule, at in findings[:5]]
    more = f" (+{len(findings) - 5} more)" if len(findings) > 5 else ""
    return "Refused by shell-text-guard (TXE-8055): " + "; ".join(parts) + more + ". " + REWRITE


def main(stdin, stderr):
    """stdin is a BINARY stream. The bound counts BYTES: at most MAX_BYTES + 1 bytes are read,
    so an oversize input is detected before any decode or JSON materialization."""
    try:
        raw = stdin.read(MAX_BYTES + 1)
        if not isinstance(raw, bytes):
            raise Refusal("P0", "hook input stream is not binary")
        if len(raw) > MAX_BYTES:
            raise Refusal("P0", "hook input is larger than the guard's bound")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except ValueError:  # UnicodeDecodeError and json.JSONDecodeError are both ValueError
            raise Refusal("P0", "hook input is not UTF-8 JSON")
        findings = []
        for text in command_texts(payload):
            findings.extend(check(text))
        if findings:
            print(_reason(findings), file=stderr)
            return 2
        return 0
    except Refusal as r:
        print(f"Refused by shell-text-guard (TXE-8055): {r.rule}: {r.detail}. Ask your coordinator.", file=stderr)
        return 2
    except Exception as e:  # fail closed, visibly
        print(f"Refused by shell-text-guard (TXE-8055): internal error ({type(e).__name__}). "
              "Ask your coordinator; do not rephrase to get past this check.", file=stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.stdin.buffer, sys.stderr))
