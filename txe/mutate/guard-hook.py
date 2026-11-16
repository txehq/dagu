#!/usr/bin/env python3
"""PreToolUse hook (TXE-7549, TXE-7641): a mutation run outside mutate-sandboxed is refused.

A mutant breaks a guard on purpose, so it may only run where it cannot reach host state: through
txe/mutate/mutate-sandboxed.py, which runs each mutant in a container with no mount of the shared
caches, HOME or the Docker socket (postmortem TXE-7547). This hook is what makes forgetting that
loud: a shell command that runs a mutation script or a mutation tool any other way is denied.

It reads the hook input (Claude Code and Codex share the shape) on stdin, and for a refused
command exits 2 with the reason on stderr, which both harnesses feed back to the agent. It prints
nothing and exits 0 for anything else, including input it cannot parse: it only ever adds a
refusal.

The command is read the way a shell reads it (quotes, escapes, pipelines, lists, subshells,
command and process substitution, redirections and here-documents), and only what a shell would
EXECUTE is judged. A command is a mutation run when, past assignments, keywords and wrappers
(env, timeout, nohup, xargs, ...), its program is:
- a mutation tool (mutmut, go-mutesting, gremlins, cosmic-ray, ...), or a file whose name says
  mutant/mutation (`./mutants.py`, `run-mutations.sh`), run directly or with `source`/`.`;
- an interpreter (python, bash, node, ...) whose script operand is such a file, also as a process
  substitution (`python3 -I <(git show x:mutants.py)`), a module (`python3 -m mutmut`), a file fed
  on stdin (`python3 - < mutants.py`, `cat mutants.py | python3`), or `go run` of one;
- a runner (`uv run`, `uvx`, `poetry run`, `find -exec`, ...) whose command is one of the above;
- a shell given shell code (`bash -c '...'`, `eval '...'`, a here-document to `bash`): that code
  is read the same way;
- a non-shell interpreter given code (`python3 -c`, `node -e`, `perl -e`, a here-document on
  python3's stdin) that imports a mutant module, or names a mutant script or mutation tool and
  calls something that runs a file or a process (runpy, exec, subprocess, os.system, require,
  child_process, ...).
Words that are only data are never judged: a grep or sed pattern, an echo/printf argument, a
`--body` or `--text` message, a path given to cat or shasum, the body of a here-document written
to a file, a comment, and code that only mentions the names (prints them, edits text containing
them). A command whose program is mutate-sandboxed itself is allowed, whatever it names.

It is a heuristic, and a determined agent can get past it: a renamed script, a program or file
name assembled at run time, a mutation run inside a script the command calls, or one started by a
tool it does not know. It is defence in depth that catches the habit that caused the incident; the
AGENTS.md rule is the policy.
"""
import json
import os
import re
import shlex
import sys

TOOLS = re.compile(r"^(?:mutmut|go-mutesting|gremlins|cosmic-ray|mull-runner|mull-cxx|stryker|"
                   r"mutatest|mutpy|pitest|ooze)$", re.I)
# A file named for mutation testing: mutant(s), mutation(s), mutate(s), mutmut, as a word in the name.
MUTANT_FILE = re.compile(r"(?:^|[^A-Za-z0-9])(?:mutants?|mutations?|mutates?|mutmut)(?:[^A-Za-z0-9]|$)", re.I)
SCRIPT_EXT = re.compile(r"\.(?:py|sh|bash|zsh|go|js|mjs|ts|rb|pl)$", re.I)
ALLOWED = re.compile(r"^mutate-sandboxed(?:\.py)?$")
# The guard's own files: running them tests the guard, it is not a mutation run.
GUARD_FILES = {"mutant-run-guard", "guard-hook.py"}
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^]]*\])?\+?=")
VARIABLE = re.compile(r"^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$")

SHELLS = re.compile(r"^(?:bash|sh|zsh|dash|ksh|mksh|ash|fish)$")
PYTHONS = re.compile(r"^(?:python[0-9.]*|pypy[0-9.]*)$")
OTHER_INTERPRETERS = {"node", "nodejs", "deno", "bun", "ruby", "perl", "tsx", "ts-node", "php", "Rscript"}
KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "time", "coproc"}
DATA_KEYWORDS = {"for", "select", "case", "function", "fi", "done", "esac", "in", "[[", "]]"}
# Wrapper commands run their arguments as a command. Value: options that take a separate value,
# and how many positional words come before the command (timeout's duration, chrt's priority).
WRAPPERS = {
    "env": ({"-u", "--unset", "-C", "--chdir", "-P", "-S", "--split-string"}, 0),
    "timeout": ({"-s", "--signal", "-k", "--kill-after"}, 1),
    "gtimeout": ({"-s", "--signal", "-k", "--kill-after"}, 1),
    "nice": ({"-n", "--adjustment"}, 0),
    "nohup": (set(), 0),
    "setsid": (set(), 0),
    "caffeinate": ({"-t", "-w"}, 0),
    "command": (set(), 0),
    "exec": ({"-a"}, 0),
    "builtin": (set(), 0),
    "time": ({"-f", "--format", "-o", "--output"}, 0),
    "sudo": ({"-u", "--user", "-g", "--group", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"}, 0),
    "doas": ({"-u", "-C"}, 0),
    "xargs": ({"-I", "-J", "-L", "-n", "-P", "-s", "-d", "-E", "-a", "-R", "-S"}, 0),
    "stdbuf": ({"-i", "-o", "-e"}, 0),
    "ionice": ({"-c", "-n", "-p", "-P", "-u"}, 0),
    "chrt": (set(), 1),
    "taskset": (set(), 1),
    "watch": ({"-n", "--interval", "-d"}, 0),
    "strace": ({"-o", "-e", "-p", "-s"}, 0),
    "arch": (set(), 0),
}
# Tools that run a command named after a subcommand (or directly, for the x-style ones).
RUNNERS = {"uv": "run", "poetry": "run", "pipenv": "run", "pdm": "run", "hatch": "run", "rye": "run",
           "pipx": "run", "npm": "exec", "pnpm": "exec", "yarn": "run", "conda": "run", "mamba": "run",
           "uvx": None, "npx": None, "bunx": None, "pnpx": None}
RUNNER_VALUE_OPTS = {"--with", "--python", "-p", "--project", "--directory", "--from", "--env-file",
                     "--group", "--extra", "--package", "-n", "--name", "--prefix", "-e", "--env",
                     "--spec", "--index", "--index-url"}
FIND_EXEC = {"-exec", "-execdir", "-ok", "-okdir"}
GO_VALUE_FLAGS = {"-C", "-o", "-p", "-tags", "-ldflags", "-gcflags", "-asmflags", "-exec", "-mod",
                  "-modfile", "-overlay", "-pkgdir", "-toolexec", "-pgo", "-covermode", "-coverpkg"}
MAX_DEPTH = 24
# Code given to a non-shell interpreter (`python3 -c`, `node -e`, a here-document on python3's
# stdin) runs a mutant when it imports one, or when it names a mutant script or tool AND calls
# something that runs a file or a process.
CODE_RUNS = re.compile(r"runpy|\bexec(?:file)?\s*\(|subprocess|\bos\s*\.\s*(?:system|exec\w*|spawn\w*|popen|posix_spawn\w*)"
                       r"|Popen|import_module|__import__|SourceFileLoader|spec_from_file_location|child_process"
                       r"|\b(?:execSync|execFile\w*|spawnSync|fork)\b|\brequire\s*\(|\bimport\s*\(|\bsystem\s*\("
                       r"|\bload\s*\(|\bdo\s*\(?\s*['\"]|`|%x|\bpty\s*\.\s*spawn")
CODE_IMPORTS_MUTANT = re.compile(r"(?:^|[\s;:])(?:import|from)\s+(?:[\w.]*\.)?(?:mutants?|mutations?|mutmut)\b")
CODE_TOKEN = re.compile(r"[^\s'\"(),\[\]{};=+<>]+")

REASON = ("Refused: this runs a mutation test outside the sandboxed runner. A mutant breaks a guard on "
          "purpose and must not run against this host's shared caches, HOME or worktree (TXE-7547). "
          "Run it through mutate-sandboxed: `mutate-sandboxed --mutants <list.json> --tree <dir> "
          "--image sha256:<local image id> -- <test cmd>` (~/.coding_global/bin/mutate-sandboxed runs the "
          "reviewed txehq/dagu txe/mutate/mutate-sandboxed.py its launcher pins by commit and sha256). "
          "If this is not a mutation run, do not rename anything to get past this check: ask your "
          "coordinator, since this hook is a heuristic over command text.")


class Word:
    """One shell word after quote removal. A substitution contributes nothing to the text (its
    command is judged on its own); a word that is a process substitution keeps its commands."""

    def __init__(self):
        self.text = ""
        self.procsub: "list[Cmd] | None" = None  # when the word is <(...) or >(...)


class Cmd:
    """A simple command: its words, what it reads on stdin, and the command piped into it."""

    def __init__(self):
        self.words: list[Word] = []
        self.stdin_file: "str | None" = None
        self.stdin_text: "str | None" = None  # a here-document's body or a here-string's word
        self.piped_from: "Cmd | None" = None


REDIRECT = re.compile(r"(?:\d+|\{[A-Za-z_][A-Za-z0-9_]*\})?(?:<<<|<<-|<<|<>|<&|>&|>>|>\||&>>|&>|<|>)")
WORD_END = set(" \t\n;&|()<>")


class Parser:
    """A small reader of POSIX/bash command syntax. It never fails: unterminated quotes run to the
    end, and constructs it does not know are read as words."""

    def __init__(self, src: str, depth: int = 0):
        self.s, self.i, self.depth = src, 0, depth
        self.cmds = []  # every simple command found, nested ones included
        self.heredocs = []  # (cmd, delimiter, strip_tabs, quoted) waiting for the next newline

    def parse(self) -> list:
        self.seq(None)
        return self.cmds

    def sub(self, src: str) -> list:
        """Commands in shell code found inside this one (backticks, here-document substitutions)."""
        if self.depth >= MAX_DEPTH:
            return []
        p = Parser(src, self.depth + 1)
        found = p.parse()
        self.cmds.extend(found)
        return found

    def seq(self, end):
        """Read commands up to `end` (')' for a substitution or subshell, None for the end)."""
        s = self.s
        start = len(self.cmds)
        cur, prev = Cmd(), None

        def finish():
            nonlocal cur
            if cur.words or cur.stdin_file is not None or cur.stdin_text is not None:
                self.cmds.append(cur)
            done, cur = cur, Cmd()
            return done

        while self.i < len(s):
            c = s[self.i]
            if c in " \t":
                self.i += 1
            elif c == "\\" and s.startswith("\\\n", self.i):
                self.i += 2
            elif c == "\n":
                finish()
                prev = None
                self.i += 1
                self.read_heredocs()
            elif c == "#" and (self.i == 0 or s[self.i - 1] in " \t\n;&|()"):
                while self.i < len(s) and s[self.i] != "\n":
                    self.i += 1
            elif c == ")":
                self.i += 1
                finish()
                prev = None
                if end == ")":
                    return self.cmds[start:]
            elif c in ";&|" and not s.startswith("&>", self.i):
                op = next(o for o in ("||", "&&", ";;&", ";;", ";&", "|&", "|", ";", "&") if s.startswith(o, self.i))
                self.i += len(op)
                done = finish()
                prev = done if op in ("|", "|&") else None
                cur.piped_from = prev
            elif c == "(" and not cur.words:
                if s.startswith("((", self.i):
                    self.skip_balanced("((")
                else:
                    self.i += 1
                    if self.depth < MAX_DEPTH:
                        self.depth += 1
                        self.seq(")")
                        self.depth -= 1
            elif c == "(":
                self.i += 1  # a function definition's () or a stray bracket
            elif s.startswith(("<(", ">("), self.i):
                cur.words.append(self.word())
            elif (m := REDIRECT.match(s, self.i)) and (m.group(0)[0] in "<>&{" or not self.at_word_tail()):
                self.redirect(cur, m.group(0))
            else:
                cur.words.append(self.word())
        finish()
        return self.cmds[start:]

    def at_word_tail(self) -> bool:
        return self.i > 0 and self.s[self.i - 1] not in " \t\n;&|()"

    def redirect(self, cur: Cmd, op: str):
        self.i += len(op)
        op = op.lstrip("0123456789")
        if op.startswith("{"):
            op = op[op.index("}") + 1:]
        while self.i < len(self.s) and self.s[self.i] in " \t":
            self.i += 1
        start = self.i
        target = self.word()
        if op in ("<<", "<<-"):
            raw = self.s[start:self.i]
            self.heredocs.append((cur, target.text, op == "<<-", any(q in raw for q in "'\"\\")))
        elif op == "<<<":
            cur.stdin_text = target.text
        elif op == "<":
            cur.stdin_file = target.text

    def read_heredocs(self):
        s = self.s
        for cmd, delim, strip_tabs, quoted in self.heredocs:
            lines = []
            while self.i < len(s):
                nl = s.find("\n", self.i)
                line = s[self.i:] if nl < 0 else s[self.i:nl]
                self.i = len(s) if nl < 0 else nl + 1
                if (line.lstrip("\t") if strip_tabs else line) == delim:
                    break
                lines.append(line)
            body = "\n".join(lines)
            cmd.stdin_text = body
            if not quoted:  # an unquoted body expands $(...) and backticks: those commands run
                p = Parser(body, self.depth)
                p.dquote(None)
                self.cmds.extend(p.cmds)
        self.heredocs = []

    def skip_balanced(self, opener: str):
        depth, self.i = 1, self.i + len(opener)
        while self.i < len(self.s) and depth:
            if self.s.startswith("((", self.i) or self.s[self.i] == "(":
                depth += 1
            elif self.s[self.i] == ")":
                depth -= 1
            self.i += 1
        if depth and self.s.startswith(")", self.i):
            self.i += 1

    def word(self) -> Word:
        s, w = self.s, Word()
        if s.startswith(("<(", ">("), self.i):
            self.i += 2
            if self.depth < MAX_DEPTH:
                self.depth += 1
                w.procsub = self.seq(")")
                self.depth -= 1
            return w
        while self.i < len(s) and s[self.i] not in WORD_END:
            c = s[self.i]
            if c == "'":
                end = s.find("'", self.i + 1)
                end = len(s) if end < 0 else end
                w.text += s[self.i + 1:end]
                self.i = end + 1
            elif s.startswith("$'", self.i):
                self.i += 2
                while self.i < len(s) and s[self.i] != "'":
                    if s[self.i] == "\\" and self.i + 1 < len(s):
                        self.i += 1
                    w.text += s[self.i]
                    self.i += 1
                self.i += 1
            elif c == '"':
                self.i += 1
                w.text += self.dquote('"')
            elif c == "\\":
                if self.i + 1 < len(s) and s[self.i + 1] != "\n":
                    w.text += s[self.i + 1]
                self.i += 2
            elif c in "$`":
                w.text += self.substitution()
            else:
                w.text += c
                self.i += 1
        return w

    def substitution(self) -> str:
        """At $ or a backtick: read a command substitution (its commands are recorded), an
        arithmetic expansion, or a plain $; return the text it adds to the word."""
        s = self.s
        if s.startswith("$((", self.i):
            self.skip_balanced("$((")
            return ""
        if s.startswith("$(", self.i):
            self.i += 2
            if self.depth < MAX_DEPTH:
                self.depth += 1
                self.seq(")")
                self.depth -= 1
            return ""
        if s[self.i] == "`":
            j, inner = self.i + 1, ""
            while j < len(s) and s[j] != "`":
                if s[j] == "\\" and j + 1 < len(s) and s[j + 1] in "`$\\":
                    j += 1
                inner += s[j]
                j += 1
            self.i = j + 1
            self.sub(inner)
            return ""
        self.i += 1
        return "$"

    def dquote(self, stop) -> str:
        """Read double-quoted text (or an unquoted here-document body when stop is None)."""
        s, text = self.s, ""
        while self.i < len(s):
            c = s[self.i]
            if c == stop:
                self.i += 1
                return text
            if c == "\\" and self.i + 1 < len(s) and s[self.i + 1] in "$`\"\\\n":
                if s[self.i + 1] != "\n":
                    text += s[self.i + 1]
                self.i += 2
            elif c == "`" or s.startswith("$(", self.i):
                text += self.substitution()
            else:
                text += c
                self.i += 1
        return text


def base(text: str) -> str:
    """The file a word names: a `rev:` prefix and directories removed."""
    return os.path.basename(text.rsplit(":", 1)[-1].rstrip("/"))


def mutant_named(text: str, need_ext: bool = False) -> bool:
    name = base(text)
    if not MUTANT_FILE.search(name) or ALLOWED.match(name) or name in GUARD_FILES:
        return False
    return bool(SCRIPT_EXT.search(name)) or not need_ext


def names_mutant_script(words) -> bool:
    return any(mutant_named(w.text, need_ext=True) for w in words)


def operand_is_mutant(w: Word) -> bool:
    """The script an interpreter runs: a file, or the output of a process substitution."""
    if w.procsub is not None:
        return any(names_mutant_script(c.words) for c in w.procsub)
    return mutant_named(w.text)


def code_runs_mutant(code: str) -> bool:
    """Whether code for a non-shell interpreter runs a mutant: it imports one, or it names a
    mutant script or a mutation tool and calls something that runs a file or a process. Code that
    only mentions the names (prints them, edits text that contains them) is data."""
    if CODE_IMPORTS_MUTANT.search(code):
        return True
    if not CODE_RUNS.search(code):
        return False
    return any(mutant_named(t, need_ext=True) or TOOLS.match(base(t)) for t in CODE_TOKEN.findall(code))


def stdin_is_mutant(cmd, shell: bool, depth: int) -> bool:
    """An interpreter with no script reads its program from stdin."""
    if cmd is None:
        return False
    if cmd.stdin_file is not None and mutant_named(cmd.stdin_file):
        return True
    if cmd.piped_from is not None and names_mutant_script(cmd.piped_from.words):
        return True
    if cmd.stdin_text is None:
        return False
    return refuses(cmd.stdin_text, depth + 1) if shell else code_runs_mutant(cmd.stdin_text)


class Judge:
    def __init__(self, depth: int):
        self.depth = depth
        self.vars = {}

    def runs_mutation(self, cmd: Cmd) -> bool:
        words = list(cmd.words)
        for w in words:  # a simple VAR=value before the command names a program later
            if ASSIGN.match(w.text) and w.procsub is None:
                k, _, v = w.text.partition("=")
                self.vars[k.rstrip("+")] = v
            else:
                break
        return self.program(words, cmd)

    def program(self, words: list, cmd) -> bool:
        i = 0
        while i < len(words):
            t = words[i].text
            if ASSIGN.match(t) or t in KEYWORDS:
                i += 1
                continue
            if t in DATA_KEYWORDS:
                return False
            prog = base(t)
            var = VARIABLE.match(t)
            if var and (var.group(1) or var.group(2)) in self.vars:
                prog = base(self.vars[var.group(1) or var.group(2)].split(" ")[0])
            if prog in WRAPPERS:
                nxt = self.past_wrapper(prog, words, i + 1)
                if isinstance(nxt, bool):
                    return nxt
                i = nxt
                continue
            return self.judge(prog, words[i], words[i + 1:], cmd)
        return False

    def past_wrapper(self, prog: str, words: list, i: int) -> "int | bool":
        """Index of the wrapped command, or the verdict when the wrapper decides it: `command -v`
        runs nothing, and `env -S STRING` runs STRING split into words."""
        value_opts, positionals = WRAPPERS[prog]
        while i < len(words):
            t = words[i].text
            if t == "--":
                i += 1
                break
            if prog == "command" and t in ("-v", "-V"):
                return False
            if prog == "env" and t in ("-S", "--split-string") and i + 1 < len(words):
                rest = " ".join(shlex.quote(w.text) for w in words[i + 2:])
                return refuses(words[i + 1].text + " " + rest, self.depth + 1)
            if t.startswith("-") and len(t) > 1:
                i += 2 if t in value_opts else 1
            elif prog == "env" and ASSIGN.match(t):
                i += 1
            else:
                break
        return min(i + positionals, len(words))

    def judge(self, prog: str, w0: Word, args: list, cmd) -> bool:
        if ALLOWED.match(prog):
            return False
        if TOOLS.match(prog):
            return True
        if prog in ("source", "."):
            return bool(args) and mutant_named(args[0].text)
        if prog == "eval":
            return refuses(" ".join(a.text for a in args), self.depth + 1)
        if w0.procsub is None and mutant_named(prog):
            return True
        if SHELLS.match(prog):
            return self.shell(args, cmd)
        if PYTHONS.match(prog):
            return self.python(args, cmd)
        if prog in OTHER_INTERPRETERS:
            return self.other_interpreter(prog, args, cmd)
        if prog == "go":
            return self.go_run(args)
        if prog in RUNNERS:
            return self.runner(prog, args, cmd)
        if prog == "find":
            return self.find_exec(args)
        if VARIABLE.match(w0.text):  # an unknown program in a variable: judge it as an interpreter
            ops = [a for a in args if not a.text.startswith("-")]
            return bool(ops) and mutant_named(ops[0].text, need_ext=True)
        return False

    def shell(self, args: list, cmd) -> bool:
        j, code = 0, False
        while j < len(args):
            t = args[j].text
            if t == "--":
                j += 1
                break
            if t in ("-o", "+o", "-O", "+O"):
                j += 2
            elif len(t) > 1 and t[0] in "-+":
                code = code or (not t.startswith("--") and "c" in t[1:])
                j += 1
            else:
                break
        if code:
            return j < len(args) and refuses(args[j].text, self.depth + 1)
        if j < len(args) and args[j].text not in ("-", "/dev/stdin"):
            return operand_is_mutant(args[j])
        return stdin_is_mutant(cmd, True, self.depth)

    def python(self, args: list, cmd) -> bool:
        j = 0
        while j < len(args):
            t = args[j].text
            if t == "--":
                j += 1
                break
            if t.startswith("--"):
                j += 2 if t == "--check-hash-based-pycs" else 1
                continue
            if not t.startswith("-") or t == "-":
                break
            for k in range(1, len(t)):
                ch = t[k]
                if ch == "c":
                    code = t[k + 1:] or (args[j + 1].text if j + 1 < len(args) else "")
                    return code_runs_mutant(code)
                if ch == "m":
                    mod = t[k + 1:] or (args[j + 1].text if j + 1 < len(args) else "")
                    return bool(TOOLS.match(mod) or mutant_named(mod))
                if ch in "WXQ":
                    j += 0 if t[k + 1:] else 1
                    break
            j += 1
        if j < len(args) and args[j].text not in ("-", "/dev/stdin"):
            return operand_is_mutant(args[j])
        return stdin_is_mutant(cmd, False, self.depth)

    def other_interpreter(self, prog: str, args: list, cmd) -> bool:
        j = 0

        def code_at(n: int) -> bool:
            return n < len(args) and code_runs_mutant(args[n].text)

        if prog in ("deno", "bun") and args and args[0].text in ("run", "x"):
            j = 1
        elif prog == "deno" and args and args[0].text == "eval":
            return code_at(1)
        while j < len(args):
            t = args[j].text
            if t in ("-e", "--eval", "-p", "--print", "-E", "-r", "--require", "--import", "--loader",
                     "--experimental-loader", "-C", "--conditions", "-I", "-M") and prog not in ("perl", "ruby"):
                if t in ("-e", "--eval", "-p", "--print", "-E"):
                    return code_at(j + 1)
                j += 2
            elif prog in ("perl", "ruby") and t.startswith("-") and not t.startswith("--") and re.search("[eE]", t):
                return code_at(j + 1)
            elif prog in ("perl", "ruby") and t in ("-I", "-r", "-M", "-x"):
                j += 2
            elif t.startswith("-") and t != "-":
                j += 1
            else:
                break
        if j < len(args) and args[j].text not in ("-", "/dev/stdin"):
            return operand_is_mutant(args[j])
        return stdin_is_mutant(cmd, False, self.depth)

    def go_run(self, args: list) -> bool:
        if not args or args[0].text != "run":
            return False
        j, ops = 1, []
        while j < len(args):
            t = args[j].text
            if t == "--":
                j += 1
                continue
            if t.startswith("-"):
                j += 2 if t in GO_VALUE_FLAGS else 1
                continue
            if ops and not t.endswith(".go"):
                break
            ops.append(args[j])
            j += 1
        return any(operand_is_mutant(o) for o in ops)

    def runner(self, prog: str, args: list, cmd) -> bool:
        sub, j = RUNNERS[prog], 0
        if sub is not None:
            while j < len(args) and args[j].text != sub:
                if not args[j].text.startswith("-"):
                    return False  # another subcommand: not a run
                j += 2 if args[j].text in RUNNER_VALUE_OPTS else 1
            j += 1
        while j < len(args) and args[j].text.startswith("-"):
            j += 2 if args[j].text in RUNNER_VALUE_OPTS else 1
        if j < len(args) and prog == "hatch":
            args = list(args)
            w = Word()
            w.text = args[j].text.split(":", 1)[-1]  # hatch run env:cmd
            args[j] = w
        return self.program(args[j:], cmd)

    def find_exec(self, args: list) -> bool:
        for j, a in enumerate(args):
            if a.text in FIND_EXEC:
                rest = []
                for b in args[j + 1:]:
                    if b.text in (";", "+"):
                        break
                    rest.append(b)
                if self.program(rest, None):
                    return True
        return False


def refuses(command: str, depth: int = 0) -> bool:
    if depth > MAX_DEPTH:
        return False
    judge = Judge(depth)
    for cmd in Parser(command, depth).parse():
        if judge.runs_mutation(cmd):
            return True
    return False


def command_of(data: dict):
    """The shell command a tool call runs, or None. Claude's Bash and Codex's shell tools carry
    it as tool_input.command or tool_input.cmd, as a string or an argv list (quoted back into one
    command line, so `["bash", "-lc", "python3 x.py"]` keeps its code string whole)."""
    tool_input = data.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    for key in ("command", "cmd"):
        value = tool_input.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, list) and value:
            return shlex.join(map(str, value))
    return None


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0
    if not isinstance(data, dict):
        return 0
    command = command_of(data)
    if command is not None and refuses(command):
        print(REASON, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
