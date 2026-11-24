#!/usr/bin/env python3
"""PreToolUse hook (TXE-7549, TXE-7641): a mutation run outside mutate-sandboxed is refused.

A mutant breaks a guard on purpose, so it may only run where it cannot reach host state: through
txe/mutate/mutate-sandboxed.py, which runs each mutant in a container with no mount of the shared
caches, HOME or the Docker socket (postmortem TXE-7547). This hook is what makes forgetting that
loud: a shell command that runs a mutation script or a mutation tool any other way is denied.

It reads the hook input (Claude Code and Codex share the shape) on stdin, and for a refused
command exits 2 with the reason on stderr, which both harnesses feed back to the agent. It prints
nothing and exits 0 for anything else, including hook input that is not JSON or carries no shell
command, and a call from a file-edit tool named exactly in FILE_EDIT_TOOLS by the harness (Codex's
apply_patch; TXE-8344), whose payload is file content. A command it cannot judge fails closed:
nesting deeper than MAX_DEPTH levels, or an internal error, is refused.

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
  child_process, ...). Python code is also parsed (TXE-8183): in one supported form (isolated
  `python3 -I -c` or `-I` with stdin, not interactive, top level, no PYTHON* variable), code
  proven within a small grammar to only read, parse and print data (json.load, ast.parse, open
  in a read mode, print) is data whatever its arguments name; other Python code that may run
  something is refused when any input it is given names a mutant in any path component, whatever
  the extension (`exec(open("mutants.json").read())`, a file under a mutate-sandboxed work
  directory). With -i, the stdin read after the code is judged as a program. Whether Python code
  may run something is read from its code, never from its string literals or comments (TXE-8351):
  a backtick or `system` in replacement text an editing script writes is data. That holds only
  for code Python runs exactly as written (no shell expansion, no flag such as -x that changes the
  source), that imports only text-handling modules (sys only through a few attributes) and that
  has no construct which can turn a string into a call (a dunder, a frame attribute, help(),
  sys.modules); anything else is judged on its full text, strings included.
One command is also a mutation run when it does what TXE-7547's hand runner did: it writes .go, .py
or .sh source (an output redirection, tee, sed -i/perl -i, or interpreter code that writes a file
it names), runs go test, pytest, python -m pytest or bazel test, and names a mutant or a mutation
anywhere in its text (TXE-8351).
Words that are only data are never judged: a grep or sed pattern, an echo/printf argument, a
`--body` or `--text` message, a path given to cat or shasum, the body of a here-document written
to a file, a comment, and code that only mentions the names (prints them, edits text containing
them). A command whose program is mutate-sandboxed itself is allowed, whatever it names.

It is a heuristic, and a determined agent can get past it: a renamed script, a program or file
name assembled at run time, a mutation run inside a script the command calls, or one started by a
tool it does not know. It is defence in depth that catches the habit that caused the incident; the
AGENTS.md rule is the policy.
"""
import ast
import builtins
import io
import json
import os
import re
import shlex
import sys
import tokenize
import unicodedata

TOOLS = re.compile(r"^(?:mutmut|go-mutesting|gremlins|cosmic-ray|mull-runner|mull-cxx|stryker|"
                   r"mutatest|mutpy|pitest|ooze)$", re.I)
# A file named for mutation testing: mutant(s), mutation(s), mutate(s), mutmut, as a word in the name.
MUTANT_FILE = re.compile(r"(?:^|[^A-Za-z0-9])(?:mutants?|mutations?|mutates?|mutmut)(?:[^A-Za-z0-9]|$)", re.I)
SCRIPT_EXT = re.compile(r"\.(?:py|sh|bash|zsh|go|js|mjs|ts|rb|pl)$", re.I)
ALLOWED = re.compile(r"^mutate-sandboxed(?:\.py)?$")
# The guard's own files: running them tests the guard, it is not a mutation run.
GUARD_FILES = {"mutant-run-guard", "guard-hook.py"}
# Harness-supplied tool names of file-edit tools: their payload is file content and runs nothing
# (TXE-8344). Codex sends a patch as {"tool_name": "apply_patch", "tool_input": {"command":
# "<patch>"}} (openai/codex rust-v0.171.0: core/src/tools/hook_names.rs, where Write and Edit are
# matcher aliases only, and core/src/tools/handlers/apply_patch.rs). Matched exactly, never by
# payload text: a shell or exec tool, an unknown, missing or non-string name, or a case variant
# is judged as a command.
FILE_EDIT_TOOLS = frozenset({"apply_patch"})
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^]]*\])?\+?=")
VARIABLE = re.compile(r"^\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))$")

SHELLS = re.compile(r"^(?:bash|sh|zsh|dash|ksh|mksh|ash|fish)$")
PYTHONS = re.compile(r"^(?:python[0-9.]*|pypy[0-9.]*)$")
OTHER_INTERPRETERS = {"node", "nodejs", "deno", "bun", "ruby", "perl", "tsx", "ts-node", "php", "Rscript"}
KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "time", "coproc"}
# Their words are data: a loop's or case's own commands come after `do`, `;` or `)`, which start a
# new command here. `function NAME` is skipped instead, so its body is judged.
DATA_KEYWORDS = {"for", "select", "case", "fi", "done", "esac", "in", "[[", "]]"}
# Python modules and tools that run a script given as a later argument.
SCRIPT_RUNNER_MODULES = {"runpy", "pdb", "cProfile", "profile", "trace", "coverage", "debugpy", "pyinstrument",
                         "memray", "scalene", "viztracer", "line_profiler", "kernprof", "py_spy"}
SCRIPT_RUNNER_TOOLS = {"coverage", "pdb", "pyinstrument", "memray", "scalene", "viztracer", "kernprof", "py-spy"}
# Shell long options whose value is the next word (bash --rcfile FILE, --init-file FILE).
SHELL_LONG_VALUE = {"--rcfile", "--init-file"}
PRELOAD_OPTS = {"-r", "--require", "--import", "--loader", "--experimental-loader", "--preload"}
NODE_VALUE_OPTS = {"-C", "--conditions", "--title", "--input-type", "--env-file", "--inspect-port",
                   "--cwd", "--config", "--tsconfig-override", "--define", "--loader-type"}
# perl and ruby switch clusters: code switches; switches whose value is attached or the next word;
# switches whose optional value can only be attached (the rest of the cluster).
PERL_CODE, PERL_VALUE, PERL_ATTACHED = "eE", "IMm", "ixDCV"
RUBY_CODE, RUBY_VALUE, RUBY_ATTACHED = "e", "rIEC", "x"
DIGIT_VALUE = "l0TW"
RUBY_LONG_VALUE = {"--encoding", "--external-encoding", "--internal-encoding", "--enable", "--disable",
                   "--dump", "--backtrace-limit", "--crash-report", "--parser"}
SWITCH_DIGITS = re.compile(r"x[0-9A-Fa-f]*|[0-9]*")
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
# go's flags that name a program go runs, alone (value in the next word) or with =value, also
# inside a GOFLAGS=... word.
DECLARERS = {"export", "declare", "typeset", "readonly", "local"}
GO_EXEC_FLAG = re.compile(r"(?:^|=)--?(?:exec|toolexec|vettool)(?:=(.*))?$")
# Code given to a non-shell interpreter (`python3 -c`, `node -e`, a here-document on python3's
# stdin) runs a mutant when it imports one, or when it names a mutant script or tool AND calls
# something that runs a file or a process.
CODE_RUNS = re.compile(r"runpy|\bexec(?:file)?\s*\(|subprocess|\bos\s*\.\s*(?:system|exec\w*|spawn\w*|popen|posix_spawn\w*)"
                       r"|Popen|import_module|__import__|SourceFileLoader|spec_from_file_location|child_process"
                       r"|\b(?:execSync|execFile\w*|spawnSync|fork)\b|\brequire\b|\bimport\s*\(|\bsystem\b"
                       r"|\bload\b|\bdo\s*\(?\s*['\"$]|\beval\b|\bexec\b|`|%x|\bpty\s*\.\s*spawn")
CODE_IMPORTS_MUTANT = re.compile(r"(?:^|[\s;:])(?:import|from)\s+(?:[\w.]*\.)?(?:mutants?|mutations?|mutmut)\b")
CODE_STRING_OR_COMMENT = re.compile(r"#[^\n]*|//[^\n]*|'(?:\\.|[^'\\\n])*'|\"(?:\\.|[^\"\\\n])*\"")
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
        # Whether the shell expands anything in it ($VAR, ${...}, $(...), $((...)), backticks, and
        # unquoted * ? [ { ~), so that `text` is not what the program receives (TXE-8183: such
        # code is never cleared; TXE-8351: its strings are never blanked).
        self.expanded = False


class Cmd:
    """A simple command: its words, what each of its descriptors is redirected to, and the
    command piped into it."""

    def __init__(self):
        self.words: list[Word] = []
        # Descriptor ("0" is stdin, "3", "{name}") -> ("file", path) | ("procsub", cmds) |
        # ("text"|"text-expanding", here-string) | ["text"|"text-expanding", here-document body]
        # ("text-expanding" when the shell expands it first; a list, filled in when the body
        # is read at the next newline, so a duplication made before then shares it) |
        # ("unknown", descriptor) for a duplication of a descriptor this command does not set.
        self.fds: dict = {}
        self.piped_from: "Cmd | None" = None
        self.group: "list[Cmd] | None" = None  # the commands of a `( ... )` this command is

    def source(self, key: str):
        """What descriptor `key` reads, as (kind, value), or None when the command does not set it."""
        return self.fds.get(key)

    def set_source(self, key: str, src):
        self.fds[key] = src

    def duplicate(self, key: str, other: str):
        """`key<&other`: key reads what `other` holds NOW (redirections apply left to right, so a
        later change to `other` does not change key)."""
        self.fds[key] = self.fds.get(other) or ("unknown", other)


REDIRECT = re.compile(r"(?:\d+|\{[A-Za-z_][A-Za-z0-9_]*\})?(?:<<<|<<-|<<|<>|<&|>&|>>|>\||&>>|&>|<|>)")
WORD_END = set(" \t\n;&|()<>")
# Unquoted characters a shell expands into other text: pathname (* ? [), brace ({) and tilde (~).
UNQUOTED_EXPANDING = set("*?[{~")


class Parser:
    """A small reader of POSIX/bash command syntax. It never fails: unterminated quotes run to the
    end, and constructs it does not know are read as words."""

    def __init__(self, src: str, depth: int = 0):
        self.s, self.i, self.depth = src, 0, depth
        self.cmds = []  # every simple command found, nested ones included
        self.heredocs = []  # (cmd, delimiter, strip_tabs, quoted) waiting for the next newline
        self.too_deep = False  # nesting past MAX_DEPTH was not read: the caller refuses
        self.braces = []  # where each open `{ ...` group starts in self.cmds
        self.expansions = 0  # how many expansions have been read (Word.expanded compares counts)
        self.writes = []  # files output redirections write (`> x.go`, `>> x.py`, `&> x.sh`)

    def parse(self) -> list:
        self.seq(None)
        return self.cmds

    def deeper(self) -> bool:
        """Whether one more level of nesting may be read; records it when not."""
        if self.depth < MAX_DEPTH:
            return True
        self.too_deep = True
        return False

    def sub(self, src: str) -> list:
        """Commands in shell code found inside this one (backticks, here-document substitutions)."""
        if not self.deeper():
            return []
        p = Parser(src, self.depth + 1)
        found = p.parse()
        self.too_deep = self.too_deep or p.too_deep
        self.cmds.extend(found)
        self.writes.extend(p.writes)
        return found

    def seq(self, end):
        """Read commands up to `end` (')' for a substitution or subshell, None for the end)."""
        s = self.s
        start = len(self.cmds)
        cur, prev = Cmd(), None

        def finish():
            nonlocal cur
            first = cur.words[0].text if cur.words else None
            group = cur.group
            if first == "{":
                self.braces.append(len(self.cmds))
            elif first == "}" and self.braces:
                group = self.cmds[self.braces.pop():]
            if group:
                # `(python3) < x.py`, `{ python3; } < x.py`, `cat x.py | (python3)`: the group's
                # redirections and pipe apply to every command inside it (an inner one wins).
                for c in group:
                    for k, v in cur.fds.items():
                        c.fds.setdefault(k, v)
                    if c.piped_from is None:
                        c.piped_from = cur.piped_from
            if cur.words or cur.fds:
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
                    self.arithmetic("((")
                else:
                    self.i += 1
                    if self.deeper():
                        self.depth += 1
                        cur.group = self.seq(")")
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
        fd = op[:len(op) - len(op.lstrip("0123456789"))]
        op = op.lstrip("0123456789")
        if op.startswith("{"):
            fd, op = op[:op.index("}") + 1], op[op.index("}") + 1:]
        # The descriptor this redirection sets, as a number ("00" is stdin), a {name}, or the
        # operator's default: 0 for input, 1 for output.
        key = str(int(fd)) if fd.isdigit() else (fd or ("0" if op.startswith("<") else "1"))
        while self.i < len(self.s) and self.s[self.i] in " \t":
            self.i += 1
        start = self.i
        target = self.word()
        src = ("procsub", target.procsub) if target.procsub is not None else ("file", target.text)
        if target.procsub is None and op in (">", ">>", ">|", "&>", "&>>", "<>", ">&"):
            self.writes.append(target.text)  # `>&2` names no file and matches no source extension
        if op in ("<<", "<<-"):
            raw = self.s[start:self.i]
            quoted = any(q in raw for q in "'\"\\")
            # An unquoted body is expanded by the shell ($VAR, $(...), backticks, backslashes), so
            # the text read here is not the text the program receives: "text-expanding" is never
            # cleared as data (TXE-8183).
            pending = ["text" if quoted else "text-expanding", ""]  # its body is read at the next newline
            cur.set_source(key, pending)
            self.heredocs.append((pending, target.text, op == "<<-", quoted))
        elif op == "<<<":
            cur.set_source(key, ("text-expanding" if target.expanded else "text", target.text))
        elif op in ("<&", ">&") and re.fullmatch(r"[0-9]+-?", target.text):
            cur.duplicate(key, str(int(target.text.rstrip("-"))))  # `<&3` or `<&3-` (move)
        elif op in ("<&", ">&") and target.text == "-":
            cur.fds.pop(key, None)  # closed
        elif op in ("&>", "&>>") or (op == ">&" and not fd):
            cur.set_source("1", src)
            cur.set_source("2", src)
        else:  # <, <>, >, >>, >| and a descriptor-less <& target: the file it opens
            fdp = fd_of_path(target.text) if target.procsub is None and op in ("<", "<>") else None
            if fdp == "0":
                src = cur.fds.get("0") or ("pipe", None)  # `< /dev/stdin`: what stdin holds now
            elif fdp == "?":
                src = ("unknown", "?")
            elif fdp is not None:
                src = cur.fds.get(fdp) or ("unknown", fdp)  # `< /dev/fd/3` reopens fd 3 as it is NOW
            cur.set_source(key, src)

    def read_heredocs(self):
        s = self.s
        for pending, delim, strip_tabs, quoted in self.heredocs:
            lines = []
            while self.i < len(s):
                nl = s.find("\n", self.i)
                line = s[self.i:] if nl < 0 else s[self.i:nl]
                self.i = len(s) if nl < 0 else nl + 1
                if (line.lstrip("\t") if strip_tabs else line) == delim:
                    break
                lines.append(line)
            body = "\n".join(lines)
            pending[1] = body
            if not quoted:  # an unquoted body expands $(...) and backticks: those commands run
                p = Parser(body, self.depth)
                p.dquote(None)
                self.cmds.extend(p.cmds)
                self.writes.extend(p.writes)
                self.too_deep = self.too_deep or p.too_deep
        self.heredocs = []

    def arithmetic(self, opener: str):
        """Read `((...))` or `$((...))` to its closing brackets. Bash reads `((cmd) )` as a nested
        subshell, not arithmetic, so the text inside is also read as commands: real arithmetic
        yields only harmless words."""
        s, start = self.s, self.i + len(opener)
        depth, j = 2, start
        while j < len(s) and depth:
            if s[j] == "(":
                depth += 1
            elif s[j] == ")":
                depth -= 1
            j += 1
        self.i = j
        inner = s[start:j]
        for _ in range(2):
            inner = inner.rstrip(" \t\n")
            inner = inner[:-1] if inner.endswith(")") else inner
        self.sub(inner)

    def word(self) -> Word:
        s, w = self.s, Word()
        if s.startswith(("<(", ">("), self.i):
            self.i += 2
            if self.deeper():
                self.depth += 1
                w.procsub = self.seq(")")
                self.depth -= 1
            return w
        start = self.expansions
        while self.i < len(s) and s[self.i] not in WORD_END:
            c = s[self.i]
            if c == "'":
                end = s.find("'", self.i + 1)
                end = len(s) if end < 0 else end
                w.text += s[self.i + 1:end]
                self.i = end + 1
            elif s.startswith("$'", self.i):
                # ANSI-C quoting: its escapes (\n, \x3b, ...) are not decoded here, so the text
                # differs from what the program receives; counted as an expansion.
                self.expansions += 1
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
                if c in UNQUOTED_EXPANDING:
                    # Pathname, brace or tilde expansion can replace the word (`python3 -c
                    # print\(\"x\ *\"\)` runs a file name as code), so it counts (TXE-8351 review).
                    self.expansions += 1
                w.text += c
                self.i += 1
        w.expanded = self.expansions != start
        return w

    def substitution(self) -> str:
        """At $ or a backtick: read a command substitution (its commands are recorded), an
        arithmetic expansion, or a plain $; return the text it adds to the word."""
        self.expansions += 1  # any $ or backtick, outside single quotes (TXE-8183)
        s = self.s
        if s.startswith("$((", self.i):
            self.arithmetic("$((")
            return ""
        if s.startswith("$(", self.i):
            self.i += 2
            if self.deeper():
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
                if c == "$":
                    # "$NAME", "${X}", "$1", "$@" are copied as text but the shell replaces them:
                    # every unescaped $ counts as an expansion (TXE-8183).
                    self.expansions += 1
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


FD_DIR = re.compile(r"^/(?:dev/fd|proc/[^/]+/fd)(?:/|$)")
FD_PATH = re.compile(r"^/(?:dev/fd|proc/[^/]+/fd)/([0-9]+)$")
STD_PATHS = {"/dev/stdin": "0", "/dev/stdout": "1", "/dev/stderr": "2"}


def fd_of_path(text: str):
    """The descriptor a /dev/fd/N, /proc/<pid|self|thread-self>/fd/N or /dev/std{in,out,err} path
    names (after normalising `//`, `.` and `..`); "?" for any other path in a descriptor directory
    (a variable, `/dev/fd/$N`) or under /proc (`/proc/self/root/...`, `/proc/1/cwd/...`), which
    cannot be judged; None for any other path."""
    if not text.startswith("/"):
        return None
    p = os.path.normpath("/" + text.lstrip("/"))
    if p in STD_PATHS:
        return STD_PATHS[p]
    m = FD_PATH.match(p)
    if m:
        return str(int(m.group(1)))
    return "?" if FD_DIR.match(p) or p.startswith("/proc/") else None


def operand_is_mutant(w: Word, cmd=None, shell: bool = False, depth: int = 0, lang: str = "other") -> bool:
    """The script an interpreter runs: a file, the output of a process substitution, or a
    descriptor of the command (`python3 /dev/fd/3 3< mutants.py`). A descriptor path the command
    does not set (opened by an earlier `exec 3<`, say) cannot be judged and is refused."""
    if w.procsub is not None:
        return any(names_mutant_script(c.words) for c in w.procsub)
    fd = fd_of_path(w.text)
    if fd == "0":
        return stdin_is_mutant(cmd, shell, depth, lang)
    if fd is not None:
        src = cmd.source(fd) if cmd is not None else None
        return True if src is None else source_runs_mutant(src, shell, depth, cmd, lang=lang)
    return mutant_named(w.text)


def source_runs_mutant(src, shell: bool, depth: int, cmd=None, hops: int = 0, lang: str = "other") -> bool:
    """Whether an input source, read as a program, runs a mutant. A duplicated descriptor whose
    source is not set in this command is refused, and so is a file that is a descriptor path
    (`< /dev/fd/3`) the command does not set; `< /dev/stdin` reads the pipe."""
    if src is None:
        return False
    kind, value = src
    if kind == "unknown" or hops > 8:
        return True
    if kind == "pipe":
        return cmd is not None and piped_mutant(cmd)
    if kind == "file":
        # An input redirection from a descriptor path was resolved when it was read; one that is
        # still a path here (`3> /dev/fd/4`) cannot be judged.
        return True if fd_of_path(value) is not None else mutant_named(value)
    if kind == "procsub":
        return any(names_mutant_script(c.words) for c in value)
    if kind == "text-expanding" and lang.startswith("python"):
        # The shell expands this text first: never cleared (TXE-8183), and judged on its full
        # text, since a string literal here is not the string Python receives (TXE-8351).
        lang = "python-expanded"
    return refuses(value, depth + 1) if shell else code_runs_mutant(value, lang)


def runs_evidence(code: str, lang: str) -> bool:
    """Whether code may run a file or a process. Python code that python_reads_only() could not
    clear is also judged by PY_EXTRA_RUNS, so the Python verdict is never laxer than before. Python
    code is judged on python_code_view() when it has one: its string literals and comments are
    data (TXE-8351), and constructs that can turn a string into a call count as run evidence."""
    view = python_code_view(code) if lang in ("python", "python-strict") else None
    if view is not None:
        return bool(CODE_RUNS.search(view) or PY_EXTRA_RUNS.search(view) or PY_RESOLVES.search(view))
    if lang.startswith("python"):
        code = unicodedata.normalize("NFKC", code)  # how Python reads identifiers
        return bool(CODE_RUNS.search(code) or PY_EXTRA_RUNS.search(code))
    return bool(CODE_RUNS.search(code))


def imports_mutant(code: str, lang: str) -> bool:
    """An import statement of a mutant module, not import text inside a string or a comment.
    Python code with a python_code_view() is read from that view, which knows Python's string
    syntax (a triple-quoted string holding "from mutations import x" is data)."""
    view = python_code_view(code) if lang in ("python", "python-strict") else None
    return bool(CODE_IMPORTS_MUTANT.search(view if view is not None else CODE_STRING_OR_COMMENT.sub(" ", code)))


def mutant_in_path(text: str) -> bool:
    """For Python code that may run something: the word names a mutant in any path component
    (`mutants.json`, `mutants`, `/tmp/mutate-sandboxed-x/report.json`), whatever its extension.
    A pathname alone proves neither execution nor its absence, so where the code may execute,
    any mutant-named input counts (TXE-8183)."""
    if mutant_named(text):
        return True
    return any(mutant_named(p) for p in text.rsplit(":", 1)[-1].split("/") if p)


def code_runs_mutant(code: str, lang: str = "other") -> bool:
    """Whether code for a non-shell interpreter runs a mutant: it imports one, or it names a
    mutant script or a mutation tool and calls something that runs a file or a process. Code that
    only mentions the names (prints them, edits text that contains them) is data. Python code that
    python_reads_only() proves non-executing is data, whatever it names."""
    if lang == "python" and python_reads_only(code):
        return False
    if imports_mutant(code, lang):
        return True
    if not runs_evidence(code, lang):
        return False
    if lang.startswith("python"):
        return any(mutant_in_path(t) or TOOLS.match(base(t)) for t in CODE_TOKEN.findall(code))
    return any(mutant_named(t, need_ext=True) or TOOLS.match(base(t)) for t in CODE_TOKEN.findall(code))


# ------------------------------------------------- Python code proven not to execute (TXE-8183)
# A shared bare-word regex cannot tell `json.load(f)` (data) from `pickle.load(f)` or `exec(...)`
# (execution). Python code is therefore parsed (ast.parse only builds a tree; nothing runs) and
# cleared as data only in one supported form (Judge.python decides the form): an isolated
# interpreter (`-I`, optionally with -B/-u, and no other flag), not interactive, at the top level of
# the command or behind timeout/nice/nohup/command/env without -S, with no PYTHON* variable set.
# The code must then fit this deliberately small read/parse/print grammar, one module scope only:
# - statements: `import M[, M2]` of the modules below (no alias that shadows a builtin, a module or
#   another binding), `NAME = expr`, `with open(...) as NAME:` and expression statements;
# - expressions: constants, f-strings, tuples, lists, dicts, subscripts, comparisons and
#   arithmetic, names bound above, `module.attr` from the module's list, calls of the listed
#   builtins (open() in a literal read mode) and of the listed methods, with only the keywords
#   listed per callee;
# - nothing else: no def, lambda, class, comprehension, decorator, loop, del, global, attribute or
#   subscript assignment, rebinding of a module or builtin, *args/**kwargs, `_` name or attribute,
#   coding declaration, \r or BOM.
# Anything else, including code that does not parse, is not cleared and is judged by the run-call
# rule with the Python additions above. Trusted, not checked: the python3 found on PATH is CPython
# with an unmodified standard library, and its site-packages .pth files (which -I does not disable)
# are system state outside the command.
PY_READ_MODULES = {
    "json": {"load", "loads", "dumps"},
    # Parsing source is data: ast.parse builds a tree, and compile/exec are not in the grammar.
    "ast": {"parse", "dump", "literal_eval"},
    "sys": {"argv", "stdin", "stderr"},
}
PY_READ_BUILTINS = {"print", "len", "str", "int", "float", "bool", "repr", "list", "dict", "tuple",
                    "sorted", "min", "max", "sum", "any", "all", "open"}
PY_READ_METHODS = {"read", "get", "keys", "values", "items", "split", "strip", "splitlines",
                   "startswith", "endswith", "join", "count", "lower"}
# Keywords a cleared call may pass, per callee; none for any other call. No callable-taking keyword
# (key=, default=, object_hook=, cls=, opener=, ...).
PY_READ_KEYWORDS = {"print": {"sep", "end", "file"}, "open": {"mode", "encoding", "errors", "newline"},
                    "json.dumps": {"indent", "sort_keys", "ensure_ascii"}, "sorted": {"reverse"}}
# Every builtin name: none may be bound as a variable or used as an import alias.
BUILTIN_NAMES = set(dir(builtins))
# The flags of the supported isolated form.
PY_CLEAR_FLAGS = {"I", "B", "u"}
# Wrappers a cleared command may sit behind (env without -S: -S recurses and is not a clearance form).
PY_CLEAR_WRAPPERS = {"timeout", "gtimeout", "nice", "nohup", "command", "env"}
# Run evidence for Python code that was not cleared, on top of CODE_RUNS: dynamic access to
# builtins, executable deserialization (pickle.load is execution; json.load is not), loaders,
# interpreters and process pools.
PY_EXTRA_RUNS = re.compile(r"\b(?:getattr|setattr|__builtins__|builtins|globals|locals|vars|compile|breakpoint|"
                           r"pickle|cPickle|_pickle|marshal|shelve|dill|cloudpickle|joblib|ctypes|cffi|"
                           r"multiprocessing|pty|importlib|exec_module|load_module|run_path|run_module|"
                           r"startfile|create_subprocess_\w+|InteractiveInterpreter|InteractiveConsole|codeop|"
                           # os's process calls imported by name (`from os import execv, popen`).
                           r"exec[lv]\w*|spawn[lv]\w*|posix_spawnp?|popen\w*|"
                           # sys calls that resolve a callable by name or run a file (TXE-8351 review).
                           r"breakpointhook|remote_exec)\b"
                           r"|\bcode\s*\.\s*interact")
# A coding declaration on line 1 or 2 makes Python decode a program read as bytes (stdin, a
# here-document, a descriptor) differently from the text parsed here (utf-7 can hide code).
# Python's lines end at \r, \n or \r\n, str.splitlines() also splits at \f, \x1c-\x1e, \x85 and
# others, so "line 1 or 2" is not located here at all: a coding comment ANYWHERE, a \r, or a BOM
# keeps code from being cleared.
PY_CODING_COOKIE = re.compile(r"#.*?coding[:=]|\r|\ufeff")  # re reads \ufeff as U+FEFF (BOM)
_read_only_cache: dict = {}


def python_reads_only(code: str) -> bool:
    """Whether Python code is proven, within the supported grammar above, not to execute anything."""
    if code not in _read_only_cache:
        try:
            _read_only_cache[code] = _python_reads_only(code)
        except Exception:  # noqa: BLE001 - SyntaxError, RecursionError, ...: not cleared
            _read_only_cache[code] = False
    return _read_only_cache[code]


def _python_reads_only(code: str) -> bool:
    if PY_CODING_COOKIE.search(code):
        return False
    tree = ast.parse(code)
    if not isinstance(tree, ast.Module):
        return False
    # Bindings, in one module scope (the grammar has no def, lambda, class or comprehension).
    modules, variables = {}, set()

    def bind(name: str) -> bool:
        """A new or repeated plain variable; never a module or any builtin name (exec, open, print,
        ...), and never `_`-prefixed."""
        if name in modules or name in PY_READ_MODULES or name in BUILTIN_NAMES or name.startswith("_"):
            return False
        variables.add(name)
        return True

    for stmt in tree.body:
        if isinstance(stmt, ast.Import):
            for a in stmt.names:
                name = a.asname or a.name
                if a.name not in PY_READ_MODULES or name in BUILTIN_NAMES or name in variables \
                        or modules.get(name, a.name) != a.name or name.startswith("_"):
                    return False
                modules[name] = a.name
        elif isinstance(stmt, ast.Assign):
            if not all(isinstance(t, ast.Name) and bind(t.id) for t in stmt.targets):
                return False  # no attribute, subscript, tuple or starred target
        elif isinstance(stmt, ast.With):
            for item in stmt.items:
                ctx = item.context_expr
                if not (isinstance(ctx, ast.Call) and isinstance(ctx.func, ast.Name) and ctx.func.id == "open"):
                    return False
                if item.optional_vars is not None and not (
                        isinstance(item.optional_vars, ast.Name) and bind(item.optional_vars.id)):
                    return False
            if not all(isinstance(s, (ast.Expr, ast.Assign)) for s in stmt.body):
                return False
            for s in stmt.body:
                if isinstance(s, ast.Assign) and not all(isinstance(t, ast.Name) and bind(t.id) for t in s.targets):
                    return False
        elif not isinstance(stmt, ast.Expr):
            return False
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    allowed = (ast.Module, ast.Expr, ast.Assign, ast.With, ast.withitem, ast.Import, ast.alias, ast.Call,
               ast.keyword, ast.Name, ast.Attribute, ast.Subscript, ast.Slice, ast.Constant, ast.JoinedStr,
               ast.FormattedValue, ast.Tuple, ast.List, ast.Dict, ast.Compare, ast.BoolOp, ast.BinOp,
               ast.UnaryOp, ast.IfExp, ast.Load, ast.Store, ast.operator, ast.boolop, ast.cmpop, ast.unaryop)
    for node in ast.walk(tree):
        if not isinstance(node, allowed):
            return False  # def, lambda, comprehension, loop, del, global, starred, await, ...
        if isinstance(node, ast.Name):
            parent = parents.get(node)
            if isinstance(node.ctx, ast.Store):
                continue  # checked by bind() above
            if node.id in modules:
                if not isinstance(parent, ast.Attribute):
                    return False  # a module only as `module.attr`, never passed on
            elif node.id in PY_READ_BUILTINS:
                if not (isinstance(parent, ast.Call) and parent.func is node):
                    return False  # a builtin only called, never passed as a callback
            elif node.id not in variables:
                return False  # an unbound or unknown name
        elif isinstance(node, ast.Attribute):
            if not isinstance(node.ctx, ast.Load) or node.attr.startswith("_"):
                return False  # no attribute assignment or deletion (json.load = ...)
            parent = parents.get(node)
            if isinstance(node.value, ast.Name) and node.value.id in modules:
                if node.attr not in PY_READ_MODULES[modules[node.value.id]]:
                    return False
            elif not (isinstance(parent, ast.Call) and parent.func is node and node.attr in PY_READ_METHODS):
                return False  # any other attribute only as a listed method being called
        elif isinstance(node, (ast.Subscript, ast.Tuple, ast.List)) and not isinstance(node.ctx, ast.Load):
            return False
        elif isinstance(node, ast.Call):
            if any(isinstance(a, ast.Starred) for a in node.args):
                return False
            f = node.func
            if isinstance(f, ast.Name) and f.id in PY_READ_BUILTINS:
                callee = f.id
            elif isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in modules:
                callee = modules[f.value.id] + "." + f.attr
            elif isinstance(f, ast.Attribute) and f.attr in PY_READ_METHODS:
                callee = "." + f.attr
            else:
                return False  # a call of a call's result, a subscript, a variable, ...: not judged
            if any(k.arg is None or k.arg not in PY_READ_KEYWORDS.get(callee, ()) for k in node.keywords):
                return False
            if callee == "open" and not _open_reads_only(node):
                return False
    return True


def _open_reads_only(node) -> bool:
    """open() with no mode, or a literal mode that neither writes, appends, creates nor updates,
    and no opener."""
    if len(node.args) > 2:
        return False  # buffering, encoding, ... and the opener only by keyword, if at all
    mode = node.args[1] if len(node.args) > 1 else None
    for k in node.keywords:
        if k.arg == "mode":
            mode = k.value
    if mode is None:
        return True
    return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and not set(mode.value) & set("wax+")


# ------------------------------------------- Python string literals are data (TXE-8351)
# An editing script carries the text it writes as string literals: Markdown with `code spans`,
# TypeScript whose writes are called mutations. Searched as one text, those literals supplied both
# halves of the run-call rule (a backtick or `system` as the run call, `mutation` as the name),
# so a script that only replaced text was refused. The run call is therefore looked for in the
# code itself: python_code_view() is the source with every string literal and comment blanked out,
# positions kept (tokenize, which runs nothing, knows Python's string syntax: triple quotes,
# prefixes, f-strings). Names are still looked for in the full text, strings included, because a
# string is what names the file a real run call runs (`subprocess.run(["python3", "mutants.py"])`).
#
# The view exists only when blanking a string cannot hide how a string becomes a call; otherwise
# the code is judged on its full text, as before:
# - Python runs the text as written (not "python-expanded": shell expansion, or an interpreter flag
#   outside PY_VIEW_FLAGS, such as -x, which skips the first line, a PYTHON* variable, or code
#   nested in bash -c, eval, env -S or go -exec, whose text an outer shell expanded first), it
#   tokenizes and parses, and it
#   has no coding comment, \r or BOM (PY_CODING_COOKIE); the view is judged in NFKC form, the
#   form in which Python reads identifiers;
# - every import comes before any other statement, at module level;
# - every import is of a module in PY_TEXT_MODULES, absolute, and sys is used only as
#   `sys.<attr>` for an attribute in PY_SYS_ATTRS; no from-import of a private name or `*`;
# - in 3.11 and earlier an f-string is one STRING token, so a string with an f or t prefix is kept.
# On the view, PY_RESOLVES also counts as run evidence: a dunder, a private attribute, a frame or
# code attribute, help() (it imports a module by name) and sys.modules can each look up a callable
# by a name that only a string holds.
# Text-handling modules whose calls never turn a string into code or a process. os is one: each of
# its process calls is a name in the code, which CODE_RUNS or PY_EXTRA_RUNS sees.
PY_TEXT_MODULES = frozenset({"os", "sys", "re", "json", "pathlib", "io", "shutil", "textwrap", "difflib",
                             "glob", "fnmatch", "hashlib", "tempfile"})
# sys is a text module only through these attributes (TXE-8351 review): others resolve a callable
# from a string or the environment (breakpointhook reads PYTHONBREAKPOINT="os.system"), run a file
# (remote_exec) or reach other modules (modules, path, meta_path). The name sys may not be used any
# other way (passed on, rebound, aliased to something that is).
PY_SYS_ATTRS = frozenset({"argv", "stdin", "stdout", "stderr", "exit", "platform", "version",
                          "version_info", "maxsize", "byteorder", "getdefaultencoding",
                          "getfilesystemencoding"})
# Interpreter flags that leave the source Python runs as written and import nothing. Any other
# means the view is not built (TXE-8351 review): -x skips the first line, -W imports a warning
# category's module, and -X and -i are not modelled.
PY_VIEW_FLAGS = frozenset("BbdEIOPqRsSuv")
PY_RESOLVES = re.compile(r"\b__\w+|\.\s*_\w*|\.\s*(?:f|gi|cr|ag|tb|co)_\w+|\b(?:help|modules|_getframe)\b")
PY_BLANKED = {tokenize.COMMENT} | {getattr(tokenize, n) for n in ("FSTRING_MIDDLE", "TSTRING_MIDDLE")
                                   if hasattr(tokenize, n)}
_view_cache: dict = {}


def python_code_view(code: str):
    """Python code with its string literals and comments blanked, or None when that view is not
    sound for this code (see above)."""
    if code not in _view_cache:
        try:
            _view_cache[code] = _python_code_view(code)
        except Exception:  # noqa: BLE001 - SyntaxError, TokenError, RecursionError, ...: no view
            _view_cache[code] = None
    return _view_cache[code]


def _python_code_view(code: str):
    if PY_CODING_COOKIE.search(code):
        return None
    tree = ast.parse(code)
    # Every import runs before anything else (TXE-8351 review): an import after a statement could
    # load a module file that statement wrote (`open("json.py", "w").write(...); import json`).
    leading = 0
    while leading < len(tree.body) and (isinstance(tree.body[leading], (ast.Import, ast.ImportFrom)) or (
            leading == 0 and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant))):
        leading += 1
    if any(isinstance(n, (ast.Import, ast.ImportFrom)) for s in tree.body[leading:] for n in ast.walk(s)):
        return None
    sys_names = {"sys"}  # names bound to the sys module: `import sys`, `import sys as s`
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules = [a.name for a in node.names]
            sys_names.update(a.asname for a in node.names if a.asname and a.name.split(".")[0] == "sys")
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                return None  # a relative import names no module this list can judge
            modules = [node.module]
            if node.module == "sys" and any(a.name not in PY_SYS_ATTRS for a in node.names):
                return None
            if any(a.name.startswith("_") or a.name == "*" for a in node.names):
                return None  # a private name (`from os import _execvpe`) or `*` is not judged by name
        else:
            continue
        if any(m.split(".")[0] not in PY_TEXT_MODULES for m in modules):
            return None
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in sys_names:
            parent = parents.get(node)
            if not (isinstance(parent, ast.Attribute) and parent.value is node and parent.attr in PY_SYS_ATTRS):
                return None  # sys.breakpointhook, sys.modules, `m = sys`, f(sys), ...
        if isinstance(node, ast.Attribute) and node.attr == "sys":
            return None  # os.sys is the sys module by another path
    line_starts = [0] + [i + 1 for i, ch in enumerate(code) if ch == "\n"]
    view = list(code)
    for tok in tokenize.generate_tokens(io.StringIO(code).readline):
        if tok.type == tokenize.ERRORTOKEN:
            return None
        prefix = re.match(r"[A-Za-z]*", tok.string).group(0).lower() if tok.type == tokenize.STRING else ""
        if tok.type in PY_BLANKED or (tok.type == tokenize.STRING and not set(prefix) & set("ft")):
            a = line_starts[tok.start[0] - 1] + tok.start[1]
            b = line_starts[tok.end[0] - 1] + tok.end[1]
            if code[a:b] != tok.string:
                return None  # positions that do not match the text (an escaped {{ in an f-string)
            for k in range(a, b):
                if view[k] != "\n":
                    view[k] = " "
    # Python reads identifiers in NFKC form, so a fullwidth `ｅｘｅｃ` is exec: judge that form.
    return unicodedata.normalize("NFKC", "".join(view))


def stdin_is_mutant(cmd, shell: bool, depth: int, lang: str = "other") -> bool:
    """An interpreter with no script reads its program from stdin."""
    if cmd is None:
        return False
    # A redirection of stdin wins over the pipe: a file, a process substitution
    # (python3 < <(cat mutants.py)), a here-document or here-string, or a duplicated descriptor.
    # A redirection from a descriptor path (`< /dev/stdin`, `< /dev/fd/3`) is followed.
    if cmd.source("0") is not None:
        return source_runs_mutant(cmd.source("0"), shell, depth, cmd, lang=lang)
    return piped_mutant(cmd)


def piped_mutant(cmd) -> bool:
    return cmd.piped_from is not None and names_mutant_script(cmd.piped_from.words)


def code_and_args_run_mutant(code: str, rest: list, env=(), lang: str = "other") -> bool:
    """Code given on the command line, its arguments and the command's variable assignments: the
    code runs a mutant itself, or it calls something that runs a file or a process and an
    argument or an assigned value names a mutant (`python3 -c 'exec(open(sys.argv[1]).read())'
    mutants.py`, `M=mutants.py python3 -c '...os.environ["M"]...'`). Python code proven not to
    execute (python_reads_only) only reads its arguments, so they are data."""
    if lang == "python" and python_reads_only(code):
        return False
    if code_runs_mutant(code, lang):
        return True
    if not runs_evidence(code, lang):
        return False
    named = mutant_in_path if lang.startswith("python") else mutant_named
    return any(named(w.text) for w in rest) or any(named(v) for v in env)


class Judge:
    def __init__(self, depth: int, outer=None):
        self.depth = depth
        self.vars = {}
        # Assignments of the command this one is nested in (eval, env -S, bash -c, go -exec): read
        # as values its code may see and for PYTHON* detection, never to resolve a program, since
        # an unexported variable is empty in a child shell.
        self.outer = dict(outer or {})
        self.env_assigned = []
        self.env_assigned_names = []
        self.via = []  # wrappers and runners the current command was reached through
        self.nest = 0

    def env_values(self) -> list:
        """Values a command's code may read from its environment: shell assignments made so far
        (conservatively, exported or not), the enclosing command's, and this command's own
        `env NAME=value` assignments."""
        return list(self.vars.values()) + list(self.outer.values()) + self.env_assigned

    def context(self) -> dict:
        """Assignments a nested command inherits as values (see `outer`)."""
        ctx = {**self.outer, **self.vars}
        ctx.update(n.partition("=")[::2] for n in self.env_assigned_names)
        return ctx

    def runs_mutation(self, cmd: Cmd) -> bool:
        self.env_assigned = []  # per command; never used to resolve a program
        self.env_assigned_names = []
        self.via = []
        words = list(cmd.words)
        if words and words[0].text in DECLARERS:  # export NAME=value, declare -x NAME=value, ...
            for w in words[1:]:
                if ASSIGN.match(w.text) and w.procsub is None:
                    k, _, v = w.text.partition("=")
                    self.vars[k.rstrip("+")] = v
        for w in words:  # a simple VAR=value before the command names a program later
            if ASSIGN.match(w.text) and w.procsub is None:
                k, _, v = w.text.partition("=")
                self.vars[k.rstrip("+")] = v
            else:
                break
        return self.program(words, cmd)

    def program(self, words: list, cmd) -> bool:
        """Runners and find -exec recurse here; past MAX_DEPTH levels the command is refused, so
        a deep chain cannot exhaust the stack and fail open."""
        self.nest += 1
        try:
            return True if self.nest > MAX_DEPTH else self._program(words, cmd)
        finally:
            self.nest -= 1

    def _program(self, words: list, cmd) -> bool:
        i = 0
        while i < len(words):
            t = words[i].text
            if ASSIGN.match(t) or t in KEYWORDS:
                i += 1
                continue
            if t == "function":  # function NAME [()] { body }: the body is judged as commands
                i += 2
                continue
            if t in DATA_KEYWORDS:
                return False
            prog = base(t)
            var = VARIABLE.match(t)
            if var and (var.group(1) or var.group(2)) in self.vars:
                prog = base(self.vars[var.group(1) or var.group(2)].split(" ")[0])
            if prog in WRAPPERS:
                self.via.append(prog)
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
                # `env -- NAME=value cmd` still assigns NAME (TXE-8351 review): record them too.
                while prog == "env" and i < len(words) and ASSIGN.match(words[i].text):
                    self.env_assigned.append(words[i].text.partition("=")[2])
                    self.env_assigned_names.append(words[i].text)
                    i += 1
                break
            if prog == "command" and t in ("-v", "-V"):
                return False
            if prog == "env" and (t in ("-S", "--split-string") or t.startswith(("-S", "--split-string="))):
                # -S STRING, -SSTRING or --split-string=STRING: STRING is split into the command
                if t in ("-S", "--split-string"):
                    payload, after = (words[i + 1].text if i + 1 < len(words) else ""), i + 2
                else:
                    payload, after = t.split("=", 1)[1] if t.startswith("--") else t[2:], i + 1
                rest = " ".join(shlex.quote(w.text) for w in words[after:])
                return refuses(payload + " " + rest, self.depth + 1, self.context())
            if t.startswith("-") and len(t) > 1:
                i += 2 if t in value_opts else 1
            elif prog == "env" and ASSIGN.match(t):
                self.env_assigned.append(t.partition("=")[2])  # env NAME=value cmd: this command sees it
                self.env_assigned_names.append(t)
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
            return refuses(" ".join(a.text for a in args), self.depth + 1, self.context())
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
        if prog in SCRIPT_RUNNER_TOOLS:  # coverage run x.py, pdb x.py, py-spy record -- python3 x.py
            return names_mutant_script(args)
        if VARIABLE.match(w0.text):  # an unknown program in a variable: judge it as an interpreter
            ops = [a for a in args if not a.text.startswith("-")]
            return bool(ops) and mutant_named(ops[0].text, need_ext=True)
        return False

    def shell(self, args: list, cmd) -> bool:
        j, code, from_stdin = 0, False, False
        while j < len(args):
            t = args[j].text
            if t == "--":
                j += 1
                break
            if t in SHELL_LONG_VALUE or t.split("=")[0] in SHELL_LONG_VALUE:
                # --rcfile FILE / --rcfile=FILE: an interactive shell runs FILE first, so it is
                # judged as a script operand (process substitution and /dev/fd paths included)
                if "=" in t:
                    value = Word()
                    value.text = t.split("=", 1)[1]
                else:
                    value = args[j + 1] if j + 1 < len(args) else Word()
                if value.text or value.procsub is not None:
                    if operand_is_mutant(value, cmd, True, self.depth):
                        return True
                j += 1 if "=" in t else 2
            elif t in ("-o", "+o", "-O", "+O"):
                j += 2
            elif len(t) > 1 and t[0] in "-+":
                code = code or (not t.startswith("--") and "c" in t[1:])
                from_stdin = from_stdin or (t[0] == "-" and not t.startswith("--") and "s" in t[1:])
                j += 1
            else:
                break
        if code:
            return j < len(args) and refuses(args[j].text, self.depth + 1, self.context())
        if from_stdin:  # bash -s [args]: the program is stdin, the words are its arguments
            return stdin_is_mutant(cmd, True, self.depth)
        if j < len(args) and args[j].text not in ("-", "/dev/stdin"):
            return operand_is_mutant(args[j], cmd, True, self.depth)
        return stdin_is_mutant(cmd, True, self.depth)

    def python_names(self) -> list:
        """Variable names this command's interpreter may see: shell, enclosing and env ones."""
        return list(self.vars) + list(self.outer) + [n.partition("=")[0] for n in self.env_assigned_names]

    def view_allowed(self, flags: set) -> bool:
        """Whether this interpreter's code may be judged on python_code_view() (TXE-8351 review):
        only flags in PY_VIEW_FLAGS, no PYTHON* variable, and the top level of the command. Code
        inside bash -c, eval, env -S or go -exec was text of an outer command first, and an outer
        expansion (`bash -c "python3 -c 'print(\\"$X\\")'"`) can turn a Python string into code;
        the nested reader sees the words after quote removal, not what the outer shell expands.
        Wrappers and runners too: only PY_CLEAR_WRAPPERS exec their arguments unchanged; watch runs
        them through sh -c, xargs -I rewrites them, sudo -s starts a shell, and runners resolve."""
        return (not flags - PY_VIEW_FLAGS and self.depth == 0 and set(self.via) <= PY_CLEAR_WRAPPERS
                and not any(n.startswith("PYTHON") for n in self.python_names()))

    def python_lang(self, flags: set, unsupported: bool) -> str:
        """"python" when Python code here may be cleared by python_reads_only(), which is only in
        the supported form: isolated (-I, plus only -B/-u), at the top level of the command (not
        inside eval, env -S, bash -c or go -exec), reached directly or through PY_CLEAR_WRAPPERS
        only, with no PYTHON* variable set. Anything else is "python-strict": the Python run-call
        and path rules, never clearance (TXE-8183 review F1, F2). A flag that may change the source
        or import a module (-x, -W, ...), or a PYTHON* variable (PYTHONPATH, PYTHONWARNINGS), makes
        it "python-expanded": judged on its full text, strings included (TXE-8351 review)."""
        if not self.view_allowed(flags):
            return "python-expanded"
        if (unsupported or "I" not in flags or not flags <= PY_CLEAR_FLAGS or self.depth != 0
                or not set(self.via) <= PY_CLEAR_WRAPPERS
                or any(n.startswith("PYTHON") for n in self.python_names())):
            return "python-strict"
        return "python"

    def warnings_import_mutant(self, args: list) -> bool:
        """A warning filter's category is imported at startup (`-W ignore::mutants.Warning`,
        PYTHONWARNINGS=...): a category in a mutant-named module runs it (TXE-8351 review). Every
        -W value and every PYTHONWARNINGS the command shows is judged, isolated or not."""
        specs = [v for n, v in {**self.outer, **self.vars}.items() if n == "PYTHONWARNINGS"]
        specs += [n.partition("=")[2] for n in self.env_assigned_names if n.startswith("PYTHONWARNINGS=")]
        j = 0
        while j < len(args):
            t = args[j].text
            if t == "--" or t == "-" or not t.startswith("-"):
                break  # the options end at a script, `-` or `--`
            if t.startswith("--"):
                j += 2 if t == "--check-hash-based-pycs" else 1
                continue
            value_in_next = False
            for k in range(1, len(t)):
                if t[k] in "cm":
                    return self._category_mutant(specs)  # the rest is code or a module, and arguments
                if t[k] in "WX":
                    if t[k] == "W":
                        specs.append(t[k + 1:] or (args[j + 1].text if j + 1 < len(args) else ""))
                    value_in_next = not t[k + 1:]
                    break
            j += 2 if value_in_next else 1
        return self._category_mutant(specs)

    @staticmethod
    def _category_mutant(specs: list) -> bool:
        for spec in (s for v in specs for s in v.split(",")):
            fields = spec.split(":")
            category = fields[2].strip() if len(fields) > 2 else ""
            if category and any(mutant_named(p) for p in category.split(".")):
                return True
        return False

    def python(self, args: list, cmd) -> bool:
        if self.warnings_import_mutant(args):
            return True
        flags, unsupported = set(), False
        j = 0
        while j < len(args):
            t = args[j].text
            if t == "--":
                j += 1
                break
            if t.startswith("--"):
                unsupported = True  # a long option is not part of the supported form
                j += 2 if t == "--check-hash-based-pycs" else 1
                continue
            if not t.startswith("-") or t == "-":
                break
            for k in range(1, len(t)):
                ch = t[k]
                if ch == "c":
                    code = t[k + 1:] or (args[j + 1].text if j + 1 < len(args) else "")
                    lang = self.python_lang(flags, unsupported)
                    code_word = args[j] if t[k + 1:] else (args[j + 1] if j + 1 < len(args) else None)
                    if code_word is None or code_word.expanded:
                        lang = "python-expanded"  # "...$(cmd)..." or $'...': not the text Python gets
                    return (code_and_args_run_mutant(code, args[j + (1 if t[k + 1:] else 2):], self.env_values(), lang)
                            or self.interactive_stdin(flags, cmd))
                if ch == "m":
                    attached = bool(t[k + 1:])
                    mod = t[k + 1:] or (args[j + 1].text if j + 1 < len(args) else "")
                    if TOOLS.match(mod) or mutant_named(mod):
                        return True
                    # python3 -m runpy|pdb|cProfile|coverage ... runs a script named later.
                    rest = args[j + (1 if attached else 2):]
                    return ((mod.split(".")[0] in SCRIPT_RUNNER_MODULES and names_mutant_script(rest))
                            or self.interactive_stdin(flags, cmd))
                flags.add(ch)
                if ch in "WXQ":
                    unsupported = True
                    j += 0 if t[k + 1:] else 1
                    break
            j += 1
        if j < len(args) and args[j].text not in ("-", "/dev/stdin"):
            # A script operand (or a descriptor holding the program) is never a clearance form.
            lang = "python-strict" if self.view_allowed(flags) else "python-expanded"
            return (operand_is_mutant(args[j], cmd, False, self.depth, lang)
                    or self.interactive_stdin(flags, cmd))
        return stdin_is_mutant(cmd, False, self.depth, self.python_lang(flags, unsupported))

    def interactive_stdin(self, flags: set, cmd) -> bool:
        """-i (or PYTHONINSPECT in the command's variables) reads more program from stdin after the
        code, module or script: that stdin is judged as a program too (TXE-8183 review F1)."""
        if "i" not in flags and "PYTHONINSPECT" not in self.python_names():
            return False
        return stdin_is_mutant(cmd, False, self.depth, "python-strict" if self.view_allowed(flags) else "python-expanded")

    def other_interpreter(self, prog: str, args: list, cmd) -> bool:
        j = 0

        def code_at(n: int) -> bool:  # code at args[n], with the arguments after it
            return n < len(args) and code_and_args_run_mutant(args[n].text, args[n + 1:], self.env_values())

        if prog in ("perl", "ruby"):
            return self.perl_ruby(prog, args, cmd)
        if prog in ("deno", "bun") and args and args[0].text in ("run", "x"):
            j = 1
        elif prog == "deno" and args and args[0].text == "eval":
            return code_at(1)
        evaluated = False  # -e code runs instead of a script; preloads after it still load
        while j < len(args):
            t = args[j].text
            opt, eq, val = t.partition("=")
            if opt in PRELOAD_OPTS and t.startswith("--") and eq and mutant_named(val):
                return True  # --require=./mutants.js, bun --preload=./mutants.js
            if t in PRELOAD_OPTS and j + 1 < len(args) and mutant_named(args[j + 1].text):
                return True  # node -r ./mutants.js: a preloaded module runs
            if opt in ("--eval", "--print") and eq:
                if code_and_args_run_mutant(val, args[j + 1:], self.env_values()):
                    return True  # node --eval='...'
                evaluated = True
                j += 1
            elif t in ("-e", "--eval", "-p", "--print") or t in PRELOAD_OPTS or t in NODE_VALUE_OPTS:
                if t in ("-e", "--eval", "-p", "--print"):
                    if code_at(j + 1):
                        return True
                    evaluated = True
                j += 2
            elif t.startswith("-") and t != "-":
                j += 1
            elif evaluated:
                j += 1  # an argument of the -e code: keep looking for options after it
            else:
                break
        if evaluated:
            return False
        if j < len(args) and args[j].text not in ("-", "/dev/stdin"):
            first = args[j]
            if first.procsub is None and not SCRIPT_EXT.search(base(first.text)) and "/" not in first.text:
                # Not a script file: a subcommand that runs one (node inspect, tsx watch, deno test,
                # bun test x.ts), or the value of an option this reader does not know
                # (`node --some-flag x mutants.js`), so a later word naming a mutant script is refused.
                if names_mutant_script(args[j + 1:]):
                    return True
            return operand_is_mutant(first, cmd, False, self.depth)
        return stdin_is_mutant(cmd, False, self.depth)

    def perl_ruby(self, prog: str, args: list, cmd) -> bool:
        """Every word up to the last code payload is judged as code (-e may be given more than
        once, attached to any switch cluster, after switches this reader does not model): a word is
        refused only when it both names a mutant and calls something that runs one, so a pattern
        or a file name alone stays data. The words after the last payload are the code's
        arguments: refused when the code runs something and an argument names a mutant script.
        The switch clusters (`-lne'code'`) are then read a character at a time, only to skip switch
        values, catch a mutant preload (`-Mname`, `-r name`, `-d:name`) and find the script operand."""
        code_letters = "eE" if prog == "perl" else "e"
        last = max((n for n, a in enumerate(args) if a.text.startswith("-") and not a.text.startswith("--")
                    and any(c in a.text[1:] for c in code_letters)), default=-1)
        if last >= 0:
            end = last + (2 if args[last].text[-1] in code_letters else 1)
            payload, rest = args[:end], args[end:]
            if any(code_runs_mutant(a.text) for a in payload):
                return True
            # Where the switches end is not modelled exactly, so any word in the command counts
            # as a possible argument of code that runs something.
            if any(CODE_RUNS.search(a.text) for a in payload) and (
                    any(mutant_named(a.text) for a in args[:last] + rest) or any(mutant_named(v) for v in self.env_values())):
                return True
        elif any(code_runs_mutant(a.text) for a in args if a.text.startswith("-")):
            return True
        code_sw = PERL_CODE if prog == "perl" else RUBY_CODE
        either, attached_only = (PERL_VALUE, PERL_ATTACHED) if prog == "perl" else (RUBY_VALUE, RUBY_ATTACHED)
        code, j = False, 0
        while j < len(args):
            t = args[j].text
            if t == "--":
                j += 1
                break
            if not t.startswith("-") or t == "-":
                break
            if t.startswith("--"):
                j += 2 if prog == "ruby" and "=" not in t and t in RUBY_LONG_VALUE else 1
                continue
            k = 1
            while k < len(t):
                ch, rest = t[k], t[k + 1:]
                k += 1
                if ch in DIGIT_VALUE:  # -l, -0, -T, -W take only digits (-0x1F aside): skip them
                    if ch == "W" and rest.startswith(":"):
                        break  # ruby -W:no-deprecated
                    m = SWITCH_DIGITS.match(rest)
                    k += m.end() if m else 0
                    continue
                if prog == "ruby" and ch == "K":
                    k += 1  # -K takes exactly one character (-Ku)
                    continue
                if prog == "perl" and ch == "d":  # -d, -dt, -d:Module, -dt:Module=args
                    mod = rest[1:] if rest.startswith("t") else rest
                    if mod[:1] in (":", "="):
                        if mutant_named(mod[1:].split("=")[0].split(",")[0]):
                            return True
                        break
                    k += 1 if rest.startswith("t") else 0
                    continue
                if ch in code_sw or ch in either:
                    if not rest and j + 1 < len(args):
                        j += 1
                        rest = args[j].text
                    if ch in code_sw:
                        code = True
                        if code_runs_mutant(rest):  # attached code (`-esystem(...)`) has no word boundary above
                            return True
                    elif ch in "Mmr" and mutant_named(rest.split("=")[0]):
                        return True  # perl -Mmutants, ruby -r ./mutants.rb
                    break
                if ch in attached_only:
                    break
            j += 1
        if code:
            return False  # -e code runs instead of a script; the words after it are its arguments
        if j < len(args) and args[j].text not in ("-", "/dev/stdin"):
            return operand_is_mutant(args[j], cmd, False, self.depth)
        return stdin_is_mutant(cmd, False, self.depth)

    def go_exec_runs_mutant(self, words: list, env: list) -> bool:
        """`-exec XPROG`, `-toolexec XPROG` and `-vettool XPROG` make go run XPROG, on any go
        subcommand and also through GOFLAGS (in the environment or `go env -w GOFLAGS=...`): each
        value is judged as a command. A variable in it is resolved from this command's assignments;
        one that cannot be resolved cannot be judged and is refused."""
        tokens = list(words) + [w for v in env for w in v.split()]  # GOFLAGS is split on spaces
        for n, tok in enumerate(tokens):
            m = GO_EXEC_FLAG.search(tok)
            if not m:
                continue
            value = m.group(1) if m.group(1) is not None else (tokens[n + 1] if n + 1 < len(tokens) else "")
            if "$" in value or "`" in value:
                return True  # a variable or substitution in the program go runs cannot be judged
            if refuses(value, self.depth + 1, self.context()) or mutant_named(value.split(" ")[0]):
                return True
        return False

    def go_run(self, args: list) -> bool:
        if "GOENV" in self.vars or any(v.startswith("GOENV=") for v in self.env_assigned_names):
            return True  # another go env file may set GOFLAGS=-exec=...: it cannot be judged
        if self.go_exec_runs_mutant([a.text for a in args], self.env_values()):
            return True
        if not args or args[0].text not in ("run", "test"):
            return False
        j, ops = 1, []
        while j < len(args):
            t = args[j].text
            if t == "--":
                j += 1
                continue
            if t.startswith("-"):
                j += 2 if t in GO_VALUE_FLAGS and "=" not in t else 1
                continue
            if args[0].text == "test":
                j += 1  # go test's packages are not scripts; only -exec matters here
                continue
            if ops and not t.endswith(".go"):
                break
            ops.append(args[j])
            j += 1
        return any(operand_is_mutant(o) for o in ops)

    def runner(self, prog: str, args: list, cmd) -> bool:
        self.via.append(prog)
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
        self.via.append("find")
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


# ------------------------------------------------- A hand mutation run in one command (TXE-8351)
# The TXE-7547 incident shape: edit executable source, then run the tests over the live tree, in one
# command, outside mutate-sandboxed. No program in it is named for mutation, so the rules above see
# nothing to run. One command is refused when all three hold (coordinator ruling on PR 306):
# 1. it writes executable source (.go, .py, .sh): an output redirection or `tee` to such a file, an
#    in-place `sed -i`/`perl -i`/`ruby -i` of one, or interpreter code (an argument, a here-document
#    or a here-string) that may write a file while the command names such a file anywhere. Which
#    file the code writes is not resolved, so a source name inside written Markdown counts too: an
#    over-refusal on the safe side (TXE-8351 review);
# 2. the same command runs a test runner: go test, pytest, python -m pytest, bazel test;
# 3. its text names a mutant or a mutation (MUTANT_FILE, with mutate-sandboxed's own name removed).
# An edit of .md or .ts files, an edit with no test, and a test with no mutation word stay allowed;
# so does a test run by mutate-sandboxed, whose program is the runner, not the test.
SOURCE_EXT = re.compile(r"\.(?:go|py|sh)$")
TEST_PROGRAMS = re.compile(r"^(?:pytest(?:-3)?|py\.test)$")
# Interpreter code that may write a file: a deliberately wide net, matched anywhere in the code's
# text (fail closed; TXE-8351 review). It is one half of condition 1; the other is a source token
# anywhere in the command.
CODE_WRITES = re.compile(r"""\bopen\s*\(|\.write(?:_text|_bytes|lines)?\s*\(|\bwrite\w*\s*\("""
                         r"""|\.(?:rename|replace|symlink_to|hardlink_to|link_to|touch|truncate)\s*\("""
                         r"""|\b(?:copy\w*|move|copyfileobj|symlink|link|fileinput|inplace|FileIO|mkstemp)\b"""
                         r"""|\bwriteFile(?:Sync)?\b|\bFile\s*\.\s*write\b|\bprint\s*\{|>>?\s*['"]""")


def program_words(ws: list) -> list:
    """The words from the program on: assignments, keywords, wrappers and runners skipped (an
    approximation of Judge._program for the rule below)."""
    i = 0
    while i < len(ws):
        t, b = ws[i], base(ws[i])
        if ASSIGN.match(t) or t in KEYWORDS:
            i += 1
        elif b in WRAPPERS:
            value_opts, positionals = WRAPPERS[b]
            i += 1
            while i < len(ws) and (ws[i].startswith("-") or (b == "env" and ASSIGN.match(ws[i]))):
                i += 2 if ws[i] in value_opts else 1
            i += positionals
        elif b in RUNNERS:
            i += 1
            if RUNNERS[b] is not None:
                while i < len(ws) and ws[i] != RUNNERS[b]:
                    i += 1
                i += 1
            while i < len(ws) and ws[i].startswith("-"):
                i += 2 if ws[i] in RUNNER_VALUE_OPTS else 1
        else:
            return ws[i:]
    return []


def runs_tests(cmd: Cmd) -> bool:
    """Whether this command's program is a test runner over a tree: go test, pytest, python -m
    pytest, bazel test."""
    ws = program_words([w.text for w in cmd.words])
    if not ws:
        return False
    prog, args = base(ws[0]), ws[1:]
    if prog in ("go", "bazel", "bazelisk"):
        return "test" in [a for a in args if not a.startswith("-")][:2]
    if TEST_PROGRAMS.match(prog):
        return True
    if PYTHONS.match(prog):
        return any((a == "-m" and args[n + 1:n + 2] == ["pytest"]) or (a.startswith("-") and a.endswith("mpytest"))
                   for n, a in enumerate(args))
    return False


def writes_source(cmd: Cmd, names_source: bool) -> bool:
    """Whether this command writes executable source other than by an output redirection (those
    are in Parser.writes): tee or an in-place editor of a source file, or interpreter code that
    may write a file while the command names source anywhere (`names_source`). Which file the code
    writes is not resolved: a variable, an argument, a shell expansion or an API not modelled
    could each hide it, so the guard fails closed (TXE-8351 review)."""
    ws = program_words([w.text for w in cmd.words])
    if not ws:
        return False
    prog, args = base(ws[0]), ws[1:]
    if prog == "tee":
        return any(SOURCE_EXT.search(a) for a in args)
    in_place = any(a.startswith("--in-place") or (a.startswith("-") and not a.startswith("--") and "i" in a[1:])
                   for a in args)
    if prog in ("sed", "gsed", "perl", "ruby") and in_place and any(SOURCE_EXT.search(a) for a in args):
        return True
    if (PYTHONS.match(prog) or prog in OTHER_INTERPRETERS) and names_source:
        texts = list(args) + [src[1] for src in cmd.fds.values()
                              if isinstance(src, (list, tuple)) and src[0] in ("text", "text-expanding")]
        return any(CODE_WRITES.search(t) for t in texts)
    return False


def hand_mutation_run(command: str, cmds: list, writes: list) -> bool:
    if not MUTANT_FILE.search(command.replace("mutate-sandboxed", " ")):
        return False
    if not any(runs_tests(c) for c in cmds):
        return False
    if any(SOURCE_EXT.search(w) for w in writes):
        return True
    # A source name anywhere: in code, a here-document, an argument or a shell variable's value.
    names_source = any(SOURCE_EXT.search(tok) for tok in CODE_TOKEN.findall(command))
    return any(writes_source(c, names_source) for c in cmds)


def refuses(command: str, depth: int = 0, outer=None) -> bool:
    if depth > MAX_DEPTH:
        return True  # shell code nested this deep is not read: refused rather than let through
    judge = Judge(depth, outer)
    parser = Parser(command, depth)
    cmds = parser.parse()
    if parser.too_deep:
        return True
    return any(judge.runs_mutation(cmd) for cmd in cmds) or hand_mutation_run(command, cmds, parser.writes)


def command_of(data: dict):
    """The shell command a tool call runs, or None. Claude's Bash and Codex's shell tools carry
    it as tool_input.command or tool_input.cmd, as a string or an argv list (quoted back into one
    command line, so `["bash", "-lc", "python3 x.py"]` keeps its code string whole). A call whose
    harness-supplied tool_name is exactly a file-edit tool carries file content, not a command."""
    tool_name = data.get("tool_name")
    if isinstance(tool_name, str) and tool_name in FILE_EDIT_TOOLS:
        return None
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
    if command is None:
        return 0
    try:
        refused = refuses(command)
    except Exception as e:  # noqa: BLE001 - fail closed: a command the guard cannot judge is refused
        print(f"Refused: the mutant-run guard (TXE-7549) could not read this command ({type(e).__name__}). "
              "Ask your coordinator; do not rephrase or rename anything to get past this check.", file=sys.stderr)
        return 2
    if refused:
        print(REASON, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
