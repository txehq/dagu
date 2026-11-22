#!/usr/bin/env python3
"""PreToolUse hook (TXE-7549, TXE-7641): a mutation run outside mutate-sandboxed is refused.

A mutant breaks a guard on purpose, so it may only run where it cannot reach host state: through
txe/mutate/mutate-sandboxed.py, which runs each mutant in a container with no mount of the shared
caches, HOME or the Docker socket (postmortem TXE-7547). This hook is what makes forgetting that
loud: a shell command that runs a mutation script or a mutation tool any other way is denied.

It reads the hook input (Claude Code and Codex share the shape) on stdin, and for a refused
command exits 2 with the reason on stderr, which both harnesses feed back to the agent. It prints
nothing and exits 0 for anything else, including hook input that is not JSON or carries no shell
command. A command it cannot judge fails closed: nesting deeper than MAX_DEPTH levels, or an
internal error, is refused.

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
  child_process, ...). Python code is also parsed (TXE-8183): code proven, within a small
  supported grammar, to only read and print data (json.load, open in a read mode, print, ...)
  is data whatever its arguments name; any other Python code that may run something is refused
  when any input it is given names a mutant in any path component, whatever the extension
  (`exec(open("mutants.json").read())`, a file under a mutate-sandboxed work directory).
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


class Cmd:
    """A simple command: its words, what each of its descriptors is redirected to, and the
    command piped into it."""

    def __init__(self):
        self.words: list[Word] = []
        # Descriptor ("0" is stdin, "3", "{name}") -> ("file", path) | ("procsub", cmds) |
        # ("text", here-string) | ["text", here-document body] (a list, filled in when the body
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


class Parser:
    """A small reader of POSIX/bash command syntax. It never fails: unterminated quotes run to the
    end, and constructs it does not know are read as words."""

    def __init__(self, src: str, depth: int = 0):
        self.s, self.i, self.depth = src, 0, depth
        self.cmds = []  # every simple command found, nested ones included
        self.heredocs = []  # (cmd, delimiter, strip_tabs, quoted) waiting for the next newline
        self.too_deep = False  # nesting past MAX_DEPTH was not read: the caller refuses
        self.braces = []  # where each open `{ ...` group starts in self.cmds

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
        if op in ("<<", "<<-"):
            raw = self.s[start:self.i]
            pending = ["text", ""]  # its body is read at the next newline
            cur.set_source(key, pending)
            self.heredocs.append((pending, target.text, op == "<<-", any(q in raw for q in "'\"\\")))
        elif op == "<<<":
            cur.set_source(key, ("text", target.text))
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
    return refuses(value, depth + 1) if shell else code_runs_mutant(value, lang)


def runs_evidence(code: str, lang: str) -> bool:
    """Whether code may run a file or a process. Python code that python_reads_only() could not
    clear is also judged by PY_EXTRA_RUNS, so the Python verdict is never laxer than before."""
    return bool(CODE_RUNS.search(code) or (lang == "python" and PY_EXTRA_RUNS.search(code)))


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
    if CODE_IMPORTS_MUTANT.search(CODE_STRING_OR_COMMENT.sub(" ", code)):
        return True  # an import statement, not import text inside a string or a comment
    if not runs_evidence(code, lang):
        return False
    if lang == "python":
        return any(mutant_in_path(t) or TOOLS.match(base(t)) for t in CODE_TOKEN.findall(code))
    return any(mutant_named(t, need_ext=True) or TOOLS.match(base(t)) for t in CODE_TOKEN.findall(code))


# ------------------------------------------------- Python code proven not to execute (TXE-8183)
# A shared bare-word regex cannot tell `json.load(f)` (data) from `pickle.load(f)` or `exec(...)`
# (execution). Python code is therefore parsed (ast.parse only builds a tree; nothing runs) and
# cleared as data only when every construct is in this small supported grammar: imports only of the
# modules below, attributes of a module only from its list, any other attribute only as a listed
# method being called, calls only to the listed builtins (open() in a read mode only), the listed
# methods and functions the code defines itself, no *args or **kwargs, no coding declaration, no
# name or attribute starting with "_", no class, async or dangerous builtin name anywhere. Anything
# else, including code that does not parse, is not cleared and is judged as before, with the
# additions above: an unsupported or ambiguous path is refused when it names a mutant.
PY_READ_MODULES = {
    "json": {"load", "loads", "dumps", "JSONDecodeError"},
    # Parsing source is data: ast.parse builds a tree, and compile/exec stay unsafe names.
    "ast": {"parse", "dump", "walk", "literal_eval", "get_docstring", "unparse"},
    "sys": {"argv", "stdin", "stdout", "stderr", "exit"},
    "re": {"search", "match", "fullmatch", "findall", "finditer", "sub", "subn", "split", "compile",
           "escape", "I", "M", "S", "IGNORECASE", "MULTILINE", "DOTALL"},
    "hashlib": {"sha256", "sha1", "sha512", "md5"},
    "pprint": {"pprint", "pformat"},
    "collections": {"Counter", "OrderedDict", "defaultdict"},
    "csv": {"reader", "DictReader"},
    "base64": {"b64decode", "b64encode"},
}
PY_READ_BUILTINS = {"print", "len", "sorted", "reversed", "list", "dict", "set", "frozenset", "tuple", "str",
                    "int", "float", "bool", "bytes", "repr", "min", "max", "sum", "any", "all", "enumerate",
                    "zip", "range", "map", "filter", "isinstance", "abs", "round", "format", "hex", "ord",
                    "chr", "next", "iter", "open"}
PY_READ_METHODS = {"read", "readline", "readlines", "close", "get", "keys", "values", "items", "split",
                   "rsplit", "splitlines", "partition", "rpartition", "strip", "lstrip", "rstrip",
                   "startswith", "endswith", "join", "count", "index", "find", "rfind", "lower", "upper",
                   "title", "replace", "format", "encode", "decode", "zfill", "ljust", "rjust", "center",
                   "isdigit", "isalpha", "isspace", "hexdigest", "digest", "update", "append", "extend",
                   "sort", "copy", "pop", "setdefault", "most_common", "group", "groups", "groupdict",
                   "search", "match", "fullmatch", "findall", "finditer", "sub"}
# No write or flush: a cleared program has no writable file (open() is read-only), and output goes
# through print().
# Names that reach execution or the interpreter's internals: never cleared, wherever they appear.
PY_UNSAFE_NAMES = {"exec", "eval", "compile", "getattr", "setattr", "delattr", "globals", "locals", "vars",
                   "breakpoint", "input", "help", "memoryview", "type", "object", "super", "classmethod",
                   "staticmethod", "property", "builtins", "exit", "quit"}
# Run evidence for Python code that was not cleared, on top of CODE_RUNS: dynamic access to
# builtins, executable deserialization (pickle.load is execution; json.load is not), loaders,
# interpreters and process pools.
PY_EXTRA_RUNS = re.compile(r"\b(?:getattr|setattr|__builtins__|builtins|globals|locals|vars|compile|breakpoint|"
                           r"pickle|cPickle|_pickle|marshal|shelve|dill|cloudpickle|joblib|ctypes|cffi|"
                           r"multiprocessing|pty|importlib|exec_module|load_module|run_path|run_module|"
                           r"startfile|create_subprocess_\w+|InteractiveInterpreter|InteractiveConsole|codeop)\b"
                           r"|\bcode\s*\.\s*interact")
# A coding declaration on line 1 or 2 makes Python decode a program read as bytes (stdin, a
# here-document, a descriptor) differently from the text parsed here (utf-7 can hide code).
# Python's lines end at \r, \n or \r\n, str.splitlines() also splits at \f, \x1c-\x1e, \x85 and
# others, so "line 1 or 2" is not located here at all: a coding comment ANYWHERE, a \r, or a BOM
# keeps code from being cleared.
PY_CODING_COOKIE = re.compile(r"#.*?coding[:=]|\r|﻿")
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
    modules, functions, parents = {}, set(), {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
        if isinstance(node, (ast.ClassDef, ast.AsyncFunctionDef, ast.Await, ast.AsyncFor, ast.AsyncWith)):
            return False
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name not in PY_READ_MODULES:
                    return False
                modules[a.asname or a.name] = a.name
        elif isinstance(node, ast.ImportFrom):
            if node.level or node.module not in PY_READ_MODULES:
                return False
            for a in node.names:
                if a.name not in PY_READ_MODULES[node.module]:
                    return False  # also refuses `from json import *`
                functions.add(a.asname or a.name)
        elif isinstance(node, ast.FunctionDef):
            functions.add(node.name)
        elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Lambda):
            functions.update(t.id for t in node.targets if isinstance(t, ast.Name))
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            if node.id in PY_UNSAFE_NAMES or node.id.startswith("_"):
                return False
            # A module may only be used as `module.attribute`, never passed on or rebound.
            if node.id in modules and not isinstance(parents.get(node), ast.Attribute):
                return False
            # open only as the function of a call, where its mode is checked (never map(open, ...)).
            parent = parents.get(node)
            if node.id == "open" and not (isinstance(parent, ast.Call) and parent.func is node):
                return False
        elif isinstance(node, ast.Attribute):
            if node.attr.startswith("_"):
                return False
            if isinstance(node.value, ast.Name) and node.value.id in modules:
                if node.attr not in PY_READ_MODULES[modules[node.value.id]]:
                    return False
            else:
                # Any other attribute only as a listed method being called: never a bare value
                # (gi_frame, f_globals, co_code, d.get passed to map, ...).
                parent = parents.get(node)
                if not (isinstance(parent, ast.Call) and parent.func is node and node.attr in PY_READ_METHODS):
                    return False
        elif isinstance(node, ast.Call):
            # *args and **kwargs hide which argument is which (open(*["f", "w"])): not judged.
            if any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords):
                return False
            f = node.func
            if isinstance(f, ast.Name):
                if f.id not in PY_READ_BUILTINS and f.id not in functions:
                    return False
                if f.id == "open" and not _open_reads_only(node):
                    return False
            elif isinstance(f, ast.Attribute):
                on_module = isinstance(f.value, ast.Name) and f.value.id in modules
                if not on_module and f.attr not in PY_READ_METHODS:
                    return False
            else:
                return False  # a call of a call's result, a subscript, ...: not judged
    return True


def _open_reads_only(node) -> bool:
    """open() with no mode, or a literal mode that neither writes, appends, creates nor updates,
    and no opener."""
    mode = node.args[1] if len(node.args) > 1 else None
    for k in node.keywords:
        if k.arg == "mode":
            mode = k.value
        elif k.arg is None or k.arg == "opener":
            return False
    if len(node.args) > 7:
        return False  # the opener given by position
    if mode is None:
        return True
    return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and not set(mode.value) & set("wax+")


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
    named = mutant_in_path if lang == "python" else mutant_named
    return any(named(w.text) for w in rest) or any(named(v) for v in env)


class Judge:
    def __init__(self, depth: int):
        self.depth = depth
        self.vars = {}
        self.env_assigned = []
        self.env_assigned_names = []
        self.nest = 0

    def env_values(self) -> list:
        """Values a command's code may read from its environment: shell assignments made so far
        (conservatively, exported or not) and this command's own `env NAME=value` assignments."""
        return list(self.vars.values()) + self.env_assigned

    def runs_mutation(self, cmd: Cmd) -> bool:
        self.env_assigned = []  # per command; never used to resolve a program
        self.env_assigned_names = []
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
            if prog == "env" and (t in ("-S", "--split-string") or t.startswith(("-S", "--split-string="))):
                # -S STRING, -SSTRING or --split-string=STRING: STRING is split into the command
                if t in ("-S", "--split-string"):
                    payload, after = (words[i + 1].text if i + 1 < len(words) else ""), i + 2
                else:
                    payload, after = t.split("=", 1)[1] if t.startswith("--") else t[2:], i + 1
                rest = " ".join(shlex.quote(w.text) for w in words[after:])
                return refuses(payload + " " + rest, self.depth + 1)
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
            return j < len(args) and refuses(args[j].text, self.depth + 1)
        if from_stdin:  # bash -s [args]: the program is stdin, the words are its arguments
            return stdin_is_mutant(cmd, True, self.depth)
        if j < len(args) and args[j].text not in ("-", "/dev/stdin"):
            return operand_is_mutant(args[j], cmd, True, self.depth)
        return stdin_is_mutant(cmd, True, self.depth)

    def python_lang(self) -> str:
        """"python" when Python code here may be cleared by python_reads_only(); "other" (the
        language-neutral rule) when the command sets any PYTHON* variable (PYTHONPATH,
        PYTHONSTARTUP, PYTHONHOME, ...), which can change what `import json` loads."""
        names = list(self.vars) + [n.partition("=")[0] for n in self.env_assigned_names]
        return "other" if any(n.startswith("PYTHON") for n in names) else "python"

    def python(self, args: list, cmd) -> bool:
        lang = self.python_lang()
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
                    return code_and_args_run_mutant(code, args[j + (1 if t[k + 1:] else 2):], self.env_values(), lang)
                if ch == "m":
                    attached = bool(t[k + 1:])
                    mod = t[k + 1:] or (args[j + 1].text if j + 1 < len(args) else "")
                    if TOOLS.match(mod) or mutant_named(mod):
                        return True
                    # python3 -m runpy|pdb|cProfile|coverage ... runs a script named later.
                    rest = args[j + (1 if attached else 2):]
                    return mod.split(".")[0] in SCRIPT_RUNNER_MODULES and names_mutant_script(rest)
                if ch in "WXQ":
                    j += 0 if t[k + 1:] else 1
                    break
            j += 1
        if j < len(args) and args[j].text not in ("-", "/dev/stdin"):
            return operand_is_mutant(args[j], cmd, False, self.depth, lang)
        return stdin_is_mutant(cmd, False, self.depth, lang)

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
            if refuses(value, self.depth + 1) or mutant_named(value.split(" ")[0]):
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
        return True  # shell code nested this deep is not read: refused rather than let through
    judge = Judge(depth)
    parser = Parser(command, depth)
    cmds = parser.parse()
    if parser.too_deep:
        return True
    return any(judge.runs_mutation(cmd) for cmd in cmds)


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
