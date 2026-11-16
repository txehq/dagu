#!/usr/bin/env python3
"""PreToolUse hook (TXE-7549): a mutation run outside mutate-sandboxed is refused.

A mutant breaks a guard on purpose, so it may only run where it cannot reach host state: through
txe/mutate/mutate-sandboxed.py, which runs each mutant in a container with no mount of the shared
caches, HOME or the Docker socket (postmortem TXE-7547). This hook is what makes forgetting that
loud: a shell command that runs a mutation script or a mutation tool any other way is denied.

It reads the hook input (Claude Code and Codex share the shape) on stdin, and for a refused
command exits 2 with the reason on stderr, which both harnesses feed back to the agent. It prints
nothing and exits 0 for anything else, including input it cannot parse: it only ever adds a
refusal.

What counts as a mutation run, per shell segment (split on ; & | and newlines, quoting removed):
- the program is a mutation tool (mutmut, go-mutesting, gremlins, cosmic-ray, mull-runner, ...)
  or a file whose name says mutant/mutation (mutants.py, mutants-7538.py, run-mutations.sh), or
- the program is an interpreter or `go run` (python, bash, sh, node, uv run, ...) and the segment
  names such a file anywhere (`python3 -I <(git show x:mutants.py)` included), or runs one as a
  module (`python3 -m mutmut`).
A segment whose program is mutate-sandboxed itself is allowed, whatever it names.

It does not parse shell, and a determined agent can rename a script. It is defence in depth that
catches the habit that caused the incident; the AGENTS.md rule is the policy.
"""
import json
import os
import re
import sys

TOOLS = re.compile(r"^(?:mutmut|go-mutesting|gremlins|cosmic-ray|mull-runner|mull-cxx|stryker|"
                   r"mutatest|mutpy|pitest|ooze)$", re.I)
# A file named for mutation testing: mutant(s), mutation(s), mutate(s), mutmut, as a word in the name.
MUTANT_FILE = re.compile(r"(?:^|[^A-Za-z0-9])(?:mutants?|mutations?|mutates?|mutmut)(?:[^A-Za-z0-9]|$)", re.I)
SCRIPT_EXT = re.compile(r"\.(?:py|sh|bash|zsh|go|js|mjs|ts|rb|pl)$", re.I)
INTERPRETERS = re.compile(r"^(?:python[0-9.]*|pypy[0-9.]*|bash|sh|zsh|dash|ksh|node|deno|bun|ruby|perl|"
                          r"uv|uvx|poetry|pipenv|pdm|hatch|go|tsx|ts-node)$")
WRAPPERS = {"env", "time", "nohup", "nice", "timeout", "gtimeout", "caffeinate", "command", "exec",
            "sudo", "doas", "xargs", "stdbuf", "setsid", "ionice", "chrt"}
ALLOWED = re.compile(r"^mutate-sandboxed(?:\.py)?$")
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

REASON = ("Refused: this runs a mutation test outside the sandboxed runner. A mutant breaks a guard on "
          "purpose and must not run against this host's shared caches, HOME or worktree (TXE-7547). "
          "Run it through mutate-sandboxed: `mutate-sandboxed --mutants <list.json> --tree <dir> "
          "--image sha256:<local image id> -- <test cmd>` (~/.coding_global/bin/mutate-sandboxed runs the "
          "reviewed txehq/dagu txe/mutate/mutate-sandboxed.py its launcher pins by commit and sha256). "
          "If this is not a mutation run, do not rename anything to get past this check: ask your "
          "coordinator, since this hook is a heuristic over command text.")


def flatten(command: str) -> str:
    s = command.replace("\\\n", " ")
    s = re.sub(r"""['"]""", "", s)
    return re.sub(r"\\(.)", r"\1", s)


def segments(command: str) -> list[list[str]]:
    """Words of each pipeline element. A substitution is read both inside the segment that uses it
    and on its own, so `echo $(python3 mutants.py)` is seen as running python3."""
    out = []
    for part in re.split(r"[;&|\n]+", flatten(command)):
        for piece in [part, *re.split(r"\$\(|<\(|>\(|`", part)[1:]]:
            if piece.strip():
                out.append(piece.replace(")", " ").split() if piece is not part else piece.split())
    return out


def normalize(word: str) -> str:
    """The file a word names: substitution brackets and a `rev:` prefix removed, then the basename."""
    w = re.sub(r"^(?:[<>$]?\(|`)+|[)`]+$", "", word)
    return os.path.basename(w.rsplit(":", 1)[-1].rstrip("/"))


def program(words: list[str]) -> tuple[str, list[str]]:
    """The program a segment runs, past assignments and wrapper commands, and its arguments."""
    i = 0
    while i < len(words):
        w = words[i]
        base = normalize(w)
        if ASSIGN.match(w) or w in ("(", "{", "!", "then", "do", "else", "if", "while", "until", "time"):
            i += 1
        elif base in WRAPPERS:
            i += 1
            while i < len(words) and (words[i].startswith("-") or ASSIGN.match(words[i])
                                      or (base in ("timeout", "gtimeout", "nice") and re.match(r"^\d", words[i]))):
                i += 1
        else:
            return base, words[i + 1:]
    return "", []


def is_mutant_script(name: str) -> bool:
    return bool(MUTANT_FILE.search(name)) and bool(SCRIPT_EXT.search(name)) and not ALLOWED.match(name)


def refuses(command: str) -> bool:
    for words in segments(command):
        prog, args = program(words)
        if not prog or ALLOWED.match(prog):
            continue
        if TOOLS.match(prog) or MUTANT_FILE.search(prog):
            return True
        if not INTERPRETERS.match(prog) or (prog == "go" and args[:1] != ["run"]):
            continue
        names = [normalize(a) for a in args]
        for n in names:
            if ALLOWED.match(n):
                break  # the interpreter runs mutate-sandboxed; what follows is its own arguments
            if is_mutant_script(n) or TOOLS.match(n):
                return True
    return False


def command_of(data: dict):
    """The shell command a tool call runs, or None. Claude's Bash and Codex's shell tools carry
    it as tool_input.command or tool_input.cmd, as a string or an argv list."""
    tool_input = data.get("tool_input")
    if not isinstance(tool_input, dict):
        return None
    for key in ("command", "cmd"):
        value = tool_input.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, list) and value:
            return " ".join(map(str, value))
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
