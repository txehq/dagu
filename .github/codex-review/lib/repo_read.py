#!/usr/bin/env python3
"""A read-only view of the review's checkouts for Codex, as an MCP server on stdio (txe TXE-3469; ported for TXE-4205).

    repo_read.py serve --tree head=DIR [--tree base=DIR ...]   # what codex-run.sh configures
    repo_read.py call  --tree head=DIR ... TOOL JSON-ARGS       # one call, for tests and probes

The review turn can run no command (plan.md D-12), so this gives it the repository to read
instead (D-15). By construction: nothing is executed or written (search is a literal scan of
bytes, no subprocess, no regex); every path is resolved with realpath() and refused outside its
tree (`..`, absolute paths, symlinks out, `.git`, non-regular files); the server refuses to serve
with a credential in its environment and reads no environment; every answer is bounded (MAX_*).
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import stat
import sys

sys.dont_write_bytecode = True

# codex-cli 0.157.1 starts an MCP server with HOME, PATH and the locale only (measured), so none
# of these should be here; if one is, serve refuses and `required = true` fails the pass.
CREDENTIAL = re.compile(r"^(TOKUN_.*|GITHUB_TOKEN|GH_TOKEN|GITHUB_PAT|ACTIONS_.*|.*_API_KEY|.*_TOKEN|.*SECRET.*)$")
_CREDENTIALS_SEEN = sorted(n for n in os.environ if CREDENTIAL.match(n))
# Then drop everything but what a pure-Python reader needs; nothing below reads the environment.
for _name in list(os.environ):
    if _name not in ("PATH", "LANG", "LC_ALL"):
        del os.environ[_name]

PROTOCOL = "2025-06-18"
MAX_FILE = 4_000_000        # a file larger than this is not read at all
MAX_LINES = 2_000           # lines per read_file answer
MAX_ANSWER = 120_000        # characters per answer, any tool
MAX_ENTRIES = 1_000         # entries per list_dir / find_files answer
MAX_MATCHES = 300           # matching lines per search answer
MAX_SCANNED = 60_000_000    # bytes one search may read before it stops and says so
MAX_PATTERN = 400
MAX_WALK = 200_000       # directory entries one find_files / search call may visit


class Refused(Exception):
    """The call cannot be answered. The message says why; it is returned to Codex."""


class Trees:
    def __init__(self, specs: list):
        self.roots: dict = {}
        for spec in specs:
            name, sep, path = spec.partition("=")
            if not sep or not name or name in self.roots:
                raise SystemExit(f"repo_read: --tree must be NAME=DIR, each name once: {spec!r}")
            root = os.path.realpath(path)
            if not os.path.isdir(root):
                raise SystemExit(f"repo_read: tree {name} is not a directory")
            self.roots[name] = root
        if "head" not in self.roots:
            raise SystemExit("repo_read: a head tree is required")

    def resolve(self, tree: object, path: object) -> tuple:
        """(root, absolute path, path relative to the root) inside the tree, or Refused."""
        tree = "head" if tree in (None, "") else tree
        if not isinstance(tree, str) or tree not in self.roots:
            raise Refused(f"tree must be one of {sorted(self.roots)}")
        if path is None:
            path = ""
        if not isinstance(path, str) or "\0" in path or len(path) > 4096:
            raise Refused("path must be a string without NUL")
        if os.path.isabs(path):
            raise Refused("path must be relative to the repository root")
        root = self.roots[tree]
        full = os.path.realpath(os.path.join(root, path))
        if full != root and not full.startswith(root + os.sep):
            raise Refused(f"{path!r} is outside the {tree} tree")
        rel = os.path.relpath(full, root)
        rel = "" if rel == "." else rel
        if rel == ".git" or rel.startswith(".git" + os.sep):
            raise Refused(".git is not readable")
        return root, full, rel


def _regular(full: str) -> os.stat_result:
    st = os.stat(full)
    if not stat.S_ISREG(st.st_mode):
        raise Refused("not a regular file")
    if st.st_size > MAX_FILE:
        raise Refused(f"file is {st.st_size} bytes, over the {MAX_FILE}-byte read limit")
    return st


def _read_bytes(full: str) -> bytes:
    _regular(full)
    fd = os.open(full, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Refused("not a regular file")
        chunks, size = [], 0
        while True:
            b = os.read(fd, 1 << 20)
            if not b:
                break
            size += len(b)
            if size > MAX_FILE:
                raise Refused("file grew past the read limit")
            chunks.append(b)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _cap(text: str) -> str:
    if len(text) <= MAX_ANSWER:
        return text
    return text[:MAX_ANSWER] + f"\n[answer cut at {MAX_ANSWER} characters; ask for a narrower range]"


def _int(v: object, name: str, default: int) -> int:
    if v is None:
        return default
    if isinstance(v, bool) or not isinstance(v, int):
        raise Refused(f"{name} must be an integer")
    return v


def read_file(t: Trees, a: dict) -> str:
    _, full, rel = t.resolve(a.get("tree"), a.get("path"))
    data = _read_bytes(full)
    if b"\0" in data[:8192]:
        return f"{rel}: binary file, {len(data)} bytes; not shown"
    lines = data.decode("utf-8", "replace").splitlines()
    start = max(1, _int(a.get("start_line"), "start_line", 1))
    end = _int(a.get("end_line"), "end_line", start + MAX_LINES - 1)
    end = min(end, len(lines), start + MAX_LINES - 1)
    head = f"{a.get('tree') or 'head'}:{rel} lines {start}-{end} of {len(lines)}\n"
    body = "".join(f"{n:>6} | {lines[n - 1]}\n" for n in range(start, end + 1))
    more = "" if end >= len(lines) else f"[more: start_line={end + 1}]\n"
    return _cap(head + body + more)


class Walk:
    """Files below top, relative to root, lazily, never following a symlink and never entering .git.
    It stops after MAX_WALK entries and says so (`cut`), so a vast or deep tree cannot hold a call
    open, and an answer built from a cut walk says it is incomplete."""

    def __init__(self, root: str, top: str):
        self.root, self.top, self.cut = root, top, False

    def __iter__(self):
        seen = 0
        for d, dirs, files in os.walk(self.top, followlinks=False):
            dirs[:] = sorted(x for x in dirs if not (d == self.root and x == ".git"))
            seen += len(dirs)
            if seen > MAX_WALK:
                self.cut = True
                return
            for f in sorted(files):
                seen += 1
                if seen > MAX_WALK:
                    self.cut = True
                    return
                yield os.path.relpath(os.path.join(d, f), self.root)


def list_dir(t: Trees, a: dict) -> str:
    root, full, rel = t.resolve(a.get("tree"), a.get("path"))
    if not os.path.isdir(full):
        raise Refused("not a directory")
    out = []
    for name in sorted(os.listdir(full)):
        if full == root and name == ".git":
            continue
        p = os.path.join(full, name)
        kind = "link" if os.path.islink(p) else "dir" if os.path.isdir(p) else "file"
        out.append(f"{name}/" if kind == "dir" else f"{name} -> (symlink)" if kind == "link" else name)
        if len(out) >= MAX_ENTRIES:
            out.append(f"[listing cut at {MAX_ENTRIES} entries]")
            break
    return _cap(f"{a.get('tree') or 'head'}:{rel or '.'}/\n" + "\n".join(out) + "\n")


def find_files(t: Trees, a: dict) -> str:
    root, full, _ = t.resolve(a.get("tree"), a.get("path"))
    glob = a.get("glob")
    if not isinstance(glob, str) or not glob or len(glob) > MAX_PATTERN:
        raise Refused("glob must be a non-empty string, e.g. *_test.go or ops/review/*.py")
    if not os.path.isdir(full):
        raise Refused("path must be a directory")
    out, walk = [], Walk(root, full)
    for rel in walk:
        if fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(os.path.basename(rel), glob):
            out.append(rel)
            if len(out) >= MAX_ENTRIES:
                out.append(f"[INCOMPLETE: cut at {MAX_ENTRIES} paths]")
                break
    if walk.cut:
        out.append(f"[INCOMPLETE: the walk stopped after {MAX_WALK} entries; search a narrower path]")
    return _cap("\n".join(out) + "\n" if out else "no file matches\n")


def search(t: Trees, a: dict) -> str:
    """Lines containing a literal string, in files below a path (optionally filtered by glob)."""
    root, full, _ = t.resolve(a.get("tree"), a.get("path"))
    pat = a.get("text")
    if not isinstance(pat, str) or not pat or len(pat) > MAX_PATTERN or "\n" in pat:
        raise Refused(f"text must be a one-line literal string of at most {MAX_PATTERN} characters")
    glob = a.get("glob")
    if glob is not None and (not isinstance(glob, str) or len(glob) > MAX_PATTERN):
        raise Refused("glob must be a string")
    fold = a.get("ignore_case") is True
    needle = pat.lower() if fold else pat
    single = os.path.isfile(full)
    walk = Walk(root, full)
    files = [os.path.relpath(full, root)] if single else walk
    out, scanned, skipped, note = [], 0, 0, ""
    for rel in files:
        if glob and not (fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(os.path.basename(rel), glob)):
            continue
        p = os.path.join(root, rel)
        if os.path.islink(p):
            continue
        try:
            data = _read_bytes(p)
        except (Refused, OSError):
            skipped += 1  # not a regular file, too large, or unreadable: counted, never hidden
            continue
        if b"\0" in data[:8192]:
            continue
        scanned += len(data)
        for n, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            if needle in (line.lower() if fold else line):
                out.append(f"{rel}:{n}: {line[:400]}")
                if len(out) >= MAX_MATCHES:
                    break
        if len(out) >= MAX_MATCHES:
            note = f"[INCOMPLETE: cut at {MAX_MATCHES} matching lines]"
            break
        if scanned > MAX_SCANNED:
            note = f"[INCOMPLETE: stopped after reading {MAX_SCANNED} bytes; search a narrower path]"
            break
    notes = [note] if note else []
    if walk.cut:
        notes.append(f"[INCOMPLETE: the walk stopped after {MAX_WALK} entries; search a narrower path]")
    if skipped:
        notes.append(f"[{skipped} file(s) not searched: not regular, over {MAX_FILE} bytes, or unreadable]")
    body = "\n".join(out) + "\n" if out else "no line matches\n"
    return _cap(body + "".join(n + "\n" for n in notes))


TREE_PROP = {"type": "string", "description": "head (the PR head, default) or base (the merge base)"}
TOOLS = [
    ("read_file", read_file, "Read a file of the repository at the PR head (tree=head) or at the merge base "
     "(tree=base), with line numbers. At most 2000 lines per call; use start_line/end_line for more.",
     {"path": {"type": "string"}, "tree": TREE_PROP,
      "start_line": {"type": "integer"}, "end_line": {"type": "integer"}}, ["path"]),
    ("list_dir", list_dir, "List a directory of the repository (\"\" or omitted = the root).",
     {"path": {"type": "string"}, "tree": TREE_PROP}, []),
    ("find_files", find_files, "Find files whose path or name matches a shell glob (e.g. *_test.go), "
     "below path (default the root).",
     {"glob": {"type": "string"}, "path": {"type": "string"}, "tree": TREE_PROP}, ["glob"]),
    ("search", search, "Find lines containing a literal string (not a regular expression) in files below "
     "path (default the root), optionally only files matching glob. Use it to find callers, tests and "
     "other uses of what the diff changes.",
     {"text": {"type": "string"}, "path": {"type": "string"}, "glob": {"type": "string"},
      "ignore_case": {"type": "boolean"}, "tree": TREE_PROP}, ["text"]),
]
BY_NAME = {name: fn for name, fn, *_ in TOOLS}


def call(t: Trees, name: str, args: object) -> tuple:
    """(text, is_error)."""
    fn = BY_NAME.get(name)
    if fn is None:
        return f"unknown tool {name!r}", True
    if not isinstance(args, dict):
        return "arguments must be an object", True
    try:
        return fn(t, args), False
    except Refused as why:
        return f"refused: {why}", True
    except OSError as why:
        return f"refused: {why.strerror or 'cannot read'}", True


def serve(t: Trees) -> int:
    out = sys.stdout
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if not isinstance(msg, dict) or "id" not in msg:
            continue  # a notification (initialized, cancelled): nothing to answer
        mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
        if method == "initialize":
            result = {"protocolVersion": params.get("protocolVersion") or PROTOCOL,
                      "capabilities": {"tools": {"listChanged": False}},
                      "serverInfo": {"name": "repo_read", "version": "1"}}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": [{"name": n, "description": d,
                                 "inputSchema": {"type": "object", "properties": p, "required": r,
                                                 "additionalProperties": False},
                                 "annotations": {"readOnlyHint": True, "openWorldHint": False}}
                                for n, _, d, p, r in TOOLS]}
        elif method == "tools/call":
            text, err = call(t, params.get("name"), params.get("arguments") or {})
            result = {"content": [{"type": "text", "text": text}], "isError": err}
        else:
            reply = {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}
            out.write(json.dumps(reply) + "\n")
            out.flush()
            continue
        out.write(json.dumps({"jsonrpc": "2.0", "id": mid, "result": result}) + "\n")
        out.flush()
    return 0


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(prog="repo_read.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("serve", "call"):
        p = sub.add_parser(name)
        p.add_argument("--tree", action="append", required=True)
        if name == "call":
            p.add_argument("tool")
            p.add_argument("args")
    a = ap.parse_args(argv)
    if a.cmd == "serve" and _CREDENTIALS_SEEN:
        # Names only, never values.
        print(f"repo_read: refused: started with credential variables {_CREDENTIALS_SEEN}", file=sys.stderr)
        return 3
    t = Trees(a.tree)
    if a.cmd == "serve":
        return serve(t)
    text, err = call(t, a.tool, json.loads(a.args))
    sys.stdout.write(text)
    return 1 if err else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
