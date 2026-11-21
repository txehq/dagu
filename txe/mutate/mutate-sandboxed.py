#!/usr/bin/env python3
"""Run mutation tests where a mutant cannot reach the host's shared state (TXE-7549).

A mutant is code that breaks a guard on purpose. On 2026-11-16 a hand-written runner ran one with
the session's real environment and the code under test deleted the Mac's shared Go module cache
(postmortem TXE-7547, txehq/txe docs/postmortems/2026-11-16-shared-gomodcache-deletion.md). This
runner owns the boundary, so no single test has to:

- Every mutant runs in a fresh copy of the tree, inside a container (`--pull never`, so an image
  is never fetched). The container gets two mounts, both inside a work directory this run
  created: the mutant's own directory (read-write) and the module proxy seeded from the shared
  cache (read-only), plus, per --ro-mount, a read-only copy the runner made inside that work
  directory, hash-checked, at an allowlisted path (TXE-8053). It gets no network, no Docker socket, no capabilities, bounded memory, CPU
  and processes, and no variable from the caller's environment. GOPATH, GOMODCACHE, GOCACHE,
  TMPDIR, XDG_CACHE_HOME and XDG_CONFIG_HOME point inside the mutant's directory. HOME is never
  set, here or anywhere in this runner: the container keeps its image user's default.
- The seed is filled on the host, before any mutant runs, by `go mod download` from the unmutated
  tree with an owned GOMODCACHE and `GOPROXY=file://<shared GOMODCACHE>/cache/download,<caller
  proxy>`. Go only reads a file proxy, and `go mod download` runs no project code. `--no-seed`
  skips it: then nothing reads the shared module cache and the container has GOPROXY=off.
- After every sandboxed command the runner checks the host: the identity (device, inode and,
  where the OS has one, birth time) of the shared GOMODCACHE, its cache/download, GOCACHE, GOPATH,
  HOME and the live tree; that no entry directly inside the shared GOMODCACHE, its cache/download
  or GOCACHE disappeared or was replaced; the content of a fixture sentinel file where one exists;
  and the content of every live-tree file a mutant names. Any change stops the run at once with
  exit 3. These checks are the alarm, not the boundary: a deletion deeper inside a cache leaves
  them unchanged. The container's mounts are the boundary.
- A killed mutant is run again in a new sandbox. A kill that does not repeat is a finding (exit 5),
  never a flake. The unmutated tree must pass before the first mutant and after the last.
- The work directory is removed only when its identity and its ownership token still match what
  this run recorded when it created it. It is never chosen from an environment variable later.

Usage:
  mutate-sandboxed.py --mutants mutants.json [--tree DIR] --image IMAGE -- go test ./pkg/...
  mutate-sandboxed.py --diagnostic [--tree DIR] --image IMAGE [--ro-mount SRC:DST:SHA256] -- CMD...
  mutate-sandboxed.py --ro-manifest DIR

--diagnostic runs the unmutated tree once, with the same boundary and checks, and records the
command's raw stdout, stderr (two files outside every mount) and exit status in the report as
evidence. It never yields a pass: a completed diagnostic exits 7 whatever the command's status,
which a reader takes only from report["diagnostic"]["command_exit"].

--ro-mount SRC:DST:SHA256 copies directory SRC (read on the host, never mounted) into this run's
work directory and mounts the copy read-only at DST, one of RO_MOUNT_DESTS. SHA256 is the copy's
--ro-manifest digest; the copy is re-checked after every run.

mutants.json is a list of {"name", "file", "old", "new"} objects, with an optional "count"
(default 1): `old` must occur exactly `count` times in `file` (relative to the tree), and every
occurrence is replaced by `new`.

Exit codes: 0 done, no finding (survivors are listed, not failures); 2 refused or bad input;
3 shared state changed (LOUD); 4 the unmutated tree failed; 5 findings (an unrepeated kill, a
sandbox error or a timeout; for --diagnostic, a run that did not complete); 6 stopped by
--deadline or a signal; 7 a --diagnostic run completed and was recorded (never 0). On a timeout, the deadline or a
signal, every container this run started whose client had not returned is force-removed, by the
id docker recorded (--cidfile, outside every mount), and only when docker reports that container's
own name and this run's owner token on it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

SENTINEL = ".mutate-sandboxed-fixture-sentinel"
OWNER_FILE = ".mutate-sandboxed-owned"
DEFAULT_EXCLUDES = (".git", "node_modules", ".local")
# docker run's own failures: the daemon refused (125), the command could not run (126, 127).
DOCKER_INFRA_EXITS = {125, 126, 127}

EXIT_OK, EXIT_REFUSED, EXIT_SHARED_CHANGED, EXIT_BASELINE, EXIT_FINDINGS, EXIT_STOPPED = 0, 2, 3, 4, 5, 6
# A completed --diagnostic run, whatever the command's own status: never 0, so no `&&` chain and no
# gate that reads exit 0 as "done, no finding" proceeds on a diagnostic (TXE-8053).
EXIT_DIAGNOSTIC = 7
# The end-of-run read-only mount check's own allowance under --deadline (it must still run on a stop
# path whose run deadline has passed); past it the check is incomplete, exit 6, never a pass.
FINAL_CHECK_S = 60.0
# The only container paths a --ro-mount may target. /work/src/.git is the one path under /work/src
# the tree copy can never hold (.git is excluded at every depth), so the mount shadows no tree
# content, and git finds it with no environment change.
RO_MOUNT_DESTS = ("/work/src/.git",)
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
OWNER_LABEL = "txe.mutate-sandboxed.owner"
CONTAINER_ID = re.compile(r"^[0-9a-f]{64}$")
# Every proxy variable Docker's automatic proxy configuration can set, cleared on the command line.
CLEARED_PROXY_ENV = {k: "" for base in ("HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "NO_PROXY", "ALL_PROXY")
                     for k in (base, base.lower())}
# docker inspect's answer for a container that does not exist (wording varies by version). Only
# this establishes absence; any other failure (daemon down, auth) establishes nothing.
NO_SUCH = re.compile(r"no such (object|container)", re.I)


class Refused(Exception):
    """A precondition does not hold; nothing has run."""


class SharedStateChanged(Exception):
    """A watched host path changed identity: the boundary failed."""


class Stopped(Exception):
    """The whole-run deadline passed, or a signal asked the run to stop."""


def stop_on_signal(signum, _frame):
    raise Stopped(f"signal {signal.Signals(signum).name}")


# ---------------------------------------------------------------- identity


def identity(path: Path) -> dict | None:
    """The identity of path itself (never followed through a final symlink), or None if absent."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:  # unreadable is a distinct state, so a change to it is seen, never skipped
        return {"unreadable": e.errno}
    ident = {"dev": st.st_dev, "ino": st.st_ino, "symlink": os.path.islink(path)}
    birth = getattr(st, "st_birthtime", None)
    if birth is not None:
        ident["birth"] = birth
    return ident


def file_digest(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except FileNotFoundError:
        return None
    except OSError as e:
        return f"unreadable: errno {e.errno}"


@dataclass
class Watch:
    """Paths whose identity must not change, and files whose content must not change."""

    dirs: dict[str, Path]
    files: dict[str, Path] = field(default_factory=dict)
    # Directories whose existing entries must neither disappear nor be replaced. New entries are
    # fine: other sessions fill the shared caches while a run is in progress.
    children: dict[str, Path] = field(default_factory=dict)

    def snapshot(self) -> dict:
        snap: dict = {name: identity(p) for name, p in self.dirs.items()}
        for name, p in self.files.items():
            snap[name] = {"identity": identity(p), "sha256": file_digest(p)}
        for name, p in self.children.items():
            snap[f"entries of {name}"] = entries(p)
        return snap

    def verify(self, before: dict, when: str) -> None:
        after = self.snapshot()
        changed = []
        for k in sorted(before):
            if k.startswith("entries of "):
                lost = {e: v for e, v in before[k].items() if after.get(k, {}).get(e) != v}
                if lost:
                    changed.append(k)
                    before = {**before, k: lost}
                    after = {**after, k: {e: after.get(k, {}).get(e) for e in lost}}
            elif before[k] != after.get(k):
                changed.append(k)
        if changed:
            lines = [f"  {k}: {self.describe(k)}\n    before {before[k]}\n    after  {after.get(k)}" for k in changed]
            raise SharedStateChanged(f"after {when}:\n" + "\n".join(lines))

    def describe(self, key: str) -> str:
        return str(self.dirs.get(key) or self.files.get(key) or self.children.get(key[len("entries of "):]))


def entries(d: Path) -> dict:
    """The identity of each entry directly inside d (empty when d is absent or unreadable)."""
    out = {}
    try:
        with os.scandir(d) as it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                out[e.name] = [st.st_dev, st.st_ino]
    except FileNotFoundError:
        pass
    except OSError as e:  # every entry read before then counts as lost: the check fails closed
        return {"<unreadable>": e.errno}
    return out


# ---------------------------------------------------------------- paths and mounts


def real(p: Path | str) -> Path:
    return Path(os.path.realpath(p))


def within(child: Path, parent: Path) -> bool:
    """child is parent or lies under it (both already resolved)."""
    return child == parent or parent in child.parents


def check_mounts(mounts: list[tuple[Path, str, bool]], owned: Path, forbidden: dict[str, Path]) -> None:
    """Refuse any bind mount that could expose host state.

    Every source must lie inside the run's own work directory, and must neither contain nor lie
    inside a forbidden path (the shared caches, GOPATH, HOME, the Docker socket, the live tree).
    """
    owned = real(owned)
    for src, _dst, _ro in mounts:
        r = real(src)
        if not within(r, owned) or r == owned:
            raise Refused(f"mount source {r} is not inside this run's work directory {owned}")
        for name, f in forbidden.items():
            fr = real(f)
            if within(fr, r) or within(r, fr):
                raise Refused(f"mount source {r} overlaps {name} ({fr})")
    targets = [dst for _src, dst, _ro in mounts]
    if len(set(targets)) != len(targets):
        raise Refused(f"two mounts share a target: {targets}")
    # A read-only source reachable through a read-write mount would be a writable alias of it.
    writable = [real(src) for src, _dst, ro in mounts if not ro]
    for src, _dst, ro in mounts:
        if ro:
            r = real(src)
            for w in writable:
                if within(r, w) or within(w, r):
                    raise Refused(f"read-only mount source {r} overlaps the read-write mount source {w}: "
                                  "a writable alias")


def check_workdir(work: Path, forbidden: dict[str, Path]) -> None:
    w = real(work)
    for name, f in forbidden.items():
        fr = real(f)
        if within(fr, w) or within(w, fr):
            raise Refused(f"work directory {w} overlaps {name} ({fr}); pass --workdir-root elsewhere")


# ---------------------------------------------------------------- read-only mounts (TXE-8053)


@dataclass
class RoMount:
    """A --ro-mount: the caller's directory is only read on the host; the runner mounts its own copy."""

    src: Path  # the caller's directory, never mounted
    dst: str  # one of RO_MOUNT_DESTS
    sha256: str  # the expected manifest digest of the copy
    copy: Path | None = None  # the runner's copy inside its work directory: the only thing mounted


def parse_ro_mounts(specs: list[str]) -> list[RoMount]:
    """Each spec is SRC:DST:SHA256. There is no option field: a writable form does not exist."""
    out: list[RoMount] = []
    for spec in specs:
        parts = spec.rsplit(":", 2)
        if len(parts) != 3:
            raise Refused(f"--ro-mount {spec!r}: expected SRC:DST:SHA256")
        src, dst, digest = parts
        if dst not in RO_MOUNT_DESTS:
            raise Refused(f"--ro-mount {spec!r}: destination {dst!r} is not one of {', '.join(RO_MOUNT_DESTS)}")
        if not SHA256_HEX.fullmatch(digest):
            raise Refused(f"--ro-mount {spec!r}: SHA256 must be 64 lowercase hex digits (the --ro-manifest digest)")
        # Exactly its own realpath: absolute, no '.', '..' or trailing slash, no symlink on the path.
        if not os.path.isabs(src) or os.path.realpath(src) != src:
            raise Refused(f"--ro-mount {spec!r}: source must be an absolute path equal to its own realpath "
                          f"({os.path.realpath(src)!r})")
        if any(m.dst == dst for m in out):
            raise Refused(f"--ro-mount {spec!r}: destination {dst} is given twice")
        out.append(RoMount(Path(src), dst, digest))
    return out


@dataclass
class RoLimits:
    """Bounds on a read-only mount's directory, checked on the source, while copying and on the copy."""

    files: int = 100_000  # entries, directories included
    depth: int = 32  # directory levels below the root
    total_bytes: int = 4096 << 20  # all regular files together, as read
    file_bytes: int = 2048 << 20  # one regular file, as read


def ro_limits(args) -> RoLimits:
    d = RoLimits()
    return RoLimits(files=getattr(args, "ro_max_files", d.files), depth=getattr(args, "ro_max_depth", d.depth),
                    total_bytes=getattr(args, "ro_max_mib", d.total_bytes >> 20) << 20,
                    file_bytes=getattr(args, "ro_max_file_mib", d.file_bytes >> 20) << 20)


# The portable filename set: no encoding, normalization or newline can make two names list alike.
RO_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
# The copy's modes, set explicitly (never from the umask or the source) and checked on every verify.
RO_DIR_MODE, RO_FILE_MODE = 0o755, 0o644
DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def ro_walk(root: Path, limits: RoLimits, deadline: float | None = None):
    """(relative path, lstat, parent directory fd, name) for every entry below root, never following
    a link. Each directory is opened relative to its parent's descriptor with O_NOFOLLOW, the root
    included, so a directory replaced by a link mid-walk cannot steer the walk off the tree. Refused:
    a root that is not a plain directory, any entry that is not a directory or a regular file, a
    name outside RO_NAME or equal to another in the same directory ignoring case, and a bound
    passed. Entries are counted while a directory is listed, so a huge directory is refused at
    limits.files + 1, never listed whole. The deadline is checked per entry (Stopped). The
    descriptor yielded is valid only until the next step."""
    try:
        top = os.open(root, DIR_FLAGS)
    except OSError as e:
        raise Refused(f"{root} is not a plain directory: {e}") from e
    count = [0]

    def walk(fd: int, prefix: str, depth: int):
        names: list[str] = []
        with os.scandir(fd) as it:
            for e in it:
                count[0] += 1
                if count[0] > limits.files:
                    raise Refused(f"{root} holds over {limits.files} entries")
                check_deadline(deadline, f"walking {root}")
                names.append(e.name)
        names.sort()
        folded: set[str] = set()
        for name in names:
            check_deadline(deadline, f"walking {root}")
            rel = prefix + name
            if not RO_NAME.fullmatch(name) or name in (".", ".."):
                raise Refused(f"{rel!r} in {root}: names must use only A-Z a-z 0-9 . _ -")
            if name.casefold() in folded:
                raise Refused(f"{rel!r} in {root}: another name in its directory differs only in case")
            folded.add(name.casefold())
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                if depth >= limits.depth:
                    raise Refused(f"{rel} in {root} is nested over {limits.depth} levels")
                yield rel, st, fd, name
                sub = os.open(name, DIR_FLAGS, dir_fd=fd)
                try:
                    yield from walk(sub, rel + "/", depth + 1)
                finally:
                    os.close(sub)
            elif stat.S_ISREG(st.st_mode):
                if st.st_size > limits.file_bytes:
                    raise Refused(f"{rel} in {root} is over {limits.file_bytes} bytes")
                yield rel, st, fd, name
            else:
                kind = "a symlink" if stat.S_ISLNK(st.st_mode) else f"a special file (mode {oct(stat.S_IFMT(st.st_mode))})"
                raise Refused(f"{rel} in {root} is {kind}; a read-only mount holds only directories and regular files")

    try:
        yield from walk(top, "", 0)
    except OSError as e:
        raise Refused(f"cannot read {root}: {e}") from e
    finally:
        os.close(top)


def open_regular_at(fd: int, name: str) -> int:
    """A descriptor on name in directory fd, refused unless it is a regular file. O_NOFOLLOW: a link
    swapped in is not followed; O_NONBLOCK: a FIFO swapped in does not block the open."""
    try:
        rfd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), dir_fd=fd)
    except OSError as e:
        raise Refused(f"cannot open {name} as a plain file: {e}") from e
    if not stat.S_ISREG(os.fstat(rfd).st_mode):
        os.close(rfd)
        raise Refused(f"{name} is not a regular file")
    return rfd


def read_bounded(rfd: int, limits: RoLimits, used: list[int], rel: str, sink,
                 deadline: float | None = None) -> int:
    """Read rfd to its end into sink, refusing once the file passes limits.file_bytes or all files
    together (used[0]) pass limits.total_bytes. Bytes are counted as read, not as stat says, so a
    file that grows during the copy is still bounded. The deadline is checked per MiB (Stopped).
    Returns the file's size."""
    n = 0
    try:
        with os.fdopen(rfd, "rb") as f:
            while chunk := f.read(1 << 20):
                check_deadline(deadline, f"reading {rel}")
                n += len(chunk)
                used[0] += len(chunk)
                if n > limits.file_bytes:
                    raise Refused(f"{rel} is over {limits.file_bytes} bytes")
                if used[0] > limits.total_bytes:
                    raise Refused(f"the read-only mount's files pass {limits.total_bytes} bytes")
                sink(chunk)
    except OSError as e:
        raise Refused(f"cannot copy or hash {rel}: {e}") from e
    return n


def ro_manifest_sha256(root: Path, limits: RoLimits | None = None, deadline: float | None = None) -> str:
    """The manifest digest of a directory: every entry below root, sorted by its relative path as
    bytes, '/'-separated, one line each, "D <rel>\\n" for a directory (empty ones included) and
    "F <size> <sha256 hex> <rel>\\n" for a regular file; the sha256 of the lines joined. Names,
    types, sizes and contents are covered. Modes, owners and times are not: the runner's copy
    writes every directory 0755 and every file 0644 whatever the source had."""
    limits = limits or RoLimits()
    used = [0]
    lines: list[str] = []
    for rel, st, fd, name in ro_walk(root, limits, deadline):
        if stat.S_ISDIR(st.st_mode):
            lines.append(f"D {rel}\n")
            continue
        h = hashlib.sha256()
        size = read_bounded(open_regular_at(fd, name), limits, used, rel, h.update, deadline)
        lines.append(f"F {size} {h.hexdigest()} {rel}\n")
    lines.sort(key=lambda line: line.split(" ")[-1].encode())
    return hashlib.sha256("".join(lines).encode()).hexdigest()


# The view TXE-8047 mounts at /work/src/.git: commit C's objects, `shallow`, a detached HEAD, the
# index, and a core-only config. Byte integrity says nothing about what the bytes are, so the copy
# is also held to this shape: no hooks, no alternates, no remotes, refs or reflogs, no config but
# these core keys, no include, no worktree link. Anything not listed is refused.
GIT_VIEW_TOP = {"HEAD": "file", "config": "file", "index": "file", "shallow": "file", "objects": "dir",
                "refs": "dir"}
GIT_VIEW_REQUIRED = ("HEAD", "config", "objects", "refs")
GIT_CORE_KEYS = {"repositoryformatversion", "filemode", "bare", "logallrefupdates", "ignorecase",
                 "precomposeunicode", "symlinks"}
GIT_OID = r"(?:[0-9a-f]{40}|[0-9a-f]{64})"
GIT_VIEW_PATHS = [
    re.compile(r"^objects/(?:pack|info|[0-9a-f]{2})$"),  # directories
    re.compile(r"^objects/pack/pack-" + GIT_OID + r"\.(?:pack|idx|rev)$"),
    re.compile(r"^objects/[0-9a-f]{2}/(?:[0-9a-f]{38}|[0-9a-f]{62})$"),
    re.compile(r"^refs(?:/[A-Za-z0-9._-]+)*$"),  # directories only: no ref files (checked below)
]


def check_git_view(copy: Path, limits: RoLimits, deadline: float | None = None) -> None:
    """Refuse a git directory outside the TXE-8047 view contract (see GIT_VIEW_TOP)."""
    seen: dict[str, bool] = {}
    for rel, st, fd, name in ro_walk(copy, limits, deadline):
        is_dir = stat.S_ISDIR(st.st_mode)
        seen[rel] = is_dir
        if "/" not in rel:
            want = GIT_VIEW_TOP.get(rel)
            if want is None or (want == "dir") != is_dir:
                raise Refused(f"git view: {rel} is not part of the view (allowed: {', '.join(sorted(GIT_VIEW_TOP))})")
            continue
        if rel.startswith("refs/") and not is_dir:
            raise Refused(f"git view: {rel}: the view holds no refs")
        if rel.startswith("objects/info/"):
            raise Refused(f"git view: {rel}: objects/info holds nothing (no alternates)")
        if not any(p.fullmatch(rel) for p in GIT_VIEW_PATHS):
            raise Refused(f"git view: {rel} is not part of the view")
        if is_dir != (rel.count("/") == 1 or rel.startswith("refs/")):
            raise Refused(f"git view: {rel} has the wrong type")
    for req in GIT_VIEW_REQUIRED:
        if req not in seen:
            raise Refused(f"git view: {req} is missing")

    def text(rel: str, cap: int = 1 << 16) -> str:
        try:
            with open(copy / rel, "rb") as f:  # the runner's own copy, walked link-free just above
                raw = f.read(cap + 1)
        except OSError as e:
            raise Refused(f"git view: cannot read {rel}: {e}") from e
        if len(raw) > cap:
            raise Refused(f"git view: {rel} is over {cap} bytes")
        try:
            return raw.decode("ascii")
        except UnicodeDecodeError:
            raise Refused(f"git view: {rel} is not ASCII") from None

    if not re.fullmatch(GIT_OID + r"\n?", text("HEAD")):
        raise Refused("git view: HEAD must be a detached object id")
    if "shallow" in seen and not re.fullmatch(r"(?:" + GIT_OID + r"\n)+", text("shallow")):
        raise Refused("git view: shallow must list object ids, one per line")
    section = None
    for line in text("config").splitlines():
        s = line.strip()
        if not s or s[0] in "#;":
            continue
        if s.startswith("["):
            section = s.lower()
            if section != "[core]":
                raise Refused(f"git view: config section {s!r}: only [core] is allowed")
            continue
        m = re.fullmatch(r"([A-Za-z][A-Za-z0-9-]*)\s*=\s*([A-Za-z0-9]+)", s)
        if section != "[core]" or not m or m.group(1).lower() not in GIT_CORE_KEYS:
            raise Refused(f"git view: config line {s!r}: only core.{{{', '.join(sorted(GIT_CORE_KEYS))}}} "
                          "with a plain value is allowed")


def check_ro_source(m: RoMount, forbidden: dict[str, Path], limits: RoLimits, deadline: float | None = None) -> None:
    """Before anything runs: the source is a plain directory within the bounds, holding only
    directories and regular files, and is not, does not contain and does not lie inside protected
    state. Lying inside HOME is allowed (it is only read on the host); containing HOME is not."""
    src = real(m.src)
    for name, f in forbidden.items():
        fr = real(f)
        if within(fr, src) or (name != "HOME" and within(src, fr)):
            raise Refused(f"--ro-mount source {src} overlaps {name} ({fr})")
    for _entry in ro_walk(m.src, limits, deadline):
        pass


def verify_ro_copy(m: RoMount, limits: RoLimits, deadline: float | None = None) -> None:
    """The runner's copy is still what was checked: its manifest, one link per file, owned by this
    process's uid (the uid the container runs as, so git's ownership check holds), and, for the git
    view, the view's shape. Called after the copy, immediately before every mount and after every
    run; a failure after the first check is the read-only boundary failing."""
    if m.copy is None:
        raise Refused(f"read-only mount {m.dst} is not prepared")
    got = ro_manifest_sha256(m.copy, limits, deadline)
    if got != m.sha256:
        raise Refused(f"--ro-mount {m.dst}: the copy's manifest is {got}, expected {m.sha256}")
    entries = [("", os.lstat(m.copy))] + [(rel, st) for rel, st, _fd, _name in ro_walk(m.copy, limits, deadline)]
    for rel, st in entries:
        what = rel or "(root)"
        if stat.S_ISREG(st.st_mode) and st.st_nlink != 1:
            raise Refused(f"--ro-mount copy {what} has {st.st_nlink} links: a writable alias")
        if st.st_uid != os.getuid():
            raise Refused(f"--ro-mount copy {what} is owned by uid {st.st_uid}, not {os.getuid()}")
        want = RO_DIR_MODE if stat.S_ISDIR(st.st_mode) else RO_FILE_MODE
        if stat.S_IMODE(st.st_mode) != want:
            raise Refused(f"--ro-mount copy {what} has mode {oct(stat.S_IMODE(st.st_mode))}, not {oct(want)}")
    if m.dst == "/work/src/.git":
        check_git_view(m.copy, limits, deadline)


def prepare_ro_mount(m: RoMount, work: Path, index: int, forbidden: dict[str, Path], limits: RoLimits,
                     deadline: float | None = None) -> None:
    """Copy m.src into a directory this run creates inside its work directory (new files, 0644, and
    directories, 0755: no inode is shared with anything), through the same descriptor-anchored walk,
    with every byte bounded as read; then verify_ro_copy. Hashing the copy, not the source, means
    what is mounted is what was checked: a writer racing on the source can only cause a refusal."""
    check_ro_source(m, forbidden, limits, deadline)
    src, w = real(m.src), real(work)
    if within(w, src) or within(src, w):
        raise Refused(f"--ro-mount source {src} overlaps this run's work directory {w}")
    base = work / "ro"
    base.mkdir(exist_ok=True)
    copy = base / f"{index:02d}"
    copy.mkdir()  # exclusive: never a directory something else made
    used = [0]
    try:
        os.chmod(copy, RO_DIR_MODE)  # modes are set explicitly, whatever the umask (Linux or macOS)
        for rel, st, fd, name in ro_walk(m.src, limits, deadline):
            check_deadline(deadline, "copying a --ro-mount source")
            target = copy / rel
            if stat.S_ISDIR(st.st_mode):
                target.mkdir()
                os.chmod(target, RO_DIR_MODE)
                continue
            out = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), RO_FILE_MODE)
            os.fchmod(out, RO_FILE_MODE)
            with os.fdopen(out, "wb") as fout:
                read_bounded(open_regular_at(fd, name), limits, used, rel, fout.write, deadline)
    except OSError as e:
        raise Refused(f"--ro-mount source {m.src}: copy failed: {e}") from e
    m.copy = copy
    verify_ro_copy(m, limits, deadline)


# ---------------------------------------------------------------- mutants


@dataclass
class Mutant:
    name: str
    file: str
    old: str
    new: str
    count: int = 1


def plain_target(root: Path, rel: str) -> Path:
    """root/rel, refused unless every component under root is a real directory or file (no
    symlink anywhere on the path) and it resolves inside root. A link on the path could point
    back into the live tree, and writing through it would edit the live file."""
    target, cur = root / rel, root
    for part in Path(rel).parts:
        cur = cur / part
        if cur.is_symlink():
            raise Refused(f"{rel} runs through the symlink {cur.relative_to(root)}")
    if not within(real(target), real(root)):
        raise Refused(f"{rel} resolves outside {root}")
    return target


def load_mutants(path: Path, tree: Path) -> list[Mutant]:
    try:
        raw = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise Refused(f"cannot read mutants from {path}: {e}") from e
    if not isinstance(raw, list) or not raw:
        raise Refused("mutants file must be a non-empty JSON list")
    out, names = [], set()
    for i, m in enumerate(raw):
        if not isinstance(m, dict):
            raise Refused(f"mutant {i} is not an object")
        unknown = set(m) - {"name", "file", "old", "new", "count"}
        if unknown:
            raise Refused(f"mutant {i} has unknown keys {sorted(unknown)}")
        try:
            mu = Mutant(str(m["name"]), str(m["file"]), str(m["old"]), str(m["new"]), int(m.get("count", 1)))
        except KeyError as e:
            raise Refused(f"mutant {i} lacks {e}") from e
        if mu.name in names:
            raise Refused(f"duplicate mutant name {mu.name!r}")
        names.add(mu.name)
        if not mu.old or mu.old == mu.new or mu.count < 1:
            raise Refused(f"mutant {mu.name!r}: old must be non-empty, differ from new, count >= 1")
        rel = Path(mu.file)
        if rel.is_absolute() or ".." in rel.parts:
            raise Refused(f"mutant {mu.name!r}: file must be relative to the tree, without '..'")
        try:
            target = plain_target(tree, mu.file)
        except Refused as e:
            raise Refused(f"mutant {mu.name!r}: {e}") from e
        try:
            text = target.read_text()
        except OSError as e:
            raise Refused(f"mutant {mu.name!r}: cannot read {mu.file}: {e}") from e
        found = text.count(mu.old)
        if found != mu.count:
            raise Refused(f"mutant {mu.name!r}: old text occurs {found} times in {mu.file}, expected {mu.count}")
        out.append(mu)
    return out


def apply_mutant(copy: Path, mu: Mutant) -> None:
    try:
        target = plain_target(copy, mu.file)
    except Refused as e:
        raise Refused(f"mutant {mu.name!r} in the copy: {e}") from e
    text = target.read_text()
    if text.count(mu.old) != mu.count:
        raise Refused(f"mutant {mu.name!r}: copy of {mu.file} no longer matches")
    target.write_text(text.replace(mu.old, mu.new))


# ---------------------------------------------------------------- the owned work directory


class WorkDir:
    """A directory this run created, removable only while it is still the one it created."""

    def __init__(self, root: Path):
        self.path = Path(tempfile.mkdtemp(prefix="mutate-sandboxed-", dir=root))
        self.token = secrets.token_hex(16)
        (self.path / OWNER_FILE).write_text(self.token)
        self.ident = identity(self.path)

    def remove(self) -> None:
        if identity(self.path) != self.ident:
            raise Refused(f"work directory {self.path} changed identity; leaving it")
        if (self.path / OWNER_FILE).read_text() != self.token:
            raise Refused(f"work directory {self.path} lost its ownership token; leaving it")
        shutil.rmtree(self.path)


def check_deadline(deadline: float | None, what: str) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise Stopped(f"the whole-run deadline passed while {what}")


def refuse_special(path: str) -> None:
    """Only directories, regular files and symlinks are copied on the host. A FIFO would block the
    copy forever; sockets and devices have no place in a source tree or a build cache."""
    mode = os.lstat(path).st_mode
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
        raise Refused(f"{path} is a special file (mode {oct(stat.S_IFMT(mode))}); a host-side copy refuses it")


def scan_tree(root: Path, deadline: float | None, what: str) -> None:
    """Before a host-side copy: every entry under root (not following links) is a directory, a
    regular file or a symlink."""
    refuse_special(str(root))
    for d, dirs, files in os.walk(root):
        check_deadline(deadline, what)
        for n in dirs + files:
            refuse_special(os.path.join(d, n))


def checked_copy(deadline: float | None, what: str):
    """A shutil copy function that stops the copy at the deadline, file by file, and refuses
    special files."""
    def copy(s, d):
        check_deadline(deadline, what)
        refuse_special(s)
        return shutil.copy2(s, d)
    return copy


def copy_tree(src: Path, dst: Path, excludes: tuple[str, ...], deadline: float | None = None) -> None:
    """Copy the tree, keeping symlinks as links, and refuse any link that leads outside the copy.

    A link that resolves outside the copy (an absolute link into the live tree, say) would let a
    host-side step such as `go mod download` updating go.sum write through it into live files.
    Inside the container such a link dangles; on the host it is a hole, so it is refused."""
    def ignore(_d, names):
        check_deadline(deadline, "copying the tree")
        return [n for n in names if n in excludes]

    shutil.copytree(src, dst, symlinks=True, ignore=ignore, copy_function=checked_copy(deadline, "copying the tree"))
    top = real(dst)
    for d, dirs, files in os.walk(dst):
        check_deadline(deadline, "checking the copy's symlinks")
        for n in dirs + files:
            p = Path(d) / n
            if p.is_symlink() and not within(real(p), top):
                raise Refused(f"{p.relative_to(dst)} is a symlink to {os.readlink(p)}, outside the tree; "
                              "a host-side step could write through it")


def clone_dir(src: Path, dst: Path, deadline: float | None = None) -> None:
    """Copy src to dst, with copy-on-write clones on APFS when cp supports them, inside the
    deadline."""
    check_deadline(deadline, f"copying {src.name}")
    scan_tree(src, deadline, f"checking {src.name} before copying it")
    if sys.platform == "darwin":
        limit = None if deadline is None else max(0.1, deadline - time.monotonic())
        try:
            if subprocess.run(["cp", "-cR", str(src), str(dst)], capture_output=True, timeout=limit).returncode == 0:
                return
        except subprocess.TimeoutExpired as e:
            raise Stopped(f"the whole-run deadline passed while copying {src.name}") from e
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, symlinks=True, copy_function=checked_copy(deadline, f"copying {src.name}"))


# ---------------------------------------------------------------- host go facts


def go_env(names: list[str], env: dict[str, str], deadline_at: float | None = None) -> dict[str, str]:
    limit = min(60.0, deadline_at - time.monotonic()) if deadline_at else 60.0
    if limit <= 0:
        raise Stopped("the whole-run deadline passed before go env")
    try:
        # From a neutral directory and with no workspace, so the caller's own go.mod or go.work
        # cannot select (and try to download) a toolchain for a tree that is not the one tested.
        out = subprocess.run(["go", "env", "-json", *names], capture_output=True, text=True,
                             env={**env, "GOWORK": "off"}, cwd=os.path.abspath(os.sep), timeout=limit)
    except subprocess.TimeoutExpired as e:
        raise Stopped(f"go env took longer than {limit:.0f}s") from e
    if out.returncode != 0:
        raise Refused(f"go env failed: {out.stderr.strip()}")
    return json.loads(out.stdout)


def file_url(p: Path) -> str:
    return Path(p).resolve().as_uri()


# ---------------------------------------------------------------- the sandbox


# HOME is deliberately absent: the container keeps its image user's default home.
SANDBOX_ENV_DIRS = {
    "GOPATH": "gopath",
    "GOMODCACHE": "gomodcache",
    "GOCACHE": "gocache",
    "TMPDIR": "tmp",
    "XDG_CACHE_HOME": "xdg-cache",
    "XDG_CONFIG_HOME": "xdg-config",
}


def call_limit(cap: float, hard_end: float | None) -> float:
    """A cleanup call's timeout: cap, cut to what the hard deadline leaves, never under 1 s (a
    container is still removed when the deadline has just passed; the overrun is bounded)."""
    if hard_end is None:
        return cap
    return max(1.0, min(cap, hard_end - time.monotonic()))


def remove_owned_container(docker: str, cidfile: Path, name: str, token: str, env: dict[str, str],
                           hard_end: float | None = None) -> str:
    """Force-remove one container this run started, and nothing else.

    The container is the one docker recorded in cidfile (kept outside every mount, so no sandboxed
    code can rewrite it), or failing that the run's unique name. It is removed only when docker
    reports that exact name and this run's owner label on it. Returns what happened.
    """
    target = name
    try:
        cid = cidfile.read_text().strip()
        if CONTAINER_ID.match(cid):
            target = cid
    except OSError:
        pass
    probe = subprocess.run([docker, "inspect", "--format", "{{.Name}} {{index .Config.Labels \"" + OWNER_LABEL + "\"}}",
                            target], capture_output=True, text=True, env=env, timeout=call_limit(15, hard_end))
    if probe.returncode != 0:
        if NO_SUCH.search(probe.stderr):
            return f"{target}: absent"
        return f"{target}: cleanup error: inspect failed: {probe.stderr.strip()[-200:]}"
    if probe.stdout.strip() != f"/{name} {token}":
        return f"{target}: not ours ({probe.stdout.strip()!r}); left alone"
    rm = subprocess.run([docker, "rm", "-f", target], capture_output=True, text=True, env=env,
                        timeout=call_limit(30, hard_end))
    if rm.returncode == 0:
        return f"{target}: removed"
    # rm -f can fail while docker's own --rm is still removing it ("removal already in progress"):
    # look once more, and count only docker's own "no such" as absent.
    again = subprocess.run([docker, "inspect", "--format", "{{.Name}}", target], capture_output=True, text=True,
                           env=env, timeout=call_limit(15, hard_end))
    if again.returncode != 0 and NO_SUCH.search(again.stderr):
        return f"{target}: absent"
    return f"{target}: rm failed: {rm.stderr.strip()[-200:]}"


def output_tail(log_path: Path, size: int = 8192) -> str:
    try:
        with open(log_path, "rb") as f:
            f.seek(max(0, log_path.stat().st_size - size))
            return f.read().decode("utf-8", "replace")
    except OSError as e:
        return f"<unreadable: {e}>"


class _Overrun(Exception):
    pass


def dir_usage(d: Path, max_entries: int, budget: float, max_depth: int = 256,
              skip: tuple[str, ...] = ()) -> tuple[int, int, str | None]:
    """Bytes allocated and entries under d, not following links. The tree is written by sandboxed
    code, so the walk fails closed: an unreadable entry, more than max_entries entries, a walk
    longer than budget seconds, or nesting deeper than max_depth is a reason to stop the run.

    Entries are streamed (os.scandir on a directory descriptor) and the limits checked per entry,
    so a huge single directory is never listed whole into host memory. Each directory is opened
    relative to its parent's descriptor with O_NOFOLLOW, so a directory swapped for a symlink
    mid-walk cannot steer the walk onto a host path. One descriptor is open per level."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    started = time.monotonic()
    tally = [0, 0]  # bytes, entries

    def walk(fd: int, depth: int) -> None:
        if depth > max_depth:
            raise _Overrun(f"run directory nested over {max_depth} levels")
        with os.scandir(fd) as it:
            for entry in it:
                if entry.name in skip:  # what the copy excludes, at any depth, as copy_tree does
                    continue
                tally[1] += 1
                if tally[1] > max_entries:
                    raise _Overrun(f"run directory over {max_entries} entries")
                if time.monotonic() - started > budget:
                    raise _Overrun(f"run directory took over {budget:.0f}s to measure")
                try:
                    st = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                # A copy writes a sparse file's holes out in full: count what a copy would take.
                allocated = getattr(st, "st_blocks", 0) * 512
                tally[0] += max(allocated, st.st_size) if stat.S_ISREG(st.st_mode) else allocated
                if stat.S_ISDIR(st.st_mode):
                    try:
                        sub = os.open(entry.name, flags, dir_fd=fd)
                    except FileNotFoundError:
                        continue
                    try:
                        walk(sub, depth + 1)
                    finally:
                        os.close(sub)

    try:
        top = os.open(d, flags)
    except FileNotFoundError:
        return 0, 0, None
    except OSError as e:
        return 0, 0, f"unreadable entry in the run directory: {e}"
    try:
        walk(top, 0)
    except _Overrun as e:
        return tally[0], tally[1], str(e)
    except OSError as e:
        return tally[0], tally[1], f"unreadable entry in the run directory: {e}"
    finally:
        os.close(top)
    return tally[0], tally[1], None


def refuse_declared_volumes(image: str, volumes_json: str) -> None:
    """An image that declares a VOLUME gets an anonymous host-backed writable volume on every run,
    even with --read-only: a writable path outside the run's own mount and its disk bounds. Such
    an image is refused. volumes_json is `docker image inspect --format '{{json .Config.Volumes}}'`."""
    text = volumes_json.strip()
    if text in ("", "null", "{}"):
        return
    try:
        declared = sorted(json.loads(text))
    except (ValueError, TypeError):
        raise Refused(f"cannot read the volumes image {image} declares: {text[:200]!r}") from None
    if declared:
        raise Refused(f"image {image} declares VOLUME {', '.join(declared)}: each would be a writable host "
                      "path outside the sandbox's bounds; use an image without declared volumes")


def docker_client_env() -> dict[str, str]:
    """What the docker client itself needs from the caller, unchanged; none of it reaches a
    container (docker run passes only --env values)."""
    keep = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "USER", "LANG")
    return {k: os.environ[k] for k in keep if k in os.environ}


@dataclass
class Result:
    name: str
    outcome: str  # PASSED, KILLED, SURVIVED, ERROR, TIMEOUT
    exit_code: int | None
    seconds: float
    log: str
    output_tail: str = ""  # the last 8 KiB of the run's output, kept in the report
    dir: str = ""  # the run's own directory (its /work)


class Runner:
    def __init__(self, args, watch: Watch, forbidden: dict[str, Path], work: WorkDir, docker: str,
                 live_targets: list[Mutant]):
        self.args = args
        self.watch = watch
        self.forbidden = forbidden
        self.work = work
        self.docker = docker
        self.seq = 0
        # Runs stop a cleanup reserve before the hard deadline, so removing a container whose
        # client was killed fits inside it.
        self.hard_end = args.deadline_at
        self.reserve = min(45.0, args.deadline / 3) if args.deadline else 0.0
        self.deadline = args.deadline_at - self.reserve if args.deadline_at else None
        # Every mutation target's live content, read before the tree was copied.
        self.live = {m.file: file_digest(args.tree / m.file) for m in live_targets}
        # (name, cidfile) of every container started whose docker client has not returned.
        self.pending: dict[str, Path] = {}
        # label -> (cidfile, name) of every container started, for checks after the run.
        self.containers: dict[str, tuple[Path, str]] = {}
        self.cleanup_log: list[str] = []
        # TXE-8053: prepared read-only mounts (each with its runner-made copy), and diagnostic mode,
        # where a run's stdout and stderr are recorded apart and its outcome is never a pass.
        self.ro_mounts: list[RoMount] = []
        self.ro_limits = ro_limits(args)
        self.diagnostic = bool(getattr(args, "diagnostic", False))
        self.err_log = None  # the open stderr file of the run in progress, in diagnostic mode
        self.err_path: Path | None = None  # the last run's stderr file, in diagnostic mode

    def check_allowance(self) -> float | None:
        """The deadline for a check after a run: FINAL_CHECK_S from now, never past the hard deadline."""
        if self.hard_end is None:
            return None
        return min(self.hard_end, time.monotonic() + FINAL_CHECK_S)

    def verify_ro_mounts(self, when: str, deadline: float | None = None) -> None:
        """Each read-only mount's copy still passes verify_ro_copy. Called immediately before every
        mount and after every run (inside the run deadline), and at the end of the run (inside the
        final check's own allowance): once the copy was verified, a failure means the read-only
        boundary failed, so it is exit 3 with no verdict, never a refusal. A deadline passed during
        the check raises Stopped: the check did not complete, which is never a pass."""
        for m in self.ro_mounts:
            try:
                verify_ro_copy(m, self.ro_limits, deadline if deadline is not None else self.deadline)
            except (Refused, OSError) as e:
                raise SharedStateChanged(f"{when}: the read-only mount {m.dst} (copy {m.copy}) changed: {e}") from e

    def room(self, what: str, sources: tuple[Path, ...] = (), skip: tuple[str, ...] = ()) -> None:
        """Before copying sources into the work directory: with the copy's full size added (sparse
        files counted at their apparent size), the work directory stays under --max-work-mib and
        the free space beside it over --min-free-mib, or the run stops."""
        used, _entries, problem = dir_usage(self.work.path, self.args.max_files * 4, 30.0)
        if problem:
            raise Stopped(f"before {what}: {problem}")
        need = 0
        for src in sources:
            size, _n, problem = dir_usage(src, self.args.max_files, 30.0, skip=skip)
            if problem:
                raise Stopped(f"before {what}: {problem}")
            need += size
        if used + need > self.args.max_work_mib * 2**20:
            raise Stopped(f"before {what}: the work directory would pass {self.args.max_work_mib} MiB")
        if shutil.disk_usage(self.work.path).free - need < self.args.min_free_mib * 2**20:
            raise Stopped(f"before {what}: free space would fall under {self.args.min_free_mib} MiB")

    def assert_stopped(self, result: "Result") -> None:
        """Before the host reads a run's directory: the run's container is gone, or exists and is
        not running. A container still running could change the paths between check and read."""
        cidfile, name = self.containers.get(result.name, (None, None))
        if cidfile is None:
            raise Refused(f"no container recorded for {result.name}")
        target = name
        try:
            cid = cidfile.read_text().strip()
            if CONTAINER_ID.match(cid):
                target = cid
        except OSError:
            pass
        limit = 15.0 if self.hard_end is None else min(15.0, self.hard_end - time.monotonic())
        if limit <= 0:
            self.pending[name] = cidfile
            raise Stopped(f"the whole-run deadline passed before checking that {result.name} stopped")
        try:
            probe = subprocess.run([self.docker, "inspect", "--format", "{{.State.Running}}", target],
                                   capture_output=True, text=True, env=self.docker_env(), timeout=limit)
        except subprocess.TimeoutExpired as e:
            self.pending[name] = cidfile
            raise Stopped(f"docker did not say inside the deadline whether {result.name} stopped") from e
        if probe.returncode == 0:
            if probe.stdout.strip() != "false":
                self.pending[name] = cidfile  # the finalizer removes it, ownership-checked
                raise Refused(f"the container of {result.name} ({target}) is still running; "
                              "the host will not read its files")
        elif not NO_SUCH.search(probe.stderr):
            self.pending[name] = cidfile
            raise Refused(f"cannot establish that the container of {result.name} ({target}) has stopped "
                          f"({probe.stderr.strip()[-200:]}); the host will not read its files")

    def discard(self, result: "Result") -> None:
        """A finished run's directory goes once its result is recorded (its log, outside it, stays),
        so runs do not accumulate on the host."""
        d = Path(result.dir)
        if d.parent == self.work.path and d.name[:3].isdigit() and d.is_dir() and not d.is_symlink():
            shutil.rmtree(d)

    def remaining(self, what: str) -> float:
        """Seconds the next step may take: the per-run timeout, cut to what the deadline leaves."""
        if self.deadline is None:
            return float(self.args.timeout)
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise Stopped(f"the whole-run deadline ({self.args.deadline}s) passed before {what}")
        return min(float(self.args.timeout), left)

    def remove_pending(self) -> bool:
        """Remove every pending container. An entry leaves pending only when its removal or its
        absence is confirmed; anything else stays, for the finalizer's retry. Returns whether
        nothing is left pending."""
        for name, cidfile in list(self.pending.items()):
            try:
                outcome = remove_owned_container(self.docker, cidfile, name, self.work.token,
                                                 self.docker_env(), self.hard_end)
            except (OSError, subprocess.TimeoutExpired) as e:
                outcome = f"{name}: cleanup error {e}"
            self.cleanup_log.append(outcome)
            if outcome.endswith(": removed") or outcome.endswith(": absent"):
                del self.pending[name]
        return not self.pending

    def clear_pending(self) -> None:
        """After a run that stopped abnormally: no further run starts while one of its
        containers may still be running."""
        if not self.remove_pending():
            raise Stopped("a container could not be confirmed removed: " + ", ".join(self.pending))

    # A run gets its own directory: src (the tree copy) and sandbox/<env dirs>.
    def prepare(self, label: str, pristine: Path, mutant: Mutant | None) -> Path:
        self.seq += 1
        d = self.work.path / f"{self.seq:03d}-{''.join(c if c.isalnum() else '-' for c in label)[:40]}"
        d.mkdir()
        clone_dir(pristine, d / "src", self.deadline)
        if mutant:
            apply_mutant(d / "src", mutant)
        for m in self.ro_mounts:
            # The mountpoint is made here, as a plain directory, so docker neither creates it nor
            # resolves it through a link. The copy never holds it (.git is excluded at every depth).
            point = d / m.dst[len("/work/"):]
            if os.path.lexists(point):
                raise Refused(f"the tree copy already holds {m.dst}; a read-only mount would shadow it")
            point.mkdir()
        sb = d / "sandbox"
        for sub in SANDBOX_ENV_DIRS.values():
            (sb / sub).mkdir(parents=True)
        warm = self.work.path / "warm-gocache"
        if self.args.warm_gocache and warm.is_dir():
            shutil.rmtree(sb / "gocache")
            clone_dir(warm, sb / "gocache", self.deadline)
        return d

    def docker_argv(self, d: Path, name: str, cidfile: Path) -> list[str]:
        mounts: list[tuple[Path, str, bool]] = [(d, "/work", False)]
        seed = self.work.path / "seed" / "gomodcache" / "cache" / "download"
        if seed.is_dir():
            mounts.append((seed, "/goproxy", True))
        self.verify_ro_mounts(f"before mounting into {d.name}")
        for m in self.ro_mounts:
            point = plain_target(d, m.dst[len("/work/"):])  # no symlink on the path to the mountpoint
            if m.copy is None or not point.is_dir() or any(point.iterdir()):
                raise Refused(f"read-only mount {m.dst} has no empty plain mountpoint")
            mounts.append((m.copy, m.dst, True))
        check_mounts(mounts, self.work.path, self.forbidden)
        env = {k: f"/work/sandbox/{v}" for k, v in SANDBOX_ENV_DIRS.items()}
        env.update({
            "GOPROXY": "file:///goproxy" if seed.is_dir() else "off",
            "GOSUMDB": "off",  # go.sum still verifies every module; there is no network to ask
            # -count=1: the copied build cache must not replay a cached test result, so every
            # baseline and mutant run executes its tests.
            "GOFLAGS": "-modcacherw -count=1",
            "GOTOOLCHAIN": "local",
            "GOENV": "off",
            "MUTATE_SANDBOXED": "1",
            # Docker adds proxy settings from the client's config.json to every container unless
            # the command line sets them; set each to empty, so no proxy URL (or credential in
            # one) reaches sandboxed code.
            **CLEARED_PROXY_ENV,
        })
        if any(m.dst == "/work/src/.git" for m in self.ro_mounts):
            # git skips its optional index refresh, which would try .git/index.lock on a read-only
            # view; a command that needs a lock fails on the read-only mount instead of half-writing.
            env["GIT_OPTIONAL_LOCKS"] = "0"
        # --log-driver none: Docker keeps no second, unbounded copy of the output on its data root;
        # the attached stream the runner captures (and bounds) is unaffected.
        argv = [self.docker, "run", "--rm", "--pull", "never", "--log-driver", "none", "--name", name,
                "--cidfile", str(cidfile),
                "--label", f"{OWNER_LABEL}={self.work.token}", "--network", self.args.network,
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", str(self.args.pids),
                "--memory", self.args.memory, "--cpus", self.args.cpus,
                "--read-only", "--tmpfs", "/tmp:rw,size=256m", "--user", f"{os.getuid()}:{os.getgid()}",
                "--workdir", "/work/src", "--entrypoint", ""]
        for src, dst, ro in mounts:
            argv += ["--mount", f"type=bind,source={real(src)},target={dst}" + (",readonly" if ro else "")]
        for k in sorted(env):
            argv += ["--env", f"{k}={env[k]}"]
        return argv + [self.args.image, *self.args.command]

    def run(self, label: str, pristine: Path, mutant: Mutant | None) -> Result:
        before = self.watch.snapshot()
        self.remaining(label)  # the deadline is checked before the run's own copies start
        warm = self.work.path / "warm-gocache"
        self.room(label, (pristine, warm) if self.args.warm_gocache and warm.is_dir() else (pristine,))
        d = self.prepare(label, pristine, mutant)
        name = f"mutate-sandboxed-{self.work.token[:12]}-{self.seq:03d}"
        # Outside every mount: sandboxed code cannot rewrite which container cleanup removes.
        cidfile = self.work.path / "cids" / f"{self.seq:03d}.cid"
        cidfile.parent.mkdir(exist_ok=True)
        argv = self.docker_argv(d, name, cidfile)
        limit = self.remaining(label)
        # Outside every mount: sandboxed code cannot truncate or replace its own output log.
        log_path = self.work.path / "logs" / f"{self.seq:03d}.log"
        log_path.parent.mkdir(exist_ok=True)
        # Diagnostic mode records the two streams apart: <seq>.stdout and <seq>.stderr.
        self.err_path = None
        if self.diagnostic:
            log_path = log_path.with_suffix(".stdout")
            self.err_path = log_path.with_suffix(".stderr")
        start = time.monotonic()
        code, outcome = None, None
        self.pending[name] = cidfile
        self.containers[label] = (cidfile, name)
        self.overrun = None
        with open(log_path, "wb") as log, open(self.err_path or os.devnull, "wb") as err:
            self.err_log = err if self.err_path else None
            proc = subprocess.Popen(argv, stdout=log, stderr=err if self.err_path else subprocess.STDOUT,
                                    env=self.docker_env())
            try:
                code = self.watch_run(proc, d, log, start, limit)
            except BaseException:
                proc.kill()
                proc.wait()
                raise
            finally:
                self.err_log = None
        if code is None:  # stopped by the watchdog: time, output or disk
            self.clear_pending()
            if self.overrun == "time":
                if limit < self.args.timeout:
                    raise Stopped(f"the whole-run deadline ({self.args.deadline}s) passed during {label}")
                outcome = "TIMEOUT"
            else:
                outcome = "ERROR"
                self.cleanup_log.append(f"{name}: stopped: {self.overrun}")
                print(f"mutate-sandboxed: {label}: stopped: {self.overrun}", file=sys.stderr)
        elif code < 0:
            # The docker client died by a signal: nothing shows the container finished.
            self.clear_pending()
            outcome = "ERROR"
        else:
            del self.pending[name]
        secs = time.monotonic() - start
        # The boundary check comes before any verdict: a run that touched host state has no result.
        self.watch.verify(before, f"{label}")
        for f, digest in self.live.items():
            if file_digest(self.args.tree / f) != digest:
                raise SharedStateChanged(f"after {label}: the live tree's {f} changed")
        # A run that used its whole limit still gets its after-run check: a fixed allowance, capped at
        # the hard deadline (the cleanup reserve lies between the run deadline and it).
        self.verify_ro_mounts(f"after {label}", self.check_allowance())
        if outcome is None:
            if code in DOCKER_INFRA_EXITS:
                outcome = "ERROR"
            elif self.diagnostic:
                outcome = "DIAGNOSTIC"  # the command's status stays in exit_code; never a pass
            elif code == 0:
                outcome = "PASSED" if mutant is None else "SURVIVED"
            else:
                outcome = "FAILED" if mutant is None else "KILLED"
        return Result(label, outcome, code, round(secs, 2), str(log_path), output_tail(log_path), str(d))

    def docker_env(self) -> dict[str, str]:
        return docker_client_env()

    def over_output(self, log) -> str | None:
        size = os.fstat(log.fileno()).st_size
        if self.err_log is not None:  # diagnostic mode: the bound covers both streams together
            size += os.fstat(self.err_log.fileno()).st_size
        if size > self.args.max_output_mib * 2**20:
            return f"output over {self.args.max_output_mib} MiB"
        return None

    def over_disk(self, d: Path) -> str | None:
        used, _entries, problem = dir_usage(d, self.args.max_files, 10.0)
        if problem:
            return problem
        if used > self.args.max_disk_mib * 2**20:
            return f"run directory over {self.args.max_disk_mib} MiB"
        if shutil.disk_usage(d).free < self.args.min_free_mib * 2**20:
            return f"free space under {self.args.min_free_mib} MiB"
        return None

    def watch_run(self, proc: subprocess.Popen, d: Path, log, start: float, limit: float) -> int | None:
        """Wait for the docker client, bounding what the run may consume on the host: its time,
        its captured output, the size of its own directory (the only host path it can write),
        and the free space left beside it. Past a bound, kill the client and return None, with
        self.overrun saying which bound."""
        last_size_check = 0.0
        while True:
            try:
                code = proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                code = None
            if code is not None:
                # A run that wrote past a bound just before exiting is still over it: check once
                # more before accepting the exit.
                self.overrun = self.over_output(log) or self.over_disk(d)
                return None if self.overrun else code
            now = time.monotonic()
            if now - start >= limit:
                self.overrun = "time"
            else:
                self.overrun = self.over_output(log)
                if not self.overrun and now - last_size_check >= 5.0:
                    last_size_check = now
                    self.overrun = self.over_disk(d)
            if self.overrun:
                proc.kill()
                proc.wait()
                return None


# The caller's resolved go settings the seed keeps (read from `go env`, never inherited raw).
SEED_GO_FACTS = ("GOPROXY", "GOSUMDB", "GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOINSECURE", "GOTOOLCHAIN")
# Variables the seed's network access may need, passed through unchanged.
SEED_PASS = ("PATH", "HOME", "USER", "LANG", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy",
             "https_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR")


def seed_env(seed: Path, shared_modcache: Path, facts: dict[str, str]) -> dict[str, str]:
    """The seed's whole environment, built from nothing: no caller variable that could point Go at
    a live file (GOWORK, GOFLAGS=-modfile=..., a go env file) reaches it. HOME is passed unchanged,
    never overridden."""
    env = {k: os.environ[k] for k in SEED_PASS if k in os.environ}
    env.update({k: facts[k] for k in SEED_GO_FACTS if facts.get(k)})
    env.update({
        "GOMODCACHE": str(seed / "gomodcache"),
        "GOPATH": str(seed / "gopath"),
        "GOCACHE": str(seed / "gocache"),
        "GOFLAGS": "-modcacherw",
        "GOWORK": "off",  # only the copy's own go.mod, never a workspace file named from outside
        "GOENV": "off",
        "GOPROXY": ",".join(p for p in (file_url(shared_modcache / "cache" / "download"), facts.get("GOPROXY", ""))
                            if p),
    })
    return env


def seed_modules(args, work: WorkDir, pristine: Path, shared_modcache: Path, facts: dict[str, str],
                 limit: float) -> None:
    """Fill an owned module cache from the unmutated tree. Reads the shared cache only as a file proxy."""
    seed = work.path / "seed"
    seed.mkdir()  # go mod download creates nothing for a module with no dependencies
    env = seed_env(seed, shared_modcache, facts)
    try:
        out = subprocess.run(["go", "mod", "download"], cwd=pristine, env=env, capture_output=True, text=True,
                             timeout=limit)
    except subprocess.TimeoutExpired as e:
        raise Stopped(f"seeding the module proxy took longer than {limit:.0f}s") from e
    (seed / "download.log").write_text(out.stdout + out.stderr)
    if out.returncode != 0:
        raise Refused(f"seeding the module proxy failed (log {seed / 'download.log'}):\n{out.stderr[-2000:]}")


# ---------------------------------------------------------------- main


def parse(argv: list[str]):
    p = argparse.ArgumentParser(description="Run mutation tests in a sandbox that cannot reach shared host state.")
    p.add_argument("--mutants", type=Path, help="the mutant list; required unless --diagnostic")
    p.add_argument("--diagnostic", action="store_true",
                   help="one run of the unmutated tree, no mutants: its raw stdout, stderr and exit status are "
                        "recorded as evidence, never as a pass (runner exit 7 when it completed)")
    p.add_argument("--ro-mount", action="append", default=[], metavar="SRC:DST:SHA256",
                   help=f"mount a copy the runner makes of directory SRC read-only at DST (one of "
                        f"{', '.join(RO_MOUNT_DESTS)}); the copy's --ro-manifest digest must be SHA256")
    p.add_argument("--ro-manifest", type=Path, metavar="DIR",
                   help="print DIR's manifest digest (the SHA256 --ro-mount checks) and exit; runs nothing")
    p.add_argument("--tree", type=Path, default=Path.cwd())
    p.add_argument("--image", help="an image present locally, best named by its immutable id (sha256:...); never pulled")
    p.add_argument("--network", default="none", help="docker network for the sandbox (default none)")
    p.add_argument("--timeout", type=int, default=1800, help="seconds per sandboxed run")
    p.add_argument("--deadline", type=int, default=0,
                   help="seconds for the whole run, every container included; 0 means none. Past it the "
                        "run stops, removes the containers it started and exits 6")
    p.add_argument("--memory", default="8g", help="docker --memory per sandboxed run")
    p.add_argument("--cpus", default="4", help="docker --cpus per sandboxed run")
    p.add_argument("--pids", type=int, default=4096, help="docker --pids-limit per sandboxed run")
    p.add_argument("--max-output-mib", type=int, default=64,
                   help="a run whose captured output passes this is stopped as ERROR")
    p.add_argument("--max-disk-mib", type=int, default=16384,
                   help="a run whose own directory (its only writable host path) passes this is stopped as ERROR")
    p.add_argument("--max-work-mib", type=int, default=32768,
                   help="the whole work directory (copies, seed, build caches) may not pass this; checked "
                        "before every copy into it")
    p.add_argument("--max-files", type=int, default=500000,
                   help="a run whose own directory passes this many entries is stopped as ERROR")
    p.add_argument("--min-free-mib", type=int, default=2048,
                   help="a run is stopped as ERROR when free space beside the work directory falls under this")
    p.add_argument("--workdir-root", type=Path, default=Path(tempfile.gettempdir()))
    p.add_argument("--exclude", action="append", default=list(DEFAULT_EXCLUDES),
                   help="top-level or nested names not copied into the sandbox tree")
    p.add_argument("--no-seed", action="store_true", help="the tree needs no modules: GOPROXY=off inside")
    p.add_argument("--no-confirm-kills", dest="confirm_kills", action="store_false")
    p.add_argument("--no-warm-gocache", dest="warm_gocache", action="store_false",
                   help="do not give each mutant a copy of the baseline's build cache")
    p.add_argument("--shared-modcache", type=Path, help="default: the caller's go env GOMODCACHE")
    p.add_argument("--shared-gocache", type=Path, help="default: the caller's go env GOCACHE")
    p.add_argument("--ro-max-files", type=int, default=RoLimits.files,
                   help="a --ro-mount directory may hold at most this many entries")
    p.add_argument("--ro-max-depth", type=int, default=RoLimits.depth,
                   help="a --ro-mount directory may nest at most this many levels")
    p.add_argument("--ro-max-mib", type=int, default=RoLimits.total_bytes >> 20,
                   help="a --ro-mount directory's files may total at most this many MiB")
    p.add_argument("--ro-max-file-mib", type=int, default=RoLimits.file_bytes >> 20,
                   help="one file in a --ro-mount directory may be at most this many MiB")
    p.add_argument("--keep", action="store_true", help="keep the work directory")
    p.add_argument("--report", type=Path, help="also write the JSON report here")
    p.add_argument("--docker", default="docker")
    p.add_argument("command", nargs=argparse.REMAINDER)
    args = p.parse_args(argv)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    # The deadline clock starts here, before any preflight, so it bounds the whole run.
    args.deadline_at = time.monotonic() + args.deadline if args.deadline else None
    args.tree = real(args.tree)
    if args.ro_manifest is not None:
        if args.command or args.mutants or args.diagnostic or args.ro_mount or args.image:
            p.error("--ro-manifest DIR prints a manifest digest and takes no run options")
        return args
    if not args.command:
        p.error("give the test command after --")
    if not args.image:
        p.error("the following arguments are required: --image")
    if args.diagnostic and args.mutants is not None:
        p.error("--diagnostic runs no mutants: --mutants is refused with it (no dummy mutant, no empty list)")
    if not args.diagnostic and args.mutants is None:
        p.error("the following arguments are required: --mutants (or --diagnostic)")
    if args.diagnostic:
        args.keep = True  # the raw stdout and stderr files live in the work directory
    return args


def resolve_shared(args) -> tuple[Path, Path, Path, dict[str, str]]:
    """The shared GOMODCACHE, GOCACHE and GOPATH, and the caller's go settings the seed keeps."""
    facts = go_env(["GOMODCACHE", "GOCACHE", "GOPATH", *SEED_GO_FACTS], dict(os.environ), args.deadline_at)
    modcache = real(args.shared_modcache or facts["GOMODCACHE"])
    gocache = real(args.shared_gocache or facts["GOCACHE"])
    gopath = real(facts["GOPATH"].split(os.pathsep)[0])
    return modcache, gocache, gopath, facts


def run_all(args, mutants: list[Mutant], runner: Runner, pristine: Path, report: dict) -> int:
    base = runner.run("baseline", pristine, None)
    report["results"].append(base.__dict__)
    print(f"baseline: {base.outcome} ({base.seconds}s)", flush=True)
    if base.outcome != "PASSED":
        print(f"mutate-sandboxed: the unmutated tree did not pass; log {base.log}", file=sys.stderr)
        return EXIT_BASELINE
    if args.warm_gocache:
        # The baseline's container wrote this tree: no symlink may lie on the path to it, and it
        # must resolve inside the baseline's own directory, or the host-side clone could read a
        # host directory into every later mutant's mount.
        runner.assert_stopped(base)  # nothing may still be changing the paths read below
        cache = plain_target(Path(base.dir), "sandbox/gocache")
        if not cache.is_dir():
            raise Refused("the baseline left no build cache directory to warm from")
        runner.room("the warm build cache", (cache,))
        clone_dir(cache, runner.work.path / "warm-gocache", runner.deadline)
    runner.discard(base)

    findings = []
    for mu in mutants:
        r = runner.run(mu.name, pristine, mu)
        line = f"{mu.name}: {r.outcome} ({r.seconds}s)"
        if r.outcome == "KILLED" and args.confirm_kills:
            again = runner.run(f"{mu.name} (again)", pristine, mu)
            r.__dict__["confirm"] = again.__dict__
            runner.discard(again)
            if again.outcome != "KILLED":
                r.outcome = "UNREPEATED-KILL"
                findings.append(f"{mu.name}: killed once, then {again.outcome} alone in a new sandbox")
            line = f"{mu.name}: {r.outcome} ({r.seconds}s; again {again.outcome})"
        if r.outcome in ("ERROR", "TIMEOUT"):
            findings.append(f"{mu.name}: {r.outcome}, log {r.log}")
        report["results"].append(r.__dict__)
        runner.discard(r)
        print(line, flush=True)

    final = runner.run("baseline (after)", pristine, None)
    report["results"].append(final.__dict__)
    runner.discard(final)
    print(f"baseline after: {final.outcome}", flush=True)
    if final.outcome != "PASSED":
        findings.append(f"the unmutated tree failed after the mutants: {final.outcome}, log {final.log}")
    report["findings"] = findings
    killed = sum(1 for r in report["results"] if r["outcome"] == "KILLED")
    print(f"mutants: {killed}/{len(mutants)} killed; findings: {len(findings)}", flush=True)
    for f in findings:
        print(f"FINDING: {f}", file=sys.stderr)
    return EXIT_FINDINGS if findings else EXIT_OK


DOCKER_STDERR_NOTE = "stderr is the docker client's: it carries the container's stderr and anything docker itself prints"


def stream_evidence(path: Path | None) -> dict:
    if path is None:
        return {"path": None}
    try:
        size = path.stat().st_size
    except OSError as e:
        size = f"unreadable: {e}"
    return {"path": str(path), "bytes": size, "sha256": file_digest(path), "tail": output_tail(path)}


def command_attribution(code: int | None) -> str:
    """What the docker client's exit status says about the command. docker run reports its own
    failures as 125-127, which a command can also return: those are ambiguous, never attributed."""
    if code is None:
        return "none: the docker client was stopped before it returned"
    if code < 0:
        return "none: the docker client died by a signal"
    if code in DOCKER_INFRA_EXITS:
        return "ambiguous: docker-or-command"
    return "command"


def run_diagnostic(runner: Runner, pristine: Path, report: dict) -> int:
    """One run of the unmutated tree, recorded as evidence. The report keeps apart the command's
    raw result (command_exit, always kept, with its attribution), settlement (the container
    confirmed removed or absent), integrity (the end-of-run checks, set by main) and evidence
    completeness; the overall exit is report["exit"]. Exit EXIT_DIAGNOSTIC only when the run
    completed and settled; never EXIT_OK, and command_exit 0 is never a gate success."""
    r = runner.run("diagnostic", pristine, None)
    report["results"].append(r.__dict__)
    diag = {"command_exit": r.exit_code, "command_exit_attribution": command_attribution(r.exit_code),
            "run_outcome": r.outcome, "settlement": "not checked", "integrity": "not checked",
            "evidence": "incomplete", "stdout": stream_evidence(Path(r.log)),
            "stderr": stream_evidence(runner.err_path), "stderr_note": DOCKER_STDERR_NOTE}
    report["diagnostic"] = diag
    # Settlement is positive and bounded: docker's --rm after the client returned is not taken on
    # trust. The run's container must be confirmed removed or absent by the owner-checked cleanup
    # call (each docker call under its own timeout) before the run's directory is touched.
    cidfile, name = runner.containers[r.name]
    runner.pending[name] = cidfile
    if not runner.remove_pending():
        diag.update(settlement="unconfirmed", status="not-completed: container not confirmed removed")
        report["findings"] = [f"diagnostic: container {name} not confirmed removed"]
        print(f"FINDING: diagnostic did not complete: container {name} not confirmed removed", file=sys.stderr)
        return EXIT_FINDINGS  # the run's directory is kept: the container may still mount it
    diag["settlement"] = "confirmed"
    runner.discard(r)
    if r.outcome == "DIAGNOSTIC":
        diag["status"] = "completed"
        return EXIT_DIAGNOSTIC  # main prints the DIAGNOSTIC line once the end-of-run checks held
    # ERROR (docker's own 125-127, a bound, a client signal) or TIMEOUT: the run did not complete.
    diag["status"] = f"not-completed: {r.outcome}"
    report["findings"] = [f"diagnostic: {r.outcome} (docker client exit {r.exit_code}), log {r.log}"]
    print(f"FINDING: diagnostic did not complete: {r.outcome} (docker client exit {r.exit_code})", file=sys.stderr)
    return EXIT_FINDINGS


def loud(msg: str) -> None:
    bar = "!" * 72
    print(f"\n{bar}\nMUTATE-SANDBOXED: SHARED STATE CHANGED. STOP AND TELL YOUR COORDINATOR.\n{msg}\n{bar}\n",
          file=sys.stderr, flush=True)


def main(argv: list[str]) -> int:
    try:
        args = parse(argv)
        if args.ro_manifest is not None:
            try:
                print(ro_manifest_sha256(args.ro_manifest, ro_limits(args)))
            except OSError as e:
                raise Refused(f"cannot read {args.ro_manifest}: {e}") from e
            return EXIT_OK
        mutants = [] if args.diagnostic else load_mutants(args.mutants, args.tree)
        ro_mounts = parse_ro_mounts(args.ro_mount)
        modcache, gocache, gopath, go_facts = resolve_shared(args)
    except Refused as e:
        print(f"mutate-sandboxed: refused: {e}", file=sys.stderr)
        return EXIT_REFUSED
    except Stopped as e:
        print(f"mutate-sandboxed: stopped: {e}", file=sys.stderr)
        return EXIT_STOPPED
    home = real(os.environ.get("HOME") or Path.home())
    forbidden = {"shared GOMODCACHE": modcache, "shared GOCACHE": gocache, "GOPATH": gopath, "HOME": home,
                 "live tree": args.tree, "docker socket": Path("/var/run/docker.sock")}
    watch = Watch({"GOMODCACHE": modcache, "GOMODCACHE/cache/download": modcache / "cache" / "download",
                   "GOCACHE": gocache, "GOPATH": gopath, "HOME": home, "live tree": args.tree},
                  children={"GOMODCACHE": modcache, "GOMODCACHE/cache/download": modcache / "cache" / "download",
                            "GOCACHE": gocache})
    for name, root in (("GOMODCACHE", modcache), ("GOCACHE", gocache)):
        if (root / SENTINEL).exists():
            watch.files[f"{name}/{SENTINEL}"] = root / SENTINEL
    report: dict = {"tree": str(args.tree), "image": args.image, "seeded": not args.no_seed,
                    "watched": {k: str(v) for k, v in watch.dirs.items()}, "results": []}
    if args.diagnostic:
        report.update(mode="diagnostic", gate="never")
    if ro_mounts:
        report["ro_mounts"] = [{"src": str(m.src), "dst": m.dst, "sha256": m.sha256} for m in ro_mounts]
    initial = watch.snapshot()
    report["identity_before"] = initial
    work = None
    runner = None
    # Undecided until a path below sets it: a path that sets nothing is never reported as a pass.
    code = EXIT_FINDINGS
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop_on_signal)
    try:
        check_workdir(args.workdir_root, {k: v for k, v in forbidden.items() if k != "HOME"})
        for m in ro_mounts:  # refused before anything is created or run
            check_ro_source(m, forbidden, ro_limits(args), args.deadline_at)
        left = args.deadline_at - time.monotonic() if args.deadline_at else 60.0
        if left <= 0:
            raise Stopped(f"the whole-run deadline ({args.deadline}s) passed before the image check")
        try:
            inspected = subprocess.run([args.docker, "image", "inspect", "--format", "{{json .Config.Volumes}}",
                                        args.image], capture_output=True, text=True,
                                       env=docker_client_env(), timeout=min(left, 60.0))
        except subprocess.TimeoutExpired as e:
            raise Stopped(f"docker image inspect took longer than {min(left, 60.0):.0f}s") from e
        if inspected.returncode != 0:
            raise Refused(f"image {args.image} is not present locally (or {args.docker} cannot reach a daemon); "
                          "this runner never pulls")
        refuse_declared_volumes(args.image, inspected.stdout)
        work = WorkDir(args.workdir_root)
        report["workdir"] = str(work.path)
        check_workdir(work.path, {k: v for k, v in forbidden.items() if k != "HOME"})
        runner = Runner(args, watch, forbidden, work, args.docker, mutants)  # reads live targets first
        pristine = work.path / "pristine"
        runner.room("copying the tree", (args.tree,), tuple(args.exclude))
        copy_tree(args.tree, pristine, tuple(args.exclude), runner.deadline)
        for i, m in enumerate(ro_mounts):
            runner.room(f"copying the --ro-mount for {m.dst}", (m.src,))
            prepare_ro_mount(m, work.path, i, forbidden, runner.ro_limits, runner.deadline)
            report["ro_mounts"][i]["copy"] = str(m.copy)
        runner.ro_mounts = ro_mounts
        runner.room("seeding")
        if not args.no_seed:
            seed_modules(args, work, pristine, modcache, go_facts, runner.remaining("seeding"))
            watch.verify(initial, "seeding the module proxy")
        if args.diagnostic:
            code = run_diagnostic(runner, pristine, report)
        else:
            code = run_all(args, mutants, runner, pristine, report)
    except SharedStateChanged as e:
        loud(str(e))
        report["shared_state_changed"] = str(e)
        code = EXIT_SHARED_CHANGED
        args.keep = True  # evidence
    except Refused as e:
        print(f"mutate-sandboxed: refused: {e}", file=sys.stderr)
        code = EXIT_REFUSED
    except Stopped as e:
        print(f"mutate-sandboxed: stopped: {e}; removing the containers this run started", file=sys.stderr)
        report["stopped"] = str(e)
        code = EXIT_STOPPED
        args.keep = True  # evidence
    except Exception as e:  # anything unexpected (an OSError from a host-side step, say) is a finding
        report["error"] = f"{type(e).__name__}: {e}"
        print(f"mutate-sandboxed: error: {type(e).__name__}: {e}", file=sys.stderr)
        code = EXIT_FINDINGS
        args.keep = True  # evidence
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)  # cleanup is not interrupted
        if runner:
            if not runner.remove_pending():  # the retry of anything an earlier attempt left
                left = ", ".join(runner.pending)
                report["containers_left"] = left
                print(f"mutate-sandboxed: CONTAINERS NOT CONFIRMED REMOVED: {left}; remove them by hand "
                      "after checking their owner label", file=sys.stderr)
                if code in (EXIT_OK, EXIT_DIAGNOSTIC):
                    code = EXIT_FINDINGS
                args.keep = True  # never delete a directory a container may still have mounted
            report["container_cleanup"] = runner.cleanup_log
            for line in runner.cleanup_log:
                print(f"mutate-sandboxed: container {line}", file=sys.stderr)
        # Every exit path, a stop by the deadline or a signal included, ends with the host check
        # against the state read at the start: a boundary failure is never reported as exit 6.
        if code != EXIT_SHARED_CHANGED:
            try:
                watch.verify(initial, "the end of the run")
                if runner:
                    for f, digest in runner.live.items():
                        if file_digest(args.tree / f) != digest:
                            raise SharedStateChanged(f"at the end of the run: the live tree's {f} changed")
                    # Its own allowance when a --deadline was given: the run's deadline may already
                    # have passed on a stop path, and this check must still run (overrun <= FINAL_CHECK_S).
                    final_by = time.monotonic() + FINAL_CHECK_S if args.deadline_at else None
                    runner.verify_ro_mounts("at the end of the run", final_by)
            except SharedStateChanged as e:
                loud(str(e))
                report["shared_state_changed"] = str(e)
                code = EXIT_SHARED_CHANGED
                args.keep = True
            except OSError as e:  # a check that cannot read the host fails closed
                loud(f"at the end of the run the host check could not read: {e}")
                report["shared_state_changed"] = f"final check unreadable: {e}"
                code = EXIT_SHARED_CHANGED
                args.keep = True
            except Stopped as e:  # the final check did not complete: never a pass, never 7
                print(f"mutate-sandboxed: the final read-only mount check did not complete: {e}", file=sys.stderr)
                report["final_check"] = f"incomplete: {e}"
                code = EXIT_STOPPED
                args.keep = True
        d = report.get("diagnostic")
        if isinstance(d, dict):
            # Separate facts, never merged: the raw command_exit stays as recorded; integrity,
            # settlement and evidence completeness are set here, after cleanup and the final checks.
            if code == EXIT_SHARED_CHANGED:
                d["integrity"] = "failed"
            elif "final_check" in report:
                d["integrity"] = "incomplete"
            else:
                d["integrity"] = "held"
            if "containers_left" in report:
                d["settlement"] = "unconfirmed"
            d["evidence"] = "complete" if code == EXIT_DIAGNOSTIC else "incomplete"
            if code == EXIT_SHARED_CHANGED:
                d["status"] = "invalid: shared state changed"
            elif d["settlement"] == "unconfirmed":
                d["status"] = "not-completed: container not confirmed removed"
            elif code != EXIT_DIAGNOSTIC and not str(d.get("status", "")).startswith("not-completed"):
                d["status"] = f"not-completed: runner exit {code}"
        try:
            report["identity_after"] = watch.snapshot()
        except OSError as e:
            report["identity_after"] = f"unreadable: {e}"
        # The work directory goes (when it may) BEFORE either report is written, so the exit both
        # reports carry is final: a removal that fails turns a pass into a finding, and the
        # directory, kept then, receives the report.
        kept = True
        if work:
            if args.keep or code in (EXIT_BASELINE, EXIT_FINDINGS):  # a failure keeps its evidence
                print(f"work directory kept: {work.path}", file=sys.stderr)
            else:
                try:
                    work.remove()
                    kept = False
                except (Refused, OSError) as e:
                    print(f"mutate-sandboxed: cleanup error: {e}", file=sys.stderr)
                    report["cleanup_error"] = f"{type(e).__name__}: {e}"
                    if code == EXIT_OK:  # a pass whose cleanup failed is a finding, and says so
                        code = EXIT_FINDINGS
                    print(f"work directory kept: {work.path}", file=sys.stderr)
        report["exit"] = code
        text = json.dumps(report, indent=2, default=str)
        if args.report:
            args.report.write_text(text)
        if work and kept:
            try:
                (work.path / "report.json").write_text(text)
            except OSError as e:  # a partly removed directory: --report, if given, still holds it
                print(f"mutate-sandboxed: cannot write {work.path / 'report.json'}: {e}", file=sys.stderr)
        if code == EXIT_DIAGNOSTIC:  # only now: settled, checked and both reports written
            d = report["diagnostic"]
            try:
                print(f"DIAGNOSTIC: command exit {d['command_exit']} (evidence only, never a pass; runner exit "
                      f"{EXIT_DIAGNOSTIC}); stdout {d['stdout']['path']}, stderr {d['stderr']['path']}", flush=True)
            except OSError:  # stdout closed (`| head`): the reports already hold the result
                try:
                    os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())  # no second error at exit
                except OSError:
                    pass
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
