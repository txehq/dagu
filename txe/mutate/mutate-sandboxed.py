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
  where the filesystem records one, birth time: st_birthtime on macOS, statx on Linux) of the
  shared GOMODCACHE, its cache/download, GOCACHE, GOPATH, HOME and the live tree; that at least one
  entry each of those held when the run began is still there, unchanged (a directory removed and
  recreated with its inode handed back holds none: TXE-8535); that no entry directly inside the
  shared GOMODCACHE, its cache/download or GOCACHE disappeared or was replaced; the content of a
  fixture sentinel file where one exists;
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
  mutate-sandboxed.py --node-seed-build NEWDIR --tree PNPM_WORKSPACE --image IMAGE [--node-seed-allow-build PKG]
  mutate-sandboxed.py --node-seed DIR --no-seed --mutants mutants.json --tree PNPM_WORKSPACE --image IMAGE -- CMD...

--node-seed-build installs a pnpm workspace's Linux node_modules once, in one container with network,
from its manifests alone and with lifecycle scripts disabled (TXE-8348); --node-seed copies it into the
tree before any run, refused unless its lockfile, manifests, image and content match. A tree with a
package.json or pnpm-lock.yaml at its root needs --node-seed (or --no-node-seed).

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
signal, every container this run started and has not confirmed gone (a client that returned proves nothing) is force-removed, by the
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
import struct
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
# The runner's COOPERATIVE bounds under --deadline D (TXE-8053; see Runner.__init__ and the README).
# They bound what the runner checks a clock around, not the process:
# - D, the ACTIVE AND INTEGRITY deadline: every run, settlement after a run and every integrity
#   check (the read-only mount re-hashes) ends by it; its last min(45, D/3) s are the reserve;
# - EMERGENCY_CLEANUP_S after D: the one budget every container-removal call past D consumes;
# - TERMINATION_MARGIN_S: the allowance a caller is told to add for the local steps left (the
#   end-of-run host check, the report writes, the work directory's removal, terminal output).
#   Those do host I/O with NO deadline of their own, and the finalizer ignores SIGTERM, SIGINT and
#   SIGHUP, so neither the margin nor D is enforced on them.
# The runner therefore makes NO process-exit guarantee. A caller that needs one must bound the
# process from outside (a hard deadline it enforces, e.g. SIGKILL, at D + EMERGENCY_CLEANUP_S +
# TERMINATION_MARGIN_S or later) and keep custody of what a kill leaves: the work directory with its
# cids/ (each container's id and name, owner-labelled with the run's token) for removal by hand.
EMERGENCY_CLEANUP_S = 10.0
TERMINATION_MARGIN_S = 5.0
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


# statx(2) (TXE-8535): Python's os.stat reports no birth time on Linux, and ext4 hands a freed inode
# straight back, so a directory removed and recreated there can match by device and inode alone.
STATX_BTIME, STATX_AT_FDCWD, STATX_AT_SYMLINK_NOFOLLOW = 0x800, -100, 0x100
STATX_SIZE, STATX_BTIME_OFFSET = 256, 80  # struct statx; stx_btime is {s64 tv_sec; u32 tv_nsec}
_statx: list = []  # [(ctypes, the libc function), or None where there is none], loaded on first use


def _statx_function():
    if not _statx:
        found = None
        if sys.platform.startswith("linux"):
            import ctypes
            try:
                fn = ctypes.CDLL(None, use_errno=True).statx
            except (OSError, AttributeError):  # no libc statx (glibc before 2.28, say)
                pass
            else:
                # Declared, never left to ctypes' defaults: an undeclared call read a wrong birth time
                # in the TXE-8535 probe.
                fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_uint, ctypes.c_void_p]
                fn.restype = ctypes.c_int
                found = (ctypes, fn)
        _statx.append(found)
    return _statx[0]


def statx_birth(path) -> int | None:
    """The birth time of path itself (never followed through a final symlink), in nanoseconds, from
    statx(2); None where there is no statx, it fails, or the filesystem records no birth time."""
    found = _statx_function()
    if found is None:
        return None
    ctypes, fn = found
    buf = ctypes.create_string_buffer(STATX_SIZE)
    if fn(STATX_AT_FDCWD, os.fsencode(path), STATX_AT_SYMLINK_NOFOLLOW, STATX_BTIME, buf) != 0:
        return None
    (mask,) = struct.unpack_from("=I", buf, 0)  # stx_mask: the fields the filesystem filled
    if not mask & STATX_BTIME:
        return None
    sec, nsec = struct.unpack_from("=qI", buf, STATX_BTIME_OFFSET)
    return sec * 1_000_000_000 + nsec


def birth_time(path, st: os.stat_result):
    """path's birth time: st_birthtime where the OS reports one (macOS), else statx's (Linux)."""
    birth = getattr(st, "st_birthtime", None)
    return birth if birth is not None else statx_birth(path)


def identity(path: Path) -> dict | None:
    """The identity of path itself (never followed through a final symlink), or None if absent."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:  # unreadable is a distinct state, so a change to it is seen, never skipped
        return {"unreadable": e.errno}
    ident = {"dev": st.st_dev, "ino": st.st_ino, "symlink": os.path.islink(path)}
    birth = birth_time(path, st)
    if birth is not None:
        ident["birth"] = birth
    return ident


def file_digest(path: Path) -> str | None:
    """sha256 of the file, read in bounded chunks (a log far over its bound is never held in memory
    whole); None when it does not exist; "unreadable: errno N" for any other error, mid-read included."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except FileNotFoundError:
        return None
    except OSError as e:
        return f"unreadable: errno {e.errno}"
    return h.hexdigest()


@dataclass
class Watch:
    """Paths whose identity must not change, and files whose content must not change."""

    dirs: dict[str, Path]
    files: dict[str, Path] = field(default_factory=dict)
    # Directories whose existing entries must neither disappear nor be replaced. New entries are
    # fine: other sessions fill the shared caches while a run is in progress.
    children: dict[str, Path] = field(default_factory=dict)
    # The entries directly inside each watched directory when the Watch first looked (TXE-8535). A
    # directory removed and recreated holds none of them, even when its device, inode and every
    # time it reports match. Entries added, and some removed or replaced, are fine: HOME and the
    # live tree change during a run. Kept out of snapshot(), so a report's identity is not a listing.
    anchors: dict[str, dict] | None = field(default=None, init=False)

    def snapshot(self) -> dict:
        if self.anchors is None:
            self.anchors = {}
            for name, p in self.dirs.items():
                top = entries(p)
                if top and "<unreadable>" not in top:  # an unreadable one is the identity's to see
                    self.anchors[name] = top
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
        lines = [f"  {k}: {self.describe(k)}\n    before {before[k]}\n    after  {after.get(k)}" for k in changed]
        for name, top in sorted((self.anchors or {}).items()):
            now = entries(self.dirs[name])
            if not any(now.get(e) == v for e, v in top.items()):  # names are never printed: HOME's are private
                lines.append(f"  top level of {name}: {self.dirs[name]}\n    none of the {len(top)} entries it held "
                             "when the run began is still there, unchanged: it was removed and recreated, or "
                             f"cannot be read ({len(now)} entries now)")
        if lines:
            raise SharedStateChanged(f"after {when}:\n" + "\n".join(lines))

    def describe(self, key: str) -> str:
        return str(self.dirs.get(key) or self.files.get(key) or self.children.get(key[len("entries of "):]))


def entries(d: Path) -> dict:
    """The identity (device, inode and, where there is one, birth time) of each entry directly
    inside d (empty when d is absent or unreadable)."""
    out = {}
    try:
        with os.scandir(d) as it:
            for e in it:
                try:
                    st = e.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                birth = birth_time(e.path, st)
                out[e.name] = [st.st_dev, st.st_ino] + ([] if birth is None else [birth])
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


MOUNT_FIELD_FORBIDDEN = {",": "a comma", '"': "a double quote", "\n": "a line feed", "\r": "a carriage return"}


def check_mount_field(what: str, value: str) -> None:
    """Refuse a path that docker's --mount cannot carry as written. The value is comma-separated
    key=value fields (CSV), and this runner does not quote, so a comma, a double quote or a line
    break would split or corrupt a field. Every other character (spaces included) is passed as is."""
    for ch, desc in MOUNT_FIELD_FORBIDDEN.items():
        if ch in value:
            raise Refused(f"{what} {value!r} contains {desc}, which docker's comma-separated --mount value cannot "
                          "carry unquoted; use a path without commas, double quotes or line breaks "
                          "(for the work directory: pass --workdir-root elsewhere)")


def check_mounts(mounts: list[tuple[Path, str, bool]], owned: Path, forbidden: dict[str, Path]) -> None:
    """Refuse any bind mount that could expose host state, or that docker's --mount cannot carry.

    Every source must lie inside the run's own work directory, and must neither contain nor lie
    inside a forbidden path (the shared caches, GOPATH, HOME, the Docker socket, the live tree).
    Every source and target is exactly what docker_argv writes (check_mount_field).
    """
    owned = real(owned)
    for src, dst, _ro in mounts:
        check_mount_field("mount source", str(real(src)))
        check_mount_field("mount target", dst)
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
    """main checks --workdir-root here before its first docker call, so a root whose run directory
    could never be mounted is refused with no docker call at all."""
    w = real(work)
    check_mount_field("work directory", str(w))
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
    check_links(dst, deadline)


def check_links(dst: Path, deadline: float | None = None) -> None:
    """Refuse any symlink under dst that resolves outside it (see copy_tree)."""
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


def call_limit(cap: float, end: float | None) -> float:
    """A cleanup call's timeout: cap, cut to what is left of the ONE cleanup budget ending at `end`.
    Every call consumes that same budget (none restarts an allowance of its own); once it is spent
    no further call starts: TimeoutExpired, so the container stays pending and is reported."""
    if end is None:
        return cap
    left = end - time.monotonic()
    if left <= 0:
        raise subprocess.TimeoutExpired("docker (the emergency cleanup budget is spent)", 0)
    return min(cap, left)


def remove_owned_container(docker: str, cidfile: Path, name: str, token: str, env: dict[str, str],
                           end: float | None = None) -> str:
    """Force-remove one container this run started, and nothing else.

    The container is the one docker recorded in cidfile (kept outside every mount, so no sandboxed
    code can rewrite it), or failing that the run's unique name. It is removed only when docker
    reports that exact name and this run's owner label on it. Every docker call consumes what is
    left of the cleanup budget ending at `end` (call_limit). Returns what happened.
    """
    hard_end = end
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
        # The budgets under --deadline, none ever extended (TXE-8053; the sum is at EMERGENCY_CLEANUP_S):
        # - the COMMAND budget: every run ends by `deadline` (hard_end - reserve), each at most --timeout;
        # - the RESERVE, min(45, D/3) s between `deadline` and `hard_end`: settlement after a run and
        #   the integrity checks (the read-only mount re-hashes, after each run and at the end). With a
        #   view it must cover two full hashes; that it does is not measured here. Spent = Stopped = 6;
        # - `hard_end`, the ACTIVE AND INTEGRITY deadline: no run, settlement or integrity check runs past it;
        # - `cleanup_end` = hard_end + EMERGENCY_CLEANUP_S: the one budget every removal call consumes;
        # - after it, the TERMINATION_MARGIN_S local steps. The end-of-run host check (watch.verify:
        #   identities and one-level listings of the watched directories) has no deadline of its own
        #   (pre-existing) and is counted in that margin.
        self.hard_end = args.deadline_at
        self.reserve = min(45.0, args.deadline / 3) if args.deadline else 0.0
        self.deadline = args.deadline_at - self.reserve if args.deadline_at else None
        self.cleanup_end = args.deadline_at + EMERGENCY_CLEANUP_S if args.deadline_at else None
        # Every mutation target's live content, read before the tree was copied.
        self.live = {m.file: file_digest(args.tree / m.file) for m in live_targets}
        # (name, cidfile) of every container started and not yet confirmed gone (owner-checked).
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
        # TXE-8348: a node run (the seed's install, or any run with --node-seed) gets the node sandbox dirs.
        self.node = getattr(args, "node_seed", None) is not None or getattr(args, "node_seed_build", None) is not None

    def verify_ro_mounts(self, when: str, deadline: float | None = None) -> None:
        """Each read-only mount's copy still passes verify_ro_copy. Called immediately before every
        mount (by the run deadline) and after every run and at the end of the run (by hard_end, in
        the reserve): once the copy was verified, a failure means the read-only boundary failed, so
        it is exit 3 with no verdict, never a refusal. A deadline passed during the check raises
        Stopped: the check did not complete, which is never a pass."""
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

    def remove_pending(self, emergency: bool = False) -> bool:
        """Remove every pending container. An entry leaves pending only when its removal or its
        absence is confirmed; anything else stays, for the finalizer's retry. Returns whether
        nothing is left pending. During the run (settlement, and clearing a stopped run) every
        call draws on the active deadline, hard_end; only the finalizer's emergency removal
        (emergency=True) draws on the one budget that ends at cleanup_end."""
        end = self.cleanup_end if emergency else self.hard_end
        for name, cidfile in list(self.pending.items()):
            try:
                outcome = remove_owned_container(self.docker, cidfile, name, self.work.token,
                                                 self.docker_env(), end)
            except (OSError, subprocess.TimeoutExpired) as e:
                outcome = f"{name}: cleanup error {e}"
            self.cleanup_log.append(outcome)
            if outcome.endswith(": removed") or outcome.endswith(": absent"):
                del self.pending[name]
        return not self.pending

    def settle(self, result: "Result") -> tuple[bool, bool]:
        """Confirm the container of a finished run removed or absent, owner-checked, drawing on the
        active deadline. Returns (confirmed, late): late when the deadline was reached. Until it is
        confirmed the container stays pending, for the finalizer."""
        cidfile, name = self.containers[result.name]
        self.pending[name] = cidfile
        confirmed = self.remove_pending()
        return confirmed, self.hard_end is not None and time.monotonic() >= self.hard_end

    def settle_or_stop(self, result: "Result") -> None:
        """settle, for mutation mode: no further run starts, and no run directory is read or
        discarded, until the container is confirmed gone; a settlement that is late or cannot be
        confirmed is Stopped (6), the container left to the finalizer."""
        confirmed, late = self.settle(result)
        if late:
            raise Stopped(f"the whole-run deadline ({self.args.deadline}s) passed during the settlement of {result.name}")
        if not confirmed:
            raise Stopped(f"the container of {result.name} could not be confirmed removed: " + ", ".join(self.pending))

    def clear_pending(self) -> None:
        """After a run that stopped abnormally: no further run starts while one of its
        containers may still be running."""
        if not self.remove_pending():
            raise Stopped("a container could not be confirmed removed: " + ", ".join(self.pending))

    # A run gets its own directory: src (the tree copy) and sandbox/<env dirs>. With `inputs` (the
    # node seed's install, TXE-8348) src holds only those manifest files, never the tree's source.
    def prepare(self, label: str, pristine: Path, mutant: Mutant | None,
                inputs: dict[str, str] | None = None) -> Path:
        self.seq += 1
        d = self.work.path / f"{self.seq:03d}-{''.join(c if c.isalnum() else '-' for c in label)[:40]}"
        d.mkdir()
        if inputs is None:
            clone_dir(pristine, d / "src", self.deadline)
        else:
            for rel, digest in inputs.items():
                check_deadline(self.deadline, "copying the seed's manifests")
                dst = d / "src" / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(plain_target(pristine, rel), dst)
                if file_digest(dst) != digest:
                    raise Refused(f"{rel} changed while the seed's manifests were copied")
            (d / "sandbox" / "pnpm-store").mkdir(parents=True)
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
        for sub in [*SANDBOX_ENV_DIRS.values(), *(NODE_ENV_DIRS.values() if self.node else ())]:
            (sb / sub).mkdir(parents=True)
        warm = self.work.path / "warm-gocache"
        if self.args.warm_gocache and warm.is_dir() and inputs is None:
            shutil.rmtree(sb / "gocache")
            clone_dir(warm, sb / "gocache", self.deadline)
        return d

    def docker_argv(self, d: Path, name: str, cidfile: Path, command: list[str] | None = None,
                    network: str | None = None) -> list[str]:
        """The container for one run. `command` and `network` are given only for the node seed's
        install (TXE-8348); every other run takes the caller's command and --network."""
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
        if self.node:
            env.update({k: f"/work/sandbox/{v}" for k, v in NODE_ENV_DIRS.items()})
        if command is not None:
            env["MUTATE_NODE_STORE"] = NODE_STORE
        if any(m.dst == "/work/src/.git" for m in self.ro_mounts):
            # git skips its optional index refresh, which would try .git/index.lock on a read-only
            # view; a command that needs a lock fails on the read-only mount instead of half-writing.
            env["GIT_OPTIONAL_LOCKS"] = "0"
        # --log-driver none: Docker keeps no second, unbounded copy of the output on its data root;
        # the attached stream the runner captures (and bounds) is unaffected.
        argv = [self.docker, "run", "--rm", "--pull", "never", "--log-driver", "none", "--name", name,
                "--cidfile", str(cidfile),
                "--label", f"{OWNER_LABEL}={self.work.token}", "--network", network or self.args.network,
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", str(self.args.pids),
                "--memory", self.args.memory, "--cpus", self.args.cpus,
                "--read-only", "--tmpfs", "/tmp:rw,size=256m", "--user", f"{os.getuid()}:{os.getgid()}",
                "--workdir", "/work/src", "--entrypoint", ""]
        for src, dst, ro in mounts:
            argv += ["--mount", f"type=bind,source={real(src)},target={dst}" + (",readonly" if ro else "")]
        for k in sorted(env):
            argv += ["--env", f"{k}={env[k]}"]
        # Node runs launch by the immutable id resolved once at the start (resolve_image_id), the id the
        # seed records and is checked against: a tag retargeted mid-run cannot swap the image.
        image = self.args.image_id if self.node and getattr(self.args, "image_id", None) else self.args.image
        return argv + [image, *(self.args.command if command is None else command)]

    def run(self, label: str, pristine: Path, mutant: Mutant | None, inputs: dict[str, str] | None = None,
            command: list[str] | None = None, network: str | None = None) -> Result:
        before = self.watch.snapshot()
        self.remaining(label)  # the deadline is checked before the run's own copies start
        warm = self.work.path / "warm-gocache"
        self.room(label, (pristine, warm) if self.args.warm_gocache and warm.is_dir() else (pristine,))
        d = self.prepare(label, pristine, mutant, inputs)
        name = f"mutate-sandboxed-{self.work.token[:12]}-{self.seq:03d}"
        # Outside every mount: sandboxed code cannot rewrite which container cleanup removes.
        cidfile = self.work.path / "cids" / f"{self.seq:03d}.cid"
        cidfile.parent.mkdir(exist_ok=True)
        argv = self.docker_argv(d, name, cidfile, command, network)
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
        with open(log_path, "wb") as log, open(self.err_path or os.devnull, "wb") as errf:
            self.err_log = errf if self.err_path else None
            proc = subprocess.Popen(argv, stdout=log, stderr=errf if self.err_path else subprocess.STDOUT,
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
                err(f"mutate-sandboxed: {label}: stopped: {self.overrun}")
        elif code < 0:
            # The docker client died by a signal: nothing shows the container finished.
            self.clear_pending()
            outcome = "ERROR"
        # A client that returned normally proves nothing about its container (--rm is not taken on
        # trust): it STAYS pending through the checks below, so an exception there leaves it to the
        # finalizer's owner-checked emergency removal, and it leaves pending only on an owner-checked
        # confirmation of removal or absence (settle, or the finalizer).
        secs = time.monotonic() - start
        # The boundary check comes before any verdict: a run that touched host state has no result.
        self.watch.verify(before, f"{label}")
        for f, digest in self.live.items():
            if file_digest(self.args.tree / f) != digest:
                raise SharedStateChanged(f"after {label}: the live tree's {f} changed")
        # The after-run check is post-run work: it runs in the reserve, by the outer deadline, never past it.
        self.verify_ro_mounts(f"after {label}", self.hard_end)
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


# ---------------------------------------------------------------- the node seed (TXE-8348)
#
# A pnpm workspace's node_modules on a Mac holds macOS binaries (esbuild, rollup, rolldown), and a
# run's container is Linux with no network. --node-seed-build installs a Linux node_modules ONCE, in
# one container with network, from the workspace's manifests alone (no source file of the tree is
# in that container), with every lifecycle script disabled except an explicit allowlist, and
# writes it to a seed directory keyed by the lockfile's sha256. --node-seed copies that seed into
# the tree before any run; every run stays offline. A tree with a package.json or pnpm-lock.yaml
# at its root and no seed is refused, as is a seed whose lockfile, manifests, image or content
# differs from what it was built with.

NODE_SEED_FORMAT = 1
NODE_TREE_MARKERS = ("package.json", "pnpm-lock.yaml")
# What the seed's install sees: these root files when present, and every package.json.
NODE_ROOT_INPUTS = ("pnpm-lock.yaml", "pnpm-workspace.yaml", ".npmrc")
# npm's package-name rule (lower case, optional scope): an allowlisted name is never shell text.
NPM_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$")
# Extra sandbox directories for node runs (the seed and every run with --node-seed). HOME stays unset.
NODE_ENV_DIRS = {"XDG_DATA_HOME": "xdg-data", "XDG_STATE_HOME": "xdg-state", "npm_config_cache": "npm-cache"}
NODE_STORE = "/work/sandbox/pnpm-store"
# The seed container's whole command: fixed here, never from the caller or the tree. `set -x`
# records each command as it ran; allowlisted package names arrive as positional arguments.
# pnpm 10's build policy blocks even a named `pnpm rebuild` of a package the workspace has not
# approved, silently (measured with pnpm 10.33.0, 2026-11-24). With dangerously-allow-all-builds
# the named rebuild runs exactly the packages named: another package's postinstall and the
# workspace's own stayed unrun in the same measurement. `-r` makes it reach a package that only
# a workspace project depends on; without it the rebuild ran nothing there (same measurement).
# The rebuild carries the install's pnpmfile and package-manager settings: it rejects the
# --ignore-pnpmfile flag, and --config.ignore-pnpmfile=true kept a .pnpmfile.cjs unloaded where the
# same rebuild without it loaded one (pnpm 10.33.0, measured). The install's other flags do not
# apply to a rebuild: it resolves nothing (--frozen-lockfile), imports nothing
# (--package-import-method), and its scripts are the point (--ignore-scripts).
NODE_SEED_SCRIPT = """set -eux
pnpm --version
pnpm install --frozen-lockfile --ignore-scripts --ignore-pnpmfile --package-import-method=copy \
 --config.manage-package-manager-versions=false --store-dir="$MUTATE_NODE_STORE" --reporter=append-only
if [ "$#" -gt 0 ]; then pnpm rebuild -r --config.dangerously-allow-all-builds=true --config.ignore-pnpmfile=true \
 --config.manage-package-manager-versions=false --store-dir="$MUTATE_NODE_STORE" --reporter=append-only "$@"; fi
"""
WORKSPACE_SCRIPTS = ("preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare")
DEPENDENCY_SCRIPTS = ("preinstall", "install", "postinstall")
JSON_CAP = 1 << 20


# The closed set (TXE-8348): the pnpm configuration and layout features the seed was built and
# tested for, okr/web's on 2026-11-24. Anything else is refused by name, at build and at apply,
# never built into a different seed. Supporting more is a reviewed change to these lists and
# their tests.
WORKSPACE_KEYS = {"packages", "overrides", "ignoredBuiltDependencies"}
LOCKFILE_KEYS = {"lockfileVersion", "settings", "overrides", "importers", "packages", "snapshots"}
LOCKFILE_VERSIONS = {"'9.0'"}
LOCKFILE_SETTINGS = {"autoInstallPeers": "true", "excludeLinksFromLockfile": "false"}
# Manifest keys pnpm's install reads that the tested layout uses, and keys the install never reads.
MANIFEST_KEYS = {"name", "version", "private", "type", "scripts", "engines", "packageManager", "dependencies",
                 "devDependencies", "peerDependencies", "bin",
                 "description", "license", "author", "contributors", "repository", "homepage", "bugs", "keywords",
                 "main", "module", "types", "typings", "files", "exports", "imports", "sideEffects", "browser"}
DEPENDENCY_FIELDS = ("dependencies", "devDependencies", "peerDependencies")
# A registry version, range or dist-tag (no ':' or '/', so no file:, link:, git, URL or GitHub
# shorthand), `workspace:*`, or an npm alias of a registry version.
SPEC_RANGE = re.compile(r"^[0-9A-Za-z.^~<>=| *+-]+$")
SPEC_ALIAS = re.compile(r"^npm:(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*@[0-9A-Za-z.^~<>=| *+-]+$")
CONFIG_CAP = 64 << 20


def config_text(root: Path, rel: str) -> str:
    p = plain_target(root, rel)
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as e:
        raise Refused(f"cannot open {rel}: {e}") from e
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Refused(f"{rel} is not a regular file")
        raw = f.read(CONFIG_CAP + 1)
    if len(raw) > CONFIG_CAP:
        raise Refused(f"{rel} is over {CONFIG_CAP} bytes")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Refused(f"{rel} is not UTF-8") from None


YAML_KEY = re.compile(r"^(?:'([^']*)'|([A-Za-z0-9._/(][A-Za-z0-9._/@()+~-]*)):(?: (.*))?$")


def yaml_block(text: str, rel: str):
    """A block-style YAML document as nested dicts and lists of string scalars, read by a
    deliberately small grammar, the one pnpm writes: `key: value`, `key:` with an indented block
    below, and `- scalar` list items; keys bare or single-quoted. A scalar is bare or single-quoted
    (no escape); `{...}` and `[...]` stay raw text for the caller to match whole. Refused, never
    guessed: a duplicate key, tabs, a double-quoted string, an anchor, alias, tag or block scalar,
    a list item holding a mapping, a key with no value and no block, and a document marker."""
    lines = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        body = line.lstrip(" ")
        if "\t" in line or " #" in body:
            raise Refused(f"{rel}:{n}: tabs and trailing comments are outside the YAML the seed reads")
        lines.append((n, len(line) - len(body), body))

    def scalar(raw: str, n: int) -> str:
        if raw.startswith("'"):
            if len(raw) < 2 or not raw.endswith("'") or "'" in raw[1:-1]:
                raise Refused(f"{rel}:{n}: {raw[:60]!r} is not a plain single-quoted scalar")
            return raw[1:-1]
        if not raw or raw[0] in "\"&*!|>%@`" or raw in ("~", "null"):
            raise Refused(f"{rel}:{n}: the value {raw[:60]!r} is outside the YAML the seed reads")
        return raw

    def block(i: int, indent: int):
        is_list = lines[i][2].startswith("- ")
        out: dict | list = [] if is_list else {}
        while i < len(lines):
            n, ind, body = lines[i]
            if ind < indent:
                break
            if ind > indent or body.startswith("- ") != is_list:
                raise Refused(f"{rel}:{n}: {body[:60]!r} does not fit its block (YAML the seed reads)")
            if is_list:
                item = body[2:]
                if YAML_KEY.match(item) and not item.startswith("'"):
                    raise Refused(f"{rel}:{n}: a list item holding a mapping is outside the YAML the seed reads")
                out.append(scalar(item, n))
                i += 1
                continue
            m = YAML_KEY.match(body)
            if not m:
                raise Refused(f"{rel}:{n}: {body[:60]!r} is outside the YAML the seed reads (block mappings only)")
            key = m.group(1) if m.group(1) is not None else m.group(2)
            if key in out:
                raise Refused(f"{rel}:{n}: the key {key!r} is given twice")
            i += 1
            if m.group(3) is not None:
                out[key] = scalar(m.group(3), n)
                if i < len(lines) and lines[i][1] > indent:
                    raise Refused(f"{rel}:{lines[i][0]}: an indented block under a key that has a value")
            elif i < len(lines) and lines[i][1] > indent:
                out[key], i = block(i, lines[i][1])
            else:
                raise Refused(f"{rel}:{n}: the key {key!r} has no value")
        return out, i

    if not lines:
        return {}
    if lines[0][1] != 0:
        raise Refused(f"{rel}:{lines[0][0]}: the document must start at column 0")
    doc, end = block(0, 0)
    if end != len(lines) or not isinstance(doc, dict):
        raise Refused(f"{rel}: not one block mapping (YAML the seed reads)")
    return doc


# Nested values of the closed set, matched whole. A name is npm's; a version is a registry version
# with pnpm's optional peer suffix; nothing below admits ':' except the one `link:` form noted.
PKG_NAME = r"(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+"
REG_VERSION = r"[0-9][0-9A-Za-z.+-]*(?:\([A-Za-z0-9._~@/+()-]*\))*"
NAME_RE = re.compile(rf"^{PKG_NAME}$")
LOCK_VERSION = re.compile(rf"^(?:{PKG_NAME}@)?{REG_VERSION}$")  # `x@1.0.0` is an npm: alias's version
PKG_KEY = re.compile(rf"^{PKG_NAME}@[0-9][0-9A-Za-z.+-]*$")
SNAP_KEY = re.compile(rf"^{PKG_NAME}@{REG_VERSION}$")
GLOB_RE = re.compile(r"^!?[A-Za-z0-9._*/-]+$")
RESOLUTION = re.compile(r"^\{integrity: sha512-[A-Za-z0-9+/]+=*\}$")
FLOW_ENGINES = re.compile(r"^\{[A-Za-z0-9_-]+: '?[0-9A-Za-z.^~<>=| *+-]+'?(?:, [A-Za-z0-9_-]+: '?[0-9A-Za-z.^~<>=| *+-]+'?)*\}$")
FLOW_PLATFORMS = re.compile(r"^\[!?[A-Za-z0-9_-]+(?:, !?[A-Za-z0-9_-]+)*\]$")
PACKAGE_FIELDS = {"resolution", "engines", "peerDependencies", "peerDependenciesMeta", "hasBin", "cpu", "os", "libc"}
SNAPSHOT_FIELDS = {"dependencies", "optionalDependencies", "transitivePeerDependencies", "optional"}
IMPORTER_FIELDS = {"dependencies", "devDependencies", "optionalDependencies"}


def node_spec_ok(spec) -> bool:
    return isinstance(spec, str) and bool(spec == "workspace:*" or SPEC_RANGE.fullmatch(spec)
                                          or SPEC_ALIAS.fullmatch(spec))


def check_node_config(root: Path, inputs: dict[str, str]) -> dict:
    """Refuse a workspace whose pnpm configuration or layout is outside the closed set above: every
    key and every nested value of .npmrc, pnpm-workspace.yaml, pnpm-lock.yaml and the manifests.
    Returns the lockfile it checked, as yaml_block read it."""
    def refuse(where: str, what: str) -> None:
        raise Refused(f"{where}: {what} is outside the pnpm configuration the node seed supports (TXE-8348: "
                      "okr/web's, as tested); supporting it is a reviewed change to the runner")

    def mapping(where: str, v) -> dict:
        if v == "{}":
            return {}
        if not isinstance(v, dict):
            refuse(where, f"the value {str(v)[:60]!r} (a mapping is expected)")
        return v

    def overrides(where: str, v) -> None:
        for name, spec in mapping(where, v).items():
            if not NAME_RE.fullmatch(name):
                refuse(where, f"the override selector {name!r} (a plain package name only)")
            if spec == "workspace:*" or not node_spec_ok(spec):
                refuse(where, f"the override {name}: {spec!r}")

    if ".npmrc" in inputs:
        for n, line in enumerate(config_text(root, ".npmrc").splitlines(), 1):
            if line.strip() and not line.lstrip().startswith(("#", ";")):
                refuse(f".npmrc:{n}", f"the setting {line.strip()[:60]!r} (no .npmrc setting is supported)")
    if "pnpm-workspace.yaml" in inputs:
        ws = yaml_block(config_text(root, "pnpm-workspace.yaml"), "pnpm-workspace.yaml")
        for key, v in ws.items():
            if key not in WORKSPACE_KEYS:
                refuse("pnpm-workspace.yaml", f"the setting {key!r}")
            if key == "overrides":
                overrides("pnpm-workspace.yaml overrides", v)
                continue
            if not isinstance(v, list):
                refuse(f"pnpm-workspace.yaml {key}", f"the value {str(v)[:60]!r} (a list is expected)")
            for item in v:
                glob = item[1:] if key == "packages" and item.startswith("!") else item
                if not (GLOB_RE if key == "packages" else NAME_RE).fullmatch(item) or ".." in glob.split("/") \
                        or glob.startswith("/"):
                    refuse(f"pnpm-workspace.yaml {key}", f"the entry {item!r}")  # a glob stays inside the tree
    lock = yaml_block(config_text(root, "pnpm-lock.yaml"), "pnpm-lock.yaml")
    for key in lock:
        if key not in LOCKFILE_KEYS:
            refuse("pnpm-lock.yaml", f"the section {key!r}")
    if lock.get("lockfileVersion") not in {v.strip("'") for v in LOCKFILE_VERSIONS}:
        refuse("pnpm-lock.yaml", f"lockfileVersion {lock.get('lockfileVersion')!r}")
    for k, v in mapping("pnpm-lock.yaml settings", lock.get("settings", {})).items():
        if LOCKFILE_SETTINGS.get(k) != v:
            refuse("pnpm-lock.yaml settings", f"{f'{k}: {v}'!r}")
    overrides("pnpm-lock.yaml overrides", lock.get("overrides", {}))
    projects = set(project_dirs(inputs))
    for imp, entry in mapping("pnpm-lock.yaml importers", lock.get("importers", {})).items():
        where = f"pnpm-lock.yaml importers {imp}"
        if imp not in projects:
            refuse(where, "an importer that is not a workspace project")
        for field, deps in mapping(where, entry).items():
            if field not in IMPORTER_FIELDS:
                refuse(where, f"the field {field!r}")
            for name, dep in mapping(f"{where} {field}", deps).items():
                d = mapping(f"{where} {field} {name}", dep)
                spec, ver = d.get("specifier"), d.get("version")
                if set(d) != {"specifier", "version"} or not NAME_RE.fullmatch(name) or not node_spec_ok(spec):
                    refuse(f"{where} {field}", f"the entry {name}: {d!r}")
                if spec == "workspace:*":
                    # The one link: form: pnpm's link to a workspace project, which must be one.
                    target = ver[5:] if isinstance(ver, str) and ver.startswith("link:") else None
                    if target is None or os.path.normpath(os.path.join(imp, target)) not in projects:
                        refuse(f"{where} {field}", f"the workspace version {name}: {ver!r}")
                elif not isinstance(ver, str) or not LOCK_VERSION.fullmatch(ver):
                    refuse(f"{where} {field}", f"the version {name}: {ver!r}")
    for key, entry in mapping("pnpm-lock.yaml packages", lock.get("packages", {})).items():
        where = f"pnpm-lock.yaml packages {key}"
        if not PKG_KEY.fullmatch(key):
            refuse("pnpm-lock.yaml packages", f"the package {key!r} (registry packages only)")
        e = mapping(where, entry)
        if not RESOLUTION.fullmatch(str(e.get("resolution", ""))):
            refuse(where, f"the resolution {str(e.get('resolution'))[:80]!r} (a registry integrity only)")
        for field, v in e.items():
            if field not in PACKAGE_FIELDS:
                refuse(where, f"the field {field!r}")
            ok = {"resolution": True, "hasBin": v == "true",
                  "engines": isinstance(v, str) and bool(FLOW_ENGINES.fullmatch(v)),
                  "cpu": isinstance(v, str) and bool(FLOW_PLATFORMS.fullmatch(v)),
                  "os": isinstance(v, str) and bool(FLOW_PLATFORMS.fullmatch(v)),
                  "libc": isinstance(v, str) and bool(FLOW_PLATFORMS.fullmatch(v)),
                  "peerDependencies": isinstance(v, dict) and all(NAME_RE.fullmatch(k) and isinstance(r, str)
                                                                  and SPEC_RANGE.fullmatch(r) for k, r in v.items()),
                  "peerDependenciesMeta": isinstance(v, dict) and all(NAME_RE.fullmatch(k) and m == {"optional": "true"}
                                                                      for k, m in v.items())}[field]
            if not ok:
                refuse(where, f"the {field} value {str(v)[:80]!r}")
    for key, entry in mapping("pnpm-lock.yaml snapshots", lock.get("snapshots", {})).items():
        where = f"pnpm-lock.yaml snapshots {key}"
        if not SNAP_KEY.fullmatch(key):
            refuse("pnpm-lock.yaml snapshots", f"the snapshot {key!r} (registry packages only)")
        for field, v in mapping(where, entry).items():
            if field not in SNAPSHOT_FIELDS:
                refuse(where, f"the field {field!r}")
            if field == "optional":
                ok = v == "true"
            elif field == "transitivePeerDependencies":
                ok = isinstance(v, list) and all(NAME_RE.fullmatch(x) for x in v)
            else:
                ok = isinstance(v, dict) and all(NAME_RE.fullmatch(k) and isinstance(x, str) and LOCK_VERSION.fullmatch(x)
                                                 for k, x in v.items())
            if not ok:
                refuse(where, f"the {field} value {str(v)[:80]!r}")
    for rel in inputs:
        if Path(rel).name != "package.json":
            continue
        m = read_json_file(root, rel)
        for key in m:
            if key not in MANIFEST_KEYS:
                refuse(rel, f"the field {key!r}")
        for field in DEPENDENCY_FIELDS:
            deps = m.get(field, {})
            if not isinstance(deps, dict):
                refuse(rel, f"a non-object {field}")
            for dep, spec in deps.items():
                if not node_spec_ok(spec):
                    refuse(rel, f"the {field} specifier {dep}: {spec!r}")
    return lock


def workspace_bin_users(lock: dict, manifests: dict[str, dict]) -> list[str]:
    """Each lockfile importer link to another workspace project whose manifest has a `bin`, as
    "<importer's manifest> uses <name> (<bin project's manifest>)". lock is what check_node_config
    returned. Only an importer's `link:` version links a project (check_node_config admits it for a
    workspace:* specifier alone, and no package or snapshot can be one), so a registry release that
    only shares a bin project's name is not a link and is not listed (TXE-8374)."""
    def entries(v) -> dict:
        return v if isinstance(v, dict) else {}  # check_node_config admitted "{}" as the only other value
    manifest_of = {os.path.dirname(rel) or ".": rel for rel in manifests}
    binned = {os.path.dirname(rel) or ".": rel for rel, m in manifests.items()
              if m.get("bin") or (isinstance(m.get("directories"), dict) and m["directories"].get("bin"))}
    users = set()
    for imp, entry in entries(lock.get("importers")).items():
        for field in sorted(IMPORTER_FIELDS):
            for name, dep in entries(entries(entry).get(field)).items():
                ver = entries(dep).get("version")
                if not (isinstance(ver, str) and ver.startswith("link:")):
                    continue
                target = os.path.normpath(os.path.join(imp, ver[5:]))
                if target in binned and target != os.path.normpath(imp):
                    users.add(f"{manifest_of[imp]} uses {name} ({binned[target]})")
    return sorted(users)


def is_node_tree(tree: Path) -> bool:
    return any(os.path.lexists(tree / n) for n in NODE_TREE_MARKERS)


def check_outside(p: Path, forbidden: dict[str, Path], what: str) -> None:
    """p neither is, contains nor lies inside protected state; lying inside HOME is allowed."""
    for name, f in forbidden.items():
        fr = real(f)
        if within(fr, p) or (name != "HOME" and within(p, fr)):
            raise Refused(f"{what} {p} overlaps {name} ({fr})")


def node_inputs(root: Path, deadline: float | None = None) -> dict[str, str]:
    """{relative path: sha256} of what the seed's install may read: the root's lockfile, workspace
    file and .npmrc, and every package.json (node_modules is never copied). Each is a regular file."""
    found = [n for n in NODE_ROOT_INPUTS if os.path.lexists(root / n)]
    for d, dirs, files in os.walk(root):
        check_deadline(deadline, "listing the workspace's manifests")
        dirs[:] = sorted(x for x in dirs if x != "node_modules")
        if "package.json" in files:
            found.append(os.path.relpath(os.path.join(d, "package.json"), root))
    return {rel: regular_digest(root, rel, deadline) for rel in sorted(set(found))}


def regular_digest(root: Path, rel: str, deadline: float | None = None) -> str:
    """sha256 of root/rel, refused unless the path is link-free and the file is regular. It is
    opened O_NOFOLLOW | O_NONBLOCK and checked on its descriptor, so a FIFO or a link a container
    swapped in is refused, never waited on; the read checks the deadline per MiB."""
    p = plain_target(root, rel)
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as e:
        raise Refused(f"cannot open {rel} as a plain file: {e}") from e
    h = hashlib.sha256()
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Refused(f"{rel} is not a regular file")
        while chunk := f.read(1 << 20):
            check_deadline(deadline, f"hashing {rel}")
            h.update(chunk)
    return h.hexdigest()


def tree_digest_at(top: int, root: str, max_entries: int, max_bytes: int,
                   deadline: float | None = None) -> tuple[str, int]:
    """(sha256, entries) of the directory open on descriptor top (root names it in messages), never
    following a link. One line per entry, sorted by its relative path as bytes: "D\\0rel",
    "F\\0rel\\0size sha256 x<execute bits, octal>" or "L\\0rel\\0target". Each directory is opened
    relative to its parent's descriptor with O_NOFOLLOW. Refused: a special file, a name or link
    target holding a line break, more than max_entries entries or max_bytes bytes. top stays open."""
    lines: list[bytes] = []
    tally = [0, 0]  # entries, bytes

    def walk(fd: int, prefix: bytes, depth: int) -> None:
        if depth > 256:
            raise Refused(f"{root} is nested over 256 levels")
        names = []
        with os.scandir(fd) as it:
            for e in it:
                tally[0] += 1
                if tally[0] > max_entries:
                    raise Refused(f"{root} holds over {max_entries} entries")
                check_deadline(deadline, f"hashing {root}")
                names.append(e.name)
        for name in sorted(names, key=os.fsencode):
            b = os.fsencode(name)
            if b"\n" in b or b"\r" in b:
                raise Refused(f"{root}: a name holds a line break: {name!r}")
            rel = prefix + b
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                lines.append(b"D\0" + rel + b"\n")
                sub = os.open(name, DIR_FLAGS, dir_fd=fd)
                try:
                    walk(sub, rel + b"/", depth + 1)
                finally:
                    os.close(sub)
            elif stat.S_ISREG(st.st_mode):
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    # A setuid or setgid file would be exported with its mode (copy2), owned by the
                    # runner's uid: a privilege a script inside the container could plant on the host.
                    raise Refused(f"{root}: {rel.decode(errors='replace')} is setuid or setgid "
                                  f"(mode {oct(stat.S_IMODE(st.st_mode))}); a seed never holds one")
                h, n = hashlib.sha256(), 0
                with os.fdopen(open_regular_at(fd, name), "rb") as f:
                    while chunk := f.read(1 << 20):
                        check_deadline(deadline, f"hashing {root}")
                        n += len(chunk)
                        tally[1] += len(chunk)
                        if tally[1] > max_bytes:
                            raise Refused(f"{root} holds over {max_bytes} bytes")
                        h.update(chunk)
                # The execute bits too: a seed whose .bin shim or native binary lost +x (an archive or a
                # filesystem that drops modes) would hash alike and fail only when a run executes it.
                lines.append(b"F\0" + rel + b"\0" + f"{n} {h.hexdigest()} x{stat.S_IMODE(st.st_mode) & 0o111:o}".encode()
                             + b"\n")
            elif stat.S_ISLNK(st.st_mode):
                target = os.fsencode(os.readlink(name, dir_fd=fd))
                if b"\n" in target or b"\r" in target:
                    raise Refused(f"{root}: the link {name!r} has a line break in its target")
                lines.append(b"L\0" + rel + b"\0" + target + b"\n")
            else:
                raise Refused(f"{root}: {rel.decode(errors='replace')} is a special file "
                              f"(mode {oct(stat.S_IFMT(st.st_mode))})")

    try:
        walk(top, b"", 0)
    except OSError as e:
        raise Refused(f"cannot read {root}: {e}") from e
    return hashlib.sha256(b"".join(lines)).hexdigest(), tally[0]


def tree_digest(root: Path, max_entries: int, max_bytes: int, deadline: float | None = None) -> tuple[str, int]:
    """tree_digest_at on root, opened O_DIRECTORY | O_NOFOLLOW."""
    try:
        top = os.open(root, DIR_FLAGS)
    except OSError as e:
        raise Refused(f"{root} is not a plain directory: {e}") from e
    try:
        return tree_digest_at(top, str(root), max_entries, max_bytes, deadline)
    finally:
        os.close(top)


def read_json_file(root: Path, rel: str) -> dict:
    """A JSON object from a file under root, refused unless the path is link-free and the file is a
    regular file of at most JSON_CAP bytes. Used on files a container wrote."""
    p = plain_target(root, rel)
    try:
        fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError as e:
        raise Refused(f"cannot open {rel}: {e}") from e
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise Refused(f"{rel} is not a regular file")
        raw = f.read(JSON_CAP + 1)
    if len(raw) > JSON_CAP:
        raise Refused(f"{rel} is over {JSON_CAP} bytes")
    try:
        data = json.loads(raw)
    except ValueError as e:
        raise Refused(f"{rel} is not JSON: {e}") from e
    if not isinstance(data, dict):
        raise Refused(f"{rel} is not a JSON object")
    return data


def scripts_of(data: dict, keys: tuple[str, ...]) -> dict[str, str]:
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return {}
    return {k: str(scripts[k]) for k in keys if k in scripts}


def node_modules_dirs(inputs: dict[str, str]) -> list[str]:
    """The node_modules beside each manifest: where pnpm puts each project's dependencies."""
    return sorted({os.path.normpath(os.path.join(os.path.dirname(rel), "node_modules"))
                   for rel in inputs if Path(rel).name == "package.json"})


def record_roots(inputs: dict[str, str], src: Path) -> list[str]:
    return [nm for nm in node_modules_dirs(inputs) if os.path.isdir(src / nm) and not os.path.islink(src / nm)]


def package_parents(src: Path, roots: list[str], max_files: int) -> list[str]:
    """Every directory named node_modules at or below each root (links never followed), relative to
    src: the parents of installed packages in any pnpm layout, isolated (.pnpm/<id>/node_modules)
    or hoisted (node_modules/<pkg>/node_modules)."""
    out, seen = [], 0
    for root in roots:
        for d, dirs, _files in os.walk(src / root):
            seen += len(dirs)
            if seen > max_files:
                raise Refused(f"the seed holds over {max_files} directories")
            dirs[:] = sorted(x for x in dirs if not os.path.islink(os.path.join(d, x)))
            if os.path.basename(d) == "node_modules":
                out.append(os.path.relpath(d, src))
    return out


def check_seed_links(src: Path, dirs: list[str], projects: list[str], deadline: float | None = None) -> None:
    """Every link in the seeded node_modules resolves inside one of them, or is exactly a workspace
    project's directory (pnpm's link to a workspace package). A link anywhere else (a virtual store
    outside node_modules, set by the tree's .npmrc, say) would dangle once only node_modules is
    copied, so the seed is refused instead of silently incomplete."""
    nms = [real(src / nm) for nm in dirs]
    allowed = {real(src / p) for p in projects}
    for nm in dirs:
        for d, subdirs, files in os.walk(src / nm):
            check_deadline(deadline, "checking the seed's links")
            for n in subdirs + files:
                p = Path(d) / n
                if p.is_symlink():
                    r = real(p)
                    if r not in allowed and not any(within(r, x) for x in nms):
                        raise Refused(f"the seed's {p.relative_to(src)} links to {os.readlink(p)}, outside every "
                                      "node_modules: the tree's pnpm settings (.npmrc or pnpm-workspace.yaml) put "
                                      "packages where the seed does not copy them")


def lifecycle_record(src: Path, inputs: dict[str, str], allowed: list[str], max_files: int) -> dict:
    """What install-time code the seed's packages carry, read on the host after the install: each
    workspace project's own lifecycle scripts (never run: --ignore-scripts), and each installed
    package's preinstall/install/postinstall (or a binding.gyp, which implies `node-gyp rebuild`),
    marked allowlisted (run by the `pnpm rebuild` step) or skipped."""
    record: dict = {"workspace_skipped": {}, "dependencies": {}, "installed": []}  # installed: (name, path), popped by the caller
    for rel in inputs:
        if Path(rel).name == "package.json":
            s = scripts_of(read_json_file(src, rel), WORKSPACE_SCRIPTS)
            if s:
                record["workspace_skipped"][rel] = s
    seen = 0
    for nm in package_parents(src, record_roots(inputs, src), max_files):
        pkgs = []
        for name in sorted(os.listdir(src / nm)):
            p = src / nm / name
            if p.is_symlink() or not p.is_dir():
                continue  # a link to another package, or .bin
            if name.startswith("@"):
                pkgs += [f"{name}/{s}" for s in sorted(os.listdir(p))
                         if (p / s).is_dir() and not (p / s).is_symlink()]
            else:
                pkgs.append(name)
        for pkg in pkgs:
            seen += 1
            if seen > max_files:
                raise Refused(f"the seed holds over {max_files} packages")
            rel = f"{nm}/{pkg}"
            if not os.path.isfile(src / rel / "package.json"):
                continue
            data = read_json_file(src, f"{rel}/package.json")
            record["installed"].append((str(data.get("name", pkg)), rel))
            s = scripts_of(data, DEPENDENCY_SCRIPTS)
            if os.path.lexists(src / rel / "binding.gyp") and "install" not in s and "preinstall" not in s:
                s["install"] = "node-gyp rebuild (implied by binding.gyp)"
            if s:
                name = str(data.get("name", pkg))
                entry = record["dependencies"].setdefault(f"{name}@{data.get('version', '?')}", {
                    "ran": "allowlisted" if name in allowed else "skipped", "paths": {}})
                # Scripts per path: one name@version can be installed at several paths (hoisted), and
                # nothing makes their bytes equal, so no path's scripts hide behind another's.
                entry["paths"][rel] = s
    return record


def project_dirs(inputs: dict[str, str]) -> list[str]:
    return sorted({os.path.dirname(rel) or "." for rel in inputs if Path(rel).name == "package.json"})


def resolve_image_id(args) -> str:
    """The local image's immutable id: a node seed is bound to the image it was built with (its
    platform, libc and node decide which native packages pnpm installs)."""
    left = args.deadline_at - time.monotonic() if args.deadline_at else 60.0
    if left <= 0:
        raise Stopped("the whole-run deadline passed before the image id was read")
    try:
        out = subprocess.run([args.docker, "image", "inspect", "--format", "{{.Id}}", args.image],
                             capture_output=True, text=True, env=docker_client_env(), timeout=min(left, 60.0))
    except subprocess.TimeoutExpired as e:
        raise Stopped("docker image inspect took too long") from e
    iid = out.stdout.strip()
    if out.returncode != 0 or not re.fullmatch(r"sha256:[0-9a-f]{64}", iid):
        raise Refused(f"cannot read the id of image {args.image}: {out.stderr.strip()[-200:] or iid!r}")
    return iid


# ---------------------------------------------------------------- writing the seed (TXE-8385)
#
# The seed is written relative to descriptors, never by pathname: the build opens the parent
# directory it screened (and checks it is still that directory), creates the seed directory in it
# with mkdirat, opens and checks it, and every later write is relative to that descriptor:
# directories with mkdirat, files opened O_CREAT | O_EXCL | O_NOFOLLOW, links with symlinkat. Once
# the descriptor is obtained, a rename of the seed directory or of any ancestor moves the writes
# with it, never elsewhere, and an entry planted inside it is refused, never followed.
#
# Prerequisite (trusted namespace): from the screening (check_seed_parent) through the create and
# the open of the seed directory, no untrusted party can rename or create entries in the parent,
# or replace it through an ancestor. The checks on each descriptor (device and inode against the
# name, owner, mode, emptiness) detect the swaps they can see; they do not prove the directory
# opened is the inode mkdirat created. A process of the invoker's uid is trusted.

SEED_DIR_MODE = 0o700
SEED_FILE_MODE = 0o644
NEW_FILE_FLAGS = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                  | getattr(os, "O_CLOEXEC", 0))


def open_dir_at(parent_fd: int, name: str, what: str) -> int:
    """A descriptor on directory name in parent_fd, opened O_DIRECTORY | O_NOFOLLOW, refused unless
    it is the directory name holds now (fstat against an lstat of name, by device and inode) and is
    owned by this process's euid. That does not prove it is the inode an earlier mkdirat created: a
    party who can rename entries in parent_fd between the two could put its own there (the
    trusted-namespace prerequisite, write_seed). Once returned, the descriptor is unaffected by any
    later rename."""
    try:
        fd = os.open(name, DIR_FLAGS | getattr(os, "O_CLOEXEC", 0), dir_fd=parent_fd)
    except OSError as e:
        raise Refused(f"{what}: cannot open {name} as a plain directory: {e}") from e
    try:
        st = os.fstat(fd)
        lst = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(st.st_mode) or (st.st_dev, st.st_ino) != (lst.st_dev, lst.st_ino):
            raise Refused(f"{what}: {name} changed while it was opened")
        if st.st_uid != os.geteuid():
            raise Refused(f"{what}: {name} is owned by uid {st.st_uid}, not by the build's")
    except BaseException:
        os.close(fd)
        raise
    return fd


def open_seed_parent(parent: Path, ident: tuple[int, int]) -> int:
    """A descriptor on the seed's parent directory, refused unless it is still the directory
    check_seed_parent screened (ident: the device and inode of the very lstat it screened): a
    replacement of it, or a rename of an ancestor that leads the path elsewhere, since then is
    refused, and a rename after this open cannot move the writes away from it."""
    try:
        fd = os.open(parent, DIR_FLAGS | getattr(os, "O_CLOEXEC", 0))
    except OSError as e:
        raise Refused(f"--node-seed-build: cannot open {parent} as a plain directory: {e}") from e
    try:
        st = os.fstat(fd)
        if (st.st_dev, st.st_ino) != ident:
            raise Refused(f"--node-seed-build: {parent} is no longer the directory screened at the start "
                          "(it or an ancestor was renamed); nothing was written")
    except BaseException:
        os.close(fd)
        raise
    return fd


def make_seed_dir(parent_fd: int, name: str) -> None:
    """Create the seed directory name in parent_fd, exclusively (checked absent before the run; never
    a directory something else made), with mode 0700 at creation (root's review of 1ad1243e): with a
    permissive umask (0002, 0000) a plain mkdir would make it group- or world-writable. The mode is
    never widened after. A second line of defence since TXE-8385: no write into it is by pathname."""
    try:
        os.mkdir(name, SEED_DIR_MODE, dir_fd=parent_fd)
    except OSError as e:
        raise Refused(f"--node-seed-build: cannot create the seed directory {name}: {e}") from e


def open_seed_dir(parent_fd: int, name: str) -> int:
    """make_seed_dir, then a checked descriptor on the directory at that name (open_dir_at): owned
    by the euid, mode 0700 exactly (a umask that removes owner bits is refused), and empty. These
    checks do not prove it is the inode mkdirat created; that rests on the trusted-namespace
    prerequisite (write_seed). From here on, the descriptor is what every write uses."""
    make_seed_dir(parent_fd, name)
    fd = open_dir_at(parent_fd, name, "--node-seed-build")
    try:
        mode = stat.S_IMODE(os.fstat(fd).st_mode)
        if mode != SEED_DIR_MODE:
            raise Refused(f"--node-seed-build: the seed directory was created with mode {mode:04o}, not "
                          f"{SEED_DIR_MODE:04o} (the umask removes owner bits?)")
        if os.listdir(fd):
            raise Refused("--node-seed-build: the seed directory was not empty when opened")
    except BaseException:
        os.close(fd)
        raise
    return fd


def makedirs_at(top: int, parts: list[str], what: str) -> int:
    """A descriptor on top/parts..., each component created (mode 0755, never a link) when absent
    and opened with open_dir_at. The caller closes it."""
    fd = os.dup(top)
    try:
        for part in parts:
            try:
                os.mkdir(part, 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            nxt = open_dir_at(fd, part, what)
            os.close(fd)
            fd = nxt
    except BaseException:
        os.close(fd)
        raise
    return fd


def write_new_at(dir_fd: int, name: str, chunks, like: os.stat_result | int, deadline: float | None,
                 what: str) -> str:
    """Write chunks to the new file name in dir_fd, opened O_CREAT | O_EXCL | O_NOFOLLOW (an entry
    already there, a planted link included, is refused, never followed). like is the explicit
    mode, or a source's stat whose mode and times the file keeps (keep_mode_and_times). Returns the
    sha256 of the bytes written."""
    try:
        fd = os.open(name, NEW_FILE_FLAGS, 0o600, dir_fd=dir_fd)
    except OSError as e:
        raise Refused(f"{what}: cannot create {name}: {e}") from e
    h = hashlib.sha256()
    with os.fdopen(fd, "wb") as f:
        for chunk in chunks:
            check_deadline(deadline, what)
            h.update(chunk)
            f.write(chunk)
        f.flush()
        if isinstance(like, int):
            os.fchmod(f.fileno(), like)
        else:
            keep_mode_and_times(f.fileno(), like)
    return h.hexdigest()


def read_chunks(fd: int):
    """The bytes of descriptor fd, a MiB at a time. It never closes fd: the caller owns it, and
    closes it whether or not the chunks were ever read (a refused destination reads none)."""
    while chunk := os.read(fd, 1 << 20):
        yield chunk


def copy_dir_at(src: int, dst: int, budget: list[int], deadline: float | None, what: str, depth: int = 0) -> None:
    """Copy every entry of the directory open on src into the empty directory open on dst, never
    following a link, relative to the two descriptors only: directories with mkdirat (opened with
    open_dir_at), regular files created O_CREAT | O_EXCL | O_NOFOLLOW, links with symlinkat. As
    shutil.copytree(symlinks=True) with copy2 did: a link is copied as a link, and a file or
    directory keeps its permission bits (setuid, setgid and sticky dropped) and its times. Not kept:
    a link's own mode and times (they grant nothing) and BSD file flags. A special file is refused;
    so is more than budget[0] entries."""
    if depth > 256:
        raise Refused(f"{what}: nested over 256 levels")
    for name in sorted(os.listdir(src), key=os.fsencode):
        check_deadline(deadline, what)
        budget[0] -= 1
        if budget[0] < 0:
            raise Refused(f"{what}: over the entry limit")
        st = os.stat(name, dir_fd=src, follow_symlinks=False)
        if stat.S_ISDIR(st.st_mode):
            os.mkdir(name, 0o700, dir_fd=dst)
            s = os.open(name, DIR_FLAGS | getattr(os, "O_CLOEXEC", 0), dir_fd=src)
            try:
                d = open_dir_at(dst, name, what)
                try:
                    copy_dir_at(s, d, budget, deadline, what, depth + 1)
                    keep_mode_and_times(d, os.fstat(s))
                finally:
                    os.close(d)
            finally:
                os.close(s)
        elif stat.S_ISREG(st.st_mode):
            r = open_regular_at(src, name)
            try:
                write_new_at(dst, name, read_chunks(r), os.fstat(r), deadline, what)
            finally:
                os.close(r)
        elif stat.S_ISLNK(st.st_mode):
            os.symlink(os.readlink(name, dir_fd=src), name, dir_fd=dst)
        else:
            raise Refused(f"{what}: {name} is a special file (mode {oct(stat.S_IFMT(st.st_mode))})")


def keep_mode_and_times(fd: int, st: os.stat_result) -> None:
    """Give the file or directory open on fd the permission bits (setuid, setgid and sticky
    dropped) and access and modification times of st."""
    os.fchmod(fd, stat.S_IMODE(st.st_mode) & 0o777)
    os.utime(fd, ns=(st.st_atime_ns, st.st_mtime_ns))


def write_seed(dest: Path, parent_ident: tuple[int, int], src: Path, dirs: list[str], digests: dict[str, str],
               log: Path, limits: tuple[int, int], deadline: float | None) -> tuple[int, str]:
    """Create the seed directory dest and write into it, relative to its descriptor only: each
    node_modules in dirs (from src, the install's tree) under tree/, checked against digests by
    hashing the copy through the same descriptors, then install.log. Returns the seed directory's
    open descriptor (the caller writes seed.json through it and closes it) and install.log's sha256.
    Every descriptor it opens is closed on every path, a refusal included. The trusted-namespace
    prerequisite (above make_seed_dir's section) holds from the screening through the open."""
    what = "writing the seed"
    parent_fd = open_seed_parent(dest.parent, parent_ident)
    try:
        seed_fd = open_seed_dir(parent_fd, dest.name)
    finally:
        os.close(parent_fd)
    try:
        for nm in dirs:
            check_deadline(deadline, what)
            *above, last = nm.split("/")
            try:
                s = os.open(plain_target(src, nm), DIR_FLAGS | getattr(os, "O_CLOEXEC", 0))
            except OSError as e:
                raise Refused(f"the seed's {nm} cannot be opened as a plain directory: {e}") from e
            try:
                up = makedirs_at(seed_fd, ["tree", *above], what)
                try:
                    os.mkdir(last, 0o700, dir_fd=up)
                    d = open_dir_at(up, last, what)
                finally:
                    os.close(up)
                try:
                    copy_dir_at(s, d, [limits[0]], deadline, f"{what} ({nm})")
                    keep_mode_and_times(d, os.fstat(s))
                    if tree_digest_at(d, f"{dest}/tree/{nm}", *limits, deadline)[0] != digests[nm]:
                        raise Refused(f"the seed's {nm} changed while it was written to {dest}")
                finally:
                    os.close(d)
            finally:
                os.close(s)
        try:
            lfd = os.open(log, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        except OSError as e:
            raise Refused(f"cannot open the install log {log}: {e}") from e
        try:
            if not stat.S_ISREG(os.fstat(lfd).st_mode):
                raise Refused(f"the install log {log} is not a regular file")
            log_sha256 = write_new_at(seed_fd, "install.log", read_chunks(lfd), SEED_FILE_MODE, deadline, what)
        finally:
            os.close(lfd)
    except OSError as e:  # an entry that cannot be read, made or opened: a refusal, never an internal error
        os.close(seed_fd)
        raise Refused(f"{what} to {dest}: {e}") from e
    except BaseException:
        os.close(seed_fd)
        raise
    return seed_fd, log_sha256


def check_seed_parent(parent: Path, euid: int) -> os.stat_result:
    """A second line of defence since TXE-8385, which writes the seed relative to a pinned
    descriptor (write_seed). Screening, not a guarantee: the parent and every ancestor up to / are
    screened by owner uid, POSIX mode bits and the sticky bit (security reviews of a63cbc52 and
    d33fb7db). Each must be owned by the invoker or root, and either writable by no group or other
    user, or sticky (as /tmp is: only an entry's owner, or the directory's, can rename it, so the
    directory's owner must be trusted too). The build never runs as root. NOT examined: ACLs and
    other non-mode permissions; a process of the same uid is trusted (README).

    Returns the lstat of parent that was screened: its device and inode are the identity the build
    later requires of the parent it opens (open_seed_parent), never a second, later sample (root's
    review of 2837c048)."""
    if euid == 0:
        raise Refused("--node-seed-build refuses to run as root: run it as an ordinary user")
    d = Path(parent)
    screened = None
    while True:
        try:
            st = os.lstat(d)  # parent is a resolved path: no link to follow on the way up
        except OSError as e:
            raise Refused(f"--node-seed-build: cannot read {d}: {e}") from e
        trusted = st.st_uid in (euid, 0)
        if not (trusted and (not st.st_mode & (stat.S_IWGRP | stat.S_IWOTH) or st.st_mode & stat.S_ISVTX)):
            where = "its parent directory" if d == Path(parent) else "an ancestor of its parent directory"
            who = f"owned by uid {st.st_uid}" if not trusted else "writable by its group or other users and not sticky"
            raise Refused(f"--node-seed-build: {where} {d} is {who}: another user could replace the seed directory "
                          "while it is written; put the seed in a directory only you (or root) can write, all the way up")
        if screened is None:
            screened = st
        if d.parent == d:
            return screened
        d = d.parent


def check_node_mode(args, forbidden: dict[str, Path]) -> None:
    """Before anything is created: a JavaScript tree runs only with a seed (or --no-node-seed), a
    seed is used only for a tree with a lockfile, and a seed being built goes to a new directory."""
    tree = args.tree
    if args.node_seed_build is not None:
        for n in ("package.json", "pnpm-lock.yaml"):
            if not (tree / n).is_file() or (tree / n).is_symlink():
                raise Refused(f"--node-seed-build needs a pnpm workspace: {tree} has no regular {n} at its root")
        out = Path(os.path.abspath(args.node_seed_build))
        if os.path.lexists(out):
            raise Refused(f"--node-seed-build {out} already exists; a seed is written to a new directory")
        if not out.parent.is_dir():
            raise Refused(f"--node-seed-build {out}: its parent directory does not exist")
        args.node_seed_build = real(out.parent) / out.name
        check_outside(args.node_seed_build, forbidden, "--node-seed-build directory")
        st = check_seed_parent(args.node_seed_build.parent, os.geteuid())
        args.node_seed_parent_ident = (st.st_dev, st.st_ino)  # the screened directory: the build writes only into it
    elif args.node_seed is not None:
        if not (tree / "pnpm-lock.yaml").is_file():
            raise Refused(f"--node-seed is for a pnpm workspace: {tree} has no pnpm-lock.yaml at its root")
        seed = real(args.node_seed)
        check_outside(seed, forbidden, "--node-seed directory")
        if not (seed / "seed.json").is_file() or not (seed / "tree").is_dir():
            raise Refused(f"--node-seed {seed} is not a seed (no seed.json and tree/); build one with --node-seed-build")
        args.node_seed = seed
    elif is_node_tree(tree) and not args.no_node_seed:
        marker = next(n for n in NODE_TREE_MARKERS if os.path.lexists(tree / n))
        raise Refused(f"{tree} is a JavaScript workspace ({marker} at its root) and no --node-seed was given. "
                      "Its node_modules is never copied (it holds the host's native binaries), and a run's "
                      "container has no network to install one, so every run would fail. Build a Linux seed "
                      "once with --node-seed-build DIR (with network, lifecycle scripts disabled) and pass "
                      "--node-seed DIR; or pass --no-node-seed when the command needs no node_modules")


def build_node_seed(args, runner: "Runner", pristine: Path, report: dict) -> int:
    """--node-seed-build: one container, with network, installs the workspace's node_modules from
    its manifests alone; the host checks the result and writes the seed directory."""
    inputs = node_inputs(pristine, runner.deadline)
    lockfile = check_node_config(pristine, inputs)  # the closed set: refused before the container starts
    lock = inputs["pnpm-lock.yaml"]
    allowed = list(args.node_seed_allow_build)
    # `pnpm rebuild -r NAME` selects by name: a workspace project of that name would have its own
    # scripts (code from the tree) run. Refused before the container starts.
    manifests = {rel: read_json_file(pristine, rel) for rel in inputs if Path(rel).name == "package.json"}
    projects = {str(m.get("name")): rel for rel, m in manifests.items()}
    clash = sorted(n for n in allowed if n in projects)
    if clash:
        raise Refused(f"--node-seed-allow-build {', '.join(clash)} names a workspace project "
                      f"({', '.join(projects[n] for n in clash)}), whose own scripts never run; allowlist dependencies only")
    # A workspace package's `bin` points at its source, which a manifest-only install does not have,
    # so pnpm links no shim for the projects linked to it (with only a warning), and a command that
    # uses it would fail in every run. Refused before the container starts. The lockfile's importer
    # links decide, never a dependency's name (TXE-8374).
    users = workspace_bin_users(lockfile, manifests)
    if users:
        raise Refused(f"a workspace package with a `bin` is a dependency of another project ({'; '.join(users)}): "
                      "the seed's install sees manifests only, so pnpm cannot link that bin, and a seed cannot be "
                      "built for this workspace")
    command = ["sh", "-c", NODE_SEED_SCRIPT, "sh", *allowed]
    r = runner.run("node seed", pristine, None, inputs=inputs, command=command, network=args.node_seed_network)
    runner.settle_or_stop(r)
    report["results"].append(r.__dict__)
    out(f"node seed install: {r.outcome} ({r.seconds}s)")
    if r.outcome != "PASSED":
        args.keep = True  # the install log is evidence
        raise Refused(f"the seed's install did not pass ({r.outcome}, exit {r.exit_code}); log {r.log}")
    src = plain_target(Path(r.dir), "src")
    for rel, digest in inputs.items():  # written by the container: a FIFO or link here is refused, never read
        if regular_digest(src, rel, runner.deadline) != digest:
            raise Refused(f"the seed's install changed {rel}; the lockfile must install as it is (--frozen-lockfile)")
    dirs = []
    for rel in inputs:
        if Path(rel).name == "package.json":
            nm = os.path.normpath(os.path.join(os.path.dirname(rel), "node_modules"))
            if os.path.lexists(src / nm):
                p = plain_target(src, nm)
                if not p.is_dir():
                    raise Refused(f"the seed's {nm} is not a directory")
                dirs.append(nm)
    if "node_modules" not in dirs:
        raise Refused("the seed's install left no node_modules at the workspace root")
    check_links(src, runner.deadline)
    check_seed_links(src, dirs, project_dirs(inputs), runner.deadline)
    limits = (args.max_files, args.max_work_mib * 2**20)
    digests = {nm: tree_digest(src / nm, *limits, runner.deadline)[0] for nm in sorted(dirs)}
    scripts = lifecycle_record(src, inputs, allowed, args.max_files)
    found = scripts.pop("installed")  # (name, path) of every installed package directory
    installed = {name for name, _rel in found}
    # A workspace package pnpm INJECTS (injectWorkspacePackages, dependenciesMeta.injected) is a copy
    # of the project in the virtual store, and this install saw manifests only, so the copy holds the
    # project's package.json, byte for byte, and no source. A linked workspace package is a symlink,
    # which the scan never counts; a published release of a project (same name, fetched from a
    # registry) has its own package.json and is not refused.
    injected = sorted(f"{name} at {rel}" for name, rel in found if name in projects
                      and regular_digest(src, f"{rel}/package.json", runner.deadline) == inputs[projects[name]])
    if injected:
        raise Refused(f"the seed's install injected workspace project copies ({', '.join(injected)}: "
                      "injectWorkspacePackages or dependenciesMeta.injected); the seed sees manifests only, so "
                      "those copies hold no source: a seed cannot be built for an injected workspace package")
    missing = sorted(set(allowed) - installed)
    if missing:  # a rebuild of a name nothing installed does nothing, silently: never a recorded "allowlisted"
        raise Refused(f"--node-seed-allow-build {', '.join(missing)}: no installed dependency has that name")
    dest = args.node_seed_build
    seed_fd, log_sha256 = write_seed(dest, args.node_seed_parent_ident, src, sorted(dirs), digests, Path(r.log),
                                     limits, runner.deadline)
    try:
        seed = {"format": NODE_SEED_FORMAT, "lockfile_sha256": lock, "inputs": inputs, "image": args.image,
                "image_id": args.image_id, "network": args.node_seed_network, "script": NODE_SEED_SCRIPT,
                "allow_build": allowed, "lifecycle_scripts": scripts, "node_modules": digests,
                "install_log_sha256": log_sha256, "built_from": str(args.tree)}
        write_new_at(seed_fd, "seed.json", [(json.dumps(seed, indent=2, sort_keys=True) + "\n").encode()],
                     SEED_FILE_MODE, runner.deadline, "writing the seed")  # last: a seed without it is no seed
    finally:
        os.close(seed_fd)
    report["node_seed"] = {"built": str(dest), **{k: seed[k] for k in ("lockfile_sha256", "image_id", "allow_build",
                                                                       "lifecycle_scripts", "node_modules")}}
    runner.discard(r)
    skipped = sorted(k for k, v in scripts["dependencies"].items() if v["ran"] == "skipped")
    out(f"node seed: {dest} (lockfile sha256 {lock}); lifecycle scripts skipped: {', '.join(skipped) or 'none'}; "
        f"allowlisted: {', '.join(allowed) or 'none'}")
    return EXIT_OK


def apply_node_seed(args, pristine: Path, deadline: float | None) -> dict:
    """--node-seed: check the seed against the copied tree (lockfile, every manifest, image) and copy
    its node_modules into the copy, hashing what was copied (the copy, not the seed, is checked)."""
    seed_dir = args.node_seed
    seed = read_json_file(seed_dir, "seed.json")
    if seed.get("format") != NODE_SEED_FORMAT:
        raise Refused(f"--node-seed {seed_dir}: seed format {seed.get('format')!r} is not {NODE_SEED_FORMAT}")
    lock = regular_digest(pristine, "pnpm-lock.yaml", deadline)
    if seed.get("lockfile_sha256") != lock:
        raise Refused(f"--node-seed {seed_dir} was built for pnpm-lock.yaml sha256 {seed.get('lockfile_sha256')}, "
                      f"and the tree's is {lock}: build a new seed with --node-seed-build")
    inputs = node_inputs(pristine, deadline)
    want = seed.get("inputs") if isinstance(seed.get("inputs"), dict) else {}
    differ = sorted(k for k in set(inputs) | set(want) if inputs.get(k) != want.get(k))
    if differ:
        raise Refused(f"--node-seed {seed_dir} was built from other manifests ({', '.join(differ[:10])} differ): "
                      "build a new seed with --node-seed-build")
    check_node_config(pristine, inputs)  # the closed set, again: a seed is used only for a supported layout
    if seed.get("image_id") != args.image_id:
        raise Refused(f"--node-seed {seed_dir} was built with image {seed.get('image_id')}, and this run's image "
                      f"is {args.image_id}: native packages depend on the image; use that image or build a new seed")
    modules = seed.get("node_modules")
    if not isinstance(modules, dict) or "node_modules" not in modules:
        raise Refused(f"--node-seed {seed_dir}: seed.json lists no root node_modules")
    limits = (args.max_files, args.max_work_mib * 2**20)
    for nm, digest in sorted(modules.items()):
        parts = Path(nm).parts
        if Path(nm).is_absolute() or ".." in parts or parts[-1:] != ("node_modules",):
            raise Refused(f"--node-seed {seed_dir}: {nm!r} is not a relative node_modules path")
        if not os.path.isfile(pristine / os.path.dirname(nm) / "package.json"):
            raise Refused(f"--node-seed {seed_dir}: {nm} has no package.json beside it in the tree")
        dst = plain_target(pristine, nm)
        if os.path.lexists(dst):
            raise Refused(f"the tree copy already holds {nm}")
        shutil.copytree(plain_target(seed_dir, f"tree/{nm}"), dst, symlinks=True,
                        copy_function=checked_copy(deadline, "copying the node seed"))
        if tree_digest(dst, *limits, deadline)[0] != digest:
            raise Refused(f"--node-seed {seed_dir}: {nm} changed since the seed was built")
    check_links(pristine, deadline)
    check_seed_links(pristine, sorted(modules), project_dirs(inputs), deadline)
    return {"seed": str(seed_dir), "lockfile_sha256": lock, "image_id": args.image_id,
            "node_modules": sorted(modules), "allow_build": seed.get("allow_build", [])}


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
                   help="D: seconds for every run, settlement and integrity check (the last min(45, D/3) s are "
                        "the reserve for settlement and integrity); 0 means none. Past it the run stops (exit 6) "
                        f"and removes its containers within {EMERGENCY_CLEANUP_S:.0f} s more. These bounds are "
                        "cooperative: the end-of-run host check, report writes and the work directory's removal "
                        "have none, and the finalizer ignores signals, so the runner guarantees no process exit "
                        "time; a caller that needs one bounds the process from outside, at D + "
                        f"{EMERGENCY_CLEANUP_S + TERMINATION_MARGIN_S:.0f} s or later, and keeps the work "
                        "directory's cids/ for removal by hand after a kill. "
                        "A stop in the end-of-run check reports 6 even after an earlier 2, 4 or 5 (stderr may "
                        "already have said so); the report keeps the earlier findings and containers_left")
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
    p.add_argument("--node-seed-build", type=Path, metavar="DIR",
                   help="build a Linux node_modules seed for the pnpm workspace at --tree into the new directory "
                        "DIR, in one container with --node-seed-network, from its manifests alone, with lifecycle "
                        "scripts disabled (TXE-8348); takes no command and no mutants")
    p.add_argument("--node-seed-network", default="bridge",
                   help="docker network for the seed's install only (default bridge); every run keeps --network")
    p.add_argument("--node-seed-allow-build", action="append", default=[], metavar="PKG",
                   help="with --node-seed-build: run this package's install scripts (pnpm rebuild PKG) after the "
                        "install; every other lifecycle script stays disabled. Repeatable, recorded in seed.json")
    p.add_argument("--node-seed", type=Path, metavar="DIR",
                   help="copy the seed DIR (from --node-seed-build) into the tree before any run; refused unless "
                        "its lockfile, manifests and image match")
    p.add_argument("--no-node-seed", action="store_true",
                   help="run a tree with a root package.json or pnpm-lock.yaml without a seed (no node_modules)")
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
        if args.deadline:
            # No deadline is honoured here, so none is accepted: the walk is bounded by the
            # --ro-max-* limits, and a caller that needs a time bound wraps the command (TXE-8053).
            p.error("--ro-manifest takes no --deadline: its walk is bounded by --ro-max-files, --ro-max-depth, "
                    "--ro-max-mib and --ro-max-file-mib; bound it in time from outside")
        return args
    if args.node_seed_allow_build and args.node_seed_build is None:
        p.error("--node-seed-allow-build is used only with --node-seed-build")
    for name in args.node_seed_allow_build:
        if not NPM_NAME.fullmatch(name):
            p.error(f"--node-seed-allow-build {name!r} is not an npm package name")
    if args.node_seed is not None and args.no_node_seed:
        p.error("--node-seed and --no-node-seed exclude each other")
    if args.node_seed_build is not None:
        if args.command or args.mutants or args.diagnostic or args.ro_mount or args.node_seed or args.no_node_seed:
            p.error("--node-seed-build runs only the seed's own install: it takes no command, --mutants, "
                    "--diagnostic, --ro-mount, --node-seed or --no-node-seed")
        if not args.image:
            p.error("the following arguments are required: --image")
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
    out(f"baseline: {base.outcome} ({base.seconds}s)")
    if base.outcome != "PASSED":
        runner.settle_or_stop(base)
        err(f"mutate-sandboxed: the unmutated tree did not pass; log {base.log}")
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
    runner.settle_or_stop(base)  # after the stopped-check and the cache read, before anything is removed
    runner.discard(base)

    findings = []
    for mu in mutants:
        r = runner.run(mu.name, pristine, mu)
        runner.settle_or_stop(r)
        line = f"{mu.name}: {r.outcome} ({r.seconds}s)"
        if r.outcome == "KILLED" and args.confirm_kills:
            again = runner.run(f"{mu.name} (again)", pristine, mu)
            runner.settle_or_stop(again)
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
        out(line)

    final = runner.run("baseline (after)", pristine, None)
    runner.settle_or_stop(final)
    report["results"].append(final.__dict__)
    runner.discard(final)
    out(f"baseline after: {final.outcome}")
    if final.outcome != "PASSED":
        findings.append(f"the unmutated tree failed after the mutants: {final.outcome}, log {final.log}")
    report["findings"] = findings
    killed = sum(1 for r in report["results"] if r["outcome"] == "KILLED")
    out(f"mutants: {killed}/{len(mutants)} killed; findings: {len(findings)}")
    for f in findings:
        err(f"FINDING: {f}")
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
    # call before the run's directory is touched, and BY THE ACTIVE DEADLINE (every call draws on
    # hard_end; the emergency budget after it is the finalizer's alone). A settlement that cannot
    # finish by the deadline, or that ends past it, is Stopped: exit 6, never 7.
    _cidfile, name = runner.containers[r.name]
    settled, late = runner.settle(r)
    if late:
        diag["settlement"] = "confirmed after the deadline" if settled else "not confirmed by the deadline"
        raise Stopped(f"the whole-run deadline ({runner.args.deadline}s) passed during the diagnostic's settlement")
    if not settled:
        diag.update(settlement="unconfirmed", status="not-completed: container not confirmed removed")
        report["findings"] = [f"diagnostic: container {name} not confirmed removed"]
        err(f"FINDING: diagnostic did not complete: container {name} not confirmed removed")
        return EXIT_FINDINGS  # the run's directory is kept: the container may still mount it
    diag["settlement"] = "confirmed"
    runner.discard(r)
    if r.outcome == "DIAGNOSTIC":
        diag["status"] = "completed"
        return EXIT_DIAGNOSTIC  # main prints the DIAGNOSTIC line once the end-of-run checks held
    # ERROR (docker's own 125-127, a bound, a client signal) or TIMEOUT: the run did not complete.
    diag["status"] = f"not-completed: {r.outcome}"
    report["findings"] = [f"diagnostic: {r.outcome} (docker client exit {r.exit_code}), log {r.log}"]
    err(f"FINDING: diagnostic did not complete: {r.outcome} (docker client exit {r.exit_code})")
    return EXIT_FINDINGS


# Terminal output is best effort and never decides the result (TXE-8053). Only the EXPECTED broken
# stream (a reader that went away: BrokenPipeError, or a stream Python could not open) is absorbed,
# and noted in the report; any other write failure is recorded in STREAM_ERRORS, and main turns a
# pass or a recorded diagnostic into 5 for it. Either way the stream is pointed at the null device,
# so later writes and the interpreter's flush at exit cannot fail again.
BROKEN_STREAMS: list[str] = []
STREAM_ERRORS: list[str] = []
_DEFERRED: list[str] | None = None  # while main finishes: stderr lines held until the reports are written


def _null_out(stream) -> None:
    try:
        fd = os.open(os.devnull, os.O_WRONLY)
    except OSError:
        return
    try:
        os.dup2(fd, stream.fileno())
    except (OSError, ValueError):
        pass
    finally:
        os.close(fd)


def _emit(stream, name: str, text: str) -> None:
    if stream is None:  # Python started with that descriptor closed
        if f"{name}: closed" not in BROKEN_STREAMS:
            BROKEN_STREAMS.append(f"{name}: closed")
        return
    try:
        stream.write(text + "\n")
        stream.flush()
    except BrokenPipeError:
        if f"{name}: broken pipe" not in BROKEN_STREAMS:
            BROKEN_STREAMS.append(f"{name}: broken pipe")
        _null_out(stream)
    except (OSError, ValueError) as e:  # not the expected case: recorded, and a finding
        STREAM_ERRORS.append(f"{name}: {type(e).__name__}: {e}")
        _null_out(stream)


def out(text: str) -> None:
    """A line to stdout, best effort (see BROKEN_STREAMS)."""
    _emit(sys.stdout, "stdout", text)


def err(text: str) -> None:
    """A line to stderr, best effort; held back while main writes its reports."""
    if _DEFERRED is not None:
        _DEFERRED.append(text)
        return
    _emit(sys.stderr, "stderr", text)


def loud(msg: str) -> None:
    bar = "!" * 72
    err(f"\n{bar}\nMUTATE-SANDBOXED: SHARED STATE CHANGED. STOP AND TELL YOUR COORDINATOR.\n{msg}\n{bar}")


def main(argv: list[str]) -> int:
    try:
        args = parse(argv)
        if args.ro_manifest is not None:
            try:
                out(ro_manifest_sha256(args.ro_manifest, ro_limits(args)))
            except OSError as e:
                raise Refused(f"cannot read {args.ro_manifest}: {e}") from e
            if STREAM_ERRORS or BROKEN_STREAMS:  # the digest is this mode's only output: not delivered, not done
                err(f"mutate-sandboxed: the digest could not be written: {(STREAM_ERRORS + BROKEN_STREAMS)[-1]}")
                return EXIT_FINDINGS
            return EXIT_OK
        mutants = [] if args.diagnostic or args.node_seed_build is not None else load_mutants(args.mutants, args.tree)
        ro_mounts = parse_ro_mounts(args.ro_mount)
        modcache, gocache, gopath, go_facts = resolve_shared(args)
    except Refused as e:
        err(f"mutate-sandboxed: refused: {e}")
        return EXIT_REFUSED
    except Stopped as e:
        err(f"mutate-sandboxed: stopped: {e}")
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
    if args.node_seed_build is not None:
        report["mode"] = "node-seed-build"
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
        check_node_mode(args, forbidden)  # TXE-8348: before any docker call
        args.image_id = None
        if args.node_seed is not None or args.node_seed_build is not None:
            # Node runs launch by the immutable id, so the id is resolved FIRST and the volume check
            # reads that same image: a tag retargeted between two inspections cannot admit another
            # image's volumes (root's review of b51ba7c9).
            args.image_id = resolve_image_id(args)
        left = args.deadline_at - time.monotonic() if args.deadline_at else 60.0
        if left <= 0:
            raise Stopped(f"the whole-run deadline ({args.deadline}s) passed before the image check")
        try:
            inspected = subprocess.run([args.docker, "image", "inspect", "--format", "{{json .Config.Volumes}}",
                                        args.image_id or args.image], capture_output=True, text=True,
                                       env=docker_client_env(), timeout=min(left, 60.0))
        except subprocess.TimeoutExpired as e:
            raise Stopped(f"docker image inspect took longer than {min(left, 60.0):.0f}s") from e
        if inspected.returncode != 0:
            raise Refused(f"image {args.image} is not present locally (or {args.docker} cannot reach a daemon); "
                          "this runner never pulls")
        refuse_declared_volumes(args.image_id or args.image, inspected.stdout)
        work = WorkDir(args.workdir_root)
        report["workdir"] = str(work.path)
        check_workdir(work.path, {k: v for k, v in forbidden.items() if k != "HOME"})
        runner = Runner(args, watch, forbidden, work, args.docker, mutants)  # reads live targets first
        pristine = work.path / "pristine"
        runner.room("copying the tree", (args.tree,), tuple(args.exclude))
        copy_tree(args.tree, pristine, tuple(args.exclude), runner.deadline)
        if args.node_seed is not None:
            runner.room("copying the node seed", (args.node_seed / "tree",))
            report["node_seed"] = apply_node_seed(args, pristine, runner.deadline)
        for i, m in enumerate(ro_mounts):
            runner.room(f"copying the --ro-mount for {m.dst}", (m.src,))
            prepare_ro_mount(m, work.path, i, forbidden, runner.ro_limits, runner.deadline)
            report["ro_mounts"][i]["copy"] = str(m.copy)
        runner.ro_mounts = ro_mounts
        runner.room("seeding")
        if not args.no_seed and args.node_seed_build is None:
            seed_modules(args, work, pristine, modcache, go_facts, runner.remaining("seeding"))
            watch.verify(initial, "seeding the module proxy")
        if args.node_seed_build is not None:
            code = build_node_seed(args, runner, pristine, report)
        elif args.diagnostic:
            code = run_diagnostic(runner, pristine, report)
        else:
            code = run_all(args, mutants, runner, pristine, report)
    except SharedStateChanged as e:
        loud(str(e))
        report["shared_state_changed"] = str(e)
        code = EXIT_SHARED_CHANGED
        args.keep = True  # evidence
    except Refused as e:
        err(f"mutate-sandboxed: refused: {e}")
        code = EXIT_REFUSED
    except Stopped as e:
        err(f"mutate-sandboxed: stopped: {e}; removing the containers this run started")
        report["stopped"] = str(e)
        code = EXIT_STOPPED
        args.keep = True  # evidence
    except Exception as e:  # anything unexpected (an OSError from a host-side step, say) is a finding
        report["error"] = f"{type(e).__name__}: {e}"
        err(f"mutate-sandboxed: error: {type(e).__name__}: {e}")
        code = EXIT_FINDINGS
        args.keep = True  # evidence
    finally:
        global _DEFERRED
        _DEFERRED = []  # every stderr line from here on waits until the reports are written
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)  # cleanup is not interrupted
        if runner:
            if not runner.remove_pending(emergency=True):  # the retry of anything an earlier attempt left
                left = ", ".join(runner.pending)
                report["containers_left"] = left
                err(f"mutate-sandboxed: CONTAINERS NOT CONFIRMED REMOVED: {left}; remove them by hand "
                    "after checking their owner label")
                if code in (EXIT_OK, EXIT_DIAGNOSTIC):
                    code = EXIT_FINDINGS
                args.keep = True  # never delete a directory a container may still have mounted
            report["container_cleanup"] = runner.cleanup_log
            for line in runner.cleanup_log:
                err(f"mutate-sandboxed: container {line}")
        # Every exit path, a stop by the deadline or a signal included, ends with the host check
        # against the state read at the start: a boundary failure is never reported as exit 6.
        if code != EXIT_SHARED_CHANGED:
            try:
                watch.verify(initial, "the end of the run")
                if runner:
                    for f, digest in runner.live.items():
                        if file_digest(args.tree / f) != digest:
                            raise SharedStateChanged(f"at the end of the run: the live tree's {f} changed")
                    # By the active and integrity deadline, never extended: when it is exhausted the
                    # check is incomplete (exit 6, integrity incomplete), never a manufactured 7.
                    runner.verify_ro_mounts("at the end of the run", runner.hard_end)
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
                err(f"mutate-sandboxed: the final read-only mount check did not complete: {e}")
                report["final_check"] = f"incomplete: {e}"
                code = EXIT_STOPPED
                args.keep = True
        try:
            report["identity_after"] = watch.snapshot()
        except OSError as e:
            report["identity_after"] = f"unreadable: {e}"
        if args.deadline:
            report["budgets"] = budgets(args.deadline)
        code = finish(args, report, work, code)
    return code


def budgets(deadline: int) -> dict:
    """The runner's cooperative bounds for --deadline D, in seconds, and the least hard deadline a
    caller must enforce from outside to bound the process (see EMERGENCY_CLEANUP_S): no process exit
    time is guaranteed by the runner itself."""
    return {"active_and_integrity_deadline_s": deadline, "reserve_s": min(45.0, deadline / 3),
            "emergency_cleanup_s": EMERGENCY_CLEANUP_S, "termination_margin_s": TERMINATION_MARGIN_S,
            "cooperative_only": True,
            "least_external_hard_deadline_s": deadline + EMERGENCY_CLEANUP_S + TERMINATION_MARGIN_S}


def mark_diagnostic(report: dict, code: int) -> None:
    """Set the diagnostic's integrity, settlement, evidence and status for the exit as it now
    stands. Separate facts, never merged: the raw command_exit stays as recorded."""
    d = report.get("diagnostic")
    if not isinstance(d, dict):
        return
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
    elif code != EXIT_DIAGNOSTIC:
        for key, why in (("report_error", "report not written"), ("cleanup_error", "work directory not removed"),
                         ("stream_errors", "terminal output failed")):
            if key in report:
                d["status"] = f"not-completed: {why}"
                break
        else:
            if not str(d.get("status", "")).startswith("not-completed"):
                d["status"] = f"not-completed: runner exit {code}"


def downgrade(code: int) -> int:
    """A pass or a recorded diagnostic whose evidence was then lost or not delivered is a finding."""
    return EXIT_FINDINGS if code in (EXIT_OK, EXIT_DIAGNOSTIC) else code


def write_reports(args, report: dict, work: "WorkDir | None", kept: bool, code: int) -> list[str]:
    """Write --report and, when the work directory stays, <work>/report.json, as the report now
    stands with exit `code`. Returns the writes that failed (none is retried)."""
    report["exit"] = code
    if BROKEN_STREAMS:
        report["broken_streams"] = list(BROKEN_STREAMS)
    if STREAM_ERRORS:
        report["stream_errors"] = list(STREAM_ERRORS)
    mark_diagnostic(report, code)
    text = json.dumps(report, indent=2, default=str)
    targets = ([args.report] if args.report else []) + ([work.path / "report.json"] if work and kept else [])
    failed = []
    for p in targets:
        try:
            Path(p).write_text(text)
        except OSError as e:
            failed.append(f"{p}: {type(e).__name__}: {e}")
    return failed


def finish(args, report: dict, work: "WorkDir | None", code: int) -> int:
    """The end of every run, in this order: (1) the reports, while the work directory still exists;
    (2) the work directory's removal, only after them; (3) terminal output, best effort, last. A
    report that cannot be written, a removal that fails, and a terminal write that fails for any
    reason but a broken stream each turn a pass or a recorded diagnostic into 5, and the reports
    are written again with that exit. Whenever a report is written, its exit is the process's."""
    global _DEFERRED
    removable = bool(work) and not args.keep and code not in (EXIT_BASELINE, EXIT_FINDINGS)
    kept = bool(work) and not removable
    failed = write_reports(args, report, work, kept, code)
    if failed:
        report["report_error"] = "; ".join(failed)
        err(f"mutate-sandboxed: cannot write the report: {report['report_error']}")
        code = downgrade(code)
        kept = bool(work)  # keep the directory as the evidence that survives
        removable = False
        write_reports(args, report, work, kept, code)
    if removable and work:
        try:
            work.remove()
        except (Refused, OSError) as e:
            report["cleanup_error"] = f"{type(e).__name__}: {e}"
            err(f"mutate-sandboxed: cleanup error: {e}")
            if code == EXIT_OK:  # a pass whose cleanup failed is a finding, and says so
                code = EXIT_FINDINGS
            kept = True
            write_reports(args, report, work, kept, code)
    if work and kept:
        err(f"work directory kept: {work.path}")
    held, _DEFERRED = _DEFERRED or [], None
    for line in held:
        err(line)
    if STREAM_ERRORS and code in (EXIT_OK, EXIT_DIAGNOSTIC):
        code = downgrade(code)
        write_reports(args, report, work, kept, code)
    if code == EXIT_DIAGNOSTIC:  # only now: settled, checked, reported and no output failure
        d = report["diagnostic"]
        out(f"DIAGNOSTIC: command exit {d['command_exit']} (evidence only, never a pass; runner exit "
            f"{EXIT_DIAGNOSTIC}); stdout {d['stdout']['path']}, stderr {d['stderr']['path']}")
        if STREAM_ERRORS:
            code = downgrade(code)
            err("mutate-sandboxed: the DIAGNOSTIC line could not be written: " + STREAM_ERRORS[-1])
    if BROKEN_STREAMS or STREAM_ERRORS:
        write_reports(args, report, work, kept, code)  # the final word, with the streams recorded
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
