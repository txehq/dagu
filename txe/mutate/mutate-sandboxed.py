#!/usr/bin/env python3
"""Run mutation tests where a mutant cannot reach the host's shared state (TXE-7549).

A mutant is code that breaks a guard on purpose. On 2026-11-16 a hand-written runner ran one with
the session's real environment and the code under test deleted the Mac's shared Go module cache
(postmortem TXE-7547, txehq/txe docs/postmortems/2026-11-16-shared-gomodcache-deletion.md). This
runner owns the boundary, so no single test has to:

- Every mutant runs in a fresh copy of the tree, inside a container (`--pull never`, so an image
  is never fetched). The container gets exactly two mounts, both inside a work directory this run
  created: the mutant's own directory (read-write) and the module proxy seeded from the shared
  cache (read-only). It gets no network, no Docker socket, no capabilities, bounded memory, CPU
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

mutants.json is a list of {"name", "file", "old", "new"} objects, with an optional "count"
(default 1): `old` must occur exactly `count` times in `file` (relative to the tree), and every
occurrence is replaced by `new`.

Exit codes: 0 done, no finding (survivors are listed, not failures); 2 refused or bad input;
3 shared state changed (LOUD); 4 the unmutated tree failed; 5 findings (an unrepeated kill, a
sandbox error or a timeout); 6 stopped by --deadline or a signal. On a timeout, the deadline or a
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


def check_workdir(work: Path, forbidden: dict[str, Path]) -> None:
    w = real(work)
    for name, f in forbidden.items():
        fr = real(f)
        if within(fr, w) or within(w, fr):
            raise Refused(f"work directory {w} overlaps {name} ({fr}); pass --workdir-root elsewhere")


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
    return f"{target}: removed" if rm.returncode == 0 else f"{target}: rm failed: {rm.stderr.strip()[-200:]}"


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
        start = time.monotonic()
        code, outcome = None, None
        self.pending[name] = cidfile
        self.containers[label] = (cidfile, name)
        self.overrun = None
        with open(log_path, "wb") as log:
            proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=self.docker_env())
            try:
                code = self.watch_run(proc, d, log, start, limit)
            except BaseException:
                proc.kill()
                proc.wait()
                raise
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
        if outcome is None:
            if code == 0:
                outcome = "PASSED" if mutant is None else "SURVIVED"
            elif code in DOCKER_INFRA_EXITS:
                outcome = "ERROR"
            else:
                outcome = "FAILED" if mutant is None else "KILLED"
        return Result(label, outcome, code, round(secs, 2), str(log_path), output_tail(log_path), str(d))

    def docker_env(self) -> dict[str, str]:
        return docker_client_env()

    def over_output(self, log) -> str | None:
        if os.fstat(log.fileno()).st_size > self.args.max_output_mib * 2**20:
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
    p.add_argument("--mutants", type=Path, required=True)
    p.add_argument("--tree", type=Path, default=Path.cwd())
    p.add_argument("--image", required=True,
                   help="an image present locally, best named by its immutable id (sha256:...); never pulled")
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
    p.add_argument("--keep", action="store_true", help="keep the work directory")
    p.add_argument("--report", type=Path, help="also write the JSON report here")
    p.add_argument("--docker", default="docker")
    p.add_argument("command", nargs=argparse.REMAINDER)
    args = p.parse_args(argv)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        p.error("give the test command after --")
    # The deadline clock starts here, before any preflight, so it bounds the whole run.
    args.deadline_at = time.monotonic() + args.deadline if args.deadline else None
    args.tree = real(args.tree)
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


def loud(msg: str) -> None:
    bar = "!" * 72
    print(f"\n{bar}\nMUTATE-SANDBOXED: SHARED STATE CHANGED. STOP AND TELL YOUR COORDINATOR.\n{msg}\n{bar}\n",
          file=sys.stderr, flush=True)


def main(argv: list[str]) -> int:
    try:
        args = parse(argv)
        mutants = load_mutants(args.mutants, args.tree)
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
    initial = watch.snapshot()
    report["identity_before"] = initial
    work = None
    runner = None
    code = EXIT_OK
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop_on_signal)
    try:
        check_workdir(args.workdir_root, {k: v for k, v in forbidden.items() if k != "HOME"})
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
        runner.room("seeding")
        if not args.no_seed:
            seed_modules(args, work, pristine, modcache, go_facts, runner.remaining("seeding"))
            watch.verify(initial, "seeding the module proxy")
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
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)  # cleanup is not interrupted
        if runner:
            if not runner.remove_pending():  # the retry of anything an earlier attempt left
                left = ", ".join(runner.pending)
                report["containers_left"] = left
                print(f"mutate-sandboxed: CONTAINERS NOT CONFIRMED REMOVED: {left}; remove them by hand "
                      "after checking their owner label", file=sys.stderr)
                if code == EXIT_OK:
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
        try:
            report["identity_after"] = watch.snapshot()
        except OSError as e:
            report["identity_after"] = f"unreadable: {e}"
        report["exit"] = code
        text = json.dumps(report, indent=2, default=str)
        if args.report:
            args.report.write_text(text)
        if work:
            (work.path / "report.json").write_text(text)
            if args.keep or code in (EXIT_BASELINE, EXIT_FINDINGS):  # a failure keeps its evidence
                print(f"work directory kept: {work.path}", file=sys.stderr)
            else:
                try:
                    work.remove()
                except Refused as e:
                    print(f"mutate-sandboxed: {e}", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
