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


def copy_tree(src: Path, dst: Path, excludes: tuple[str, ...]) -> None:
    """Copy the tree, keeping symlinks as links, and refuse any link that leads outside the copy.

    A link that resolves outside the copy (an absolute link into the live tree, say) would let a
    host-side step such as `go mod download` updating go.sum write through it into live files.
    Inside the container such a link dangles; on the host it is a hole, so it is refused."""
    def ignore(_d, names):
        return [n for n in names if n in excludes]

    shutil.copytree(src, dst, symlinks=True, ignore=ignore)
    top = real(dst)
    for d, dirs, files in os.walk(dst):
        for n in dirs + files:
            p = Path(d) / n
            if p.is_symlink() and not within(real(p), top):
                raise Refused(f"{p.relative_to(dst)} is a symlink to {os.readlink(p)}, outside the tree; "
                              "a host-side step could write through it")


def clone_dir(src: Path, dst: Path) -> None:
    """Copy src to dst, with copy-on-write clones on APFS when cp supports them."""
    if sys.platform == "darwin" and subprocess.run(["cp", "-cR", str(src), str(dst)], capture_output=True).returncode == 0:
        return
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, symlinks=True)


# ---------------------------------------------------------------- host go facts


def go_env(names: list[str], env: dict[str, str], deadline_at: float | None = None) -> dict[str, str]:
    limit = min(60.0, deadline_at - time.monotonic()) if deadline_at else 60.0
    if limit <= 0:
        raise Stopped("the whole-run deadline passed before go env")
    try:
        out = subprocess.run(["go", "env", "-json", *names], capture_output=True, text=True, env=env, timeout=limit)
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
        return f"{target}: absent"
    if probe.stdout.strip() != f"/{name} {token}":
        return f"{target}: not ours ({probe.stdout.strip()!r}); left alone"
    rm = subprocess.run([docker, "rm", "-f", target], capture_output=True, text=True, env=env,
                        timeout=call_limit(30, hard_end))
    return f"{target}: removed" if rm.returncode == 0 else f"{target}: rm failed: {rm.stderr.strip()[-200:]}"


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
        self.cleanup_log: list[str] = []

    def remaining(self, what: str) -> float:
        """Seconds the next step may take: the per-run timeout, cut to what the deadline leaves."""
        if self.deadline is None:
            return float(self.args.timeout)
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise Stopped(f"the whole-run deadline ({self.args.deadline}s) passed before {what}")
        return min(float(self.args.timeout), left)

    def remove_pending(self) -> None:
        for name, cidfile in list(self.pending.items()):
            try:
                self.cleanup_log.append(remove_owned_container(self.docker, cidfile, name, self.work.token,
                                                               self.docker_env(), self.hard_end))
            except (OSError, subprocess.TimeoutExpired) as e:
                self.cleanup_log.append(f"{name}: cleanup error {e}")
            del self.pending[name]

    # A run gets its own directory: src (the tree copy) and sandbox/<env dirs>.
    def prepare(self, label: str, pristine: Path, mutant: Mutant | None) -> Path:
        self.seq += 1
        d = self.work.path / f"{self.seq:03d}-{''.join(c if c.isalnum() else '-' for c in label)[:40]}"
        d.mkdir()
        clone_dir(pristine, d / "src")
        if mutant:
            apply_mutant(d / "src", mutant)
        sb = d / "sandbox"
        for sub in SANDBOX_ENV_DIRS.values():
            (sb / sub).mkdir(parents=True)
        warm = self.work.path / "warm-gocache"
        if self.args.warm_gocache and warm.is_dir():
            shutil.rmtree(sb / "gocache")
            clone_dir(warm, sb / "gocache")
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
        })
        argv = [self.docker, "run", "--rm", "--pull", "never", "--name", name, "--cidfile", str(cidfile),
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
        d = self.prepare(label, pristine, mutant)
        name = f"mutate-sandboxed-{self.work.token[:12]}-{self.seq:03d}"
        # Outside every mount: sandboxed code cannot rewrite which container cleanup removes.
        cidfile = self.work.path / "cids" / f"{self.seq:03d}.cid"
        cidfile.parent.mkdir(exist_ok=True)
        argv = self.docker_argv(d, name, cidfile)
        limit = self.remaining(label)
        log_path = d / "output.log"
        start = time.monotonic()
        code, outcome = None, None
        self.pending[name] = cidfile
        with open(log_path, "wb") as log:
            try:
                proc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, env=self.docker_env(),
                                      timeout=limit)
                code = proc.returncode
                if code < 0:
                    # The docker client died by a signal: nothing shows the container finished.
                    self.remove_pending()
                    outcome = "ERROR"
                else:
                    del self.pending[name]
            except subprocess.TimeoutExpired:
                self.remove_pending()
                if limit < self.args.timeout:
                    raise Stopped(f"the whole-run deadline ({self.args.deadline}s) passed during {label}")
                outcome = "TIMEOUT"
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
        return Result(label, outcome, code, round(secs, 2), str(log_path))

    def docker_env(self) -> dict[str, str]:
        return docker_client_env()


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
        clone_dir(Path(base.log).parent / "sandbox" / "gocache", runner.work.path / "warm-gocache")

    findings = []
    for mu in mutants:
        r = runner.run(mu.name, pristine, mu)
        line = f"{mu.name}: {r.outcome} ({r.seconds}s)"
        if r.outcome == "KILLED" and args.confirm_kills:
            again = runner.run(f"{mu.name} (again)", pristine, mu)
            r.__dict__["confirm"] = again.__dict__
            if again.outcome != "KILLED":
                r.outcome = "UNREPEATED-KILL"
                findings.append(f"{mu.name}: killed once, then {again.outcome} alone in a new sandbox")
            line = f"{mu.name}: {r.outcome} ({r.seconds}s; again {again.outcome})"
        if r.outcome in ("ERROR", "TIMEOUT"):
            findings.append(f"{mu.name}: {r.outcome}, log {r.log}")
        report["results"].append(r.__dict__)
        print(line, flush=True)

    final = runner.run("baseline (after)", pristine, None)
    report["results"].append(final.__dict__)
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
            inspected = subprocess.run([args.docker, "image", "inspect", args.image], capture_output=True,
                                       env=docker_client_env(), timeout=min(left, 60.0))
        except subprocess.TimeoutExpired as e:
            raise Stopped(f"docker image inspect took longer than {min(left, 60.0):.0f}s") from e
        if inspected.returncode != 0:
            raise Refused(f"image {args.image} is not present locally (or {args.docker} cannot reach a daemon); "
                          "this runner never pulls")
        work = WorkDir(args.workdir_root)
        report["workdir"] = str(work.path)
        check_workdir(work.path, {k: v for k, v in forbidden.items() if k != "HOME"})
        runner = Runner(args, watch, forbidden, work, args.docker, mutants)  # reads live targets first
        pristine = work.path / "pristine"
        copy_tree(args.tree, pristine, tuple(args.exclude))
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
            runner.remove_pending()
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
