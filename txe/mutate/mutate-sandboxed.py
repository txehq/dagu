#!/usr/bin/env python3
"""Run mutation tests where a mutant cannot reach the host's shared state (TXE-7549).

A mutant is code that breaks a guard on purpose. On 2026-11-16 a hand-written runner ran one with
the session's real environment and the code under test deleted the Mac's shared Go module cache
(postmortem TXE-7547, txehq/txe docs/postmortems/2026-11-16-shared-gomodcache-deletion.md). This
runner owns the boundary, so no single test has to:

- Every mutant runs in a fresh copy of the tree, inside a container. The container gets exactly
  two mounts, both inside a work directory this run created: the mutant's own directory
  (read-write) and the module proxy seeded from the shared cache (read-only). It gets no network,
  no Docker socket, no capabilities, and no variable from the caller's environment. HOME, GOPATH,
  GOMODCACHE, GOCACHE, TMPDIR and XDG_CACHE_HOME all point inside the mutant's directory.
- The seed is filled on the host, before any mutant runs, by `go mod download` from the unmutated
  tree with an owned GOMODCACHE and `GOPROXY=file://<shared GOMODCACHE>/cache/download,<caller
  proxy>`. Go only reads a file proxy, and `go mod download` runs no project code.
- The identity (device, inode and, where the OS has one, birth time) of the shared GOMODCACHE,
  its cache/download, GOCACHE, GOPATH and HOME is read before the run and after every sandboxed
  command. Any change stops the run at once with exit 3. So does a change to any live-tree file a
  mutant names.
- A killed mutant is run again in a new sandbox. A kill that does not repeat is a finding (exit 5),
  never a flake. The unmutated tree must pass before the first mutant and after the last.
- The work directory is removed only when its identity and its ownership token still match what
  this run recorded when it created it. It is never chosen from an environment variable later.

`--unsafe-host-run-for-fixture` turns the sandbox off, to prove the identity check fires. It is
refused unless both shared caches are given explicitly and each holds the fixture sentinel file,
so it cannot be pointed at a real cache.

Usage:
  mutate-sandboxed.py --mutants mutants.json [--tree DIR] [--image REF] -- go test ./pkg/...

mutants.json is a list of {"name", "file", "old", "new"} objects, with an optional "count"
(default 1): `old` must occur exactly `count` times in `file` (relative to the tree), and every
occurrence is replaced by `new`.

Exit codes: 0 done, no finding (survivors are listed, not failures); 2 refused or bad input;
3 shared state changed (LOUD); 4 the unmutated tree failed; 5 findings (an unrepeated kill, a
sandbox error or a timeout).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_IMAGE = "golang:1.27.3-bookworm"
SENTINEL = ".mutate-sandboxed-fixture-sentinel"
OWNER_FILE = ".mutate-sandboxed-owned"
DEFAULT_EXCLUDES = (".git", "node_modules", ".local")
# docker run's own failures: the daemon refused (125), the command could not run (126, 127).
DOCKER_INFRA_EXITS = {125, 126, 127}

EXIT_OK, EXIT_REFUSED, EXIT_SHARED_CHANGED, EXIT_BASELINE, EXIT_FINDINGS = 0, 2, 3, 4, 5


class Refused(Exception):
    """A precondition does not hold; nothing has run."""


class SharedStateChanged(Exception):
    """A watched host path changed identity: the boundary failed."""


# ---------------------------------------------------------------- identity


def identity(path: Path) -> dict | None:
    """The identity of path itself (never followed through a final symlink), or None if absent."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
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


@dataclass
class Watch:
    """Paths whose identity must not change, and files whose content must not change."""

    dirs: dict[str, Path]
    files: dict[str, Path] = field(default_factory=dict)

    def snapshot(self) -> dict:
        snap = {name: identity(p) for name, p in self.dirs.items()}
        for name, p in self.files.items():
            snap[name] = {"identity": identity(p), "sha256": file_digest(p)}
        return snap

    def verify(self, before: dict, when: str) -> None:
        after = self.snapshot()
        changed = sorted(k for k in before if before[k] != after.get(k))
        if changed:
            lines = [f"  {k}: {self.describe(k)}\n    before {before[k]}\n    after  {after.get(k)}" for k in changed]
            raise SharedStateChanged(f"after {when}:\n" + "\n".join(lines))

    def describe(self, key: str) -> str:
        return str(self.dirs.get(key) or self.files.get(key))


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
    def ignore(_d, names):
        return [n for n in names if n in excludes]

    shutil.copytree(src, dst, symlinks=True, ignore=ignore)


def clone_dir(src: Path, dst: Path) -> None:
    """Copy src to dst, with copy-on-write clones on APFS when cp supports them."""
    if sys.platform == "darwin" and subprocess.run(["cp", "-cR", str(src), str(dst)], capture_output=True).returncode == 0:
        return
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, symlinks=True)


# ---------------------------------------------------------------- host go facts


def go_env(names: list[str], env: dict[str, str]) -> dict[str, str]:
    out = subprocess.run(["go", "env", "-json", *names], capture_output=True, text=True, env=env, timeout=60)
    if out.returncode != 0:
        raise Refused(f"go env failed: {out.stderr.strip()}")
    return json.loads(out.stdout)


def file_url(p: Path) -> str:
    return Path(p).resolve().as_uri()


# ---------------------------------------------------------------- the sandbox


SANDBOX_ENV_DIRS = {
    "HOME": "home",
    "GOPATH": "gopath",
    "GOMODCACHE": "gomodcache",
    "GOCACHE": "gocache",
    "TMPDIR": "tmp",
    "XDG_CACHE_HOME": "xdg-cache",
}


@dataclass
class Result:
    name: str
    outcome: str  # PASSED, KILLED, SURVIVED, ERROR, TIMEOUT
    exit_code: int | None
    seconds: float
    log: str


class Runner:
    def __init__(self, args, watch: Watch, forbidden: dict[str, Path], work: WorkDir, docker: str):
        self.args = args
        self.watch = watch
        self.forbidden = forbidden
        self.work = work
        self.docker = docker
        self.seq = 0

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

    def docker_argv(self, d: Path, name: str) -> list[str]:
        mounts: list[tuple[Path, str, bool]] = [(d, "/work", False)]
        seed = self.work.path / "seed" / "gomodcache" / "cache" / "download"
        if seed.is_dir():
            mounts.append((seed, "/goproxy", True))
        check_mounts(mounts, self.work.path, self.forbidden)
        env = {k: f"/work/sandbox/{v}" for k, v in SANDBOX_ENV_DIRS.items()}
        env.update({
            "GOPROXY": "file:///goproxy" if seed.is_dir() else "off",
            "GOSUMDB": "off",  # go.sum still verifies every module; there is no network to ask
            "GOFLAGS": "-modcacherw",
            "GOTOOLCHAIN": "local",
            "GOENV": "off",
            "MUTATE_SANDBOXED": "1",
        })
        argv = [self.docker, "run", "--rm", "--name", name, "--network", self.args.network,
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "4096",
                "--read-only", "--tmpfs", "/tmp:rw,size=256m", "--user", f"{os.getuid()}:{os.getgid()}",
                "--workdir", "/work/src", "--entrypoint", ""]
        for src, dst, ro in mounts:
            argv += ["--mount", f"type=bind,source={real(src)},target={dst}" + (",readonly" if ro else "")]
        for k in sorted(env):
            argv += ["--env", f"{k}={env[k]}"]
        return argv + [self.args.image, *self.args.command]

    def host_argv_env(self, d: Path) -> tuple[list[str], dict[str, str]]:
        """--unsafe-host-run-for-fixture: the caller's environment, aimed at the fake caches."""
        env = dict(os.environ)
        env.update({
            "GOMODCACHE": str(self.args.shared_modcache),
            "GOCACHE": str(self.args.shared_gocache),
            # Were GOMODCACHE ever ignored, the default GOPATH/pkg/mod is still not the real one.
            "GOPATH": str(self.work.path / "unsafe-gopath"),
            "GOPROXY": "off",
            "GOTOOLCHAIN": "local",
            "GOENV": "off",
        })
        return list(self.args.command), env

    def run(self, label: str, pristine: Path, mutant: Mutant | None) -> Result:
        before = self.watch.snapshot()
        live = {m.file: file_digest(self.args.tree / m.file) for m in ([mutant] if mutant else [])}
        d = self.prepare(label, pristine, mutant)
        name = f"mutate-sandboxed-{os.getpid()}-{self.seq}-{secrets.token_hex(3)}"
        if self.args.unsafe_host_run_for_fixture:
            argv, env, cwd = *self.host_argv_env(d), d / "src"
        else:
            argv, env, cwd = self.docker_argv(d, name), self.docker_env(), None
        log_path = d / "output.log"
        start = time.monotonic()
        code, outcome = None, None
        with open(log_path, "wb") as log:
            try:
                proc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, env=env, cwd=cwd,
                                      timeout=self.args.timeout)
                code = proc.returncode
            except subprocess.TimeoutExpired:
                outcome = "TIMEOUT"
                if not self.args.unsafe_host_run_for_fixture:
                    subprocess.run([self.docker, "kill", name], capture_output=True, env=self.docker_env())
        secs = time.monotonic() - start
        # The boundary check comes before any verdict: a run that touched host state has no result.
        self.watch.verify(before, f"{label}")
        for f, digest in live.items():
            if file_digest(self.args.tree / f) != digest:
                raise SharedStateChanged(f"after {label}: the live tree's {f} changed")
        if outcome is None:
            if code == 0:
                outcome = "PASSED" if mutant is None else "SURVIVED"
            elif not self.args.unsafe_host_run_for_fixture and code in DOCKER_INFRA_EXITS:
                outcome = "ERROR"
            else:
                outcome = "FAILED" if mutant is None else "KILLED"
        return Result(label, outcome, code, round(secs, 2), str(log_path))

    def docker_env(self) -> dict[str, str]:
        """What the docker client itself needs from the caller; none of it reaches the container."""
        keep = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "USER", "LANG")
        return {k: os.environ[k] for k in keep if k in os.environ}


def seed_modules(args, work: WorkDir, pristine: Path, shared_modcache: Path, caller_proxy: str) -> None:
    """Fill an owned module cache from the unmutated tree. Reads the shared cache only as a file proxy."""
    seed = work.path / "seed"
    env = dict(os.environ)
    env.update({
        "GOMODCACHE": str(seed / "gomodcache"),
        "GOPATH": str(seed / "gopath"),
        "GOCACHE": str(seed / "gocache"),
        "GOFLAGS": "-modcacherw",
        "GOPROXY": ",".join(p for p in (file_url(shared_modcache / "cache" / "download"), caller_proxy) if p),
    })
    out = subprocess.run(["go", "mod", "download"], cwd=pristine, env=env, capture_output=True, text=True,
                         timeout=args.timeout)
    (seed / "download.log").write_text(out.stdout + out.stderr)
    if out.returncode != 0:
        raise Refused(f"seeding the module proxy failed (log {seed / 'download.log'}):\n{out.stderr[-2000:]}")


# ---------------------------------------------------------------- main


def parse(argv: list[str]):
    p = argparse.ArgumentParser(description="Run mutation tests in a sandbox that cannot reach shared host state.")
    p.add_argument("--mutants", type=Path, required=True)
    p.add_argument("--tree", type=Path, default=Path.cwd())
    p.add_argument("--image", default=DEFAULT_IMAGE)
    p.add_argument("--network", default="none", help="docker network for the sandbox (default none)")
    p.add_argument("--timeout", type=int, default=1800, help="seconds per sandboxed run")
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
    p.add_argument("--unsafe-host-run-for-fixture", action="store_true",
                   help="turn the sandbox OFF; only with explicit sentinel-marked fake caches")
    p.add_argument("command", nargs=argparse.REMAINDER)
    args = p.parse_args(argv)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        p.error("give the test command after --")
    args.tree = real(args.tree)
    return args


def resolve_shared(args) -> tuple[Path, Path, Path, str]:
    """The shared GOMODCACHE, GOCACHE and GOPATH, and the caller's GOPROXY."""
    if args.unsafe_host_run_for_fixture:
        if not (args.shared_modcache and args.shared_gocache):
            raise Refused("--unsafe-host-run-for-fixture needs --shared-modcache and --shared-gocache")
        for p in (args.shared_modcache, args.shared_gocache):
            if not (p / SENTINEL).is_file():
                raise Refused(f"{p} holds no {SENTINEL}: the sandbox is only turned off for a fake cache")
        try:
            facts = go_env(["GOMODCACHE", "GOCACHE"], {k: v for k, v in os.environ.items()
                                                      if k not in ("GOMODCACHE", "GOCACHE")})
        except (Refused, OSError):
            facts = {}
        for key, fake in (("GOMODCACHE", args.shared_modcache), ("GOCACHE", args.shared_gocache)):
            if facts.get(key) and (within(real(facts[key]), real(fake)) or within(real(fake), real(facts[key]))):
                raise Refused(f"{fake} overlaps the real {key} {facts[key]}")
        gopath = real(args.shared_modcache).parent
        return real(args.shared_modcache), real(args.shared_gocache), gopath, ""
    facts = go_env(["GOMODCACHE", "GOCACHE", "GOPATH", "GOPROXY"], dict(os.environ))
    modcache = real(args.shared_modcache or facts["GOMODCACHE"])
    gocache = real(args.shared_gocache or facts["GOCACHE"])
    gopath = real(facts["GOPATH"].split(os.pathsep)[0])
    return modcache, gocache, gopath, facts.get("GOPROXY", "")


def run_all(args, mutants: list[Mutant], runner: Runner, pristine: Path, report: dict) -> int:
    base = runner.run("baseline", pristine, None)
    report["results"].append(base.__dict__)
    print(f"baseline: {base.outcome} ({base.seconds}s)", flush=True)
    if base.outcome != "PASSED":
        print(f"mutate-sandboxed: the unmutated tree did not pass; log {base.log}", file=sys.stderr)
        return EXIT_BASELINE
    if args.warm_gocache and not args.unsafe_host_run_for_fixture:
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
        modcache, gocache, gopath, caller_proxy = resolve_shared(args)
    except Refused as e:
        print(f"mutate-sandboxed: refused: {e}", file=sys.stderr)
        return EXIT_REFUSED
    home = real(os.environ.get("HOME") or Path.home())
    forbidden = {"shared GOMODCACHE": modcache, "shared GOCACHE": gocache, "GOPATH": gopath, "HOME": home,
                 "live tree": args.tree, "docker socket": Path("/var/run/docker.sock")}
    watch = Watch({"GOMODCACHE": modcache, "GOMODCACHE/cache/download": modcache / "cache" / "download",
                   "GOCACHE": gocache, "GOPATH": gopath, "HOME": home, "live tree": args.tree})
    for name, root in (("GOMODCACHE", modcache), ("GOCACHE", gocache)):
        if (root / SENTINEL).exists():
            watch.files[f"{name}/{SENTINEL}"] = root / SENTINEL
    report: dict = {"tree": str(args.tree), "image": args.image, "sandbox": not args.unsafe_host_run_for_fixture,
                    "watched": {k: str(v) for k, v in watch.dirs.items()}, "results": []}
    initial = watch.snapshot()
    report["identity_before"] = initial
    work = None
    code = EXIT_OK
    try:
        if not args.unsafe_host_run_for_fixture:
            check_workdir(args.workdir_root, {k: v for k, v in forbidden.items() if k != "HOME"})
            if subprocess.run([args.docker, "version"], capture_output=True).returncode != 0:
                raise Refused(f"{args.docker} cannot reach a daemon")
        work = WorkDir(args.workdir_root)
        report["workdir"] = str(work.path)
        if not args.unsafe_host_run_for_fixture:
            check_workdir(work.path, {k: v for k, v in forbidden.items() if k != "HOME"})
        pristine = work.path / "pristine"
        copy_tree(args.tree, pristine, tuple(args.exclude))
        if not args.no_seed and not args.unsafe_host_run_for_fixture:
            seed_modules(args, work, pristine, modcache, caller_proxy)
            watch.verify(initial, "seeding the module proxy")
        code = run_all(args, mutants, Runner(args, watch, forbidden, work, args.docker), pristine, report)
    except SharedStateChanged as e:
        loud(str(e))
        report["shared_state_changed"] = str(e)
        code = EXIT_SHARED_CHANGED
        args.keep = True  # evidence
    except Refused as e:
        print(f"mutate-sandboxed: refused: {e}", file=sys.stderr)
        code = EXIT_REFUSED
    finally:
        report["identity_after"] = watch.snapshot()
        report["exit"] = code
        text = json.dumps(report, indent=2, default=str)
        if args.report:
            args.report.write_text(text)
        if work:
            (work.path / "report.json").write_text(text)
            if args.keep:
                print(f"work directory kept: {work.path}", file=sys.stderr)
            else:
                try:
                    work.remove()
                except Refused as e:
                    print(f"mutate-sandboxed: {e}", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
