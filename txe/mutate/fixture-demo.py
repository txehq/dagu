#!/usr/bin/env python3
"""The TXE-7549 acceptance demonstration. Each step needs its own go-ahead; run one per call.

  fixture-demo.py sandboxed <evidence-dir> <image-id> [--deadline 300]
    Step 1. testdata/fixture's mutant runs Go's module-cache clean with the environment it is given,
    through the runner's real sandbox on this machine, against sentinel-only fake caches inside
    the demo's own directory (--no-seed: the real module cache is not read). Expected: runner
    exit 0, the mutant SURVIVED, the fake caches and sentinels unchanged.

  fixture-demo.py outer-negative <evidence-dir> <image-id> [--deadline 180]
    Step 2. Inside an OUTER container (no network, no capabilities, no mount but a read-only copy
    of txe/mutate, no Docker socket, no credentials), negative-in-outer.sh gives the runner a
    docker that leaks the caller's environment; the same mutant deletes the outer container's own
    fake cache and the runner inside must exit 3. Nothing runs on this machine but `docker run`.

<image-id> is an image already present locally, named by its immutable id (sha256:...); nothing
is pulled. --deadline bounds the WHOLE demo, every container, error handling and cleanup
included: the runner gets the deadline less a cleanup margin, and past it the demo stops the
runner (SIGTERM, then SIGKILL) and force-removes the containers that were recorded as started
(docker's --cidfile, outside every mount), each only when docker reports that container's own
name and owner token. SIGTERM, SIGINT or SIGHUP to the demo do the same.

The demo writes only inside one directory it creates exclusively (mkdtemp) and stamps with a
random token; it removes that directory only when the token and the directory's identity
(device, inode, birth time) still match, and keeps it as evidence after any unexpected result.
Logs and reports go to <evidence-dir>.

Exit 0 when the step showed the expected result; 1 otherwise; 2 refused.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("mutate_sandboxed", HERE / "mutate-sandboxed.py")
ms = importlib.util.module_from_spec(_spec)
sys.modules["mutate_sandboxed"] = ms
_spec.loader.exec_module(ms)

OUTER_PREFIX = "txe-7549-outer"
SENTINEL_TEXT = "TXE-7549 fixture sentinel\n"


class Demo:
    def __init__(self, args, end: float):
        self.args = args
        self.end = end
        self.margin = min(45.0, args.deadline / 3)
        self.evidence = args.evidence
        self.log_path = self.evidence / f"{args.step}.log"
        self.root: ms.WorkDir | None = None
        self.cleanup: list[str] = []

    def say(self, msg: str) -> None:
        line = f"{time.strftime('%H:%M:%SZ', time.gmtime())} {msg}"
        print(line, flush=True)
        with open(self.log_path, "a") as f:
            f.write(line + "\n")

    def left(self) -> float:
        return self.end - time.monotonic()

    def fake_state(self, modcache: Path, gocache: Path) -> dict:
        out = {}
        for name, p in (("GOMODCACHE", modcache), ("GOMODCACHE/cache/download", modcache / "cache" / "download"),
                        ("GOCACHE", gocache)):
            out[name] = {"identity": ms.identity(p), "entries": ms.entries(p)}
        for name, p in (("GOMODCACHE sentinel", modcache / ms.SENTINEL), ("GOCACHE sentinel", gocache / ms.SENTINEL)):
            out[name] = {"identity": ms.identity(p), "sha256": ms.file_digest(p)}
        return out

    def wait_bounded(self, proc: subprocess.Popen, budget: float) -> int | None:
        """Wait for proc within budget seconds; past it, or on a signal, stop it and return None."""
        try:
            return proc.wait(timeout=max(budget, 0.1))
        except subprocess.TimeoutExpired:
            self.say(f"deadline: stopping pid {proc.pid}")
        except ms.Stopped as e:
            self.say(f"{e}: stopping pid {proc.pid}")
            self.stop(proc)
            raise
        self.stop(proc)
        return None

    def stop(self, proc: subprocess.Popen) -> None:
        if proc.poll() is not None:
            return
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=min(20.0, max(self.margin / 2, 1.0)))
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    # -- step 1
    def sandboxed(self) -> bool:
        root = self.root.path
        modcache = root / "fake-gopath" / "pkg" / "mod"
        gocache = root / "fake-gocache"
        (modcache / "cache" / "download" / "example.com").mkdir(parents=True)
        gocache.mkdir()
        (root / "work").mkdir()
        for d in (modcache, gocache):
            (d / ms.SENTINEL).write_text(SENTINEL_TEXT)
        shutil.copytree(HERE / "testdata" / "fixture", root / "fixture", symlinks=True)
        before = self.fake_state(modcache, gocache)
        self.say("fake caches before: " + json.dumps(before, default=str))
        runner_deadline = int(self.left() - self.margin)
        if runner_deadline < 10:
            raise ms.Stopped(f"only {runner_deadline}s left for the runner")
        report = self.evidence / f"{self.args.step}.report.json"
        argv = [sys.executable, "-I", str(HERE / "mutate-sandboxed.py"), "--mutants", str(root / "fixture" / "mutants.json"),
                "--tree", str(root / "fixture"), "--shared-modcache", str(modcache), "--shared-gocache", str(gocache),
                "--workdir-root", str(root / "work"), "--image", self.args.image, "--docker", self.args.docker,
                "--no-seed", "--memory", "2g", "--cpus", "2", "--pids", "512", "--timeout", "600",
                "--deadline", str(runner_deadline), "--report", str(report), "--", "go", "test", "-v", "./..."]
        self.say("runner: " + " ".join(argv))
        with open(self.evidence / f"{self.args.step}.runner.log", "wb") as out:
            proc = subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT)
            rc = self.wait_bounded(proc, self.left() - self.margin / 2)
        after = self.fake_state(modcache, gocache)
        self.say("fake caches after: " + json.dumps(after, default=str))
        self.say(f"runner exit {rc} (expected 0)")
        outcome, tails = {}, {}
        try:
            results = json.loads(report.read_text())["results"]
            outcome = {r["name"]: r["outcome"] for r in results}
            tails = {r["name"]: r.get("output_tail", "") for r in results}
        except (OSError, ValueError, KeyError):
            pass
        self.say(f"outcomes {outcome}")
        mutant = "cleanup cleans the env module cache"
        survived = outcome.get(mutant) == "SURVIVED"
        # What the mutant did inside the sandbox, as the fixture test logged it (go test -v):
        # observed, not inferred. The baseline's line is the positive control.
        for name in ("baseline", mutant):
            lines = [ln.strip() for ln in tails.get(name, "").splitlines() if "cleanup" in ln.lower()]
            self.say(f"{name} reported: {lines}")
        cleaned = "cleanup returned: <nil>" in tails.get(mutant, "") and "exists=false" in tails.get(mutant, "")
        control = "exists=true" in tails.get("baseline", "")
        self.say(f"inside the sandbox: mutant's go clean returned nil and its GOMODCACHE is gone: {cleaned}; "
                 f"baseline's GOMODCACHE still there: {control}")
        return rc == 0 and survived and before == after and cleaned and control

    # -- step 2
    def outer_negative(self) -> bool:
        root = self.root.path
        runner_copy = root / "runner"
        runner_copy.mkdir()
        for name in ("mutate-sandboxed.py", "negative-in-outer.sh"):
            shutil.copy2(HERE / name, runner_copy / name)
        shutil.copytree(HERE / "testdata", runner_copy / "testdata", symlinks=True)
        name = f"{OUTER_PREFIX}-{self.root.token[:12]}"
        cidfile = root / "outer.cid"  # outside the read-only mount's source
        argv = [self.args.docker, "run", "--rm", "--pull", "never", "--name", name, "--cidfile", str(cidfile),
                "--label", f"{ms.OWNER_LABEL}={self.root.token}", "--network", "none", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--pids-limit", "512", "--memory", "2g", "--cpus", "2",
                "--mount", f"type=bind,source={runner_copy},target=/runner,readonly", "--workdir", "/",
                "--entrypoint", "", self.args.image, "bash", "/runner/negative-in-outer.sh"]
        self.outer = (name, cidfile)
        self.say("outer: " + " ".join(argv))
        with open(self.evidence / f"{self.args.step}.outer.log", "wb") as out:
            proc = subprocess.Popen(argv, stdout=out, stderr=subprocess.STDOUT, env=ms.docker_client_env())
            rc = self.wait_bounded(proc, self.left() - self.margin)
        self.say(f"outer container exit {rc} (expected 0: the runner inside exited 3)")
        return rc == 0

    def sweep(self) -> None:
        """Remove every container recorded as started under the demo root, and only those."""
        if not self.root:
            return
        env = ms.docker_client_env()
        targets = []
        if getattr(self, "outer", None):
            targets.append((self.outer[1], self.outer[0], self.root.token))
        for work in sorted((self.root.path / "work").glob("mutate-sandboxed-*")):
            try:
                token = (work / ms.OWNER_FILE).read_text()
            except OSError:
                continue
            for cid in sorted((work / "cids").glob("*.cid")):
                targets.append((cid, f"mutate-sandboxed-{token[:12]}-{cid.stem}", token))
        for cidfile, name, token in targets:
            try:
                self.cleanup.append(ms.remove_owned_container(self.args.docker, cidfile, name, token, env, self.end))
            except (OSError, subprocess.TimeoutExpired) as e:
                self.cleanup.append(f"{name}: cleanup error {e}")
        self.say(f"container sweep: {self.cleanup or 'nothing recorded'}")


def parse(argv):
    p = argparse.ArgumentParser(description="TXE-7549 acceptance demonstration, one step per call.")
    p.add_argument("step", choices=["sandboxed", "outer-negative"])
    p.add_argument("evidence", type=Path)
    p.add_argument("image")
    p.add_argument("--deadline", type=int, help="seconds for the whole demo (default 300 / 180)")
    p.add_argument("--docker", default="docker")
    args = p.parse_args(argv)
    if args.deadline is None:
        args.deadline = 300 if args.step == "sandboxed" else 180
    return args


def main(argv) -> int:
    args = parse(argv)
    end = time.monotonic() + args.deadline  # the clock starts before any preflight
    if not args.image.startswith("sha256:"):
        print("give the image by its immutable id (sha256:...), not a tag", file=sys.stderr)
        return 2
    if args.deadline < 30:
        print("--deadline must be at least 30 seconds", file=sys.stderr)
        return 2
    try:
        inspected = subprocess.run([args.docker, "image", "inspect", args.image], capture_output=True,
                                   env=ms.docker_client_env(), timeout=min(60.0, (end - time.monotonic()) / 3))
    except subprocess.TimeoutExpired:
        print("docker image inspect did not answer inside the deadline's preflight budget", file=sys.stderr)
        return 1
    if inspected.returncode != 0:
        print(f"image {args.image} is not present locally; this demonstration pulls nothing", file=sys.stderr)
        return 2
    args.evidence.mkdir(parents=True, exist_ok=True)
    demo = Demo(args, end)
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, ms.stop_on_signal)
    ok = False
    try:
        demo.root = ms.WorkDir(Path(tempfile.gettempdir()))
        demo.say(f"== {args.step} image {args.image} deadline {args.deadline}s root {demo.root.path}")
        ok = demo.sandboxed() if args.step == "sandboxed" else demo.outer_negative()
    except ms.Stopped as e:
        demo.say(f"stopped: {e}")
    finally:
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        demo.sweep()
        if demo.root:
            if ok:
                try:
                    demo.root.remove()
                    demo.say(f"removed {demo.root.path}")
                except (ms.Refused, OSError) as e:
                    demo.say(f"left {demo.root.path}: {e}")
            else:
                demo.say(f"kept {demo.root.path} as evidence")
        demo.say(f"result: {'EXPECTED' if ok else 'NOT AS EXPECTED'} after {args.deadline - demo.left():.1f}s")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
