#!/usr/bin/env python3
# Copyright (C) 2026 TXE
# SPDX-License-Identifier: GPL-3.0-or-later
"""Pin the I5 harness's binary tuple and write its manifest (TXE-7516).

The tuple is T2 (TXE-3401 root, msg_f64163e22ee5):
  W, C  the installed worker/CLI binary of the base B, copied read-only into the
        harness's own bin and hash-checked against the receipt's sha256;
  R     B's tag plus TXE-7514's commit(s), built from a `git archive` export;
  H     B's hub tag, built from a `git archive` export.
Nothing falls back to another tuple by itself. `closure` reports every package
A's commits change and whether it is inside the reviewer's dependency closure,
so a reviewer of the manifest can assess the delta. A change outside the reviewer
package sets "assessment_required", and the manifest carries it unchanged.

Usage:
  pin.py copy-installed --src F --dest F --expect-sha HEX --record F
  pin.py build   --repo D --base REF [--pick SHA..] --version V --workdir D --out F --record F
  pin.py closure --repo D --base REF --pick SHA.. --workdir D --record F
                 [--review-pkg ./internal/txe/review] [--main-pkg ./cmd]
  pin.py manifest --out F --harness-dir D --record F.. [--extra NAME=JSONFILE..]
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import io


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, cwd=None, env=None, input_bytes=None):
    r = subprocess.run(cmd, cwd=cwd, env=env, input=input_bytes, capture_output=True)
    if r.returncode != 0:
        raise SystemExit(f"pin: {' '.join(cmd[:3])}… failed ({r.returncode}): {r.stderr.decode(errors='replace')[-2000:]}")
    return r.stdout


def go_build_info(binary):
    """`go version -m`: the Go version, main module, VCS settings and every dependency."""
    r = subprocess.run(["go", "version", "-m", binary], capture_output=True, text=True)
    return r.stdout if r.returncode == 0 else f"unavailable: {r.stderr.strip()}"


def write_record(path, rec):
    with open(path, "w") as f:
        json.dump(rec, f, indent=2, sort_keys=True)
        f.write("\n")


def cmd_copy_installed(a):
    if os.path.exists(a.dest):
        raise SystemExit(f"pin: {a.dest} exists; the harness bin is written once")
    before = sha256_file(a.src)
    if before != a.expect_sha:
        raise SystemExit(f"pin: {a.src} hashes to {before}, not the receipt's {a.expect_sha}; nothing copied")
    # Read-only on the source: open for reading, write a new file we own.
    os.makedirs(os.path.dirname(os.path.abspath(a.dest)), exist_ok=True)
    with open(a.src, "rb") as src, open(a.dest, "xb") as dst:
        shutil.copyfileobj(src, dst)
    os.chmod(a.dest, 0o555)
    after_src, copied = sha256_file(a.src), sha256_file(a.dest)
    if not (before == after_src == copied):
        raise SystemExit(f"pin: hashes changed during the copy (src {before}->{after_src}, copy {copied})")
    write_record(a.record, {"role": "W/C", "method": "read-only copy of the installed binary",
                            "source_path": a.src, "path": os.path.abspath(a.dest), "sha256": copied,
                            "receipt_sha256": a.expect_sha, "build_info": go_build_info(a.dest)})
    print(f"pin: copied {os.path.basename(a.src)} sha256 {copied}")
    return 0


def export(repo, base, picks, dest):
    """B's tree from `git archive`, with each pick's diff applied in order."""
    if os.path.exists(dest):
        raise SystemExit(f"pin: {dest} exists; use a fresh workdir")
    os.makedirs(dest)
    base_commit = run(["git", "-C", repo, "rev-parse", f"{base}^{{commit}}"]).decode().strip()
    with tarfile.open(fileobj=io.BytesIO(run(["git", "-C", repo, "archive", base_commit]))) as t:
        # The archive is our own repository's; the filter exists from Python 3.12.
        if hasattr(tarfile, "data_filter"):
            t.extractall(dest, filter="data")
        else:
            t.extractall(dest)
    applied = []
    for p in picks:
        commit = run(["git", "-C", repo, "rev-parse", f"{p}^{{commit}}"]).decode().strip()
        parents = run(["git", "-C", repo, "rev-list", "--parents", "-n1", commit]).decode().split()[1:]
        if len(parents) != 1:
            raise SystemExit(f"pin: {commit} has {len(parents)} parents; pick the change's own commits")
        patch = run(["git", "-C", repo, "diff", "--binary", parents[0], commit])
        run(["git", "apply", "--whitespace=nowarn", "-"], cwd=dest, input_bytes=patch)
        applied.append(commit)
    return base_commit, applied


def tree_digest(root):
    """sha256 over every exported file's path and bytes, in path order."""
    h = hashlib.sha256()
    for d, dirs, files in os.walk(root):
        dirs.sort()
        for name in sorted(files):
            p = os.path.join(d, name)
            h.update(os.path.relpath(p, root).encode() + b"\0")
            h.update(sha256_file(p).encode() + b"\n")
    return h.hexdigest()


def cmd_build(a):
    src = os.path.join(a.workdir, "src")
    base_commit, applied = export(a.repo, a.base, a.pick, src)
    env = dict(os.environ, GOFLAGS="-mod=readonly")
    run(["go", "build", "-ldflags", f"-X 'main.version={a.version}'", "-o", os.path.abspath(a.out), a.main_pkg],
        cwd=src, env=env)
    write_record(a.record, {"role": a.role, "method": "git archive + applied picks + go build",
                            "base": a.base, "base_commit": base_commit, "picks": applied,
                            "source_tree_sha256": tree_digest(src), "version": a.version,
                            "go": run(["go", "version"], cwd=src).decode().strip(),
                            "path": os.path.abspath(a.out), "sha256": sha256_file(a.out),
                            "build_info": go_build_info(a.out)})
    print(f"pin: built {a.role} sha256 {sha256_file(a.out)}")
    return 0


def go_list_deps(src, pkg):
    out = run(["go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}} {{.Dir}}{{end}}", pkg], cwd=src,
              env=dict(os.environ, GOFLAGS="-mod=readonly"))
    deps = {}
    for line in out.decode().splitlines():
        if line.strip():
            ip, _, d = line.partition(" ")
            deps[os.path.relpath(d, src)] = ip
    return deps


def cmd_closure(a):
    src = os.path.join(a.workdir, "src")
    base_commit, applied = export(a.repo, a.base, a.pick, src)
    changed = []
    for c in applied:
        parent = run(["git", "-C", a.repo, "rev-parse", f"{c}^"]).decode().strip()
        changed += run(["git", "-C", a.repo, "diff", "--name-only", parent, c]).decode().split()
    changed = sorted(set(changed))
    review = go_list_deps(src, a.review_pkg)
    main = go_list_deps(src, a.main_pkg)
    review_dir = os.path.normpath(a.review_pkg)
    rows, outside = [], []
    for f in changed:
        d = os.path.dirname(f) or "."
        is_test = f.endswith("_test.go")
        row = {"file": f, "test_only": is_test,
               "in_reviewer_closure": d in review, "in_binary": d in main,
               "package": review.get(d) or main.get(d)}
        rows.append(row)
        # Strict on purpose: an embedded prompt or a registry change also alters the
        # reviewer, so anything but the reviewer package's own files is assessed.
        if not is_test and os.path.normpath(d) != review_dir:
            outside.append(f)
    write_record(a.record, {"base": a.base, "base_commit": base_commit, "picks": applied,
                            "changed": rows, "outside_reviewer_package": outside,
                            "assessment_required": bool(outside),
                            "note": "A non-empty outside_reviewer_package is returned for assessment; "
                                    "the harness does not switch tuples by itself (root ruling D2)."})
    print(f"pin: {len(changed)} changed file(s); {len(outside)} outside the reviewer package")
    return 0


def cmd_manifest(a):
    if os.path.exists(a.out):
        raise SystemExit(f"pin: {a.out} exists; a manifest is written once")
    harness = {}
    for name in sorted(os.listdir(a.harness_dir)):
        p = os.path.join(a.harness_dir, name)
        if os.path.isfile(p):
            harness[name] = {"path": os.path.abspath(p), "sha256": sha256_file(p)}
    binaries, records = {}, {}
    for r in a.record:
        rec = json.load(open(r))
        records[os.path.basename(r)] = rec
        if "path" in rec and "sha256" in rec:
            binaries[rec.get("role", os.path.basename(r))] = {"path": rec["path"], "sha256": rec["sha256"]}
    extra = {}
    for e in a.extra:
        name, _, path = e.partition("=")
        extra[name] = json.load(open(path))
    m = {"schema": 1, "ticket": "TXE-7516", "binaries": binaries, "harness_files": harness,
         "records": records, **extra}
    with open(a.out, "x") as f:
        json.dump(m, f, indent=2, sort_keys=True)
        f.write("\n")
    os.chmod(a.out, 0o444)
    print(f"pin: manifest {a.out} sha256 {sha256_file(a.out)}")
    return 0


def main(argv):
    p = argparse.ArgumentParser(prog="pin.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("copy-installed")
    for f in ("--src", "--dest", "--expect-sha", "--record"):
        c.add_argument(f, required=True)
    b = sub.add_parser("build")
    for f in ("--repo", "--base", "--version", "--workdir", "--out", "--record"):
        b.add_argument(f, required=True)
    b.add_argument("--pick", action="append", default=[])
    b.add_argument("--role", default="R")
    b.add_argument("--main-pkg", default="./cmd")
    k = sub.add_parser("closure")
    for f in ("--repo", "--base", "--workdir", "--record"):
        k.add_argument(f, required=True)
    k.add_argument("--pick", action="append", default=[])
    k.add_argument("--review-pkg", default="./internal/txe/review")
    k.add_argument("--main-pkg", default="./cmd")
    m = sub.add_parser("manifest")
    m.add_argument("--out", required=True)
    m.add_argument("--harness-dir", required=True)
    m.add_argument("--record", action="append", default=[])
    m.add_argument("--extra", action="append", default=[])
    a = p.parse_args(argv)
    return {"copy-installed": cmd_copy_installed, "build": cmd_build, "closure": cmd_closure,
            "manifest": cmd_manifest}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
