#!/usr/bin/env python3
"""A docker stand-in for a sandbox boundary that failed (TXE-7549, step 2 only).

It answers `version` and `image inspect`, and for `run` executes the command directly with the
CALLER's Go settings (the fake host's, from /fakehost/caller-env.json, since the runner gives its
docker client only a minimal environment), ignoring every --env, mount and limit: the mutant then
sees the fake host's GOMODCACHE, exactly as the incident's mutant saw the real one. It exists to prove that the runner's alarm
fires when the boundary is gone. It is only ever run by negative-in-outer.sh, inside an outer
container that has no mount of this Mac's caches, HOME, Docker socket or credentials, and no
network; it refuses to run anywhere without /.dockerenv.
"""
import json
import os
import subprocess
import sys

CALLER_ENV = "/fakehost/caller-env.json"  # written by negative-in-outer.sh

if not os.path.exists("/.dockerenv"):
    print("leaky-docker: refused: only inside the outer container", file=sys.stderr)
    sys.exit(2)
args = sys.argv[1:]
if args[:1] != ["run"]:
    sys.exit(0)
VALUED = {"--pull", "--memory", "--cpus", "--name", "--network", "--cap-drop", "--security-opt",
          "--pids-limit", "--tmpfs", "--user", "--workdir", "--entrypoint", "--mount", "--env", "--cidfile",
          "--label"}
i, work = 1, None
while i < len(args) and args[i].startswith("--"):
    if args[i] == "--mount" and args[i + 1].endswith("target=/work"):
        work = dict(p.split("=", 1) for p in args[i + 1].split(",") if "=" in p)["source"]
    i += 2 if args[i] in VALUED else 1
cmd = args[i + 1:]
# The fake host's Go settings, which the runner's minimal docker-client environment does not carry.
env = dict(os.environ)
with open(CALLER_ENV) as f:
    env.update(json.load(f))
sys.exit(subprocess.run(cmd, cwd=os.path.join(work, "src"), env=env).returncode)
