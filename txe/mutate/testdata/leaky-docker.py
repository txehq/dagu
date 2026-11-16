#!/usr/bin/env python3
"""A docker stand-in for a sandbox boundary that failed (TXE-7549, step 2 only).

It answers `version` and `image inspect`, and for `run` executes the command directly with the
CALLER's Go settings (the fake host's, from /fakehost/caller-env.json, since the runner gives its
docker client only a minimal environment), ignoring every --env, mount and limit: the mutant then
sees the fake host's GOMODCACHE, exactly as the incident's mutant saw the real one. It exists to
prove that the runner's alarm fires when the boundary is gone. It is only ever run by
negative-in-outer.sh, inside an outer container that has no mount of this Mac's caches, HOME,
Docker socket or credentials, and no network; it refuses to run anywhere without /.dockerenv.

parse_run is importable on its own (no side effects), so a test can check it against the exact
argument list the runner emits.
"""
import json
import os
import subprocess
import sys

CALLER_ENV = "/fakehost/caller-env.json"  # written by negative-in-outer.sh

# Options of `docker run` that take a value, as the runner emits them.
VALUED = {"--log-driver", "--pull", "--memory", "--cpus", "--name", "--network", "--cap-drop",
          "--security-opt", "--pids-limit", "--tmpfs", "--user", "--workdir", "--entrypoint", "--mount",
          "--env", "--cidfile", "--label"}


def parse_run(args: list[str]) -> tuple[str, list[str]]:
    """For `run <options> <image> <command...>`: the source of the /work mount and the command.
    An option it does not know is an error, never skipped, so a new runner flag cannot silently
    shift the image and command."""
    if args[:1] != ["run"]:
        raise ValueError("not a run")
    i, work = 1, None
    while i < len(args) and args[i].startswith("--"):
        flag = args[i]
        if flag not in VALUED and flag not in ("--rm", "--read-only"):
            raise ValueError(f"unknown docker run option {flag}")
        if flag == "--mount" and args[i + 1].endswith("target=/work"):
            work = dict(p.split("=", 1) for p in args[i + 1].split(",") if "=" in p)["source"]
        i += 2 if flag in VALUED else 1
    if work is None:
        raise ValueError("no /work mount")
    return work, args[i + 1:]


def main(args: list[str]) -> int:
    if not os.path.exists("/.dockerenv"):
        print("leaky-docker: refused: only inside the outer container", file=sys.stderr)
        return 2
    if args[:1] == ["inspect"]:
        # Its runs complete synchronously, so a recorded container is never still running: answer
        # the runner's stopped-state check, and report no container to any other inspection.
        if "{{.State.Running}}" in args:
            print("false")
            return 0
        print("Error: No such object: " + args[-1], file=sys.stderr)
        return 1
    if args[:2] == ["image", "inspect"]:
        print("null")  # declares no volumes
        return 0
    if args[:1] != ["run"]:
        return 0
    work, cmd = parse_run(args)
    # The fake host's Go settings, which the runner's minimal docker-client environment does not carry.
    env = dict(os.environ)
    with open(CALLER_ENV) as f:
        env.update(json.load(f))
    return subprocess.run(cmd, cwd=os.path.join(work, "src"), env=env).returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
