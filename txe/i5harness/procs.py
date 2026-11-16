#!/usr/bin/env python3
# Copyright (C) 2026 TXE
# SPDX-License-Identifier: GPL-3.0-or-later
"""Start and stop the I5 harness's own processes, and nothing else (TXE-7516).

`start` runs a command as the leader of a new session and process group, with its
output appended to a log, and writes a pid file holding the pid, the group, the
executable name and the start time the kernel reports, plus a random token.

`stop` signals a process group only when all of these still hold: the pid is
alive, it leads its own group, and its executable name and kernel start time are
the ones recorded. A pid that was reused by another program fails the start-time
check and is left alone. No process's arguments are read or printed: only
`ps -o pgid=,lstart=,comm=`.

Usage:
  procs.py start --pidfile F --log F [--cwd D] -- CMD [ARG..]
  procs.py check --pidfile F
  procs.py stop  --pidfile F [--timeout SEC]
"""

import argparse
import json
import os
import secrets
import signal
import subprocess
import sys
import time


def ps_identity(pid):
    """(pgid, lstart, comm) of a live pid, or None."""
    r = subprocess.run(["ps", "-o", "pgid=", "-o", "lstart=", "-o", "comm=", "-p", str(pid)],
                       capture_output=True, text=True)
    line = r.stdout.strip()
    if r.returncode != 0 or not line:
        return None
    parts = line.split()
    # pgid, then lstart's five words (e.g. "Mon Nov 16 10:31:02 2026"), then comm.
    if len(parts) < 7:
        return None
    return int(parts[0]), " ".join(parts[1:6]), " ".join(parts[6:])


def cmd_start(a):
    if os.path.exists(a.pidfile):
        print(f"procs: {a.pidfile} exists; stop that process or remove the file first", file=sys.stderr)
        return 2
    if not a.command:
        print("procs: no command", file=sys.stderr)
        return 2
    log = open(a.log, "ab")
    proc = subprocess.Popen(a.command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                            cwd=a.cwd, start_new_session=True)
    ident = None
    for _ in range(50):
        ident = ps_identity(proc.pid)
        if ident:
            break
        time.sleep(0.05)
    if ident is None or ident[0] != proc.pid:
        print(f"procs: started {proc.pid} but could not confirm it leads its group", file=sys.stderr)
        return 2
    record = {"pid": proc.pid, "pgid": ident[0], "lstart": ident[1], "comm": ident[2],
              "token": secrets.token_hex(16)}
    tmp = a.pidfile + ".tmp"
    with open(tmp, "w") as f:
        json.dump(record, f)
    os.replace(tmp, a.pidfile)
    print(json.dumps({"pid": proc.pid, "comm": os.path.basename(ident[2])}))
    return 0


def load(pidfile):
    with open(pidfile) as f:
        return json.load(f)


def matches(rec):
    """'match', 'gone' or a reason the live pid is not ours."""
    ident = ps_identity(rec["pid"])
    if ident is None:
        return "gone"
    pgid, lstart, comm = ident
    if pgid != rec["pid"]:
        return f"pid {rec['pid']} no longer leads its own group"
    if lstart != rec["lstart"]:
        return f"pid {rec['pid']} started at {lstart!r}, not {rec['lstart']!r}: another process"
    if comm != rec["comm"]:
        return f"pid {rec['pid']} runs {os.path.basename(comm)!r}, not {os.path.basename(rec['comm'])!r}"
    return "match"


def cmd_check(a):
    rec = load(a.pidfile)
    state = matches(rec)
    print(json.dumps({"pid": rec["pid"], "state": state if state in ("match", "gone") else "foreign",
                      "detail": state}))
    return 0 if state == "match" else 3


def cmd_stop(a):
    if not os.path.exists(a.pidfile):
        print(f"procs: {a.pidfile}: no pid file; nothing to stop")
        return 0
    rec = load(a.pidfile)
    state = matches(rec)
    if state == "gone":
        print(f"procs: {rec['pid']} is not running")
        os.replace(a.pidfile, a.pidfile + ".stopped")
        return 0
    if state != "match":
        print(f"procs: refusing to signal: {state}", file=sys.stderr)
        return 3
    os.killpg(rec["pid"], signal.SIGTERM)
    deadline = time.time() + a.timeout
    while time.time() < deadline:
        if matches(rec) == "gone":
            break
        time.sleep(0.2)
    else:
        if matches(rec) == "match":
            os.killpg(rec["pid"], signal.SIGKILL)
            print(f"procs: {rec['pid']} ignored SIGTERM for {a.timeout}s; group killed")
    # Reap when this process is the parent (tests); otherwise init reaps it.
    try:
        os.waitpid(rec["pid"], os.WNOHANG)
    except ChildProcessError:
        pass
    os.replace(a.pidfile, a.pidfile + ".stopped")
    print(f"procs: stopped {rec['pid']}")
    return 0


def main(argv):
    p = argparse.ArgumentParser(prog="procs.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("start")
    s.add_argument("--pidfile", required=True)
    s.add_argument("--log", required=True)
    s.add_argument("--cwd")
    s.add_argument("command", nargs=argparse.REMAINDER)
    c = sub.add_parser("check")
    c.add_argument("--pidfile", required=True)
    t = sub.add_parser("stop")
    t.add_argument("--pidfile", required=True)
    t.add_argument("--timeout", type=float, default=20)
    a = p.parse_args(argv)
    if a.cmd == "start" and a.command and a.command[0] == "--":
        a.command = a.command[1:]
    return {"start": cmd_start, "check": cmd_check, "stop": cmd_stop}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
