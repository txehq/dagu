#!/usr/bin/env python3
# Copyright (C) 2026 TXE
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail-loud checks the I5 harness runs before and after each step (TXE-7516).

The harness is only meaningful if every call the test worker makes to its hub
goes through the harness's relay, and if nothing reaches the shared Mac worker's
ports. A worker sends its owner-routed calls (claim ack, RunHeartbeat,
ReportStatus, logs) to the address the coordinator registers, which is its
advertise host and its own listen port. So the coordinator must bind somewhere
the relay is not ([::1]) and register the relay's address (127.0.0.1, same port).
If any check below fails, the step must not go on.

Each subcommand exits 0 and prints "PREFLIGHT OK: ..." when it holds, and exits 2
and prints "PREFLIGHT FAIL: ..." lines when it does not. Nothing here changes
state: it reads files, lsof output and the local port table only.

  config   --hub-config F --relay-coord HOST:PORT --relay-front HOST:PORT
  hub-log  --log F --relay-coord HOST:PORT --bind HOST
  registry --dir <hub data>/service-registry/coordinator --relay-coord HOST:PORT
  conns    --pid N --allow HOST:PORT[,..] --require HOST:PORT [--lsof-output F]
  logs     --forbid PORT[,..] FILE..
  ports    --free PORT[,..]
  pins     --manifest F
"""

import argparse
import glob
import hashlib
import json
import os
import re
import socket
import subprocess
import sys

# The shared installation's ports on this Mac (TXE-6976 report 15): the hub
# frontend and coordinator port-forward. Nothing in a harness may use them.
SHARED_PORTS = (18080, 50055)


class Failed(Exception):
    pass


def fail(msgs):
    for m in msgs:
        print(f"PREFLIGHT FAIL: {m}")
    return 2


def hostport(text):
    if text.startswith("["):
        host, _, port = text[1:].partition("]:")
    else:
        host, _, port = text.rpartition(":")
    if not port.isdigit():
        raise Failed(f"{text!r} is not host:port")
    return host, int(port)


def read_simple_yaml(path):
    """The harness's own rendered hub config: two-level 'key: value' only."""
    out, section = {}, None
    for raw in open(path):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        key, sep, value = line.strip().partition(":")
        if not sep:
            raise Failed(f"{path}: unreadable line {raw.strip()!r}")
        value = value.strip().strip('"')
        if indent == 0:
            section = key if value == "" else None
            out[key] = {} if value == "" else value
        elif section is not None and indent == 2:
            out[section][key] = value
        # deeper levels (auth.builtin...) are not checked here
    return out


def cmd_config(a):
    cfg = read_simple_yaml(a.hub_config)
    rh, rp = hostport(a.relay_coord)
    fh, fp = hostport(a.relay_front)
    coord = cfg.get("coordinator") or {}
    errs = []
    if coord.get("host") != "[::1]":
        errs.append(f"coordinator.host is {coord.get('host')!r}; it must bind [::1] so the relay can own {rh}:{rp}")
    if coord.get("advertise") != rh:
        errs.append(f"coordinator.advertise is {coord.get('advertise')!r}; it must be the relay host {rh}")
    if coord.get("port") != str(rp):
        errs.append(f"coordinator.port is {coord.get('port')!r}; it must equal the relay's coordinator port {rp}")
    front = cfg.get("port")
    if front == str(fp):
        errs.append(f"frontend port {front} equals the relay's frontend port; the relay must sit in front of it")
    for name, val in (("port", front), ("coordinator.port", coord.get("port"))):
        if val and val.isdigit() and int(val) in SHARED_PORTS:
            errs.append(f"{name} {val} is a shared-installation port")
    for p in (rp, fp):
        if p in SHARED_PORTS:
            errs.append(f"relay port {p} is a shared-installation port")
    if cfg.get("host") != "127.0.0.1":
        errs.append(f"frontend host is {cfg.get('host')!r}; it must be 127.0.0.1")
    if errs:
        return fail(errs)
    print(f"PREFLIGHT OK: config binds [::1]:{rp}, advertises {rh}:{rp}, frontend {front} behind {fh}:{fp}")
    return 0


KV = re.compile(r'(\S+?)=("(?:[^"\\]|\\.)*"|\S*)')


def fields(line):
    return {k: v.strip('"') for k, v in KV.findall(line)}


def cmd_hub_log(a):
    rh, rp = hostport(a.relay_coord)
    init = reg = None
    for line in open(a.log, errors="replace"):
        if 'msg="Coordinator initialization"' in line:
            init = fields(line)
        elif 'msg="Starting service registry"' in line and "service=coordinator" in line:
            reg = fields(line)
    errs = []
    if init is None:
        errs.append("no 'Coordinator initialization' line in the hub log")
    else:
        if init.get("bind-address") != a.bind:
            errs.append(f"coordinator bound {init.get('bind-address')!r}, not {a.bind!r}")
        if init.get("advertise-address") != rh:
            errs.append(f"coordinator advertises {init.get('advertise-address')!r}, not the relay host {rh}")
        if init.get("port") != str(rp):
            errs.append(f"coordinator port {init.get('port')!r}, not the relay's {rp}")
    if reg is None:
        errs.append("no coordinator 'Starting service registry' line in the hub log")
    elif (reg.get("host"), reg.get("port")) != (rh, str(rp)):
        errs.append(f"coordinator registered {reg.get('host')}:{reg.get('port')}, not the relay {rh}:{rp}")
    if errs:
        return fail(errs)
    print(f"PREFLIGHT OK: hub log shows bind {a.bind}, advertise and registry {rh}:{rp}")
    return 0


def cmd_registry(a):
    rh, rp = hostport(a.relay_coord)
    files = sorted(glob.glob(os.path.join(a.dir, "*.json")))
    if not files:
        return fail([f"no coordinator registration under {a.dir}"])
    errs = []
    for f in files:
        try:
            info = json.load(open(f))
        except (OSError, ValueError) as err:
            errs.append(f"{f}: unreadable: {err}")
            continue
        if (info.get("host"), info.get("port")) != (rh, rp):
            errs.append(f"{os.path.basename(f)} registers {info.get('host')}:{info.get('port')}; "
                        f"workers would send owner calls there, not through the relay {rh}:{rp}")
    if errs:
        return fail(errs)
    print(f"PREFLIGHT OK: {len(files)} coordinator registration(s), all at the relay {rh}:{rp}")
    return 0


def lsof_remotes(text):
    """Remote endpoints from `lsof -nP -a -p N -iTCP -sTCP:ESTABLISHED -Fn` output."""
    out = []
    for line in text.splitlines():
        if line.startswith("n") and "->" in line:
            out.append(line.split("->", 1)[1].strip())
    return out


def cmd_conns(a):
    if a.lsof_output:
        text = open(a.lsof_output).read()
    else:
        r = subprocess.run(["lsof", "-nP", "-a", "-p", str(a.pid), "-iTCP", "-sTCP:ESTABLISHED", "-Fn"],
                           capture_output=True, text=True)
        text = r.stdout
    remotes = lsof_remotes(text)
    allow = set(a.allow.split(","))
    errs = [f"process {a.pid} is connected to {r}, which is not an owned relay address"
            for r in remotes if r not in allow]
    if a.require and a.require not in remotes:
        errs.append(f"process {a.pid} has no connection to {a.require}")
    if errs:
        return fail(errs)
    print(f"PREFLIGHT OK: process {a.pid} connects only to {sorted(set(remotes))}")
    return 0


def cmd_logs(a):
    ports = [p for p in a.forbid.split(",") if p]
    pat = re.compile(r"(?<![0-9])(" + "|".join(map(re.escape, ports)) + r")(?![0-9])")
    errs = []
    for f in a.files:
        for n, line in enumerate(open(f, errors="replace"), 1):
            m = pat.search(line)
            if m:
                errs.append(f"{f}:{n} mentions port {m.group(1)}")
                break
    if errs:
        return fail(errs)
    print(f"PREFLIGHT OK: {len(a.files)} log file(s) never mention {','.join(ports)}")
    return 0


def port_free(port):
    for fam, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        s = socket.socket(fam, socket.SOCK_STREAM)
        try:
            s.bind((host, port))
        except OSError:
            return False
        finally:
            s.close()
    return True


def cmd_ports(a):
    errs = []
    for p in (int(x) for x in a.free.split(",") if x):
        if p in SHARED_PORTS:
            errs.append(f"port {p} is a shared-installation port")
        elif not port_free(p):
            errs.append(f"port {p} is in use on 127.0.0.1 or ::1")
    if errs:
        return fail(errs)
    print(f"PREFLIGHT OK: ports {a.free} are free on 127.0.0.1 and ::1")
    return 0


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_pins(a):
    m = json.load(open(a.manifest))
    errs = []
    entries = list(m.get("binaries", {}).items()) + list(m.get("harness_files", {}).items())
    if not entries:
        errs.append("the manifest pins nothing")
    for name, want in entries:
        path = want["path"] if isinstance(want, dict) else name
        digest = want["sha256"] if isinstance(want, dict) else want
        if not os.path.isfile(path):
            errs.append(f"{name}: {path} is missing")
        elif sha256(path) != digest:
            errs.append(f"{name}: {path} does not hash to the manifest's {digest[:12]}")
    if errs:
        return fail(errs)
    print(f"PREFLIGHT OK: {len(entries)} pinned file(s) match the manifest")
    return 0


def main(argv):
    p = argparse.ArgumentParser(prog="preflight.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("config")
    c.add_argument("--hub-config", required=True)
    c.add_argument("--relay-coord", required=True)
    c.add_argument("--relay-front", required=True)
    c = sub.add_parser("hub-log")
    c.add_argument("--log", required=True)
    c.add_argument("--relay-coord", required=True)
    c.add_argument("--bind", default="[::1]")
    c = sub.add_parser("registry")
    c.add_argument("--dir", required=True)
    c.add_argument("--relay-coord", required=True)
    c = sub.add_parser("conns")
    c.add_argument("--pid", type=int, required=True)
    c.add_argument("--allow", required=True)
    c.add_argument("--require")
    c.add_argument("--lsof-output")
    c = sub.add_parser("logs")
    c.add_argument("--forbid", default=",".join(map(str, SHARED_PORTS)))
    c.add_argument("files", nargs="+")
    c = sub.add_parser("ports")
    c.add_argument("--free", required=True)
    c = sub.add_parser("pins")
    c.add_argument("--manifest", required=True)
    a = p.parse_args(argv)
    fn = {"config": cmd_config, "hub-log": cmd_hub_log, "registry": cmd_registry, "conns": cmd_conns,
          "logs": cmd_logs, "ports": cmd_ports, "pins": cmd_pins}[a.cmd]
    try:
        return fn(a)
    except (Failed, OSError, ValueError) as err:
        return fail([str(err)])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
