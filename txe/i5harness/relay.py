#!/usr/bin/env python3
# Copyright (C) 2026 TXE
# SPDX-License-Identifier: GPL-3.0-or-later
"""The I5 harness's own route between a test machine and its test hub (TXE-7516).

It splices TCP byte streams from loopback listeners to their targets, with no
parsing and no TLS. A control socket cuts and restores every listener at once:

  cut      closes every spliced connection, established ones included (gRPC keeps
           one long-lived HTTP/2 connection, so refusing only new connections would
           not stop its heartbeats), then refuses each new connection by closing it
           as soon as it is accepted;
  restore  forwards new connections again;
  state    reports the mode and the counters as JSON;
  stop     closes everything and exits.

Every transition is one JSON line in the log, with a UTC time. The relay reads no
environment and prints no argument.

Usage:
  relay.py serve --listen 127.0.0.1:28255=[::1]:28255 --listen 127.0.0.1:28981=127.0.0.1:28980 \
                 --control <socket> --log <file.jsonl> [--start restore|cut]
  relay.py ctl <socket> cut|restore|state|stop
"""

import argparse
import datetime
import json
import os
import socket
import sys
import threading

BUF = 65536


def utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_addr(text):
    """host:port or [v6]:port -> (family, host, port)."""
    if text.startswith("["):
        host, sep, port = text[1:].partition("]:")
        if not sep:
            raise ValueError(f"address {text!r}: want [host]:port")
        family = socket.AF_INET6
    else:
        host, sep, port = text.rpartition(":")
        if not sep or ":" in host:
            raise ValueError(f"address {text!r}: want host:port, or [v6]:port")
        family = socket.AF_INET
    if not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"address {text!r}: bad port")
    if host not in ("127.0.0.1", "::1"):
        # The relay is a loopback fixture: refuse anything else outright.
        raise ValueError(f"address {text!r}: only 127.0.0.1 and ::1 are allowed")
    return family, host, int(port)


def parse_listen(text):
    left, sep, right = text.partition("=")
    if not sep:
        raise ValueError(f"--listen {text!r}: want LISTEN=TARGET")
    return text, parse_addr(left), parse_addr(right)


class Relay:
    def __init__(self, listens, log_path, start):
        self.lock = threading.Lock()
        self.mode = start
        self.conns = set()  # every live socket, both sides of every splice
        self.log = open(log_path, "a", buffering=1)
        self.listens = listens
        self.servers = []
        self.counters = {name: {"accepted": 0, "refused": 0, "bytes": 0, "bytes_since_cut": 0}
                         for name, _, _ in listens}
        self.stopped = threading.Event()

    def record(self, event, **fields):
        fields.update({"time": utc(), "event": event})
        self.log.write(json.dumps(fields, sort_keys=True) + "\n")

    def bind(self):
        for name, (fam, host, port), target in self.listens:
            srv = socket.socket(fam, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((host, port))
            srv.listen(64)
            self.servers.append(srv)
            threading.Thread(target=self.accept_loop, args=(name, srv, target), daemon=True).start()
        self.record("listening", listeners=[name for name, _, _ in self.listens], mode=self.mode)

    def accept_loop(self, name, srv, target):
        while not self.stopped.is_set():
            try:
                client, _ = srv.accept()
            except OSError:
                return
            with self.lock:
                cut = self.mode == "cut"
                if cut:
                    self.counters[name]["refused"] += 1
                else:
                    self.counters[name]["accepted"] += 1
            if cut:
                close_hard(client)
                continue
            threading.Thread(target=self.splice, args=(name, client, target), daemon=True).start()

    def splice(self, name, client, target):
        fam, host, port = target
        upstream = socket.socket(fam, socket.SOCK_STREAM)
        try:
            upstream.connect((host, port))
        except OSError as err:
            self.record("target_unreachable", listener=name, error=str(err))
            close_hard(client)
            upstream.close()
            return
        with self.lock:
            if self.mode == "cut":  # cut while connecting
                close_hard(client)
                close_hard(upstream)
                return
            self.conns.update((client, upstream))
        a = threading.Thread(target=self.pump, args=(name, client, upstream), daemon=True)
        b = threading.Thread(target=self.pump, args=(name, upstream, client), daemon=True)
        a.start()
        b.start()

    def pump(self, name, src, dst):
        try:
            while True:
                data = src.recv(BUF)
                if not data:
                    break
                dst.sendall(data)
                with self.lock:
                    c = self.counters[name]
                    c["bytes"] += len(data)
                    c["bytes_since_cut"] += len(data)
        except OSError:
            pass
        finally:
            with self.lock:
                for s in (src, dst):
                    if s in self.conns:
                        self.conns.discard(s)
                        close_hard(s)

    def cut(self):
        with self.lock:
            self.mode = "cut"
            closing = list(self.conns)
            self.conns.clear()
            for c in self.counters.values():
                c["bytes_since_cut"] = 0
        for s in closing:
            close_hard(s)
        self.record("cut", closed=len(closing))
        return {"mode": "cut", "closed": len(closing)}

    def restore(self):
        with self.lock:
            self.mode = "restore"
        self.record("restore")
        return {"mode": "restore"}

    def state(self):
        with self.lock:
            return {"mode": self.mode, "active": len(self.conns),
                    "listeners": json.loads(json.dumps(self.counters))}

    def stop(self):
        self.cut()
        self.stopped.set()
        for srv in self.servers:
            srv.close()
        self.record("stop")
        return {"mode": "stopped"}


def close_hard(sock):
    # SO_LINGER 0: the peer sees a reset at once, not a slow FIN exchange.
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
    except OSError:
        pass
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()


def serve(args):
    listens = [parse_listen(t) for t in args.listen]
    if not listens:
        raise SystemExit("relay: at least one --listen is required")
    relay = Relay(listens, args.log, args.start)
    try:
        relay.bind()
    except OSError as err:
        relay.record("bind_failed", error=str(err))
        print(f"relay: cannot listen: {err}", file=sys.stderr)
        return 2
    if len(args.control.encode()) > 100:
        relay.record("bind_failed", error="control socket path too long")
        print(f"relay: control socket path is {len(args.control.encode())} bytes; keep it under 100", file=sys.stderr)
        return 2
    if os.path.exists(args.control):
        os.unlink(args.control)
    ctl = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    ctl.bind(args.control)
    os.chmod(args.control, 0o600)
    ctl.listen(4)
    actions = {"cut": relay.cut, "restore": relay.restore, "state": relay.state, "stop": relay.stop}
    while not relay.stopped.is_set():
        conn, _ = ctl.accept()
        with conn:
            word = conn.recv(64).decode(errors="replace").strip()
            fn = actions.get(word)
            reply = fn() if fn else {"error": f"unknown command {word!r}"}
            conn.sendall((json.dumps(reply, sort_keys=True) + "\n").encode())
    ctl.close()
    os.unlink(args.control)
    return 0


def ctl(args):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect(args.socket)
    s.sendall((args.command + "\n").encode())
    data = b""
    while not data.endswith(b"\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    s.close()
    sys.stdout.write(data.decode())
    return 0 if b'"error"' not in data else 2


def main(argv):
    p = argparse.ArgumentParser(prog="relay.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--listen", action="append", default=[])
    s.add_argument("--control", required=True)
    s.add_argument("--log", required=True)
    s.add_argument("--start", choices=["restore", "cut"], default="restore")
    c = sub.add_parser("ctl")
    c.add_argument("socket")
    c.add_argument("command", choices=["cut", "restore", "state", "stop"])
    args = p.parse_args(argv)
    try:
        return serve(args) if args.cmd == "serve" else ctl(args)
    except ValueError as err:
        print(f"relay: {err}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
