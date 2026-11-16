#!/usr/bin/env python3
# Copyright (C) 2026 TXE
# SPDX-License-Identifier: GPL-3.0-or-later
"""Answer a CLI's own no-echo key prompt through a pty this helper owns (TXE-7529).

`dagu context add` takes its API key from `--api-key` (argv, readable by `ps`)
or, when stdin is a terminal, from its own prompt: "API key: " on stderr, then
term.ReadPassword on stdin. This helper uses the second path:

  - the child's stdin is the slave side of a new pty; its stdout and stderr are
    pipes, so the pty carries the key and nothing else;
  - echo is turned off on the pty, and the termios state is read back and
    required to be off immediately before any key byte is written;
  - the key is written only after stderr shows exactly the expected prompt,
    preceded by nothing but complete log lines in dagu's text format at DEBUG,
    INFO or WARN; any other output, EOF or a timeout refuses, and nothing is
    written;
  - any byte that comes back on the pty is an echo leak: it is counted, never
    kept, and fails the run;
  - the captured stdout and stderr are logged only when they do not contain the
    key; otherwise the log says so and the run fails;
  - every wait has a deadline; on failure only the child's own process group
    (a new session) is signalled, and only this helper's descriptors are closed.

The key is read from a JSON file (normally 0600) by field name, held in memory,
and never printed. The helper's stdout is one JSON status line with no key.

Usage:
  ttykey.py --key-json F --field NAME --log F [--prompt TEXT]
            [--prompt-timeout S] [--exit-timeout S] -- CMD [ARG..]
Exit: the child's exit code when the key was delivered and the child exited;
2 when the helper refused or a check failed.
"""

import argparse
import json
import os
import pty
import re
import select
import signal
import subprocess
import sys
import termios
import time

ECHO_BITS = termios.ECHO | termios.ECHONL
# Before its prompt the CLI may log complete lines in dagu's text format (it
# warns, for one, when no auth.mode is configured). Only these are accepted.
LOG_LINE = re.compile(rb"^time=\S+ level=(DEBUG|INFO|WARN) msg=")


def prelude(err):
    """(accepted, rest): rest is stderr after the leading log lines; accepted is
    False when a complete line before the prompt is not such a log line."""
    rest = bytes(err)
    while b"\n" in rest:
        line, rest = rest.split(b"\n", 1)
        if not LOG_LINE.match(line):
            return False, rest
    return True, rest


def status(**fields):
    print(json.dumps(fields, sort_keys=True))


def echo_off(fd):
    attrs = termios.tcgetattr(fd)
    attrs[3] &= ~ECHO_BITS
    termios.tcsetattr(fd, termios.TCSANOW, attrs)


def echo_is_off(fd):
    return termios.tcgetattr(fd)[3] & ECHO_BITS == 0


def stop_group(proc):
    if proc.poll() is not None:
        return
    for sig, wait in ((signal.SIGTERM, 3.0), (signal.SIGKILL, 3.0)):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            return
        try:
            proc.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


class Child:
    """The child's two output pipes and the pty master, read without blocking."""

    def __init__(self, proc, master):
        self.proc, self.master = proc, master
        self.out, self.err = bytearray(), bytearray()
        self.echoed = 0  # bytes that came back on the pty; counted, never kept
        self.open = {proc.stdout.fileno(): self.out, proc.stderr.fileno(): self.err}
        for fd in self.open:
            os.set_blocking(fd, False)
        os.set_blocking(master, False)

    def pump(self, timeout):
        fds = list(self.open) + [self.master]
        ready, _, _ = select.select(fds, [], [], timeout)
        for fd in ready:
            try:
                chunk = os.read(fd, 65536)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:  # EIO on a pty master once nothing holds the slave
                chunk = b""
            if fd == self.master:
                self.echoed += len(chunk)
                continue
            if chunk:
                self.open[fd].extend(chunk)
            else:
                del self.open[fd]

    def pipes_closed(self):
        return not self.open


def write_log(path, child, key):
    body = bytes(child.out) + b"\n--- stderr ---\n" + bytes(child.err)
    leaked = key.encode() in body
    with open(path, "wb") as f:
        if leaked:
            f.write(b"output withheld: it contained the key\n")
        else:
            f.write(body)
    return leaked


def run(a, key):
    master, slave = pty.openpty()
    proc = None
    try:
        echo_off(slave)
        if not echo_is_off(slave):
            status(ok=False, reason="echo could not be turned off on the pty")
            return 2
        proc = subprocess.Popen(a.command, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, close_fds=True)
        child = Child(proc, master)
        prompt = a.prompt.encode()

        deadline = time.monotonic() + a.prompt_timeout
        while True:
            accepted, rest = prelude(child.err)
            if accepted and rest.startswith(prompt):
                break
            if not accepted or (rest and not prompt.startswith(rest)) or child.out:
                write_log(a.log, child, key)
                status(ok=False, reason="unexpected output before the key prompt; nothing was written")
                return 2
            if child.pipes_closed() or proc.poll() is not None:
                write_log(a.log, child, key)
                status(ok=False, reason="the command ended before its key prompt; nothing was written")
                return 2
            left = deadline - time.monotonic()
            if left <= 0:
                write_log(a.log, child, key)
                status(ok=False, reason=f"no key prompt within {a.prompt_timeout}s; nothing was written")
                return 2
            child.pump(min(left, 0.2))

        if rest != prompt or child.echoed:
            write_log(a.log, child, key)
            status(ok=False, reason="the prompt was not alone, or the pty already carried output; nothing was written")
            return 2
        if not echo_is_off(slave):
            write_log(a.log, child, key)
            status(ok=False, reason="echo is on at the pty; nothing was written")
            return 2
        data = key.encode() + b"\n"
        while data:
            data = data[os.write(master, data):]

        deadline = time.monotonic() + a.exit_timeout
        # Done when the child has exited and both pipes reached EOF.
        while not (proc.poll() is not None and child.pipes_closed()):
            left = deadline - time.monotonic()
            if left <= 0:
                write_log(a.log, child, key)
                status(ok=False, reason=f"the command did not exit within {a.exit_timeout}s of the key")
                return 2
            child.pump(min(left, 0.2))
        child.pump(0)
        leaked = write_log(a.log, child, key)
        if child.echoed:
            status(ok=False, reason=f"{child.echoed} byte(s) came back on the pty: an echo of the input", exit=proc.returncode)
            return 2
        if leaked:
            status(ok=False, reason="the command's output contained the key; the log withholds it", exit=proc.returncode)
            return 2
        status(ok=proc.returncode == 0, exit=proc.returncode)
        return proc.returncode
    finally:
        if proc is not None:
            stop_group(proc)
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    pipe.close()
        os.close(master)
        os.close(slave)


def main(argv):
    p = argparse.ArgumentParser(prog="ttykey.py")
    p.add_argument("--key-json", required=True)
    p.add_argument("--field", required=True)
    p.add_argument("--log", required=True)
    p.add_argument("--prompt", default="API key: ")
    p.add_argument("--prompt-timeout", type=float, default=20)
    p.add_argument("--exit-timeout", type=float, default=30)
    p.add_argument("command", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    if a.command and a.command[0] == "--":
        a.command = a.command[1:]
    if not a.command:
        status(ok=False, reason="no command")
        return 2
    try:
        key = json.load(open(a.key_json))[a.field]
    except (OSError, ValueError, KeyError, TypeError) as err:
        status(ok=False, reason=f"cannot read field {a.field!r} from {a.key_json}: {type(err).__name__}")
        return 2
    if not isinstance(key, str) or not key or any(c in key for c in "\r\n\x00"):
        status(ok=False, reason="the key is empty or holds a line break or NUL")
        return 2
    return run(a, key)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
