"""Run the tunnel's kubectl port-forward and replace it when its connection is dead (TXE-5398).

The launchd tunnel agent runs this with `python3 -I`; it reads no environment.

  tunnel-supervise.py --ui-port N --coord-port N --worker-log PATH --state PATH [timing options] -- KUBECTL ARGS...

Why: launchd restarts the tunnel only when kubectl exits. client-go's port-forward logs
"error creating error stream" for each new local connection and keeps running until its
shared connection closes, so a forward whose connection is dead can stay up for many minutes
while nothing reaches the cluster (TXE-5369: 07:16-07:27Z on 2026-10-29).

What it does: kubectl runs as this process's child, in the same process group (so launchd's
process-group cleanup also ends it if this process is killed), with its output unchanged.
Every --interval seconds after --grace it checks two things:

  new streams    GET /api/v1/health on the UI port answers 200, and the coordinator port
                 answers an HTTP/2 client preface with a SETTINGS frame. Each opens a new
                 local connection, so each needs a new stream through the forward.
  the worker     whether ANY call of the worker to its coordinator has succeeded, read from the
                 worker's own log (text or JSON format). Its heartbeat, sent every second over
                 its existing connection, logs "Heartbeat send failed" on each failure; its
                 coordinator client logs "CoordinatorCli connection recovered" on the first
                 success after any failure. Successes are otherwise silent, so the gap between
                 failure lines proves nothing: only the absence of a recovery (or worker start)
                 line since the first failure shows the failures were uninterrupted.

New streams count as failing only when both probes fail: one that works shows the forward's
connection is alive. It replaces the forward only when new streams and the worker are both
unhealthy for the required time, measured from the first failed round: every round has failed
both probes since then (monotonic clock),
and the worker has logged heartbeat failures with no recovery or start line in between (and no
gap over --worker-gap seconds) for that long, the last one within --worker-gap. New streams failing while the worker's heartbeats
succeed (the existing stream still works) never restarts it. Neither does a worker log that is
missing or unreadable: the forward is then left as launchd would leave it. The required time is
--unhealthy-after, doubled for each replacement in the last hour (at most --max-unhealthy-after).

Replacing means: one log line, SIGTERM to kubectl, SIGKILL after --kill-timeout, then exit 75,
so launchd (KeepAlive) is the only thing that starts a new forward. If kubectl exits by itself,
this exits with its code, as the agent did before. SIGTERM, SIGINT and SIGHUP are passed to
kubectl, and this exits with the code kubectl then exits with. Lines this writes start "tunnel-supervise:" and name no argument, path or credential.
"""
import argparse, datetime, json, os, re, signal, socket, subprocess, sys, time, urllib.request

EXIT_REPLACED = 75
PREFIX = "tunnel-supervise:"
# The worker's own messages; txe/worker's tests pin each one to its source:
# internal/service/worker/worker.go (heartbeat failure, start) and
# internal/service/coordinator/client.go (the first success after a failure).
HEARTBEAT_MSG = "Heartbeat send failed; will retry with backoff"
RECOVERED_MSG = "CoordinatorCli connection recovered"
STARTED_MSG = "Starting worker"
# txe/worker/logpipe.py's markers in the worker's log (TXE-4724): each is a boundary of the file
# (opened, rotated) or of its contents (lost output), after which an earlier failure episode
# cannot be joined to a later one: a recovery or a start may lie in what is not there. Each
# resets the episode, exactly like a recovery; none is ever evidence of failure. The strings
# are pinned to logpipe.py's source by txe/worker's tests. "lost worker output" is reserved:
# the current logpipe.py never drops output, but a reader must not join across it if it ever did.
LOGPIPE_MARKERS = ("txe-logpipe: opened worker.log", "txe-logpipe: rotated worker.log",
                   "txe-logpipe: lost worker output")
# time, level, the source when the worker runs with debug (AddSource), then msg: slog's text order.
_TEXT = re.compile(r'^time=(\S+) level=\S+(?: source=(?:"(?:[^"\\]|\\.)*"|\S+))? msg="((?:[^"\\]|\\.)*)"')
# HTTP/2 client connection preface and an empty SETTINGS frame (RFC 9113 3.4, 6.5).
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
H2_SETTINGS = 0x4
LOG_TAIL_BYTES = 256 * 1024
RESTART_WINDOW_S = 3600


def say(msg):
    print(f"{PREFIX} {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} {msg}",
          file=sys.stderr, flush=True)


def probe_http(port, timeout):
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/v1/health", timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def probe_h2(port, timeout):
    """True when the server behind the port answers the HTTP/2 preface with a SETTINGS frame."""
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            s.sendall(H2_PREFACE)
            head = b""
            while len(head) < 9:
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                s.settimeout(left)
                chunk = s.recv(9 - len(head))
                if not chunk:
                    return False
                head += chunk
            return head[3] == H2_SETTINGS
    except OSError:
        return False


def _record(line):
    """(message, unix time) of one worker log line in its text or JSON format, or None."""
    if line.startswith("{"):                    # log_format: json
        try:
            rec = json.loads(line)
        except ValueError:
            return None
        if not isinstance(rec, dict) or not isinstance(rec.get("msg"), str) or not isinstance(rec.get("time"), str):
            return None
        msg, stamp = rec["msg"], rec["time"]
    else:                                       # the default text format: time=... level=... msg="..."
        m = _TEXT.match(line)
        if not m:
            return None
        stamp, msg = m.group(1), m.group(2)
    if msg not in (HEARTBEAT_MSG, RECOVERED_MSG, STARTED_MSG) and msg not in LOGPIPE_MARKERS:
        return None
    if stamp.endswith("Z"):                     # Go writes UTC as Z; fromisoformat accepts it only from 3.11
        stamp = stamp[:-1] + "+00:00"
    try:
        t = datetime.datetime.fromisoformat(stamp)
    except ValueError:
        return None
    if t.tzinfo is None:
        return None                             # a naive time cannot be placed: not evidence
    return msg, t.timestamp()


class WorkerLog:
    """Follows the worker's log across rounds and keeps its current failure episode.

    The episode is the time from which no call of the worker to its coordinator has succeeded.
    The worker's coordinator client logs RECOVERED_MSG on the first successful call after any
    recorded failure (internal/service/coordinator/client.go recordSuccess), and every heartbeat
    goes through it. So the episode starts at the first heartbeat failure after the latest
    recovery or worker start; a single success anywhere in between ends it. A failure gap over
    `gap` seconds also ends it (not shown to be one episode), and no failure within `gap` of now
    is no evidence (the worker may have stopped).

    Each poll reads only what was appended since the last one, all of it, so an episode is kept
    however much else the worker logs (its pollers' health-check warnings, for one). The first
    poll reads the last LOG_TAIL_BYTES only. A file replaced (another inode) or shortened
    (truncated) starts over from its beginning with no episode: that can only delay a
    replacement, never cause one. An unreadable log is no evidence."""

    def __init__(self, path, gap):
        self.path, self.gap = path, gap
        self.ident = None                       # (device, inode) of the file being followed
        self.offset = 0
        self.partial = b""                      # an unfinished last line, kept for the next read
        self.start = self.last = None           # the episode's first and latest failure (unix time)

    def _reset(self):
        self.partial, self.start, self.last = b"", None, None

    def _line(self, raw):
        rec = _record(raw.decode("utf-8", "replace"))
        if rec is None:
            return
        msg, t = rec
        if msg != HEARTBEAT_MSG:
            self.start = self.last = None       # a success, a new worker process, or a logpipe boundary
        elif self.last is not None and t - self.last <= self.gap:
            self.last = t
        else:
            self.start = self.last = t          # a first failure, or one after a silent stretch

    def poll(self, now_wall):
        """Read what is new and return the episode's start, or None."""
        try:
            with open(self.path, "rb") as f:
                st = os.fstat(f.fileno())
                ident = (st.st_dev, st.st_ino)
                if self.ident is None:
                    self.offset = max(0, st.st_size - LOG_TAIL_BYTES)
                    first = self.offset > 0     # the first line of a tail read is likely cut
                elif ident != self.ident or st.st_size < self.offset:
                    self._reset()
                    self.offset, first = 0, False
                else:
                    first = False
                self.ident = ident
                f.seek(self.offset)
                while True:
                    chunk = f.read(1 << 20)
                    if not chunk:
                        break
                    self.offset += len(chunk)
                    lines = (self.partial + chunk).split(b"\n")
                    self.partial = lines.pop()
                    if first:
                        lines, first = lines[1:], False
                    for raw in lines:
                        self._line(raw)
        except OSError:
            self.ident = None
            self._reset()
            return None
        if self.start is None or now_wall - self.last > self.gap:
            return None
        return self.start


def worker_unhealthy_since(path, now_wall, gap):
    """One read of the worker's log: the start of its current failure episode, or None."""
    return WorkerLog(path, gap).poll(now_wall)


class Verdict:
    """The replace decision, apart from the probes and the clocks so that tests can drive it."""

    def __init__(self, unhealthy_after, max_unhealthy_after, restarts):
        self.base, self.cap, self.restarts = unhealthy_after, max_unhealthy_after, restarts
        self.dead_since = None                  # monotonic time of the first failed new-stream round

    def required(self, now_wall):
        recent = sum(1 for t in self.restarts if now_wall - t < RESTART_WINDOW_S)
        return min(self.base * (2 ** recent), self.cap)

    def observe(self, now_mono, now_wall, streams_ok, worker_since):
        """Record one round; return the reason to replace the forward, or None."""
        if streams_ok:
            self.dead_since = None
            return None
        if self.dead_since is None:
            self.dead_since = now_mono
        need = self.required(now_wall)
        dead_for = now_mono - self.dead_since
        if dead_for < need or worker_since is None or now_wall - worker_since < need:
            return None
        return (f"new streams failing for {dead_for:.0f}s and worker heartbeats failing for "
                f"{now_wall - worker_since:.0f}s (required {need:.0f}s)")


def load_restarts(path, now_wall):
    try:
        with open(path) as f:
            data = json.load(f)
        return [float(t) for t in data.get("restarts", []) if now_wall - float(t) < RESTART_WINDOW_S]
    except (OSError, ValueError, TypeError, AttributeError):
        return []


def save_restarts(path, restarts):
    tmp = f"{path}.{os.getpid()}.tmp"
    try:
        with open(tmp, "w") as f:
            json.dump({"restarts": restarts}, f)
        os.replace(tmp, path)
    except OSError as e:
        say(f"could not record the replacement ({type(e).__name__}); the next one is not slowed")


def stop(child, kill_timeout):
    if child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(kill_timeout)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()


def parse(argv):
    p = argparse.ArgumentParser(prog="tunnel-supervise.py")
    p.add_argument("--ui-port", type=int, required=True)
    p.add_argument("--coord-port", type=int, required=True)
    p.add_argument("--worker-log", required=True)
    p.add_argument("--state", required=True)
    p.add_argument("--interval", type=float, default=30)
    p.add_argument("--grace", type=float, default=20)
    p.add_argument("--probe-timeout", type=float, default=10)
    p.add_argument("--unhealthy-after", type=float, default=90)
    p.add_argument("--max-unhealthy-after", type=float, default=600)
    p.add_argument("--worker-gap", type=float, default=45)
    p.add_argument("--kill-timeout", type=float, default=10)
    if "--" not in argv:
        p.error("the kubectl command goes after --")
    i = argv.index("--")
    a = p.parse_args(argv[:i])
    a.command = argv[i + 1:]
    if not a.command:
        p.error("the kubectl command goes after --")
    return a


def main(argv):
    a = parse(argv)
    child = subprocess.Popen(a.command)
    signalled = []

    def forward(signum, _frame):
        signalled.append(signum)
        if child.poll() is None:
            child.send_signal(signum)

    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(s, forward)
    verdict = Verdict(a.unhealthy_after, a.max_unhealthy_after, load_restarts(a.state, time.time()))
    worker = WorkerLog(a.worker_log, a.worker_gap)
    next_round = time.monotonic() + a.grace
    try:
        while True:
            try:
                rc = child.wait(max(0.0, next_round - time.monotonic()))
            except subprocess.TimeoutExpired:
                rc = None
            if rc is not None:
                return rc if rc >= 0 else 128 - rc
            if signalled:                       # the child is still stopping after a passed signal
                stop(child, a.kill_timeout)
                return 128 + signalled[0]
            next_round = time.monotonic() + a.interval
            # One new stream that works shows the forward's connection is alive: replacing it
            # cannot help, whatever the hub is doing.
            streams_ok = probe_http(a.ui_port, a.probe_timeout) or probe_h2(a.coord_port, a.probe_timeout)
            now_wall = time.time()
            was_dead = verdict.dead_since is not None
            worker_since = worker.poll(now_wall)    # every round, so nothing appended is skipped
            reason = verdict.observe(time.monotonic(), now_wall, streams_ok, None if streams_ok else worker_since)
            if not streams_ok and not was_dead:
                say("new streams through the forward are failing; watching the worker's heartbeats")
            elif streams_ok and was_dead:
                say("new streams through the forward work again")
            if reason:
                say(f"replacing the forward: {reason}")
                verdict.restarts.append(now_wall)
                save_restarts(a.state, verdict.restarts)
                stop(child, a.kill_timeout)
                return EXIT_REPLACED
    finally:
        stop(child, a.kill_timeout)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
