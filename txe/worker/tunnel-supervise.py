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
  the worker     the worker's existing coordinator connection, read from its own log (text or
                 JSON format): the heartbeat it sends every second logs "Heartbeat send failed"
                 on each failure (internal/service/worker/worker.go) and nothing on success.

New streams count as failing only when both probes fail: one that works shows the forward's
connection is alive. It replaces the forward only when new streams and the worker are both
unhealthy for the required time, measured from the first failed round: every round has failed
both probes since then (monotonic clock),
and the worker has logged heartbeat failures with no gap over --worker-gap seconds for that
long, the last one within --worker-gap. New streams failing while the worker's heartbeats
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
# The worker's own message (internal/service/worker/worker.go); txe/worker's tests pin it.
HEARTBEAT_MSG = "Heartbeat send failed; will retry with backoff"
HEARTBEAT_FAILED = 'msg="Heartbeat send failed'
_TIME = re.compile(r'^time=(\S+)')
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


def worker_unhealthy_since(path, now_wall, gap):
    """The wall time the worker's current run of heartbeat failures began, or None when the worker
    is not failing now (no failure within `gap` seconds) or its log cannot be read."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - LOG_TAIL_BYTES))
            text = f.read().decode("utf-8", "replace")
    except OSError:
        return None
    times = []
    for line in text.splitlines():
        # The worker's text format (the default) or its JSON format (log_format: json).
        if line.startswith("{"):
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if not isinstance(rec, dict) or rec.get("msg") != HEARTBEAT_MSG or not isinstance(rec.get("time"), str):
                continue
            stamp = rec["time"]
        else:
            if HEARTBEAT_FAILED not in line:
                continue
            m = _TIME.match(line)
            if not m:
                continue
            stamp = m.group(1)
        if stamp.endswith("Z"):                 # Go writes UTC as Z; fromisoformat accepts it only from 3.11
            stamp = stamp[:-1] + "+00:00"
        try:
            t = datetime.datetime.fromisoformat(stamp)
        except ValueError:
            continue
        if t.tzinfo is None:
            continue                            # a naive time cannot be placed: not evidence
        times.append(t.timestamp())
    if not times or now_wall - times[-1] > gap:
        return None
    start = times[-1]
    for t in reversed(times[:-1]):
        if start - t > gap:
            break
        start = t
    return start


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
            reason = verdict.observe(time.monotonic(), now_wall, streams_ok,
                                     None if streams_ok else worker_unhealthy_since(a.worker_log, now_wall, a.worker_gap))
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
