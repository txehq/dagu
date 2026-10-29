"""Run the worker and keep its log bounded (TXE-4724).

The launchd worker agent runs this with `python3 -I`; it reads no environment.

  logpipe.py --path LOG --max-bytes N --backups K [--chunk-bytes C] [--write-stall-seconds S]
             [--kill-timeout T] [--diag-path P] [--diag-max-bytes D] -- CHILD ARGS...

It runs the worker agent's dagu worker and, after TXE-5398, the tunnel agent's supervisor
with kubectl under it; "worker" below stands for whichever child it runs.

Why: launchd appends the worker's output to logs/worker.log and nothing bounds it (103 MB in
17 days). Renaming or compressing that file while launchd holds its descriptor bounds nothing:
the writer keeps the old inode. Only the process that owns the descriptor can rotate it, so this
process owns it: the worker runs as its child with stdout and stderr piped here, and every byte
the worker writes is appended to LOG by this process.

Bounded streaming: the pipe is read in chunks; complete lines are written as they arrive, and a
line still open after --chunk-bytes is written in pieces to the current file, so memory holds
at most one chunk. Before a write that starts a new line, if the file would exceed --max-bytes,
it is rotated first (renamed to LOG.<utc stamp>, LOG reopened). A line is never split across
two files and no marker is ever written inside a line, so a reader of any one file sees whole
lines only and nothing can be joined or forged across a boundary. --max-bytes is therefore a
soft target, not a hard cap: a file can exceed it by the length of one line (the worker's lines
are a few hundred bytes). Nothing is ever truncated; a final line without a newline is written
without one.

Rotated files are gzipped by one background thread with a queue of at most --backups entries,
so the drain only waits for the rename and reopen; a rotated file the queue cannot take is
compressed by the thread's next sweep instead. The newest --backups rotated files are kept,
compressed or not yet, and the oldest beyond that are deleted, at every rotation as well as
after every compression, so retention holds however far compression falls behind; the one
file being compressed is never deleted from under it, so at most --backups plus one exist. That deletion is the only pruning, and it never touches a file this
process did not rotate. A LOG that exists at start and was not written by this process (no
marker as its first line) is the pre-activation log: it is moved to
<stem>.legacy-<utc stamp><suffix> next to LOG, outside the pruned set, and never deleted here.
Every move here is a hard link to a name that must not exist yet (os.link refuses an existing
name) followed by the unlink of the old one, so no archive or rotated file is ever overwritten;
a name that exists already gets a "-N" suffix. A compression writes <rotated>.gz.tmp and
replaces it into place; on failure its own .tmp is removed, and at start a .tmp left by an
earlier process is removed when its source or its result exists and kept, reported, otherwise.

Markers: each file this process opens starts with one line in the worker's own text format,
  time=<RFC 3339> level=INFO msg="txe-logpipe: <what>" ...
so a reader that parses the worker's lines can place it. The message never equals a worker
message (TXE-5398's supervisor matches three of them exactly and ignores the rest), so a marker
can never pass for a worker start, a heartbeat failure or a recovery. The only markers are
"opened" and "rotated": both are boundaries of a file.

Write failures (ENOSPC, EIO, a reopen that fails): the unwritten bytes stay in memory (at most
one chunk; the pipe is not read meanwhile, so the worker blocks on its own write after the pipe
buffer, 64 KiB, fills) and the write is retried every second; a partial write advances the
offset and only the remainder is retried, so nothing is written twice. If writes still fail
after --write-stall-seconds, this process reports it, sends the worker SIGTERM (SIGKILL after
--kill-timeout) and exits 74 (EX_IOERR), and launchd restarts the service. That restart ends
the worker's running tasks, as any restart of the worker does, and the bytes still unwritten in
memory and in the pipe are lost with it: only bytes already persisted are guaranteed.

Rotation failures (the rename or the reopen fails): writes continue to the current file, which
is then over the target, and rotation is retried at most once a minute. If it keeps failing and
the file passes twice --max-bytes, the same fail-stop applies: the active log never grows past
that degraded limit (plus one line) under a claim of boundedness. A compression failure keeps
the rotated file uncompressed, counted in the retained set. Every failure is reported, at most
one line a minute per kind with the number of lines suppressed meanwhile; nothing is swallowed.

Diagnostics: this process's own lines go to --diag-path (default <stem>.logpipe.log beside LOG)
through a best-effort writer that never retries or blocks: it appends, and when the file passes
--diag-max-bytes (1 MiB) it renames it to <path>.1, keeping one previous copy. So the
diagnostic file is at most twice --diag-max-bytes. Only if that write fails does the line fall
back to stderr, launchd's own file for the agent, which otherwise receives nothing but a
traceback should this process itself crash.

Signals and descendants: the worker stays in this process's own process group, launchd's
group for the agent, exactly as when launchd ran it directly. SIGTERM, SIGINT and SIGHUP are
forwarded to the worker process alone, as launchd sends them, so the worker still decides how
its children stop (step processes; the supervisor's kubectl). If the worker is still running
--kill-timeout seconds after a forwarded signal (15, under launchd's 20 s ExitTimeOut) it is
SIGKILLed. Whatever it leaves behind is launchd's: launchd.plist(5), AbandonProcessGroup,
"When a job dies, launchd kills any remaining processes with the same process group ID as the
job", and the agents do not set that key, so a grandchild still holding a port or the pipe is
killed by launchd when this process exits, including when this process itself is killed. That
is why this process never changes the group (no setsid, no killpg: a killpg would hit itself and
everything launchd put in the group) and never needs Python 3.11's process_group.

A grandchild that outlives the worker can hold the pipe open, or keep writing to it, so EOF
alone is not the end: once the worker has exited, this process drains for at most
--orphan-grace seconds (5) more, whether or not data keeps arriving, then stops, exits with the
worker's code, and leaves the rest to launchd's group kill. It finishes the compression in
progress first. It never restarts the worker.
"""
import argparse
import datetime
import errno
import gzip
import os
import queue
import re
import select
import signal
import subprocess
import sys
import threading
import time

PREFIX = "txe-logpipe"
EXIT_IOERR = 74
DIAG_INTERVAL_S = 60
RETRY_S = 1.0
DEGRADED_FACTOR = 2
STAMP = "%Y%m%dT%H%M%S%fZ"
_STAMP_RE = r"\d{8}T\d{6}\d{6}Z(?:-\d+)?"   # a "-N" suffix when two names would collide


class FailStop(Exception):
    """Writing or rotating the log has failed for longer than allowed: stop the worker."""


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def marker(what, **fields):
    """One line in the worker's text format; the message can never be a worker message."""
    extra = "".join(f" {k}={v}" for k, v in fields.items())
    return f'time={utc_now().isoformat(timespec="microseconds")} level=INFO msg="{PREFIX}: {what}"{extra}\n'


MARKER_PREFIX = re.compile(rb'^time=\S+ level=INFO msg="' + PREFIX.encode() + rb': ')


class Diag:
    """This process's own lines: at most one per DIAG_INTERVAL_S per kind (unless always), to a
    small file bounded at twice max_bytes by a best-effort rename that never retries or blocks;
    stderr only when that file cannot be written. Nothing is dropped silently: a suppressed
    line is counted in the next one of its kind."""

    def __init__(self, path=None, max_bytes=1 << 20):
        self.path, self.max_bytes = path, max_bytes
        self.last = {}
        self.suppressed = {}

    def say(self, kind, text, always=False):
        now = time.monotonic()
        last = self.last.get(kind)
        if not always and last is not None and now - last < DIAG_INTERVAL_S:
            self.suppressed[kind] = self.suppressed.get(kind, 0) + 1
            return
        n = self.suppressed.pop(kind, 0)
        self.last[kind] = now
        more = f" ({n} more of this kind in the last {DIAG_INTERVAL_S}s)" if n else ""
        line = f"{PREFIX}: {utc_now().strftime('%Y-%m-%dT%H:%M:%SZ')} {text}{more}\n"
        if self.path is None or not self._append(line):
            print(line, end="", file=sys.stderr, flush=True)

    def _append(self, line):
        try:
            if os.path.exists(self.path) and os.path.getsize(self.path) + len(line) > self.max_bytes:
                os.replace(self.path, self.path + ".1")
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line.encode())
            finally:
                os.close(fd)
            return True
        except OSError:
            return False


class Log:
    """The bounded log file: appends with bounded retry, rotates before a write that starts a
    line would pass max_bytes, archives a pre-activation file at start, and hands rotated files
    to one compressor thread with a bounded queue."""

    def __init__(self, path, max_bytes, backups, write_stall_s, diag, sleep=None):
        self.path, self.max_bytes, self.backups, self.diag = path, max_bytes, backups, diag
        self.write_stall_s = write_stall_s
        self.sleep = sleep if sleep is not None else time.sleep  # resolved now, so a test's clock applies
        self.dir = os.path.dirname(path) or "."
        self.base = os.path.basename(path)
        stem, suffix = os.path.splitext(self.base)
        self.legacy_fmt = f"{stem}.legacy-{{stamp}}{suffix}"
        self.managed = re.compile(r"^" + re.escape(self.base) + r"\.(" + _STAMP_RE + r")(\.gz)?$")
        self.fd = None
        self.size = 0
        self.rotate_failed_at = None  # monotonic time of the latest failed rotation
        self.rotate_failing_since = None
        self.jobs = queue.Queue(maxsize=max(backups, 1))
        self.stopping = threading.Event()  # set by finish(): the compressor ends after its current job
        self.names_lock = threading.Lock()  # held while listing and deleting rotated names, and while
        self._compressing = ""              # a compression result is published; names the source in compression
        # A daemon thread: the process must be able to exit however it ends; finish() waits for
        # the compression in progress, with a bound, on every normal path.
        self.compressor = threading.Thread(target=self._compress_loop, name="compress", daemon=True)
        self.stats = {"rotations": 0, "write_retries": 0}

    # ── start ──────────────────────────────────────────────────────────────────
    def open_at_start(self):
        """Archive a pre-activation log, then open LOG and write its opening marker.
        Raises OSError: without a log the worker must not be started (that would be silent loss)."""
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        if os.path.exists(self.path) and not os.path.isfile(self.path):
            raise OSError(errno.EISDIR if os.path.isdir(self.path) else errno.EINVAL, "not a regular file", self.path)
        self._reconcile_leftovers()
        if os.path.isfile(self.path) and os.path.getsize(self.path) > 0 and not self._is_managed(self.path):
            archive = self._move_no_clobber(self.path, lambda stamp: self.legacy_fmt.format(stamp=stamp))
            self._open()
            self._write_all(marker("opened " + self.base, archived=os.path.basename(archive),
                                   archived_bytes=os.path.getsize(archive)).encode())
        else:
            self._open()
            if self.size == 0:
                self._write_all(marker("opened " + self.base, max_bytes=self.max_bytes, backups=self.backups).encode())
        self.compressor.start()
        # Rotated files left uncompressed by an earlier process (a crash, a full queue).
        for name in self._managed_names():
            if not name.endswith(".gz"):
                self._enqueue(os.path.join(self.dir, name))

    def _move_no_clobber(self, src, name_for, variants=()):
        """Move src to name_for(stamp) without ever overwriting: link to the new name, which
        os.link refuses if it exists, then unlink the old name. A stamp is skipped, with "-N"
        tried next, when the name or any of its variants (its .gz, its .gz.tmp) exists, so a
        later compression can never replace an earlier file either."""
        stamp = utc_now().strftime(STAMP)
        for n in range(0, 1000):
            name = name_for(stamp if n == 0 else f"{stamp}-{n}")
            dst = os.path.join(self.dir, name)
            if any(os.path.lexists(dst + v) for v in variants):
                continue
            try:
                os.link(src, dst)
            except FileExistsError:
                continue
            os.unlink(src)
            return dst
        raise OSError(errno.EEXIST, "no free name for", src)

    def _reconcile_leftovers(self):
        """Undo what a crash between two steps can leave: LOG still hard-linked to a rotated
        name (the unlink after the link did not happen), and <rotated>.gz.tmp files."""
        try:
            names = set(os.listdir(self.dir))
        except OSError:
            return
        if os.path.isfile(self.path):
            try:
                st = os.stat(self.path)
                if st.st_nlink > 1:
                    for n in names:
                        if self.managed.match(n) and not n.endswith(".gz"):
                            other = os.stat(os.path.join(self.dir, n))
                            if (other.st_dev, other.st_ino) == (st.st_dev, st.st_ino):
                                os.unlink(self.path)  # the content lives on under the rotated name
                                self.diag.say("reconcile", f"{self.base} was still linked to {n}; unlinked it", always=True)
                                break
            except OSError as e:
                self.diag.say("reconcile", f"could not check {self.base}'s links: {e.__class__.__name__}: {e}", always=True)
        self._reclaim_temporaries(report=True)

    def _reclaim_temporaries(self, report):
        """Remove a <rotated>.gz.tmp whose source or result exists; keep one that is the only
        copy (reported at start only), never counted as a backup."""
        try:
            names = set(os.listdir(self.dir))
        except OSError:
            return
        for n in sorted(names):
            if not n.endswith(".gz.tmp"):
                continue
            stem = n[:-len(".gz.tmp")]
            if not self.managed.match(stem):
                continue
            if stem == os.path.basename(self._compressing):
                continue  # the compression in progress owns it
            if stem in names or stem + ".gz" in names:
                try:
                    os.remove(os.path.join(self.dir, n))
                    if report:
                        self.diag.say("reconcile", f"removed {n}, left by an interrupted compression; its source is intact", always=True)
                except OSError as e:
                    self.diag.say("reconcile", f"could not remove {n}: {e.__class__.__name__}: {e}", always=report)
            elif report:
                self.diag.say("reconcile", f"{n} is the only copy of {stem} left by an interrupted compression; kept, "
                                           f"not counted as a backup; it may be incomplete", always=True)

    def _is_managed(self, path):
        try:
            with open(path, "rb") as f:
                return MARKER_PREFIX.match(f.readline(200)) is not None
        except OSError:
            return False

    def _open(self):
        self.fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        self.size = os.fstat(self.fd).st_size

    def _write_all(self, data):
        """Write all of data now; raises OSError on failure (start-up only)."""
        view = memoryview(data)
        while view:
            n = os.write(self.fd, view)
            view = view[n:]
            self.size += n

    # ── the hot path ───────────────────────────────────────────────────────────
    def write(self, data, line_start=True):
        """Append data; when it begins a line and would pass max_bytes, rotate first. A failed
        write is retried every RETRY_S from the offset already written, for at most
        write_stall_s; then FailStop. Nothing is dropped and nothing is written twice."""
        if line_start and self.size > 0 and self.size + len(data) > self.max_bytes:
            self._rotate(len(data))
        view = memoryview(data)
        stalled_since = None
        while view:
            try:
                if self.fd is None:
                    self._open()
                n = os.write(self.fd, view)
            except OSError as e:
                now = time.monotonic()
                if stalled_since is None:
                    stalled_since = now
                self.stats["write_retries"] += 1
                self._close_quietly()
                if now - stalled_since >= self.write_stall_s:
                    raise FailStop(f"could not write to {self.base} for {self.write_stall_s:g}s "
                                   f"({e.__class__.__name__}: {e}); {len(view)} bytes unwritten")
                self.diag.say("write", f"could not write {len(view)} bytes to {self.base} "
                                       f"({e.__class__.__name__}: {e}); retrying every {RETRY_S:g}s for up to "
                                       f"{self.write_stall_s:g}s, the worker is blocked meanwhile")
                self.sleep(RETRY_S)
                continue
            view = view[n:]
            self.size += n
        if stalled_since is not None:
            self.diag.say("write-ok", f"writing to {self.base} works again after "
                                      f"{time.monotonic() - stalled_since:.0f}s", always=True)

    def _rotate(self, next_write):
        """Rename LOG to LOG.<stamp> and reopen LOG; the renamed file goes to the compressor.
        A failure is reported and retried at most once a minute while writes continue to the
        current file; a write that would take it past DEGRADED_FACTOR × max_bytes with rotation
        still failing raises FailStop instead."""
        now = time.monotonic()
        if self.rotate_failed_at is not None and now - self.rotate_failed_at < DIAG_INTERVAL_S:
            self._check_degraded(next_write)
            return
        started = time.monotonic()
        previous_bytes = self.size  # read before the file is exposed under its rotated name: the
        try:                        # compressor's sweep may compress and remove it at once
            self._close_quietly()
            rotated = self._move_no_clobber(self.path, lambda stamp: f"{self.base}.{stamp}", variants=(".gz", ".gz.tmp"))
            self._open()
        except OSError as e:
            self.rotate_failed_at = now
            if self.rotate_failing_since is None:
                self.rotate_failing_since = now
            self.diag.say("rotate", f"could not rotate {self.base} ({e.__class__.__name__}: {e}); writes continue "
                                    f"to it beyond {self.max_bytes} bytes, up to {DEGRADED_FACTOR * self.max_bytes}, "
                                    f"and rotation is retried every {DIAG_INTERVAL_S}s")
            if self.fd is None:
                try:
                    self._open()
                except OSError:
                    pass  # the next write retries the open, under the write stall bound
            self._check_degraded(next_write)
            return
        self.rotate_failed_at = self.rotate_failing_since = None
        self.stats["rotations"] += 1
        took_ms = int((time.monotonic() - started) * 1000)
        self.write(marker("rotated " + self.base, previous=os.path.basename(rotated),
                          previous_bytes=previous_bytes, took_ms=took_ms).encode(), line_start=False)
        self._enqueue(rotated)
        self._prune()  # retention does not wait for the compressor

    def _check_degraded(self, next_write):
        if self.size + next_write > DEGRADED_FACTOR * self.max_bytes:
            raise FailStop(f"{self.base} is at {self.size} bytes and the next write would pass {DEGRADED_FACTOR}x its "
                           f"target; rotation has been failing for {time.monotonic() - self.rotate_failing_since:.0f}s")

    def _close_quietly(self):
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None

    # ── background compression and pruning ─────────────────────────────────────
    def _enqueue(self, rotated):
        try:
            self.jobs.put_nowait(rotated)
        except queue.Full:
            self.diag.say("queue", f"compression queue is full ({self.jobs.maxsize}); "
                                   f"{os.path.basename(rotated)} stays uncompressed and counts as a backup")

    def _managed_names(self):
        try:
            names = [n for n in os.listdir(self.dir) if self.managed.match(n)]
        except OSError as e:
            self.diag.say("prune", f"could not list {self.dir}: {e.__class__.__name__}: {e}")
            return []
        def key(n):
            s = self.managed.match(n).group(1)
            base, _, suffix = s.partition("-")
            return (base, int(suffix) if suffix else 0)
        names.sort(key=key)
        return names

    def _compress_loop(self):
        """Compress each rotated file as it is queued; after each, and at the end, prune, then
        compress any rotated file still uncompressed (one the queue could not take, or one left
        by an earlier process), newest last, so at most `backups` files are ever worked on.
        Ends after the job in progress once finish() has asked, whether or not the sentinel
        could be queued."""
        while True:
            try:
                rotated = self.jobs.get(timeout=0.5)
            except queue.Empty:
                if not self.stopping.is_set():
                    continue
                rotated = None
            if rotated is not None:
                self._compress(rotated)
            self._prune()
            for name in self._managed_names():
                if self.stopping.is_set() and rotated is not None:
                    break  # asked to stop: the final sweep runs once, on the sentinel turn
                if not name.endswith(".gz"):
                    self._compress(os.path.join(self.dir, name))
            if rotated is None:
                return

    def _compress(self, rotated):
        started = time.monotonic()
        tmp = rotated + ".gz.tmp"
        with self.names_lock:
            if not os.path.exists(rotated):
                return
            self._compressing = rotated
        try:
            with open(rotated, "rb") as src, gzip.open(tmp, "wb", compresslevel=6) as dst:
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    dst.write(chunk)
            with self.names_lock:
                if os.path.exists(rotated):     # still retained: publish the result
                    os.replace(tmp, rotated + ".gz")
                    os.remove(rotated)
                    published = True
                else:                           # pruned meanwhile: the result is not wanted
                    os.remove(tmp)
                    published = False
            if published:
                self.diag.say("compressed", f"compressed {os.path.basename(rotated)} in "
                                            f"{int((time.monotonic() - started) * 1000)} ms")
        except OSError as e:
            self.diag.say("compress", f"could not compress {os.path.basename(rotated)} "
                                      f"({e.__class__.__name__}: {e}); it is kept uncompressed")
            try:
                os.remove(tmp)  # only this attempt's own temporary file
            except OSError:
                pass
        finally:
            with self.names_lock:
                self._compressing = ""

    def _prune(self):
        """Keep the newest `backups` rotated files, compressed or not; delete the rest, and
        reclaim a stale .gz.tmp whose source or result exists (one whose removal failed at
        the time), so nothing outside the retained set accumulates while this process lives."""
        with self.names_lock:
            names = self._managed_names()
            keep = os.path.basename(self._compressing)
            for n in names[:-self.backups]:
                if n == keep:
                    continue  # being compressed: its result is published, or not, under this lock
                try:
                    os.remove(os.path.join(self.dir, n))
                except FileNotFoundError:
                    pass  # the other thread pruned it
                except OSError as e:
                    self.diag.say("prune", f"could not delete {n}: {e.__class__.__name__}: {e}")
            self._reclaim_temporaries(report=False)

    def finish(self, timeout=120.0):
        """End the compressor after the job in progress and the final sweep, within timeout:
        the stop flag is what ends the loop; the sentinel is queued only if there is room."""
        if self.compressor.is_alive():
            self.stopping.set()
            try:
                self.jobs.put_nowait(None)
            except queue.Full:
                pass  # the loop sees the flag at its next turn
            self.compressor.join(timeout)
            if self.compressor.is_alive():
                self.diag.say("compress", f"compression did not finish within {timeout:g}s at exit; a rotated file may "
                                          f"stay uncompressed or a .gz.tmp may be left (reconciled at the next start)",
                              always=True)
        self._close_quietly()


def write_bounded(log, data, chunk_bytes, line_start):
    """Write data in pieces of at most chunk_bytes, each ending at a newline when one is within
    reach. Only a piece that begins a line may rotate the file, so a line is never split across
    files. Returns whether the next write begins a line."""
    view = memoryview(data)
    while view:
        piece = view[:chunk_bytes]
        if len(view) > chunk_bytes:
            cut = bytes(piece).rfind(b"\n")
            if cut >= 0:
                piece = view[:cut + 1]
        log.write(bytes(piece), line_start)
        line_start = piece[-1] == 0x0A
        view = view[len(piece):]
    return line_start


def drain(fd, log, chunk_bytes, child=None, orphan_grace=5.0):
    """Copy the worker's output to the log: complete lines as they arrive, an open line in
    pieces of at most chunk_bytes, and whatever is left (without a newline) at the end. The
    end is EOF, or, when `child` has exited, no data for orphan_grace seconds: a grandchild
    holding the pipe does not keep this running. Raises FailStop when the log cannot be
    written within its bounds."""
    pending = b""
    line_start = True
    exited_at = None
    while True:
        if child is not None and exited_at is None and child.poll() is not None:
            exited_at = time.monotonic()
        if exited_at is not None and time.monotonic() - exited_at >= orphan_grace:
            if pending:
                write_bounded(log, pending, chunk_bytes, line_start)
            return  # the grace is absolute: data still arriving from a grandchild does not extend it
        ready, _, _ = select.select([fd], [], [], 1.0 if exited_at is None else min(1.0, max(0.05, orphan_grace)))
        if not ready:
            continue
        try:
            data = os.read(fd, 65536)
        except InterruptedError:
            continue
        if not data:
            if pending:
                write_bounded(log, pending, chunk_bytes, line_start)
            return
        pending += data
        cut = pending.rfind(b"\n")
        if cut >= 0:
            line_start = write_bounded(log, pending[:cut + 1], chunk_bytes, line_start)
            pending = pending[cut + 1:]
        if len(pending) >= chunk_bytes:
            line_start = write_bounded(log, pending, chunk_bytes, line_start)
            pending = b""


def stop_child(child, kill_timeout, diag):
    """SIGTERM to the worker, then SIGKILL to it after kill_timeout; returns the worker's exit
    code. Its remaining descendants are launchd's to kill with the group when this exits."""
    if child.poll() is None:
        try:
            child.terminate()
        except OSError:
            pass
        try:
            return child.wait(timeout=kill_timeout)
        except subprocess.TimeoutExpired:
            diag.say("kill", f"the worker did not exit {kill_timeout:g}s after SIGTERM; sending SIGKILL", always=True)
            try:
                child.kill()
            except OSError:
                pass
    return child.wait()


def main(argv):
    p = argparse.ArgumentParser(prog="logpipe.py")
    p.add_argument("--path", required=True)
    p.add_argument("--max-bytes", type=int, required=True)
    p.add_argument("--backups", type=int, required=True)
    p.add_argument("--chunk-bytes", type=int, default=1 << 20)
    p.add_argument("--write-stall-seconds", type=float, default=30)
    p.add_argument("--kill-timeout", type=float, default=15)
    p.add_argument("--diag-path", default=None)
    p.add_argument("--diag-max-bytes", type=int, default=1 << 20)
    p.add_argument("--orphan-grace", type=float, default=5)
    p.add_argument("command", nargs=argparse.REMAINDER)
    a = p.parse_args(argv)
    if a.command[:1] == ["--"]:
        a.command = a.command[1:]
    if not a.command:
        p.error("the worker command must follow --")
    if a.max_bytes < 4 * a.chunk_bytes or a.chunk_bytes < 4096:
        p.error("--max-bytes must be at least four times --chunk-bytes, and --chunk-bytes at least 4096")
    if a.backups < 1:
        p.error("--backups must be at least 1")

    if a.diag_path is None:
        stem, _ = os.path.splitext(a.path)
        a.diag_path = stem + ".logpipe.log"
    diag = Diag(a.diag_path, a.diag_max_bytes)
    log = Log(a.path, a.max_bytes, a.backups, a.write_stall_seconds, diag)
    try:
        log.open_at_start()
    except OSError as e:
        print(f"{PREFIX}: cannot open {a.path} ({e.__class__.__name__}: {e}); not starting the worker, "
              f"its output would be lost", file=sys.stderr, flush=True)
        return 1

    # Same process group as this process, launchd's group for the agent: launchd kills what is
    # left of it when this process exits (see the header), so no new group and no killpg.
    try:
        child = subprocess.Popen(a.command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except OSError as e:
        diag.say("start", f"cannot start the worker ({e.__class__.__name__}: {e}); exiting 127 so launchd retries",
                 always=True)
        log.finish()
        return 127
    forwarded = {}

    def forward(signum, _frame):
        if signum not in forwarded:
            forwarded[signum] = time.monotonic()
            diag.say("signal", f"forwarding signal {signum} to the worker", always=True)
        try:
            child.send_signal(signum)
        except OSError:
            pass
        threading.Thread(target=kill_after, args=(signum,), daemon=True).start()

    def kill_after(signum):
        deadline = forwarded[signum] + a.kill_timeout
        while child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        if child.poll() is None:
            diag.say("kill", f"the worker did not exit {a.kill_timeout:g}s after signal {signum}; sending SIGKILL",
                     always=True)
            try:
                child.kill()
            except OSError:
                pass

    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(s, forward)

    try:
        drain(child.stdout.fileno(), log, a.chunk_bytes, child, a.orphan_grace)
    except FailStop as e:
        diag.say("fail-stop", f"{e}; stopping the worker (its running tasks end) and exiting {EXIT_IOERR}; "
                              f"bytes not yet written are lost", always=True)
        stop_child(child, a.kill_timeout, diag)
        log.finish()
        return EXIT_IOERR
    except Exception as e:  # anything unforeseen: never leave the agent alive but not draining
        diag.say("crash", f"unexpected {e.__class__.__name__}: {e}; stopping the worker and exiting {EXIT_IOERR}",
                 always=True)
        stop_child(child, a.kill_timeout, diag)
        log.finish()
        raise
    code = child.wait()
    log.finish()
    if code < 0:
        return 128 - code
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
