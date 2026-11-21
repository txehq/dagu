# SPDX-License-Identifier: GPL-3.0-or-later
"""B5 host-process custody, reused VERBATIM for kube-run (TXE-8039).

Provenance. Everything from the line "# ---------- B5" to the end of this file is a byte-for-byte copy of the
B5 section of runner-final.py, the reviewed container-stage-1 runner of TXE-7974 (file sha256
c7c9708497d9296fc3f742513bb462637925ba32d41483e3bd87b634af275399, lines 294-640). The same section is unchanged
in that ticket's runner-gen-r2.4.py (lines 362-708). Both are TXE's own code and are kept as TXE-7974 evidence,
not in this repository. The section's own sha256 is
074c8f65f57b987118079e99ef92c9ec86929111679605a2552c9c8fd1ff94d8.
- test_kube_run.py fails when the section here hashes to anything else.
- kube_run.py refuses to run (KR25) when this whole file's sha256 is not the one it pins.
Do not edit below the marker: a change is a new reviewed revision of the source, then new pins in both places.

The only additions are this docstring, the licence line, the stdlib imports the section uses, and
MAX_TRANSPORT_BYTES with runner-final.py's value (line 93), which the section's bounded_run uses as its default
cap.

Platform. The section needs macOS: libproc's proc_listpids gives the explicit group membership, and os.waitid
with WNOWAIT needs Python 3.13 there. On any platform without them, bounded_run refuses BEFORE it creates any
pipe or child ("refused before any child: this platform lacks ..."). kube-run reports that as KR26. A Linux
/proc membership reader would be new code, and therefore a new reviewed section.
"""
import os
import select
import signal
import time

MAX_TRANSPORT_BYTES = 4 * 1024 * 1024            # per stream of one host child (runner-final.py:93)


# ---------- B5: bounded host children, in owned custody (r3.1, root msg_a868e2fc561d) ----------
#
# CUSTODY. A child is spawned as the leader of a NEW session and process group (posix_spawn setsid), so its group id is
# its pid. The leader is NOT reaped until the group is settled: an exited but unreaped leader keeps its pid allocated,
# so that group id cannot be reused by anyone else, and every killpg this code sends reaches only the group it created.
# Exit is observed with waitid(WEXITED|WNOHANG|WNOWAIT), which reports without reaping (macOS: Python 3.13+). The group
# is settled when explicit membership (libproc proc_listpids PROC_PGRP_ONLY) shows no member but the leader. That is
# checked BEFORE the reap. After the reap no signal is ever sent. Settlement order: observe -> TERM, wait 2 s -> KILL,
# wait 3 s -> membership -> reap. A group that keeps members, a leader that never exits, or membership that cannot be
# read is NOT settled: the call fails (rc 125) and says which.
# LIMIT, stated: a descendant that calls setsid() leaves the group. It is neither signalled nor seen by membership, and
# can outlive the call. None of the commands run here (docker CLI, git with file://, cp, lsof, ps) does that.
# EXCEPTION SAFETY: TERM, INT and HUP are blocked from before the spawn until its pid is recorded; spawn, collection and
# settlement are one try/finally. An Interrupted raised at any point after the spawn still settles the group.
# OUTPUT: bounded in the PARENT. stdout and stderr are pipes; the parent keeps at most `cap` bytes of each and discards
# (but still drains) the rest. No RLIMIT_FSIZE: a child's own file writes (cp of the proxy, a git clone) are unchanged.
# Output beyond the cap fails the call (rc 125). The pipes are read until the leader exits or the bound expires, then
# drained for at most DRAIN_S after settlement, then closed: a descendant holding them cannot hold the call.
TERM_GRACE_S, KILL_GRACE_S, DRAIN_S, POLL_S = 2.0, 3.0, 0.5, 0.05
PROC_PGRP_ONLY = 2                                # sys/proc_info.h:52 (MacOSX.sdk)
MEMBERSHIP_ATTEMPTS, MEMBERSHIP_FLOOR_BYTES = 4, 4096
CUSTODY_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)
CHILD_DEFAULT_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGPIPE, signal.SIGXFSZ)
# The proc_listpids contract is INFERRED, not documented (r6/r7, root msg_4a60ea5518c6 and msg_373c57b2471a):
# libproc.h:92 declares
#   int proc_listpids(uint32_t type, uint32_t typeinfo, void *buffer, int buffersize)
# without a comment of its own. Its SIBLING proc_listpidspath (libproc.h, same family and buffer protocol) documents:
# NULL buffer -> "the minimum buffer size needed"; otherwise "the number of bytes of data returned in the provided
# buffer; -1 if an error was encountered". The rules below follow that sibling: a negative result is an error; a
# NULL-buffer size of 0 is ambiguous; a buffered result equal to the capacity may be a FILLED, truncated listing; a
# result that is not a multiple of sizeof(int), or larger than the capacity, is malformed; a buffered result of 0
# pids is AMBIGUOUS (an empty group and a silent failure look alike). Every one of those is UNKNOWN, never a listing.
# OBSERVED on this Mac (capability probe r2, 2026-11-20T16:35:50Z, evidence probe-r2/runs/probe-20261120T163550Z.json
# sha256 1e06c128…): an exited, still-UNREAPED leader IS listed in its own group. So the custody anchor is also a
# liveness check on the listing: while the leader is unreaped, a listing of its group that does not contain it is
# UNKNOWN (settle_group's others()), and zero pids can never be read as "the group is empty".


class Unknown(Exception):
    """Group membership could not be established completely."""


def list_group(listpids, ctypes_mod, pgid, attempts=MEMBERSHIP_ATTEMPTS):
    """The complete pid list of process group pgid, or Unknown. Grows the buffer and retries while a result fills it."""
    need = listpids(PROC_PGRP_ONLY, pgid, None, 0)
    if need < 0:
        raise Unknown(f"size query returned {need} (error)")
    if need == 0:
        raise Unknown("size query returned 0 (ambiguous)")
    cap = max(MEMBERSHIP_FLOOR_BYTES, -(-need // 4) * 4 * 2)
    for _ in range(attempts):
        buf = (ctypes_mod.c_int * (cap // 4))()
        got = listpids(PROC_PGRP_ONLY, pgid, buf, cap)
        if got < 0:
            raise Unknown(f"listing returned {got} (error)")
        if got % 4 or got > cap:
            raise Unknown(f"listing returned {got} bytes for a {cap}-byte buffer (malformed)")
        if got == cap:
            cap *= 2                              # filled: it may be truncated; grow and list again
            continue
        if got == 0:
            raise Unknown("listing returned 0 pids (ambiguous: an empty group and a silent failure look alike)")
        pids = list(buf[: got // 4])
        if any(x <= 0 for x in pids):
            raise Unknown("listing holds a pid <= 0 (malformed)")
        return pids
    raise Unknown(f"listing still filled its buffer after {attempts} attempts (exhausted)")


class RealOps:
    """The operating-system calls the custody of one child group needs. The fixtures replace this with a model, and
    list_group is tested with a modelled listpids. `missing()` names any capability this platform lacks; bounded_run
    refuses BEFORE creating a child when it is not empty. Presence is not runtime proof: see probe_capabilities.py."""

    def __init__(self, listpids=None, ctypes_mod=None):
        self._listpids, self._ctypes, self._load_error = listpids, ctypes_mod, None
        if listpids is None:
            try:
                import ctypes
                lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
                f = lib.proc_listpids
                f.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
                f.restype = ctypes.c_int
                self._listpids, self._ctypes = f, ctypes
            except (OSError, AttributeError) as e:
                self._load_error = type(e).__name__

    def missing(self):
        need = [n for n in ("waitid", "waitpid", "posix_spawn", "killpg", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT",
                            "POSIX_SPAWN_OPEN", "POSIX_SPAWN_DUP2") if not hasattr(os, n)]
        if self._listpids is None:
            need.append(f"libproc proc_listpids ({self._load_error})")
        return need

    def clock(self):
        return time.monotonic()

    def sleep(self, s):
        time.sleep(s)

    def spawn(self, cmd, env, w_out, w_err):
        fa = [(os.POSIX_SPAWN_OPEN, 0, "/dev/null", os.O_RDONLY, 0),
              (os.POSIX_SPAWN_DUP2, w_out, 1), (os.POSIX_SPAWN_DUP2, w_err, 2)]
        # setsid needs POSIX_SPAWN_SETSID (sys/spawn.h:61) in CPython's build; without it posix_spawn raises
        # NotImplementedError BEFORE any child exists.
        return os.posix_spawn(cmd[0], cmd, env, file_actions=fa, setsid=True, setsigmask=(),
                              setsigdef=CHILD_DEFAULT_SIGNALS)

    def exited(self, pid):
        """True when the leader has exited; it is NOT reaped (WNOWAIT)."""
        return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None

    def members(self, pgid):
        """The complete pids of process group pgid; raises Unknown when that cannot be established."""
        return list_group(self._listpids, self._ctypes, pgid)

    def killpg(self, pgid, sig):
        os.killpg(pgid, sig)

    def reap(self, pid):
        """The wait status once the leader is reaped, or None when it has not exited."""
        got, status = os.waitpid(pid, os.WNOHANG)
        return status if got == pid else None


REAL_OPS = None


def real_ops():
    global REAL_OPS
    if REAL_OPS is None:
        REAL_OPS = RealOps()
    return REAL_OPS


class CustodyLost(Exception):
    """The leader is not (or no longer) this process's unreaped child: its group id is not provably ours."""


def leader_exited(ops, pid):
    """exited(), with ECHILD turned into CustodyLost: then nothing may be signalled."""
    try:
        return ops.exited(pid)
    except ChildProcessError:
        raise CustodyLost("the leader is not this process's unreaped child (ECHILD)")


def settle_group(pid, ops):
    """Settle the group led by `pid`, which is still unreaped. Returns a record:
    {pid, pgid, settled, reaped, status, signals, why}. Signals are sent only while the leader is PROVEN unreaped (an exit
    check right before each one); membership is decided before the reap; nothing is signalled after the reap, after
    lost custody, or after ANY error from an exit check, a membership read or a signal (PermissionError included):
    such a group is returned unsettled with its identity, and its leader is reaped only if it was safely seen to exit."""
    rec = {"pid": pid, "pgid": pid, "settled": False, "reaped": False, "status": None, "signals": [], "why": ""}

    def others():
        m = ops.members(pid)
        if pid not in m:           # observed: an unreaped leader is always listed (probe r2); its absence is UNKNOWN
            raise Unknown(f"the unreaped leader {pid} is missing from its own group's listing")
        return sorted(x for x in m if x != pid)

    def quiet():
        o = others()
        return leader_exited(ops, pid) and o == []
    exited = None
    try:
        if not quiet():
            for sig, grace in ((signal.SIGTERM, TERM_GRACE_S), (signal.SIGKILL, KILL_GRACE_S)):
                leader_exited(ops, pid)           # custody re-proven immediately before the signal
                try:
                    ops.killpg(pid, sig)          # the leader is unreaped here: the group id is still ours
                except ProcessLookupError:
                    pass
                rec["signals"].append(int(sig))
                end = ops.clock() + grace
                while ops.clock() < end and not quiet():
                    ops.sleep(POLL_S)
                if quiet():
                    break
        exited = leader_exited(ops, pid)
        left = others()                           # decided BEFORE the reap
    except CustodyLost as e:
        rec["why"] = f"pid {pid} pgid {pid}: {e}: nothing more is signalled, not reaped"
        return rec
    except Unknown as e:
        rec["why"] = f"pid {pid} pgid {pid}: membership unknown ({e}): nothing more is signalled"
        left = None
    except Exception as e:                        # noqa: BLE001 - OSError (PermissionError included) from any probe
        rec["why"] = f"pid {pid} pgid {pid}: {type(e).__name__} during settlement: nothing more is signalled"
        left = None
    if exited is None:
        try:
            exited = leader_exited(ops, pid)
        except Exception:                         # noqa: BLE001
            exited = False
    if not exited:
        rec["why"] = rec["why"] or f"pid {pid} pgid {pid}: the leader did not exit after TERM and KILL; left unreaped"
        return rec
    try:
        status = ops.reap(pid)                    # from here on, nothing is signalled
    except Exception as e:                        # noqa: BLE001
        rec["why"] = rec["why"] or f"pid {pid} pgid {pid}: reap failed ({type(e).__name__})"
        return rec
    if status is None:
        rec["why"] = rec["why"] or f"pid {pid} pgid {pid}: the leader could not be reaped"
        return rec
    rec["reaped"], rec["status"] = True, status
    if left is None:
        rec["why"] = rec["why"] or f"pid {pid} pgid {pid}: membership could not be read"
        return rec
    if left:
        rec["why"] = f"pid {pid} pgid {pid}: group members outlived TERM and KILL: {left[:10]}"
        return rec
    rec["settled"] = True
    return rec


def _exited_or_lost(ops, pid):
    """For collection only: any error from the exit check ends collection; settlement then decides, safely."""
    try:
        return ops.exited(pid)
    except Exception:                             # noqa: BLE001
        return True


def _read_ready(fds, cap, ready):
    for fd in ready:
        try:
            b = os.read(fd, 1 << 16)
        except BlockingIOError:
            continue
        if not b:
            fds["open"].discard(fd)               # EOF on this pipe
            continue
        buf = fds["buf"][fd]
        keep = max(0, cap - len(buf))
        buf += b[:keep]
        fds["over"][fd] = fds["over"][fd] or len(b) > keep


def _collect(pid, fds, deadline, cap, ops):
    """Read the pipes into bounded buffers until the leader exits or the deadline. Returns timed_out."""
    while True:
        if _exited_or_lost(ops, pid):
            return False
        now = ops.clock()
        if now >= deadline:
            return True
        if fds["open"]:
            ready, _, _ = select.select(list(fds["open"]), [], [], max(0.0, min(POLL_S, deadline - now)))
            _read_ready(fds, cap, ready)
        else:
            ops.sleep(POLL_S)


def _drain(fds, budget_s, cap):
    """After settlement: read until EVERY pipe reaches EOF, or budget_s of REAL time (monotonic: the drain is a wall-
    clock bound whatever clock the ops use). A pipe still open then (held by a descendant that escaped the group) means
    the capture is TRUNCATED, never complete. Returns truncated."""
    deadline = time.monotonic() + budget_s
    while fds["open"]:
        now = time.monotonic()
        if now >= deadline:
            return True
        ready, _, _ = select.select(list(fds["open"]), [], [], max(0.0, min(POLL_S, deadline - now)))
        _read_ready(fds, cap, ready)
    return False


def _close_each(fds_to_close):
    """Close every fd, even when a close raises; returns the errors."""
    errors = []
    for fd in fds_to_close:
        try:
            os.close(fd)
        except OSError as e:
            errors.append(f"close {fd}: {type(e).__name__}")
    return errors


def bounded_run(cmd, timeout, env, cap=MAX_TRANSPORT_BYTES, ops=None):
    """One host child in owned custody. Returns (rc, out, err): rc is the child's exit code; 124 its bound expired; 125
    the harness failed it: a missing capability (refused before any child exists), spawn failed, the group not
    settled, the capture truncated (a pipe still held after settlement), or output over the cap. An Interrupted raised
    at any point after the spawn still settles the group, then propagates. Both pipes are closed and the ORIGINAL
    signal mask is restored on every path, including a close that raises. Complete cleanup covers the OWNED group:
    a descendant that escaped into a new session is a stated limit (it shows only as a truncated capture)."""
    ops = ops or real_ops()
    if timeout < 1:
        return 124, "", f"not run: bound {timeout}"
    missing = ops.missing() if hasattr(ops, "missing") else []
    if missing:
        return 125, "", f"refused before any child: this platform lacks {missing}"
    r_out, w_out = os.pipe()
    r_err, w_err = os.pipe()
    fds = {"open": {r_out, r_err}, "buf": {r_out: bytearray(), r_err: bytearray()}, "over": {r_out: False, r_err: False}}
    pid, why, timed_out, truncated, rec, notes = None, "", False, False, None, []
    original = signal.pthread_sigmask(signal.SIG_BLOCK, CUSTODY_SIGNALS)
    try:
        try:
            for fd in (r_out, r_err):
                os.set_blocking(fd, False)
            pid = ops.spawn(cmd, env, w_out, w_err)
        except (OSError, NotImplementedError, ValueError) as e:
            why = f"spawn failed: {type(e).__name__}"
        finally:
            try:
                notes += _close_each((w_out, w_err))
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, original)   # a pending signal is delivered here
        if pid is not None:
            timed_out = _collect(pid, fds, ops.clock() + timeout, cap, ops)
    finally:
        # Settlement cannot itself be interrupted: the custody signals are blocked until it is done; then the
        # ORIGINAL mask is restored, whatever raised.
        signal.pthread_sigmask(signal.SIG_BLOCK, CUSTODY_SIGNALS)
        try:
            try:
                if pid is not None:
                    rec = settle_group(pid, ops)
                    truncated = _drain(fds, DRAIN_S, cap)
            finally:
                notes += _close_each((r_out, r_err))
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, original)
    out = fds["buf"][r_out].decode("utf-8", "replace")
    err = fds["buf"][r_err].decode("utf-8", "replace")
    over = any(fds["over"].values())
    if pid is None:
        rc = 125
    elif not rec["settled"]:
        rc, why = 125, rec["why"]
    elif timed_out:
        rc, why = 124, "timeout"
    elif truncated:
        rc, why = 125, "capture truncated: a pipe was still held open after the group settled (an escaped descendant?)"
    elif over:
        rc, why = 125, f"output over the {cap}-byte cap"
    else:
        rc = os.waitstatus_to_exitcode(rec["status"])
    if notes:                       # a harness close failure is a harness failure (125), whatever the child returned
        why = (why + "; " if why else "") + "harness close failure: " + "; ".join(notes)
        if rc not in (124, 125):
            rc = 125
    return rc, out, (err + ("\n" + why if why else ""))


