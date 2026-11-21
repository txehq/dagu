# SPDX-License-Identifier: GPL-3.0-or-later
"""capacitygate: one point-in-time capacity preflight for Mac container launchers (TXE-8043).

A launcher calls it once, before its first container. It reads the host, the Docker VM and the disks; reads the
run's budget (txe.runbudget/v1) and the coordinator's reservation inventory (txe.capacity.inventory/v1); computes the
admission formula in README.md section 2; writes one receipt; and returns a verdict. It starts, stops and signals
nothing, never polls, never retries a read, and adds no monitoring.

What it is NOT:
- not a lease and not a lock: another coordinator can start work a second later, and the inventory can go stale. Its
  correctness depends on one named coordinator owning the inventory. A later caller must reject a decision whose
  inventory generation or hash has been superseded (`check_decision`);
- not cleanup authority: an unknown owner stays unknown, every container's ownership is UNVERIFIED, and every
  container is marked cleanup_authority "none";
- not guaranteed CPU availability: CPU admission is over declared and configured allocations, and load is recorded only;
- not runtime isolation and not Kubernetes CI admission.

Stdlib only. The commands are constants with fixed bounds; the docker path must be absolute. Readings, budget and
inventory parsing, the formula and the receipt are separate functions so each is tested without a process.
"""
import argparse
import dataclasses
import datetime as _dt
import hashlib
import json
import os
import re
import stat as _stat
import subprocess
import sys
import time
from decimal import Decimal, InvalidOperation, ROUND_CEILING

# runbudget is a sibling data-contract module. A pinned consumer that loads both files by blob hash puts runbudget
# into sys.modules before loading this one; in the repository, it is found beside this directory.
if "runbudget" not in sys.modules:
    _here = os.path.dirname(os.path.abspath(__file__)) if os.path.isfile(__file__) else ""
    if _here:
        sys.path.insert(0, os.path.join(os.path.dirname(_here), "runbudget"))
import runbudget  # noqa: E402

RECEIPT_SCHEMA = "txe.capacitygate.receipt/v1"
INVENTORY_SCHEMA = "txe.capacity.inventory/v1"
LABEL_KEY = "txe.capacity.reservation"
GIB = 1024 ** 3

# Exit codes and their precedence: every reading is taken, and the CLI exits with the first failing code here.
EXIT = {"receipt": 77, "budget": 76, "inventory": 78, "host_pressure": 72, "host_estimate": 73,
        "vm_info": 74, "vm_ps": 74, "vm_stats": 74, "vm_snapshot": 74, "vm_memory": 74,
        "vm_inspect": 79, "vm_cpu": 79, "disk": 75}
EXIT_ORDER = (77, 76, 78, 72, 73, 74, 79, 75)

KINDS = ("missing", "unreadable", "inconsistent", "malformed", "insufficient", "stale", "conflict", "unbounded",
         "unknown_config")

# Policy defaults, each with its lineage. A budget may override any of them; the receipt reports value and origin.
POLICY = {
    "host_pressure_free_min_pct": (40, "TXE-8034 I9c r4 threshold proposal; kept by root's TXE-8043 Q1 ruling as a "
                                       "configurable conservative policy floor, NOT a measured safety guarantee"),
    "vm_reserve_bytes": (2 * GIB, "TXE-8034 I9c r4 threshold proposal; approved as the initial policy default by "
                                  "root's TXE-8043 Q2 ruling; the acceptance by TXE-8034's prior grants was not "
                                  "recovered; not universally sufficient"),
    "vm_cpu_reserve_milli": (0, "root's TXE-8043 D2 ruling: 0 accepted as an explicit initial policy, NOT proof that "
                                "every CPU is available"),
    "disk_floor_bytes": (2 * GIB, "txe/mutate/mutate-sandboxed.py --min-free-mib 2048, reviewed under TXE-7549"),
    "inventory_max_validity_s": (900, "root's TXE-8043 D3 ruling: accepted as a configurable policy cap; no causal "
                                      "safety guarantee"),
    "disk_walk_max_s": (30, "proposed in TXE-8043 design r3 (the I9c docker read bound); pending review"),
    "disk_walk_max_entries": (1_000_000, "proposed in TXE-8043 design r3; pending review"),
}
if set(POLICY) != set(runbudget.POLICY_KEYS):
    raise ImportError("capacitygate POLICY and runbudget POLICY_KEYS disagree")


def _docker_cmds(docker):
    return {
        "vm_info": [docker, "info", "--format", "{{.MemTotal}} {{.NCPU}} {{.ContainersRunning}}"],
        "vm_ps": [docker, "ps", "--no-trunc", "--format",
                  "{{.ID}}\t{{.Names}}\t{{.Label \"" + LABEL_KEY + "\"}}"],
        "vm_stats": [docker, "stats", "--no-stream", "--no-trunc", "--format", "{{.ID}}\t{{.MemUsage}}"],
    }


INSPECT_FORMAT = ("{{.Id}}\t{{.HostConfig.NanoCpus}}\t{{.HostConfig.CpuQuota}}\t{{.HostConfig.CpuPeriod}}\t"
                  "{{.HostConfig.CpusetCpus}}")
HOST_CMDS = {
    "host_pressure": ["/usr/bin/memory_pressure", "-Q"],
    "host_estimate": ["/usr/bin/vm_stat"],
    "load": ["/usr/sbin/sysctl", "-n", "vm.loadavg"],
}
BOUND_S = {"host_pressure": 15, "host_estimate": 10, "load": 10, "vm_info": 30, "vm_ps": 30, "vm_stats": 30,
           "vm_inspect": 30}

DISCLAIMERS = (
    "point-in-time preflight, not a lease and not a lock; another admission can follow a second later",
    "the reservation inventory's correctness is its one owning coordinator's responsibility; a decision is bound to "
    "the inventory generation and sha256 in this receipt, and a superseded decision must be rejected",
    "container ownership is UNVERIFIED: a label or a listed id is a claim, never cleanup authority",
    "CPU admission is managed-reservation admission over declared and configured allocations; it is not a guarantee "
    "that CPU is available; load is informational",
    "the host vm_stat estimate is log-only: its page classes may overlap and it gates nothing",
    "grant ids are audit references, not cryptographic approval",
)


@dataclasses.dataclass(frozen=True)
class Failure:
    reading: str
    kind: str
    code: str
    detail: str = ""

    @property
    def exit_code(self):
        return EXIT[self.reading]

    def as_dict(self):
        return {"reading": self.reading, "kind": self.kind, "code": self.code, "detail": self.detail,
                "exit_code": self.exit_code}


@dataclasses.dataclass(frozen=True)
class Verdict:
    admit: bool
    exit_code: int
    failures: tuple
    receipt_path: str
    inventory_generation: object = None
    inventory_sha256: str = ""


class Bad(Exception):
    """A reading or document that cannot be used: a KINDS value and a stable code. Never a raw value."""

    def __init__(self, kind, code, detail=""):
        super().__init__(f"{kind} {code} {detail}".strip())
        self.kind, self.code, self.detail = kind, code, detail


def exit_for(failures):
    codes = {f.exit_code for f in failures}
    for c in EXIT_ORDER:
        if c in codes:
            return c
    return 0


# ---- time ------------------------------------------------------------------------------------------------------

_TS_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")


def parse_ts(text):
    if not isinstance(text, str) or not _TS_RE.fullmatch(text):
        return None
    try:
        return _dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
    except ValueError:
        return None


def fmt_ts(t):
    return t.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_now():
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)


# ---- reading parsers (pure) ------------------------------------------------------------------------------------

_INT_RE = re.compile(r"-?(0|[1-9][0-9]*)")
_ID_RE = re.compile(r"[0-9a-f]{64}")


def parse_pressure(text):
    """`memory_pressure -Q`: the integer free percentage, exactly one line."""
    found = re.findall(r"^System-wide memory free percentage: ([0-9]+)%$", text, re.M)
    if len(found) != 1:
        raise Bad("unreadable", "P01", "free-percentage lines: %d" % len(found))
    v = int(found[0])
    if v > 100:
        raise Bad("unreadable", "P02", "percentage above 100")
    return v


_VM_CLASSES = ("free", "inactive", "speculative", "purgeable")


def parse_vm_stat(text):
    """`vm_stat`: (free + inactive + speculative + purgeable) x page size, in bytes. Log-only (README 2.5)."""
    ps = re.findall(r"^Mach Virtual Memory Statistics: \(page size of ([0-9]+) bytes\)$", text, re.M)
    if len(ps) != 1 or int(ps[0]) <= 0:
        raise Bad("unreadable", "V01", "page size")
    pages = {}
    for name in _VM_CLASSES:
        found = re.findall(r"^Pages %s:\s+([0-9]+)\.$" % name, text, re.M)
        if len(found) != 1:
            raise Bad("unreadable", "V02", "page class %s found %d times" % (name, len(found)))
        pages[name] = int(found[0])
    return {"page_size": int(ps[0]), "pages": pages, "estimate_bytes": sum(pages.values()) * int(ps[0])}


def parse_loadavg(text):
    """`sysctl -n vm.loadavg`: '{ 1.23 2.34 3.45 }'. Recorded only."""
    m = re.fullmatch(r"\{ ([0-9]+\.[0-9]+) ([0-9]+\.[0-9]+) ([0-9]+\.[0-9]+) \}\n?", text)
    if not m:
        raise Bad("unreadable", "L01")
    return list(m.groups())


def parse_info(text):
    """`docker info`: MemTotal, NCPU, ContainersRunning, one line of three non-negative integers."""
    lines = text.splitlines()
    if len(lines) != 1:
        raise Bad("unreadable", "I01", "lines: %d" % len(lines))
    parts = lines[0].split(" ")
    if len(parts) != 3 or not all(re.fullmatch(r"0|[1-9][0-9]*", p) for p in parts):
        raise Bad("unreadable", "I02", "fields")
    mem, ncpu, running = (int(p) for p in parts)
    if mem <= 0 or ncpu <= 0:
        raise Bad("unreadable", "I03", "MemTotal or NCPU is zero")
    return {"mem_total_bytes": mem, "ncpu": ncpu, "containers_running": running}


def parse_ps(text):
    """`docker ps`: {full id: (name, reservation label or "")}."""
    out = {}
    for n, line in enumerate(text.splitlines(), 1):
        parts = line.split("\t")
        if len(parts) != 3:
            raise Bad("unreadable", "S01", "ps row %d fields" % n)
        cid, name, label = parts
        if not _ID_RE.fullmatch(cid):
            raise Bad("unreadable", "S02", "ps row %d id" % n)
        if not name or cid in out:
            raise Bad("unreadable", "S03", "ps row %d name or duplicate id" % n)
        out[cid] = (name, label)
    return out


# The I9c unit table, ported in meaning: the decimal spellings map to the binary multipliers, as I9c did (that
# can only over-count, never under-count).
_UNITS = {"B": 1, "KiB": 1024, "kB": 1024, "MiB": 1024 ** 2, "MB": 1024 ** 2, "GiB": GIB, "GB": GIB}
_USAGE_RE = re.compile(r"((?:0|[1-9][0-9]*)(?:\.[0-9]+)?)(B|KiB|kB|MiB|MB|GiB|GB)")


def usage_bytes(token):
    """One MemUsage figure as integer bytes, exact decimal arithmetic, rounded UP. Raises Bad on anything else."""
    m = _USAGE_RE.fullmatch(token)
    if not m:
        raise Bad("unreadable", "M02", "unit or number")
    try:
        v = (Decimal(m.group(1)) * _UNITS[m.group(2)]).to_integral_value(rounding=ROUND_CEILING)
    except InvalidOperation:
        raise Bad("unreadable", "M02", "number") from None
    return int(v)


def parse_stats(text):
    """`docker stats`: {full id: used bytes}. The MemUsage column is '<used> / <limit>'; only <used> is charged."""
    out = {}
    for n, line in enumerate(text.splitlines(), 1):
        parts = line.split("\t")
        if len(parts) != 2:
            raise Bad("unreadable", "M01", "stats row %d fields" % n)
        cid, mem = parts
        if not _ID_RE.fullmatch(cid) or cid in out:
            raise Bad("unreadable", "M03", "stats row %d id or duplicate" % n)
        halves = mem.split(" / ")
        if len(halves) != 2:
            raise Bad("unreadable", "M01", "stats row %d MemUsage" % n)
        out[cid] = usage_bytes(halves[0])
    return out


# ---- CPU allocation of one container (README 2.3) --------------------------------------------------------------

KNOWN, VALID_UNLIMITED, UNKNOWN_CONFIG, MALFORMED = "KNOWN", "VALID_UNLIMITED", "UNKNOWN_CONFIG", "MALFORMED"


def _ceil_div(a, b):
    return -((-a) // b)


def parse_cpuset(text, ncpu):
    """Number of CPUs in a cpuset list such as '0-3,6', or None when malformed: bad syntax, a reversed range, a
    duplicate or overlapping CPU, or a CPU outside the VM's 0..ncpu-1."""
    seen = set()
    for part in text.split(","):
        m = re.fullmatch(r"(0|[1-9][0-9]*)(?:-(0|[1-9][0-9]*))?", part)
        if not m:
            return None
        a = int(m.group(1))
        b = int(m.group(2)) if m.group(2) is not None else a
        if b < a or b >= ncpu:
            return None
        rng = set(range(a, b + 1))
        if rng & seen:
            return None
        seen |= rng
    return len(seen)


def classify_cpu(nano, quota, period, cpuset, ncpu):
    """(class, effective upper bound in millicpus or None, constraints) for one container.

    Every APPLICABLE KNOWN constraint is computed, and the effective bound is their minimum, so no rule order matters:
    - NanoCpus > 0: ceil(NanoCpus / 1e6);
    - CpuQuota > 0 and CpuPeriod > 0: ceil(CpuQuota x 1000 / CpuPeriod);
    - CpusetCpus non-empty and valid: its CPU count x 1000;
    - when any of those exists, the VM itself (ncpu x 1000) is one more constraint.
    CpuQuota > 0 with CpuPeriod == 0 is UNKNOWN (Docker's default period is not assumed). It does not hide a known
    bound: with another known constraint the class is KNOWN. With none known, UNKNOWN_CONFIG; with nothing set at all,
    VALID_UNLIMITED. A negative NanoCpus or CpuPeriod, a CpuQuota below -1 (-1 and 0 both mean unset), or a malformed
    cpuset is MALFORMED, which no policy can cover."""
    if nano < 0 or period < 0 or quota < -1:
        return MALFORMED, None, ["negative field"]
    known, notes = [], []
    if nano > 0:
        known.append(("nano_cpus", _ceil_div(nano, 1_000_000)))
    unknown = False
    if quota > 0:
        if period > 0:
            known.append(("cpu_quota", _ceil_div(quota * 1000, period)))
        else:
            unknown = True
            notes.append("cpu_quota without cpu_period")
    if cpuset != "":
        n = parse_cpuset(cpuset, ncpu)
        if n is None:
            return MALFORMED, None, ["cpuset"]
        known.append(("cpuset_cpus", n * 1000))
    if known:
        known.append(("vm_ncpu", ncpu * 1000))
        bound = min(v for _, v in known)
        return KNOWN, bound, [f"{k}={v}" for k, v in known] + notes
    if unknown:
        return UNKNOWN_CONFIG, None, notes
    return VALID_UNLIMITED, None, []


def parse_inspect(text, ncpu):
    """`docker inspect` rows: {full id: (class, bound, constraints)}. A row whose shape is wrong refuses the whole
    reading (unreadable); a row whose fields are present but invalid is that container's MALFORMED class."""
    out = {}
    for n, line in enumerate(text.splitlines(), 1):
        parts = line.split("\t")
        if len(parts) != 5:
            raise Bad("unreadable", "C01", "inspect row %d fields" % n)
        cid, nano, quota, period, cpuset = parts
        if not _ID_RE.fullmatch(cid) or cid in out:
            raise Bad("unreadable", "C02", "inspect row %d id or duplicate" % n)
        if not all(_INT_RE.fullmatch(x) for x in (nano, quota, period)):
            out[cid] = (MALFORMED, None, ["non-integer field"])
            continue
        out[cid] = classify_cpu(int(nano), int(quota), int(period), cpuset, ncpu)
    return out


# ---- the reservation inventory (README 3.2) --------------------------------------------------------------------

INV_TOP = {"schema", "generation", "owner", "written_at", "valid_until", "foreign_cpu_policy", "reservations"}
INV_OWNER = {"session", "run"}
RES_KEYS = {"id", "state", "owner", "cpus_milli", "memory_bytes", "disk", "match", "deadline"}
RES_DISK = {"path", "cap_bytes"}
POLICY_CPU_KEYS = {"milli", "grant", "generation"}
RUN_RE = re.compile(r"run_[0-9a-f]{12}")


@dataclasses.dataclass(frozen=True)
class Reservation:
    id: str
    state: str                   # "running" or "pending"
    owner: tuple
    cpus_milli: int              # total, across the reservation's containers
    memory_bytes: int            # total
    disk: tuple                  # of (path, cap_bytes)
    match_kind: str              # "label" or "ids"
    match_ids: tuple
    deadline: object


@dataclasses.dataclass(frozen=True)
class Inventory:
    generation: int
    owner: tuple
    written_at: object
    valid_until: object
    foreign_cpu_milli: object    # None, or the positive charge per VALID_UNLIMITED foreign container
    foreign_cpu_grant: str
    reservations: tuple
    sha256: str

    def by_id(self):
        return {r.id: r for r in self.reservations}


def _ikeys(obj, allowed, where):
    if not isinstance(obj, dict):
        raise Bad("unreadable", "N02", where)
    extra = sorted(set(obj) - allowed)
    if extra:
        raise Bad("unreadable", "N03", f"{where} unknown key")
    missing = sorted(allowed - set(obj))
    if missing:
        raise Bad("unreadable", "N04", f"{where}.{missing[0]} missing")


def _ipos(obj, key, where, lo=1):
    v = obj[key]
    if not runbudget.is_int(v) or v < lo:
        raise Bad("unreadable", "N05", f"{where}.{key}")
    return v


def parse_inventory(data):
    """Validate inventory bytes into an Inventory. Raises Bad(unreadable|conflict, ...). Staleness and the budget
    binding are checked by `check_inventory`."""
    sha = hashlib.sha256(data).hexdigest()
    try:
        doc = runbudget.parse_json(data.decode("utf-8"))
    except (runbudget.BudgetError, UnicodeDecodeError):
        raise Bad("unreadable", "N01", "not strict JSON") from None
    if not isinstance(doc, dict) or doc.get("schema") != INVENTORY_SCHEMA:
        raise Bad("unreadable", "N01", "schema")
    _ikeys(doc, INV_TOP, "inventory")
    gen = _ipos(doc, "generation", "inventory")
    _ikeys(doc["owner"], INV_OWNER, "owner")
    if not isinstance(doc["owner"]["session"], str) or not runbudget.SESSION_RE.fullmatch(doc["owner"]["session"]) \
            or not isinstance(doc["owner"]["run"], str) or not RUN_RE.fullmatch(doc["owner"]["run"]):
        raise Bad("unreadable", "N06", "owner")
    written, valid = parse_ts(doc["written_at"]), parse_ts(doc["valid_until"])
    if written is None or valid is None:
        raise Bad("unreadable", "N07", "timestamp")
    pol = doc["foreign_cpu_policy"]
    milli, grant = None, ""
    if pol is not None:
        _ikeys(pol, POLICY_CPU_KEYS, "foreign_cpu_policy")
        milli = _ipos(pol, "milli", "foreign_cpu_policy", 1)
        if not isinstance(pol["grant"], str) or not runbudget.GRANT_RE.fullmatch(pol["grant"]):
            raise Bad("unreadable", "N08", "foreign_cpu_policy.grant")
        if not runbudget.is_int(pol["generation"]) or pol["generation"] != gen:
            raise Bad("conflict", "N09", "foreign_cpu_policy is bound to another inventory generation")
        grant = pol["grant"]
    if not isinstance(doc["reservations"], list):
        raise Bad("unreadable", "N02", "reservations")
    res, ids, listed = [], set(), {}
    for i, r in enumerate(doc["reservations"]):
        where = f"reservations[{i}]"
        _ikeys(r, RES_KEYS, where)
        rid = r["id"]
        if not isinstance(rid, str) or not runbudget.RESERVATION_ID_RE.fullmatch(rid) or rid in runbudget.RESERVED_IDS:
            raise Bad("unreadable", "N10", f"{where}.id")
        if rid in ids:
            raise Bad("unreadable", "N11", f"{where} duplicate id")
        ids.add(rid)
        if r["state"] not in ("running", "pending"):
            raise Bad("unreadable", "N12", f"{where}.state")
        _ikeys(r["owner"], runbudget.OWNER_KEYS, f"{where}.owner")
        for key, rx in (("ticket", runbudget.TICKET_RE), ("session", runbudget.SESSION_RE),
                        ("grant", runbudget.GRANT_RE)):
            if not isinstance(r["owner"][key], str) or not rx.fullmatch(r["owner"][key]):
                raise Bad("unreadable", "N06", f"{where}.owner.{key}")
        cpus = _ipos(r, "cpus_milli", where)
        mem = _ipos(r, "memory_bytes", where)
        if not isinstance(r["disk"], list):
            raise Bad("unreadable", "N02", f"{where}.disk")
        disk, seen_paths = [], set()
        for j, d in enumerate(r["disk"]):
            dw = f"{where}.disk[{j}]"
            _ikeys(d, RES_DISK, dw)
            p = d["path"]
            if not runbudget.is_normal_abs(p) or p in seen_paths:
                raise Bad("unreadable", "N13", f"{dw}.path")
            # D1: a disk path is bound to the reservation's identity: one of its components is the reservation id.
            if rid not in p.split("/"):
                raise Bad("unreadable", "N14", f"{dw}.path does not name its reservation")
            seen_paths.add(p)
            disk.append((p, _ipos(d, "cap_bytes", dw, 0)))
        m = r["match"]
        if not isinstance(m, dict) or m.get("kind") not in ("label", "ids"):
            raise Bad("unreadable", "N15", f"{where}.match")
        if m["kind"] == "label":
            _ikeys(m, {"kind"}, f"{where}.match")
            mids = ()
        else:
            _ikeys(m, {"kind", "ids"}, f"{where}.match")
            if not isinstance(m["ids"], list) or not m["ids"]:
                raise Bad("unreadable", "N15", f"{where}.match.ids")
            for cid in m["ids"]:
                if not isinstance(cid, str) or not _ID_RE.fullmatch(cid):
                    raise Bad("unreadable", "N15", f"{where}.match.ids")
                if cid in listed:
                    raise Bad("conflict", "N16", "one container id listed by two reservations")
                listed[cid] = rid
            mids = tuple(m["ids"])
            if len(set(mids)) != len(mids):
                raise Bad("unreadable", "N15", f"{where}.match.ids duplicate")
        deadline = parse_ts(r["deadline"])
        if deadline is None:
            raise Bad("unreadable", "N07", f"{where}.deadline")
        res.append(Reservation(rid, r["state"], tuple(r["owner"][k] for k in ("ticket", "session", "grant")),
                               cpus, mem, tuple(disk), m["kind"], mids, deadline))
    return Inventory(gen, (doc["owner"]["session"], doc["owner"]["run"]), written, valid, milli, grant, tuple(res),
                     sha)


def check_inventory(inv, now, max_validity_s, budget=None):
    """Staleness, then the binding to the new run. Raises Bad(stale|conflict, ...)."""
    if inv.written_at > now:
        raise Bad("stale", "T01", "written_at is in the future")
    if now >= inv.valid_until:
        raise Bad("stale", "T02", "valid_until has passed")
    if (inv.valid_until - inv.written_at).total_seconds() > max_validity_s:
        raise Bad("stale", "T03", "validity window exceeds inventory_max_validity_s")
    if budget is None:
        return
    me = inv.by_id().get(budget.reservation_id)
    if me is None:
        raise Bad("conflict", "K01", "the run is not reserved in the inventory")
    if me.state != "pending":
        raise Bad("conflict", "K02", "the run's reservation is not pending")
    if me.owner != budget.owner:
        raise Bad("conflict", "K03", "owner or grant differs from the budget")
    if me.cpus_milli != budget.need_cpus_milli or me.memory_bytes != budget.need_memory_bytes:
        raise Bad("conflict", "K04", "caps differ from the budget")
    if sorted(me.disk) != sorted((d.path, d.need_bytes) for d in budget.disk):
        raise Bad("conflict", "K05", "disk claims differ from the budget")


# ---- attribution: one owner per container id (README 2.1) ------------------------------------------------------

def attribute(inv, ps, self_id):
    """{container id: {"owner": reservation id or "unknown", "matched_by": ..., "flags": [...]}}.

    A label naming a registered `label` reservation, or an id listed by an `ids` reservation, attributes the
    container. A label naming an unregistered id attributes nothing (flag label_unregistered). Raises
    Bad("conflict") when one container would have two owners, when a pending reservation already has a container
    (the inventory is stale), or when a container belongs to the new run itself."""
    by_id = inv.by_id()
    listed = {cid: r.id for r in inv.reservations for cid in r.match_ids}
    out = {}
    for cid, (_name, label) in sorted(ps.items()):
        owners, how, flags = set(), [], []
        if label:
            r = by_id.get(label)
            if r is None:
                flags.append("label_unregistered")
            elif r.match_kind == "label":
                owners.add(r.id)
                how.append("label")
            else:
                flags.append("label_on_ids_reservation")
        if cid in listed:
            owners.add(listed[cid])
            how.append("id")
        if len(owners) > 1:
            raise Bad("conflict", "A01", "one container attributed to two reservations")
        owner = owners.pop() if owners else "unknown"
        if owner == self_id or (label and label == self_id):
            raise Bad("conflict", "A02", "a container already belongs to the new run")
        if owner != "unknown" and by_id[owner].state == "pending":
            raise Bad("conflict", "A03", "a pending reservation already has a running container")
        out[cid] = {"owner": owner, "matched_by": "+".join(how) or "none", "flags": flags}
    return out


# ---- the formula (README 2.2-2.4), pure ------------------------------------------------------------------------

def account_memory(budget, inv, info, stats, attr, policy):
    """Memory terms. Each container id is charged once: inside its reservation's max() or in U_mem."""
    run = [r for r in inv.reservations if r.state == "running"]
    pend = [r for r in inv.reservations if r.state == "pending" and r.id != budget.reservation_id]
    a_mem, flags = {}, {}
    for r in run:
        measured = sum(stats[c] for c, a in attr.items() if a["owner"] == r.id)
        a_mem[r.id] = max(measured, r.memory_bytes)
        if not any(a["owner"] == r.id for a in attr.values()):
            flags[r.id] = "unmatched"
    u_mem = sum(stats[c] for c, a in attr.items() if a["owner"] == "unknown")
    p_mem = sum(r.memory_bytes for r in pend)
    n_mem = budget.need_memory_bytes
    r_vm = policy["vm_reserve_bytes"]
    charged = sum(a_mem.values()) + u_mem + p_mem + n_mem + r_vm
    total = info["mem_total_bytes"]
    return {"terms": {"A_mem": a_mem, "U_mem": u_mem, "P_mem": p_mem, "N_mem": n_mem, "R_vm": r_vm},
            "flags": flags, "charged": charged, "total": total, "headroom": total - charged, "admit": charged <= total}


def account_cpu(budget, inv, info, cpu, attr, policy):
    """CPU terms and the containers that refuse admission. Each container id is charged once: inside its
    reservation's max(), or as one foreign term."""
    total = info["ncpu"] * 1000
    run = [r for r in inv.reservations if r.state == "running"]
    pend = [r for r in inv.reservations if r.state == "pending" and r.id != budget.reservation_id]
    refusals, basis, flags = [], {}, {}
    a_cpu = {}
    for r in run:
        mine = [c for c, a in attr.items() if a["owner"] == r.id]
        known = 0
        for c in mine:
            cls, bound, _ = cpu[c]
            if cls == MALFORMED:
                refusals.append(Failure("vm_inspect", "malformed", "C10", "reserved container allocation malformed"))
                basis[c] = "refused:malformed"
            elif cls == KNOWN:
                known += bound
                basis[c] = f"reserved:{r.id}:configured"
            else:
                flags.setdefault(r.id, []).append("reserved_container_unbounded")
                basis[c] = f"reserved:{r.id}:declared_cap_admission_policy_not_enforced_limit"
        a_cpu[r.id] = max(r.cpus_milli, known)
    f_known, f_policy, n_unbounded = 0, 0, 0
    for c, a in attr.items():
        if a["owner"] != "unknown":
            continue
        cls, bound, _ = cpu[c]
        if cls == KNOWN:
            f_known += bound
            basis[c] = "foreign:configured"
        elif cls == VALID_UNLIMITED and inv.foreign_cpu_milli is not None:
            n_unbounded += 1
            f_policy += inv.foreign_cpu_milli
            basis[c] = "foreign:inventory_policy"
        elif cls == VALID_UNLIMITED:
            n_unbounded += 1
            refusals.append(Failure("vm_cpu", "unbounded", "C11", "foreign container with no CPU limit and no "
                                                                  "inventory foreign_cpu_policy"))
            basis[c] = "refused:unbounded_no_policy"
        elif cls == UNKNOWN_CONFIG:
            refusals.append(Failure("vm_cpu", "unknown_config", "C12", "foreign container CPU configuration not "
                                                                       "classified; no policy may cover it"))
            basis[c] = "refused:unknown_config"
        else:
            refusals.append(Failure("vm_inspect", "malformed", "C10", "foreign container allocation malformed"))
            basis[c] = "refused:malformed"
    p_cpu = sum(r.cpus_milli for r in pend)
    n_cpu = budget.need_cpus_milli
    r_cpu = policy["vm_cpu_reserve_milli"]
    charged = sum(a_cpu.values()) + p_cpu + f_known + f_policy + n_cpu + r_cpu
    fits = charged <= total and budget.cpus_milli <= total
    return {"terms": {"A_cpu": a_cpu, "P_cpu": p_cpu, "F_known": f_known, "F_policy": f_policy,
                      "unbounded_foreign": n_unbounded, "N_cpu": n_cpu, "R_cpu": r_cpu},
            "policy": ({"milli": inv.foreign_cpu_milli, "grant": inv.foreign_cpu_grant,
                        "inventory_generation": inv.generation} if inv.foreign_cpu_milli is not None else None),
            "flags": flags, "basis": basis, "charged": charged, "total": total, "headroom": total - charged,
            "admit": fits and not refusals, "refusals": refusals,
            "per_container_fits": budget.cpus_milli <= total}


def nearest_device(path, stat_fn):
    """st_dev of the path, or of its nearest existing ancestor; None when nothing can be stat'ed."""
    p = path
    while True:
        try:
            return stat_fn(p).st_dev
        except OSError:
            if p == "/":
                return None
            p = os.path.dirname(p)


WALK_MAX_DEPTH = 256         # txe/mutate/mutate-sandboxed.py dir_usage's max_depth (TXE-7549)
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


class _WalkStop(Exception):
    """A walk that must fail closed; its argument is the flag recorded for that root."""


def walk_used(roots, max_s, max_entries, monotonic=time.monotonic, _open=os.open):
    """Bytes in use under each (reservation id, path) root. Returns {(rid, path): (used or None, flags)}; None means
    the walk failed and the caller charges the full remaining cap.

    The claim tree may be written by the running reservation WHILE it is walked, so the walk works on directory
    DESCRIPTORS (the txe/mutate dir_usage pattern):
    - The root, and each directory below it, is opened with O_NOFOLLOW: the root relative to its path, each child
      relative to its parent's descriptor. A directory swapped for a symlink fails to open, and the root fails.
    - Each opened directory's fstat (st_dev, st_ino) must equal the lstat taken when it was listed (or, for the root,
      before it was opened). A directory replaced between the two fails closed (identity_changed).
    - Symlinks below the root are never followed or counted. A FIFO, socket or device file fails that root. A
      different st_dev below the root is not descended (a mount).
    - Each (st_dev, st_ino) is counted once across ALL roots, so hard links and overlapping paths never count twice.
    - Bounds: a shared wall-clock bound, a per-root entry bound, and WALK_MAX_DEPTH levels. Exceeding any of them
      fails that root. One descriptor is open per level.
    Limit: the path components ABOVE the root are resolved normally. The claim path is bound to its reservation id,
    but its parent directories must not be writable by the reservation."""
    seen, out = set(), {}
    start = monotonic()

    def same(st, fd):
        f = os.fstat(fd)
        return (f.st_dev, f.st_ino) == (st.st_dev, st.st_ino) and _stat.S_ISDIR(f.st_mode)

    for rid, path in sorted(roots):
        flags, tally = [], {"used": 0, "entries": 0}
        try:
            st = os.lstat(path)
        except OSError:
            out[(rid, path)] = (None, ["lookup_failed"])
            continue
        if _stat.S_ISLNK(st.st_mode) or not _stat.S_ISDIR(st.st_mode):
            out[(rid, path)] = (None, ["root_not_a_real_directory"])
            continue
        dev = st.st_dev

        def count(s):
            k = (s.st_dev, s.st_ino)
            if k not in seen:
                seen.add(k)
                tally["used"] += s.st_blocks * 512

        def walk(fd, depth):
            if depth > WALK_MAX_DEPTH:
                raise _WalkStop("depth_bound")
            with os.scandir(fd) as it:
                for e in it:
                    tally["entries"] += 1
                    if tally["entries"] > max_entries:
                        raise _WalkStop("entry_bound")
                    if monotonic() - start > max_s:
                        raise _WalkStop("time_bound")
                    s = e.stat(follow_symlinks=False)
                    if _stat.S_ISLNK(s.st_mode):
                        if "symlink_not_followed" not in flags:
                            flags.append("symlink_not_followed")
                        continue
                    if s.st_dev != dev:
                        if "mount_not_descended" not in flags:
                            flags.append("mount_not_descended")
                        continue
                    if _stat.S_ISDIR(s.st_mode):
                        try:
                            sub = _open(e.name, _DIR_FLAGS, dir_fd=fd)
                        except OSError:
                            raise _WalkStop("open_refused") from None
                        try:
                            if not same(s, sub):
                                raise _WalkStop("identity_changed")
                            count(s)
                            walk(sub, depth + 1)
                        finally:
                            os.close(sub)
                    elif _stat.S_ISREG(s.st_mode):
                        count(s)
                    else:
                        raise _WalkStop("special_file")

        failed = None
        try:
            top = _open(path, _DIR_FLAGS)
        except OSError:
            out[(rid, path)] = (None, ["open_refused"])
            continue
        try:
            if not same(st, top):
                raise _WalkStop("identity_changed")
            count(st)
            walk(top, 0)
        except _WalkStop as stop:
            failed = stop.args[0]
        except OSError:
            failed = "lookup_failed"
        finally:
            os.close(top)
        out[(rid, path)] = (None, flags + [failed]) if failed else (tally["used"], flags)
    return out


def _statfs(path):
    """(st_dev, free bytes for an unprivileged writer) of a path or its nearest existing ancestor."""
    p = path
    while not os.path.exists(p) and p != "/":
        p = os.path.dirname(p)
    vfs = os.statvfs(p)
    return os.stat(p).st_dev, vfs.f_bavail * vfs.f_frsize


def account_disk(budget, inv, policy, statfs, stat_fn, walker, monotonic):
    """Per device the new run uses: N_disk + sum of running reservations' remaining claims + pending claims + floor,
    against free space. Returns ({"devices": [...], "other_device_claims": [...]}, failures). A claim on a device the
    new run does not use is recorded in other_device_claims and not charged."""
    failures, devices, other = [], {}, []
    for d in budget.disk:
        try:
            dev, free = statfs(d.path)
        except OSError:
            failures.append(Failure("disk", "missing", "D01", "statvfs failed for a budget path"))
            continue
        e = devices.setdefault(dev, {"st_dev": dev, "paths": [], "free": free, "N_disk": 0, "left": {}, "P_disk": {},
                                     "walks": []})
        e["paths"].append(d.path)
        e["N_disk"] += d.need_bytes
    if failures:
        return {"devices": [], "other_device_claims": []}, failures
    run = [r for r in inv.reservations if r.state == "running"]
    pend = [r for r in inv.reservations if r.state == "pending" and r.id != budget.reservation_id]
    roots = [(r.id, p) for r in run for p, _ in r.disk]
    walked = walker(roots, policy["disk_walk_max_s"], policy["disk_walk_max_entries"], monotonic) if roots else {}
    for r in run:
        for p, cap in r.disk:
            used, flags = walked.get((r.id, p), (None, ["lookup_failed"]))
            dev = nearest_device(p, stat_fn)
            targets = [dev] if dev in devices else ([] if dev is not None else list(devices))
            if dev is None:
                flags = flags + ["device_unknown_charged_to_every_budget_device"]
            left = cap if used is None else max(cap - used, 0)
            if not targets:
                other.append({"reservation": r.id, "path": p, "state": "running", "left": left})
            for t in targets:
                devices[t]["left"][f"{r.id}:{p}"] = left
                devices[t]["walks"].append({"reservation": r.id, "path": p, "cap": cap, "used": used,
                                            "status": "ok" if used is not None else "fallback_full_remaining_cap",
                                            "flags": flags})
    for r in pend:
        for p, cap in r.disk:
            dev = nearest_device(p, stat_fn)
            targets = [dev] if dev in devices else ([] if dev is not None else list(devices))
            if not targets:
                other.append({"reservation": r.id, "path": p, "state": "pending", "cap": cap})
            for t in targets:
                devices[t]["P_disk"][f"{r.id}:{p}"] = cap
    out = []
    for dev in sorted(devices):
        e = devices[dev]
        e["F_disk"] = policy["disk_floor_bytes"]
        e["charged"] = e["N_disk"] + sum(e["left"].values()) + sum(e["P_disk"].values()) + e["F_disk"]
        e["headroom"] = e["free"] - e["charged"]
        e["admit"] = e["charged"] <= e["free"]
        out.append(e)
        if not e["admit"]:
            failures.append(Failure("disk", "insufficient", "D02", "charged=%d free=%d" % (e["charged"], e["free"])))
    return {"devices": out, "other_device_claims": other}, failures


def reservation_flags(inv, attr, now):
    """{reservation id: [flags]}: past_deadline (still charged), unmatched (running with no container; still charged).
    Reconciling them is the coordinator's job; the gate never infers that a reservation ended."""
    out = {}
    for r in inv.reservations:
        flags = []
        if r.deadline <= now:
            flags.append("past_deadline")
        if r.state == "running" and attr is not None and not any(a["owner"] == r.id for a in attr.values()):
            flags.append("unmatched")
        if flags:
            out[r.id] = flags
    return out


# ---- preflight -------------------------------------------------------------------------------------------------

def _bounded_run(argv, timeout_s):
    """(returncode, stdout bytes, stderr bytes); raises OSError or subprocess.TimeoutExpired."""
    p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout_s, check=False)
    return p.returncode, p.stdout, p.stderr


def _self_sha256():
    try:
        if os.path.isfile(__file__):
            with open(__file__, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        return "unavailable: not loaded from a regular file"
    except OSError:
        return "unavailable: unreadable"


def resolve_policy(budget):
    out, values = {}, {}
    given = dict(budget.policy) if budget is not None else {}
    for k, (default, lineage) in POLICY.items():
        if k in given:
            values[k] = given[k]
            out[k] = {"value": given[k], "origin": "budget", "default": default, "lineage": lineage}
        else:
            values[k] = default
            out[k] = {"value": default, "origin": "default", "lineage": lineage}
    return values, out


class _Reader:
    """Takes each reading once, keeps its raw bytes for the receipt, and records its metadata."""

    def __init__(self, run, clock):
        self.run, self.clock = run, clock
        self.records, self.raw = [], {}

    def take(self, name, argv, parse):
        rec = {"name": name, "taken_at": fmt_ts(self.clock()), "command": list(argv), "timeout_s": BOUND_S[name]}
        self.records.append(rec)
        try:
            rc, out, err = self.run(argv, BOUND_S[name])
        except subprocess.TimeoutExpired:
            rec.update(rc=None, status="missing", code="X02")
            return None, Bad("missing", "X02", "timed out")
        except OSError:
            rec.update(rc=None, status="missing", code="X01")
            return None, Bad("missing", "X01", "could not start")
        self.raw[name] = (out, err)
        rec.update(rc=rc, raw_sha256=hashlib.sha256(out).hexdigest())
        if rc != 0:
            rec.update(status="missing", code="X03")
            return None, Bad("missing", "X03", "exit status %d" % rc)
        try:
            parsed = parse(out.decode("utf-8"))
        except UnicodeDecodeError:
            rec.update(status="unreadable", code="X04")
            return None, Bad("unreadable", "X04", "not UTF-8")
        except Bad as b:
            rec.update(status=b.kind, code=b.code)
            return None, b
        rec.update(status="ok", parsed=parsed if not isinstance(parsed, dict) or len(parsed) < 64 else
                   {"count": len(parsed)})
        return parsed, None


def _claim(receipt_path):
    """Claim the receipt path and its raw directory exclusively, before any reading. Returns (fd, raw_dir)."""
    if not runbudget.is_normal_abs(receipt_path):
        raise OSError("receipt path must be absolute and normalised")
    raw_dir = receipt_path + ".raw"
    fd = os.open(receipt_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        os.mkdir(raw_dir, 0o755)
    except OSError:
        os.close(fd)
        raise
    return fd, raw_dir


def preflight(budget_path, inventory_path, receipt_path, docker, *, run=_bounded_run, statfs=_statfs,
              stat_fn=os.stat, walker=walk_used, clock=_utc_now, monotonic=time.monotonic, pin=""):
    """One pass. Returns a Verdict; writes exactly one receipt (README 3.6). See the module docstring for limits."""
    try:
        fd, raw_dir = _claim(receipt_path)
    except OSError:
        f = Failure("receipt", "missing", "W01", "receipt path or raw directory could not be claimed exclusively")
        return Verdict(False, 77, (f,), receipt_path)
    started = clock()
    failures = []

    budget = None
    try:
        budget = runbudget.load(budget_path)
    except runbudget.BudgetError as e:
        failures.append(Failure("budget", "missing" if e.code == "B14" else "unreadable", e.code, e.where))
    policy, policy_report = resolve_policy(budget)

    inv, inv_bytes = None, b""
    try:
        with open(inventory_path, "rb") as f:
            inv_bytes = f.read()
    except OSError:
        failures.append(Failure("inventory", "missing", "N00", "inventory could not be read"))
    else:
        try:
            inv = parse_inventory(inv_bytes)
            check_inventory(inv, started, policy["inventory_max_validity_s"], budget)
        except Bad as b:
            failures.append(Failure("inventory", b.kind, b.code, b.detail))

    reader = _Reader(run, clock)
    readings = {}
    for name, parse in (("host_pressure", parse_pressure), ("host_estimate", parse_vm_stat), ("load", parse_loadavg)):
        readings[name], bad = reader.take(name, HOST_CMDS[name], parse)
        if bad and name != "load":
            failures.append(Failure(name, bad.kind, bad.code, bad.detail))
    if not runbudget.is_normal_abs(docker):
        failures.append(Failure("vm_info", "missing", "X05", "docker path is not absolute"))
        dcmds = None
    else:
        dcmds = _docker_cmds(docker)
    for name, parse in (("vm_info", parse_info), ("vm_ps", parse_ps), ("vm_stats", parse_stats)):
        if dcmds is None:
            readings[name] = None
            continue
        readings[name], bad = reader.take(name, dcmds[name], parse)
        if bad:
            failures.append(Failure(name, bad.kind, bad.code, bad.detail))
    info, ps, stats = readings.get("vm_info"), readings.get("vm_ps"), readings.get("vm_stats")
    snapshot_ok = info is not None and ps is not None and stats is not None
    if snapshot_ok and not (info["containers_running"] == len(ps) == len(stats) and set(ps) == set(stats)):
        failures.append(Failure("vm_snapshot", "inconsistent", "Z01",
                                "ContainersRunning, ps ids and stats ids disagree (no retry in v1)"))
        snapshot_ok = False
    cpu = None
    if snapshot_ok:
        if ps:
            argv = [docker, "inspect", "--format", INSPECT_FORMAT] + sorted(ps)
            cpu, bad = reader.take("vm_inspect", argv, lambda t: parse_inspect(t, info["ncpu"]))
            if bad:
                failures.append(Failure("vm_inspect", bad.kind, bad.code, bad.detail))
            elif set(cpu) != set(ps):
                failures.append(Failure("vm_inspect", "inconsistent", "Z02", "inspect ids differ from ps ids"))
                cpu = None
        else:
            cpu = {}

    if readings.get("host_pressure") is not None and readings["host_pressure"] < policy["host_pressure_free_min_pct"]:
        failures.append(Failure("host_pressure", "insufficient", "P10", "free %d%% < floor %d%%" % (
            readings["host_pressure"], policy["host_pressure_free_min_pct"])))

    attr, accounting = None, {"memory": "not_evaluated", "cpu": "not_evaluated", "disk": "not_evaluated"}
    if budget is not None and inv is not None and not any(f.reading == "inventory" for f in failures):
        if snapshot_ok:
            try:
                attr = attribute(inv, ps, budget.reservation_id)
            except Bad as b:
                failures.append(Failure("inventory", b.kind, b.code, b.detail))
        if attr is not None:
            mem = account_memory(budget, inv, info, stats, attr, policy)
            accounting["memory"] = mem
            if not mem["admit"]:
                failures.append(Failure("vm_memory", "insufficient", "E-MEM",
                                        "charged=%d total=%d" % (mem["charged"], mem["total"])))
            if cpu is not None:
                c = account_cpu(budget, inv, info, cpu, attr, policy)
                failures.extend(c.pop("refusals"))
                accounting["cpu"] = c
                if c["charged"] > c["total"] or not c["per_container_fits"]:
                    failures.append(Failure("vm_cpu", "insufficient", "E-CPU",
                                            "charged=%d total=%d" % (c["charged"], c["total"])))
        disks, dfail = account_disk(budget, inv, policy, statfs, stat_fn, walker, monotonic)
        accounting["disk"] = disks
        failures.extend(dfail)
        accounting["reservation_flags"] = reservation_flags(inv, attr, started)

    exit_code = exit_for(failures)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "module": {"sha256": _self_sha256(), "claimed_pin": pin},
        "started_at": fmt_ts(started),
        "finished_at": fmt_ts(clock()),
        "deadline": fmt_ts(started + _dt.timedelta(seconds=budget.deadline_s)) if budget else None,
        "verdict": {"admit": exit_code == 0, "exit_code": exit_code, "failures": [f.as_dict() for f in failures]},
        "decision_binding": {"inventory_generation": inv.generation if inv else None,
                             "inventory_sha256": hashlib.sha256(inv_bytes).hexdigest() if inv_bytes else None},
        "budget": {"path": budget_path, "reservation_id": budget.reservation_id if budget else None},
        "inventory": ({"path": inventory_path, "owner": list(inv.owner), "written_at": fmt_ts(inv.written_at),
                       "valid_until": fmt_ts(inv.valid_until),
                       "age_s": int((started - inv.written_at).total_seconds())} if inv else {"path": inventory_path}),
        "policy": policy_report,
        "readings": reader.records,
        "containers": _containers(ps, stats, cpu, attr, accounting),
        "accounting": accounting,
        "host_model": {"estimate_bytes": (readings.get("host_estimate") or {}).get("estimate_bytes"),
                       "compared_with": "N_mem + P_mem", "gating": False, "status": "heuristic_pending_evidence"},
        "load": readings.get("load"),
        "disclaimers": list(DISCLAIMERS),
    }
    try:
        for name, (out, err) in reader.raw.items():
            for suffix, data in (("txt", out), ("stderr.txt", err)):
                rfd = os.open(os.path.join(raw_dir, f"{name}.{suffix}"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                with os.fdopen(rfd, "wb") as f:
                    f.write(data)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(receipt, f, indent=1, sort_keys=True, default=_json_default)
            f.write("\n")
    except (OSError, TypeError, ValueError):
        failures.append(Failure("receipt", "missing", "W02", "receipt could not be written"))
        exit_code = exit_for(failures)
    return Verdict(exit_code == 0, exit_code, tuple(failures), receipt_path,
                   inv.generation if inv else None, hashlib.sha256(inv_bytes).hexdigest() if inv_bytes else "")


def _json_default(o):
    if isinstance(o, Failure):
        return o.as_dict()
    if isinstance(o, _dt.datetime):
        return fmt_ts(o)
    raise TypeError("unserialisable")


def _containers(ps, stats, cpu, attr, accounting):
    """One row per container id: identity, owner (UNVERIFIED), measured use, CPU class and the charged basis."""
    if not ps:
        return []
    basis = accounting["cpu"].get("basis", {}) if isinstance(accounting.get("cpu"), dict) else {}
    rows = []
    for cid in sorted(ps):
        a = (attr or {}).get(cid, {"owner": "unknown", "matched_by": "none", "flags": ["not_attributed"]})
        cls = cpu.get(cid) if cpu else None
        rows.append({
            "id": cid, "name": ps[cid][0], "owner": a["owner"], "owner_verification": "UNVERIFIED",
            "matched_by": a["matched_by"], "flags": a["flags"],
            "mem_use_bytes": (stats or {}).get(cid),
            "mem_basis": ("reserved:%s:max(measured,cap)" % a["owner"]) if a["owner"] != "unknown" else "foreign:U_mem",
            "cpu_class": cls[0] if cls else None, "cpu_bound_milli": cls[1] if cls else None,
            "cpu_constraints": cls[2] if cls else None, "cpu_basis": basis.get(cid),
            "cleanup_authority": "none",
        })
    return rows


def check_decision(receipt_path, inventory_path, clock=_utc_now):
    """0 when the receipt admitted, its inventory generation and sha256 are still the inventory's, AND the inventory is
    still fresh at this moment; 78 otherwise. A launcher calls it immediately before its first container.
    - A superseded decision is rejected.
    - An inventory that expired after the preflight is rejected (check_inventory's staleness rules, using the
      inventory_max_validity_s the receipt records), even when its bytes are unchanged.
    It narrows the window; it is not a lock."""
    try:
        with open(receipt_path, encoding="utf-8") as f:
            rec = json.load(f)
        with open(inventory_path, "rb") as f:
            data = f.read()
        inv = parse_inventory(data)
        max_validity = rec["policy"]["inventory_max_validity_s"]["value"]
        if not runbudget.is_int(max_validity) or max_validity < 1:
            return 78
        check_inventory(inv, clock(), max_validity)
    except (OSError, ValueError, KeyError, TypeError, Bad):
        return 78
    b = rec.get("decision_binding", {})
    ok = (rec.get("verdict", {}).get("admit") is True and b.get("inventory_generation") == inv.generation
          and b.get("inventory_sha256") == inv.sha256)
    return 0 if ok else 78


# ---- CLI -------------------------------------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(prog="capacity_gate.py", description="TXE-8043 capacity preflight (one pass)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("preflight")
    p.add_argument("--budget", required=True)
    p.add_argument("--inventory", required=True)
    p.add_argument("--receipt", required=True)
    p.add_argument("--docker", required=True)
    p.add_argument("--pin", default="")
    b = sub.add_parser("check-budget")
    b.add_argument("budget")
    i = sub.add_parser("check-inventory")
    i.add_argument("inventory")
    i.add_argument("--budget")
    d = sub.add_parser("check-decision")
    d.add_argument("receipt")
    d.add_argument("--inventory", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "preflight":
        v = preflight(a.budget, a.inventory, a.receipt, a.docker, pin=a.pin)
        for f in v.failures:
            print(f"capacitygate: {f.reading} {f.kind} {f.code} exit={f.exit_code}", file=sys.stderr)
        print(f"capacitygate: {'ADMIT' if v.admit else 'REFUSE'} exit={v.exit_code} receipt={v.receipt_path}")
        return v.exit_code
    if a.cmd == "check-budget":
        try:
            runbudget.load(a.budget)
        except runbudget.BudgetError as e:
            print(f"capacitygate: budget {e.code} {e.where}", file=sys.stderr)
            return 76
        return 0
    if a.cmd == "check-inventory":
        try:
            budget = runbudget.load(a.budget) if a.budget else None
        except runbudget.BudgetError as e:
            print(f"capacitygate: budget {e.code} {e.where}", file=sys.stderr)
            return 76
        try:
            with open(a.inventory, "rb") as f:
                inv = parse_inventory(f.read())
            values, _ = resolve_policy(budget)
            check_inventory(inv, _utc_now(), values["inventory_max_validity_s"], budget)
        except OSError:
            print("capacitygate: inventory missing N00", file=sys.stderr)
            return 78
        except Bad as e:
            print(f"capacitygate: inventory {e.kind} {e.code}", file=sys.stderr)
            return 78
        return 0
    return check_decision(a.receipt, a.inventory)


if __name__ == "__main__":
    sys.exit(main())
