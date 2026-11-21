# SPDX-License-Identifier: GPL-3.0-or-later
"""The run budget, `txe.runbudget/v1`: one container run's declared caps, as a data contract (TXE-8043).

A budget is a small JSON document that a launcher writes once per run, from the same values it puts into the
container argv. Two guards read it, and neither imports the other:
- txe/capacitygate checks the budget against the measured Mac and the coordinator's reservation inventory;
- txe/containerguard's argv_guard (or any runner) can compare it with its own argv through `caps_match`, which takes a
  plain {option: value} mapping such as argv_guard's `Schema.single`.

This module is pure: stdlib only, no process, no network, no file written. `load` reads one file.

Versioning: unknown and missing keys refuse, so any added, removed or re-meant field is a new schema string
(`txe.runbudget/v2`), never a silent extension. v1 is frozen once merged. A reader accepts exactly the versions it names.
"""
import json
import posixpath
import re
from dataclasses import dataclass

SCHEMA = "txe.runbudget/v1"

RESERVATION_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,63}")
TICKET_RE = re.compile(r"TXE-[1-9][0-9]*")
SESSION_RE = re.compile(r"cc[0-9]*-[a-z0-9][a-z0-9._-]{0,63}")
GRANT_RE = re.compile(r"msg_[0-9a-f]{12}")

# Policy keys a budget may set. Each is (minimum, maximum or None). capacitygate owns their defaults and lineage; a
# budget value is reported with origin "budget" beside the default it replaced.
POLICY_KEYS = {
    "host_pressure_free_min_pct": (0, 100),
    "vm_reserve_bytes": (0, None),
    "vm_cpu_reserve_milli": (0, None),
    "disk_floor_bytes": (0, None),
    "inventory_max_validity_s": (1, None),
    "disk_walk_max_s": (1, None),
    "disk_walk_max_entries": (1, None),
}

TOP_KEYS = {"schema", "reservation_id", "owner", "containers", "time", "disk", "policy"}
OWNER_KEYS = {"ticket", "session", "grant"}
CONTAINER_KEYS = {"concurrent", "cpus_milli", "memory_bytes"}
TIME_KEYS = {"run_bound_s", "kill_after_s", "cleanup_reserve_s"}
DISK_KEYS = {"path", "need_bytes"}

# Stable codes. A BudgetError carries one code and the JSON path of the field, never a field's value.
CODES = {
    "B01": "not a JSON object, or not valid JSON",
    "B02": "schema is not txe.runbudget/v1",
    "B03": "unknown key",
    "B04": "missing key",
    "B05": "wrong type (an integer must be a JSON integer, not a bool or a float)",
    "B06": "integer out of range",
    "B07": "reservation_id does not match ^[a-z0-9][a-z0-9._-]{2,63}$",
    "B08": "owner field does not match its pattern",
    "B09": "disk path is not absolute and normalised",
    "B10": "disk path repeated",
    "B11": "disk list is empty",
    "B12": "duplicate key in a JSON object",
    "B13": "non-finite number",
    "B14": "the file could not be read",
}


class BudgetError(ValueError):
    """A refused budget: a CODES key and the JSON path of the field. No value is ever included."""

    def __init__(self, code, where=""):
        super().__init__(f"{code} {where}".strip())
        self.code = code
        self.where = where


@dataclass(frozen=True)
class DiskNeed:
    path: str
    need_bytes: int


@dataclass(frozen=True)
class Budget:
    reservation_id: str
    owner: tuple                 # (ticket, session, grant)
    concurrent: int
    cpus_milli: int              # per container
    memory_bytes: int            # per container
    run_bound_s: int
    kill_after_s: int
    cleanup_reserve_s: int
    disk: tuple                  # of DiskNeed, in file order
    policy: tuple                # sorted (key, value) pairs the budget set

    @property
    def need_memory_bytes(self):
        return self.concurrent * self.memory_bytes

    @property
    def need_cpus_milli(self):
        return self.concurrent * self.cpus_milli

    @property
    def deadline_s(self):
        """Seconds from the gate's start that this run claims, its cleanup included. It reserves nothing."""
        return self.run_bound_s + self.kill_after_s + self.cleanup_reserve_s


def is_normal_abs(p):
    return (isinstance(p, str) and p.startswith("/") and "\x00" not in p and posixpath.normpath(p) == p
            and not p.startswith("//"))


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _no_dupes(pairs):
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise BudgetError("B12", k)
        seen[k] = v
    return seen


def _no_constants(name):
    raise BudgetError("B13", name)


def parse_json(text):
    """Strict JSON: duplicate keys and NaN/Infinity refuse."""
    try:
        return json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_no_constants)
    except BudgetError:
        raise
    except (ValueError, TypeError):
        raise BudgetError("B01") from None


def _keys(obj, allowed, where):
    if not isinstance(obj, dict):
        raise BudgetError("B05", where)
    for k in sorted(obj):
        if k not in allowed:
            raise BudgetError("B03", f"{where}.{k}" if where else k)
    for k in sorted(allowed):
        if k not in obj:
            raise BudgetError("B04", f"{where}.{k}" if where else k)


def _int(obj, key, where, lo, hi=None):
    v = obj[key]
    if not is_int(v):
        raise BudgetError("B05", f"{where}.{key}")
    if v < lo or (hi is not None and v > hi):
        raise BudgetError("B06", f"{where}.{key}")
    return v


def validate(doc):
    """Return a Budget, or raise BudgetError. `doc` is the parsed JSON value."""
    if not isinstance(doc, dict):
        raise BudgetError("B01")
    if doc.get("schema") != SCHEMA:
        raise BudgetError("B02", "schema")
    _keys(doc, TOP_KEYS, "")
    rid = doc["reservation_id"]
    if not isinstance(rid, str) or not RESERVATION_ID_RE.fullmatch(rid):
        raise BudgetError("B07", "reservation_id")
    owner = doc["owner"]
    _keys(owner, OWNER_KEYS, "owner")
    for key, rx in (("ticket", TICKET_RE), ("session", SESSION_RE), ("grant", GRANT_RE)):
        if not isinstance(owner[key], str) or not rx.fullmatch(owner[key]):
            raise BudgetError("B08", f"owner.{key}")
    c = doc["containers"]
    _keys(c, CONTAINER_KEYS, "containers")
    concurrent = _int(c, "concurrent", "containers", 1)
    cpus = _int(c, "cpus_milli", "containers", 1)
    mem = _int(c, "memory_bytes", "containers", 1)
    t = doc["time"]
    _keys(t, TIME_KEYS, "time")
    run_bound = _int(t, "run_bound_s", "time", 1)
    kill_after = _int(t, "kill_after_s", "time", 0)
    cleanup = _int(t, "cleanup_reserve_s", "time", 0)
    disk = doc["disk"]
    if not isinstance(disk, list):
        raise BudgetError("B05", "disk")
    if not disk:
        raise BudgetError("B11", "disk")
    needs, seen = [], set()
    for i, d in enumerate(disk):
        where = f"disk[{i}]"
        _keys(d, DISK_KEYS, where)
        if not is_normal_abs(d["path"]):
            raise BudgetError("B09", f"{where}.path")
        if d["path"] in seen:
            raise BudgetError("B10", f"{where}.path")
        seen.add(d["path"])
        needs.append(DiskNeed(d["path"], _int(d, "need_bytes", where, 0)))
    pol = doc["policy"]
    if not isinstance(pol, dict):
        raise BudgetError("B05", "policy")
    for k in sorted(pol):
        if k not in POLICY_KEYS:
            raise BudgetError("B03", f"policy.{k}")
        lo, hi = POLICY_KEYS[k]
        _int(pol, k, "policy", lo, hi)
    return Budget(rid, (owner["ticket"], owner["session"], owner["grant"]), concurrent, cpus, mem, run_bound,
                  kill_after, cleanup, tuple(needs), tuple(sorted(pol.items())))


def loads(data):
    """Validate budget bytes or text."""
    if isinstance(data, bytes):
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError:
            raise BudgetError("B01") from None
    return validate(parse_json(data))


def load(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        raise BudgetError("B14") from None
    return loads(data)


# ---- the argv tie, with no import of any guard ------------------------------------------------------------------

_MEM_RE = re.compile(r"(0|[1-9][0-9]*)([bkmgBKMG]?)")
_MEM_MULT = {"": 1, "b": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}
_CPUS_RE = re.compile(r"(0|[1-9][0-9]*)(?:\.([0-9]{1,3}))?")


def parse_docker_memory(text):
    """Docker `--memory` as integer bytes, or None. Accepts an integer with an optional b/k/m/g suffix (any case,
    binary multipliers). Anything else, decimals and two-letter suffixes included, is None: never a guess."""
    if not isinstance(text, str):
        return None
    m = _MEM_RE.fullmatch(text)
    if not m:
        return None
    v = int(m.group(1)) * _MEM_MULT[m.group(2).lower()]
    return v if v > 0 else None


def parse_docker_cpus(text):
    """Docker `--cpus` as integer millicpus, or None. `2` is 2000 and `1.5` is 1500; more than 3 decimals is None."""
    if not isinstance(text, str):
        return None
    m = _CPUS_RE.fullmatch(text)
    if not m:
        return None
    frac = (m.group(2) or "").ljust(3, "0")
    v = int(m.group(1)) * 1000 + int(frac)
    return v if v > 0 else None


CAPS_CODES = {
    "R01": "--cpus absent from the argv options",
    "R02": "--cpus unreadable",
    "R03": "--cpus differs from the budget's cpus_milli",
    "R04": "--memory absent from the argv options",
    "R05": "--memory unreadable",
    "R06": "--memory differs from the budget's memory_bytes",
    "R07": "--memory-swap present and unreadable or not equal to --memory",
}


def caps_match(budget, single):
    """Redacted codes (CAPS_CODES keys) where the argv's per-container caps disagree with the budget; [] when they
    agree. `single` is a plain {option: value} mapping. No value is ever returned."""
    bad = []
    cpus = single.get("--cpus")
    if cpus is None:
        bad.append("R01")
    elif parse_docker_cpus(cpus) is None:
        bad.append("R02")
    elif parse_docker_cpus(cpus) != budget.cpus_milli:
        bad.append("R03")
    mem = single.get("--memory")
    mem_v = None
    if mem is None:
        bad.append("R04")
    else:
        mem_v = parse_docker_memory(mem)
        if mem_v is None:
            bad.append("R05")
        elif mem_v != budget.memory_bytes:
            bad.append("R06")
    if "--memory-swap" in single:
        swap = parse_docker_memory(single["--memory-swap"])
        if swap is None or mem_v is None or swap != mem_v:
            bad.append("R07")
    return bad
