# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for capacity_gate.py (TXE-8043). capacitygate_test.go runs this file; directly:
    python3 -I -B test_capacity_gate.py -v

Pure: no process is started (every command goes through a fake `run`), no network, no docker, and no walk of any real
tree except temporary directories this file creates and removes. Positive readings are the sanitized TXE-8034 S-run
fixtures in testdata/s-run (see testdata/README.md for provenance, the transform and hashes). Every inventory, budget,
docker ps / inspect row and load text is synthetic. The expected byte totals are computed by hand (README 2.6), not
by the code under test.
"""
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "runbudget"))
spec = importlib.util.spec_from_file_location("capacity_gate", HERE / "capacity_gate.py")
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)
RB = G.runbudget

GIB, MIB = 1024 ** 3, 1024 ** 2
SRUN = HERE / "testdata" / "s-run"
FIXTURE_SHA256 = {
    "memory-pressure.txt": "c7fd4162b8b3cf257fd69f23111e949861775d096566963d4d0cb3745cc0cbea",
    "vm-stat.txt": "03123980fba03bada9a13c6adbbf912b53471ab2cc3898398c51a2c39d2aeb7e",
    "docker-info.txt": "7b16f0dc4adfacd3f69a408c6f6b297019fda83a88280e96896354a1bb3d4d6e",
    "docker-stats.txt": "7fdffa03633c96acec6d3c320ac0f44946666e921e4bb66ddbb82f721eb1c466",
    "docker-ps.txt": "575fff762805636e6c0a0ad42bc40cc60e4b8f751ccf4b63361c60a5a8cb8731",
}


def cid(n):
    return ("%02x" % n) * 32


def fixture(name):
    return (SRUN / name).read_text(encoding="utf-8")


# Hand-computed from the S-run stats (ceil to whole bytes per container): README 2.6.
USE = {1: 209_086_055, 2: 205_940_327, 3: 99_048_489, 4: 18_245_223, 5: 1_297_080_124, 6: 940_048_384,
       7: 1_184_337_232}
STATS_TOTAL = 3_953_785_834
MEM_TOTAL = 33_669_160_960
CHARGED_MEM = 21_034_606_529          # correct: README 2.6
NAIVE_MEM = 22_207_396_842            # all measured + all caps
CAPONLY_MEM = 20_811_268_229          # R2 charged its cap, not its larger use
MEASONLY_MEM = 18_986_171_370         # R1 charged its idle use, not its reservation
SELFTWICE_MEM = CHARGED_MEM + 4 * GIB # the new run counted again from its pending entry
FREE_S = 199_161_080 * 1024           # the S run's df: 199161080 KiB available

NOW = dt.datetime(2026, 11, 21, 6, 2, 0, tzinfo=dt.timezone.utc)
OWNER = {"ticket": "TXE-8034", "session": "cc0-example", "grant": "msg_000000000001"}


def budget_doc():
    return {
        "schema": "txe.runbudget/v1", "reservation_id": "s-run-new", "owner": dict(OWNER),
        "containers": {"concurrent": 1, "cpus_milli": 2000, "memory_bytes": 4 * GIB},
        "time": {"run_bound_s": 7200, "kill_after_s": 10, "cleanup_reserve_s": 45},
        "disk": [{"path": "/w/s-run-new/work", "need_bytes": 18 * GIB},
                 {"path": "/private/tmp/s-run-new", "need_bytes": 1 * GIB}],
        "policy": {},
    }


def res(rid, state, cpus, mem, match, disk=(), grant="msg_000000000002"):
    return {"id": rid, "state": state, "owner": {"ticket": "TXE-1", "session": "cc0-other", "grant": grant},
            "cpus_milli": cpus, "memory_bytes": mem, "disk": [{"path": p, "cap_bytes": c} for p, c in disk],
            "match": match, "deadline": "2026-11-21T09:00:00Z"}


def inventory_doc(policy_milli=1000):
    me = res("s-run-new", "pending", 2000, 4 * GIB, {"kind": "label"},
             [("/w/s-run-new/work", 18 * GIB), ("/private/tmp/s-run-new", 1 * GIB)], grant=OWNER["grant"])
    me["owner"] = dict(OWNER)
    return {
        "schema": "txe.capacity.inventory/v1", "generation": 41,
        "owner": {"session": "cc0-coordinator", "run": "run_000000000001"},
        "written_at": "2026-11-21T06:00:00Z", "valid_until": "2026-11-21T06:10:00Z",
        "foreign_cpu_policy": ({"milli": policy_milli, "grant": "msg_000000000009", "generation": 41}
                               if policy_milli else None),
        "reservations": [
            res("r1-running", "running", 2000, 2 * GIB, {"kind": "ids", "ids": [cid(3)]}, [("/w/r1-running", 16 * GIB)]),
            res("r2-running", "running", 1000, 1 * GIB, {"kind": "ids", "ids": [cid(5)]}),
            res("p1-pending", "pending", 4000, 8 * GIB, {"kind": "label"}, [("/w/p1-pending", 16 * GIB)]),
            me,
        ],
    }


# Synthetic CPU configuration for the 7 S containers (README 5.2): known for 01/02/04/03, unlimited for 05/06/07.
INSPECT = {1: ("1000000000", "0", "0", ""), 2: ("0", "50000", "100000", ""), 3: ("2000000000", "0", "0", ""),
           4: ("0", "0", "0", "0-1"), 5: ("0", "0", "0", ""), 6: ("0", "0", "0", ""), 7: ("0", "-1", "0", "")}


def inspect_text(rows=INSPECT):
    return "".join("%s\t%s\n" % (cid(n), "\t".join(v)) for n, v in sorted(rows.items()))


def default_outputs():
    return {
        "host_pressure": (0, fixture("memory-pressure.txt")),
        "host_estimate": (0, fixture("vm-stat.txt")),
        "load": (0, "{ 3.10 2.90 2.70 }\n"),
        "vm_info": (0, fixture("docker-info.txt")),
        "vm_ps": (0, fixture("docker-ps.txt")),
        "vm_stats": (0, fixture("docker-stats.txt")),
        "vm_inspect": (0, inspect_text()),
    }


def reading_of(argv):
    if argv[0] == "/usr/bin/memory_pressure":
        return "host_pressure"
    if argv[0] == "/usr/bin/vm_stat":
        return "host_estimate"
    if argv[0] == "/usr/sbin/sysctl":
        return "load"
    return "vm_" + argv[1]


class World:
    """One preflight call with fakes for every seam."""

    def __init__(self, test):
        self.test = test
        self.dir = tempfile.mkdtemp(prefix="capgate-test-")
        test.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.budget, self.inventory = budget_doc(), inventory_doc()
        self.outputs = default_outputs()
        self.free = {7: FREE_S}
        self.walk = {("r1-running", "/w/r1-running"): (6 * GIB, [])}
        self.calls = []
        self.budget_text = self.inventory_text = None

    def run(self, argv, timeout):
        name = reading_of(argv)
        self.calls.append(name)
        out = self.outputs[name]
        if isinstance(out, BaseException):
            raise out
        rc, text = out
        return rc, text.encode("utf-8") if isinstance(text, str) else text, b""

    def statfs(self, path):
        return 7, self.free[7], 1

    def stat_fn(self, path):
        return SimpleNamespace(st_dev=7)

    def walker(self, roots, max_s, max_entries, monotonic):
        return {r: self.walk.get(r, (None, ["lookup_failed"])) for r in roots}

    def go(self, receipt=None):
        b = os.path.join(self.dir, "budget.json")
        i = os.path.join(self.dir, "inventory.json")
        with open(b, "w") as f:
            f.write(self.budget_text if self.budget_text is not None else json.dumps(self.budget))
        if self.inventory_text != "ABSENT":
            with open(i, "w") as f:
                f.write(self.inventory_text if self.inventory_text is not None else json.dumps(self.inventory))
        self.receipt_path = receipt or os.path.join(self.dir, "receipt.json")
        v = G.preflight(b, i, self.receipt_path, "/fake/docker", run=self.run, statfs=self.statfs,
                        stat_fn=self.stat_fn, walker=self.walker, clock=lambda: NOW, monotonic=lambda: 0.0)
        self.verdict = v
        return v

    def receipt(self):
        with open(self.receipt_path, encoding="utf-8") as f:
            return json.load(f)

    def kinds(self):
        return {(f.reading, f.kind) for f in self.verdict.failures}


class Fixtures(unittest.TestCase):
    def test_fixture_hashes_are_the_published_sanitized_hashes(self):
        for name, sha in FIXTURE_SHA256.items():
            self.assertEqual(hashlib.sha256((SRUN / name).read_bytes()).hexdigest(), sha, name)

    def test_public_fixtures_hold_no_internal_names(self):
        # An allowlist, so this file names nothing internal itself: every container name is ctr-NN, every id is
        # synthetic, and no fixture holds a path.
        names = [line.split("\t")[1] for line in fixture("docker-ps.txt").splitlines()]
        self.assertEqual(names, ["ctr-%02d" % n for n in range(1, 8)])
        ids = [line.split("\t")[0] for line in fixture("docker-stats.txt").splitlines()]
        self.assertEqual(ids, [cid(n) for n in range(1, 8)])
        for name in FIXTURE_SHA256:
            self.assertNotIn("/", fixture(name).replace(" / ", ""), name)


class Parsers(unittest.TestCase):
    def test_s_run_positives(self):
        self.assertEqual(G.parse_pressure(fixture("memory-pressure.txt")), 56)
        v = G.parse_vm_stat(fixture("vm-stat.txt"))
        self.assertEqual(v["estimate_bytes"], (4940 + 2332823 + 2149 + 10325) * 16384)
        self.assertEqual(v["estimate_bytes"], 38_506_283_008)
        self.assertEqual(G.parse_info(fixture("docker-info.txt")),
                         {"mem_total_bytes": MEM_TOTAL, "ncpu": 18, "containers_running": 7})
        stats = G.parse_stats(fixture("docker-stats.txt"))
        self.assertEqual(stats, {cid(n): u for n, u in USE.items()})
        self.assertEqual(sum(stats.values()), STATS_TOTAL)
        ps = G.parse_ps(fixture("docker-ps.txt"))
        self.assertEqual(ps[cid(3)], ("ctr-03", ""))
        self.assertEqual(G.parse_loadavg("{ 3.10 2.90 2.70 }\n"), ["3.10", "2.90", "2.70"])

    def test_pressure_unreadable(self):
        for text in ("", "System-wide memory free percentage: 56.5%\n", "System-wide memory free percentage: 101%\n",
                     "System-wide memory free percentage: 5%\nSystem-wide memory free percentage: 6%\n"):
            with self.assertRaises(G.Bad) as e:
                G.parse_pressure(text)
            self.assertEqual(e.exception.kind, "unreadable")

    def test_vm_stat_unreadable(self):
        good = fixture("vm-stat.txt")
        for text in (good.replace("(page size of 16384 bytes)", "(page size unknown)"),
                     good.replace("Pages purgeable:", "Pages purgable:"),
                     good + "Pages free: 1.\n"):
            with self.assertRaises(G.Bad):
                G.parse_vm_stat(text)

    def test_info_unreadable(self):
        for text in ("33669160960 18\n", "33669160960.5 18 7\n", "0 18 7\n", "1 18 7\n2 18 7\n", "a b c\n"):
            with self.assertRaises(G.Bad, msg=text):
                G.parse_info(text)

    def test_stats_units_rounding_and_unreadable(self):
        self.assertEqual(G.usage_bytes("0B"), 0)
        self.assertEqual(G.usage_bytes("1.5KiB"), 1536)
        self.assertEqual(G.usage_bytes("1kB"), 1024)
        self.assertEqual(G.usage_bytes("0.1B"), 1)              # rounded up, never down
        for tok in ("1TiB", "1.2.3MiB", "--", "1 MiB", "-1MiB", "01MiB", "MiB"):
            with self.assertRaises(G.Bad, msg=tok):
                G.usage_bytes(tok)
        with self.assertRaises(G.Bad):
            G.parse_stats(cid(1) + "\t1MiB\n")                   # no ' / '
        with self.assertRaises(G.Bad):
            G.parse_stats("ctr-01\t1MiB / 2GiB\n")              # a name, not a full id
        with self.assertRaises(G.Bad):
            G.parse_stats(cid(1) + "\t1MiB / 2GiB\n" + cid(1) + "\t1MiB / 2GiB\n")

    def test_ps_unreadable(self):
        for text in (cid(1) + "\tctr-01\n", cid(1)[:12] + "\tctr-01\t\n", cid(1) + "\t\t\n",
                     cid(1) + "\ta\t\n" + cid(1) + "\tb\t\n"):
            with self.assertRaises(G.Bad):
                G.parse_ps(text)


class CpuClassification(unittest.TestCase):
    """Root's D2 clarification 2: every applicable known constraint, then their minimum."""

    def c(self, nano=0, quota=0, period=0, cpuset="", ncpu=18):
        return G.classify_cpu(nano, quota, period, cpuset, ncpu)[:2]

    def test_known_bounds_and_rounding(self):
        self.assertEqual(self.c(nano=2_000_000_000), (G.KNOWN, 2000))
        self.assertEqual(self.c(nano=1), (G.KNOWN, 1))                       # ceil
        self.assertEqual(self.c(quota=50000, period=100000), (G.KNOWN, 500))
        self.assertEqual(self.c(quota=1, period=3), (G.KNOWN, 334))          # ceil(1000/3)
        self.assertEqual(self.c(cpuset="0-3,6"), (G.KNOWN, 5000))
        self.assertEqual(self.c(nano=40_000_000_000), (G.KNOWN, 18000))     # the VM bounds it

    def test_minimum_over_constraints_regardless_of_order(self):
        self.assertEqual(self.c(nano=3_000_000_000, cpuset="0"), (G.KNOWN, 1000))
        self.assertEqual(self.c(quota=150000, period=100000, cpuset="0-3"), (G.KNOWN, 1500))
        self.assertEqual(self.c(nano=1_000_000_000, quota=300000, period=100000), (G.KNOWN, 1000))

    def test_unknown_config_does_not_hide_a_known_bound(self):
        self.assertEqual(self.c(quota=50000, period=0), (G.UNKNOWN_CONFIG, None))
        self.assertEqual(self.c(quota=50000, period=0, cpuset="0-1"), (G.KNOWN, 2000))

    def test_unlimited(self):
        self.assertEqual(self.c(), (G.VALID_UNLIMITED, None))
        self.assertEqual(self.c(quota=-1), (G.VALID_UNLIMITED, None))
        self.assertEqual(self.c(period=100000), (G.VALID_UNLIMITED, None))

    def test_malformed(self):
        for kw in ({"nano": -1}, {"period": -1}, {"quota": -2}, {"cpuset": "3-1"}, {"cpuset": "0,0"},
                   {"cpuset": "0-2,2"}, {"cpuset": "18"}, {"cpuset": "a"}, {"cpuset": "01"}, {"cpuset": "0,"},
                   {"cpuset": " 0"}):
            with self.subTest(**kw):
                self.assertEqual(self.c(**kw)[0], G.MALFORMED)

    def test_inspect_rows(self):
        got = G.parse_inspect(inspect_text(), 18)
        self.assertEqual({k: v[:2] for k, v in got.items()},
                         {cid(1): (G.KNOWN, 1000), cid(2): (G.KNOWN, 500), cid(3): (G.KNOWN, 2000),
                          cid(4): (G.KNOWN, 2000), cid(5): (G.VALID_UNLIMITED, None),
                          cid(6): (G.VALID_UNLIMITED, None), cid(7): (G.VALID_UNLIMITED, None)})
        self.assertEqual(G.parse_inspect(cid(1) + "\t1e9\t0\t0\t\n", 18)[cid(1)][0], G.MALFORMED)
        with self.assertRaises(G.Bad):
            G.parse_inspect(cid(1) + "\t0\t0\t0\n", 18)


class Formula(unittest.TestCase):
    """README 2.6 with exact bytes, and the double-count traps."""

    def setUp(self):
        self.w = World(self)

    def test_s_run_admits_with_every_term_exact(self):
        v = self.w.go()
        self.assertTrue(v.admit, v.failures)
        self.assertEqual(v.exit_code, 0)
        acc = self.w.receipt()["accounting"]
        m = acc["memory"]
        self.assertEqual(m["terms"], {"A_mem": {"r1-running": 2 * GIB, "r2-running": USE[5]},
                                      "U_mem": USE[1] + USE[2] + USE[4] + USE[6] + USE[7],
                                      "P_mem": 8 * GIB, "N_mem": 4 * GIB, "R_vm": 2 * GIB})
        self.assertEqual(m["charged"], CHARGED_MEM)
        self.assertEqual(m["headroom"], MEM_TOTAL - CHARGED_MEM)
        c = acc["cpu"]
        self.assertEqual(c["terms"], {"A_cpu": {"r1-running": 2000, "r2-running": 1000}, "P_cpu": 4000,
                                      "F_known": 1000 + 500 + 2000, "F_policy": 2 * 1000, "unbounded_foreign": 2,
                                      "N_cpu": 2000, "R_cpu": 0})
        self.assertEqual(c["charged"], 14500)
        self.assertEqual(c["flags"], {"r2-running": ["reserved_container_unbounded"]})
        d = acc["disk"]["devices"]
        self.assertEqual(len(d), 1)
        self.assertEqual((d[0]["N_disk"], sum(d[0]["left"].values()), sum(d[0]["P_disk"].values()), d[0]["F_disk"]),
                         (19 * GIB, 10 * GIB, 16 * GIB, 2 * GIB))
        self.assertEqual(d[0]["charged"], 47 * GIB)

    def _mem_with_total(self, total_bytes):
        rc, text = self.w.outputs["vm_info"]
        self.w.outputs["vm_info"] = (0, text.replace(str(MEM_TOTAL), str(total_bytes)))
        return self.w.go()

    # The wrong implementations, written out so each trap is shown to separate them from the right one.
    @staticmethod
    def wrong_naive():
        return STATS_TOTAL + 2 * GIB + 1 * GIB + 8 * GIB + 4 * GIB + 2 * GIB

    def test_trap_wrong_variants_are_the_documented_sums(self):
        self.assertEqual(self.wrong_naive(), NAIVE_MEM)
        self.assertEqual(NAIVE_MEM - CHARGED_MEM, USE[3] + 1 * GIB)     # R1's use inside its cap + R2's cap inside its use
        self.assertEqual(CAPONLY_MEM, CHARGED_MEM - USE[5] + 1 * GIB)
        self.assertEqual(MEASONLY_MEM, CHARGED_MEM - 2 * GIB + USE[3])

    def test_trap_mem_naive_21000_mib_admits(self):
        t = 21000 * MIB
        self.assertTrue(CHARGED_MEM <= t < NAIVE_MEM)
        self.assertTrue(t < SELFTWICE_MEM)                              # also catches counting the new run twice
        self.assertTrue(self._mem_with_total(t).admit)

    def test_trap_mem_capfloor_20000_mib_refuses(self):
        t = 20000 * MIB
        self.assertTrue(CAPONLY_MEM <= t < CHARGED_MEM and MEASONLY_MEM <= t)
        v = self._mem_with_total(t)
        self.assertFalse(v.admit)
        self.assertEqual(v.exit_code, 74)
        self.assertIn(("vm_memory", "insufficient"), self.w.kinds())

    def test_trap_cpu_multi_container_reservation_counts_once(self):
        inv = self.w.inventory
        inv["reservations"][0]["match"] = {"kind": "ids", "ids": [cid(3), cid(4)]}
        rows = dict(INSPECT)
        rows[3] = rows[4] = ("1000000000", "0", "0", "")
        for n in (1, 2, 6, 7):
            rows[n] = ("0", "0", "0", "0")
        self.w.outputs["vm_inspect"] = (0, inspect_text(rows))
        self.w.outputs["vm_info"] = (0, "33669160960 13 7\n")
        # 2000 (R1 once) + 1000 (R2) + 4000 (P1) + 4 x 1000 (foreign cpusets) + 2000 (new) = 13000 of 13000.
        v = self.w.go()
        self.assertTrue(v.admit, v.failures)
        self.assertEqual(self.w.receipt()["accounting"]["cpu"]["charged"], 13000)

    def test_trap_disk_left_50_gib_admits_and_ignore_40_gib_refuses(self):
        self.w.free[7] = 50 * GIB                     # right 47 fits; full-cap 53 would not
        self.assertTrue(self.w.go().admit)
        w = World(self)
        w.free[7] = 40 * GIB                          # right 47 does not fit; ignoring R1 (37) would
        v = w.go()
        self.assertEqual(v.exit_code, 75)
        self.assertIn(("disk", "insufficient"), w.kinds())

    def test_disk_walk_failure_charges_full_remaining_cap_and_flags(self):
        self.w.walk = {("r1-running", "/w/r1-running"): (None, ["special_file"])}
        self.w.free[7] = 50 * GIB                     # 19 + 16 + 16 + 2 = 53 > 50: the fallback is conservative
        v = self.w.go()
        self.assertEqual(v.exit_code, 75)
        walks = self.w.receipt()["accounting"]["disk"]["devices"][0]["walks"]
        self.assertEqual(walks[0]["status"], "fallback_full_remaining_cap")

    def test_unknown_owner(self):
        rows = fixture("docker-ps.txt").replace(cid(6) + "\tctr-06\t", cid(6) + "\tctr-06\tghost-res")
        self.w.outputs["vm_ps"] = (0, rows)
        v = self.w.go()
        self.assertTrue(v.admit, v.failures)          # numbers alone decide; ownership never does
        rec = self.w.receipt()
        by = {c["name"]: c for c in rec["containers"]}
        self.assertEqual(by["ctr-06"]["owner"], "unknown")
        self.assertEqual(by["ctr-06"]["flags"], ["label_unregistered"])
        self.assertEqual(by["ctr-07"]["owner"], "unknown")
        self.assertEqual(by["ctr-03"]["owner"], "r1-running")
        for c in rec["containers"]:
            self.assertEqual(c["cleanup_authority"], "none")
            self.assertEqual(c["owner_verification"], "UNVERIFIED")
            self.assertTrue(c["cpu_basis"])
        self.assertEqual(rec["accounting"]["memory"]["terms"]["U_mem"], USE[1] + USE[2] + USE[4] + USE[6] + USE[7])

    def test_every_container_charged_once_per_resource(self):
        self.w.go()
        rec = self.w.receipt()
        acc = rec["accounting"]
        owners = {c["id"]: c["owner"] for c in rec["containers"]}
        mem_sum = sum(USE[n] for n in USE if owners[cid(n)] == "unknown")
        self.assertEqual(acc["memory"]["terms"]["U_mem"], mem_sum)
        self.assertEqual(set(acc["cpu"]["basis"]), {cid(n) for n in USE})
        for n in USE:
            basis = acc["cpu"]["basis"][cid(n)]
            self.assertEqual(basis.startswith("reserved:"), owners[cid(n)] != "unknown")


class CpuPolicy(unittest.TestCase):
    def setUp(self):
        self.w = World(self)

    def test_unbounded_foreign_without_policy_refuses(self):
        self.w.inventory = inventory_doc(policy_milli=None)
        v = self.w.go()
        self.assertEqual(v.exit_code, 79)
        self.assertEqual([f.code for f in v.failures if f.kind == "unbounded"], ["C11", "C11"])

    def test_policy_never_covers_unknown_config_or_malformed(self):
        rows = dict(INSPECT)
        rows[6] = ("0", "50000", "0", "")
        rows[7] = ("0", "0", "0", "9-1")
        self.w.outputs["vm_inspect"] = (0, inspect_text(rows))
        v = self.w.go()
        self.assertEqual(v.exit_code, 79)
        self.assertEqual(self.w.kinds() >= {("vm_cpu", "unknown_config"), ("vm_inspect", "malformed")}, True)

    def test_policy_must_be_positive_and_generation_bound(self):
        inv = inventory_doc()
        inv["foreign_cpu_policy"]["milli"] = 0
        self.w.inventory = inv
        self.assertEqual(self.w.go().exit_code, 78)
        w = World(self)
        w.inventory["foreign_cpu_policy"]["generation"] = 40
        self.assertEqual(w.go().exit_code, 78)
        self.assertIn(("inventory", "conflict"), w.kinds())

    def test_cpu_insufficient_and_one_container_too_big(self):
        self.w.inventory["reservations"][2]["cpus_milli"] = 15000
        v = self.w.go()
        self.assertEqual(v.exit_code, 79)
        self.assertIn(("vm_cpu", "insufficient"), self.w.kinds())
        w = World(self)
        w.budget["containers"]["cpus_milli"] = 19000
        w.inventory["reservations"][3]["cpus_milli"] = 19000
        self.assertEqual(w.go().exit_code, 79)


class ReadingMatrix(unittest.TestCase):
    """README 5.2: missing / unreadable / insufficient per reading, each with its exit code."""

    def one(self, reading, value, exit_code, kind):
        w = World(self)
        w.outputs[reading] = value
        v = w.go()
        self.assertEqual(v.exit_code, exit_code, (reading, v.failures))
        self.assertTrue(any(f.kind == kind for f in v.failures), v.failures)
        return w

    def test_missing(self):
        for reading, code in (("host_pressure", 72), ("host_estimate", 73), ("vm_info", 74), ("vm_ps", 74),
                              ("vm_stats", 74), ("vm_inspect", 79)):
            with self.subTest(reading=reading, how="rc1"):
                self.one(reading, (1, ""), code, "missing")
            with self.subTest(reading=reading, how="timeout"):
                self.one(reading, subprocess.TimeoutExpired("x", 1), code, "missing")
            with self.subTest(reading=reading, how="absent"):
                self.one(reading, FileNotFoundError(), code, "missing")

    def test_unreadable(self):
        for reading, text, code in (("host_pressure", "no line\n", 72), ("host_estimate", "Pages free: 1.\n", 73),
                                    ("vm_info", "1 2\n", 74), ("vm_ps", "x\n", 74),
                                    ("vm_stats", cid(1) + "\t1TiB / 2TiB\n", 74), ("vm_inspect", "x\n", 79)):
            with self.subTest(reading=reading):
                self.one(reading, (0, text), code, "unreadable")
        self.one("host_pressure", (0, b"\xff\n"), 72, "unreadable")

    def test_insufficient_pressure_and_boundary(self):
        self.one("host_pressure", (0, "System-wide memory free percentage: 39%\n"), 72, "insufficient")
        w = World(self)
        w.outputs["host_pressure"] = (0, "System-wide memory free percentage: 40%\n")
        self.assertTrue(w.go().admit)

    def test_host_estimate_never_gates(self):
        w = World(self)
        tiny = fixture("vm-stat.txt")
        for cls in ("free", "inactive", "speculative", "purgeable"):
            tiny = "\n".join(("Pages %s:%s1." % (cls, " " * 10)) if l.startswith("Pages %s:" % cls) else l
                             for l in tiny.split("\n"))
        w.outputs["host_estimate"] = (0, tiny)
        self.assertTrue(w.go().admit)
        hm = w.receipt()["host_model"]
        self.assertEqual((hm["estimate_bytes"], hm["gating"]), (4 * 16384, False))

    def test_load_is_recorded_never_gating(self):
        for value in ((1, ""), (0, "garbage")):
            w = World(self)
            w.outputs["load"] = value
            self.assertTrue(w.go().admit)

    def test_snapshot_inconsistency_by_full_id(self):
        w = World(self)
        w.outputs["vm_stats"] = (0, "".join(fixture("docker-stats.txt").splitlines(True)[:6]))
        self.assertEqual(w.go().exit_code, 74)
        self.assertIn(("vm_snapshot", "inconsistent"), w.kinds())
        w = World(self)
        w.outputs["vm_ps"] = (0, fixture("docker-ps.txt").replace(cid(7), cid(8)))
        self.assertEqual(w.go().exit_code, 74)
        w = World(self)
        w.outputs["vm_inspect"] = (0, inspect_text({n: v for n, v in INSPECT.items() if n != 7}))
        self.assertEqual(w.go().exit_code, 79)
        self.assertIn(("vm_inspect", "inconsistent"), w.kinds())

    def test_disk_missing(self):
        w = World(self)

        def boom(path):
            raise OSError("x")
        w.statfs = boom
        self.assertEqual(w.go().exit_code, 75)

    def test_no_read_is_ever_repeated(self):
        w = World(self)
        w.go()
        self.assertEqual(sorted(w.calls), sorted(set(w.calls)))


class Documents(unittest.TestCase):
    def test_budget_refusals(self):
        w = World(self)
        w.budget["containers"]["concurrent"] = 0
        self.assertEqual(w.go().exit_code, 76)
        w = World(self)
        w.budget_text = "{not json"
        self.assertEqual(w.go().exit_code, 76)

    def test_inventory_missing_unreadable_stale_conflict(self):
        w = World(self)
        w.inventory_text = "ABSENT"
        self.assertEqual(w.go().exit_code, 78)
        self.assertIn(("inventory", "missing"), w.kinds())
        cases = [
            (lambda d: d["reservations"].append(copy.deepcopy(d["reservations"][0])), "unreadable"),
            (lambda d: d.update(extra=1), "unreadable"),
            (lambda d: d["reservations"][1]["match"].update(ids=[cid(3)]), "conflict"),
            (lambda d: d.update(valid_until="2026-11-21T06:02:00Z"), "stale"),
            (lambda d: d.update(written_at="2026-11-21T06:03:00Z"), "stale"),
            (lambda d: d.update(written_at="2026-11-21T05:50:00Z", valid_until="2026-11-21T06:05:01Z"), "stale"),
            (lambda d: d["reservations"].pop(3), "conflict"),
            (lambda d: d["reservations"][3].update(state="running"), "conflict"),
            (lambda d: d["reservations"][3].update(memory_bytes=8 * GIB), "conflict"),
            (lambda d: d["reservations"][3]["owner"].update(grant="msg_00000000000f"), "conflict"),
            (lambda d: d["reservations"][0]["disk"][0].update(path="/w/elsewhere"), "unreadable"),
        ]
        for i, (mutate, kind) in enumerate(cases):
            with self.subTest(case=i):
                w = World(self)
                mutate(w.inventory)
                v = w.go()
                self.assertEqual(v.exit_code, 78, v.failures)
                self.assertIn(("inventory", kind), w.kinds())

    def test_attribution_conflicts(self):
        w = World(self)                                  # a pending reservation already running
        w.outputs["vm_ps"] = (0, fixture("docker-ps.txt").replace(cid(6) + "\tctr-06\t", cid(6) + "\tctr-06\tp1-pending"))
        self.assertEqual(w.go().exit_code, 78)
        w = World(self)                                  # the new run already has a container
        w.outputs["vm_ps"] = (0, fixture("docker-ps.txt").replace(cid(6) + "\tctr-06\t", cid(6) + "\tctr-06\ts-run-new"))
        v = w.go()
        self.assertEqual(v.exit_code, 78)
        self.assertEqual([f.code for f in v.failures if f.reading == "inventory"], ["A02"])

    def test_exit_precedence_and_all_failures_listed(self):
        w = World(self)
        w.budget["containers"]["concurrent"] = 0                     # 76
        w.outputs["host_pressure"] = (0, "System-wide memory free percentage: 10%\n")   # 72
        w.outputs["vm_stats"] = (1, "")                              # 74
        v = w.go()
        self.assertEqual(v.exit_code, 76)
        self.assertEqual({f.exit_code for f in v.failures}, {76, 72, 74})
        self.assertEqual(G.exit_for([G.Failure("disk", "insufficient", "D02"), G.Failure("receipt", "missing", "W02"),
                                     G.Failure("vm_cpu", "unbounded", "C11")]), 77)
        self.assertEqual(G.EXIT_ORDER, (77, 76, 78, 72, 73, 74, 79, 75))


class Receipt(unittest.TestCase):
    def test_receipt_is_exclusive(self):
        w = World(self)
        path = os.path.join(w.dir, "taken.json")
        open(path, "w").close()
        v = w.go(receipt=path)
        self.assertEqual((v.admit, v.exit_code), (False, 77))
        self.assertEqual(w.calls, [])                               # nothing was read

    def test_receipt_relative_path_refuses(self):
        w = World(self)
        self.assertEqual(w.go(receipt="relative/receipt.json").exit_code, 77)

    def test_receipt_contents(self):
        os.environ["CAPGATE_TEST_SENTINEL"] = "sekrit-env-7f3a91"
        self.addCleanup(os.environ.pop, "CAPGATE_TEST_SENTINEL", None)
        w = World(self)
        w.go()
        text = Path(w.receipt_path).read_text(encoding="utf-8")
        self.assertNotIn("sekrit-env-7f3a91", text)
        rec = json.loads(text)
        self.assertEqual(rec["schema"], "txe.capacitygate.receipt/v1")
        self.assertEqual(rec["decision_binding"]["inventory_generation"], 41)
        self.assertEqual(rec["decision_binding"]["inventory_sha256"],
                         hashlib.sha256(json.dumps(w.inventory).encode()).hexdigest())
        self.assertEqual(rec["deadline"], "2026-11-21T08:02:55Z")      # 06:02:00 + 7200 + 10 + 45 s
        self.assertEqual(rec["policy"]["vm_reserve_bytes"]["origin"], "default")
        self.assertIn("not a lease", " ".join(rec["disclaimers"]))
        self.assertEqual(sorted(os.listdir(w.receipt_path + ".raw")),
                         sorted(f"{n}.{s}" for n in default_outputs() for s in ("txt", "stderr.txt")))

    def test_budget_policy_override_is_reported_with_origin(self):
        w = World(self)
        w.budget["policy"] = {"host_pressure_free_min_pct": 30}
        w.go()
        p = w.receipt()["policy"]["host_pressure_free_min_pct"]
        self.assertEqual((p["value"], p["origin"], p["default"]), (30, "budget", 40))


class Decision(unittest.TestCase):
    def test_superseded_decision_is_rejected(self):
        w = World(self)
        self.assertTrue(w.go().admit)
        inv_path = os.path.join(w.dir, "inventory.json")
        self.assertEqual(G.check_decision(w.receipt_path, inv_path, clock=lambda: NOW), 0)
        w.inventory["generation"] = 42
        w.inventory["foreign_cpu_policy"]["generation"] = 42
        with open(inv_path, "w") as f:
            f.write(json.dumps(w.inventory))
        self.assertEqual(G.check_decision(w.receipt_path, inv_path, clock=lambda: NOW), 78)

    def test_an_inventory_that_expired_after_the_preflight_is_rejected_with_unchanged_bytes(self):
        w = World(self)
        self.assertTrue(w.go().admit)                                  # preflight at 06:02:00; valid_until 06:10:00
        inv_path = os.path.join(w.dir, "inventory.json")
        before = Path(inv_path).read_bytes()
        at = lambda h, m, s: (lambda: dt.datetime(2026, 11, 21, h, m, s, tzinfo=dt.timezone.utc))  # noqa: E731
        self.assertEqual(G.check_decision(w.receipt_path, inv_path, clock=at(6, 9, 59)), 0)
        self.assertEqual(G.check_decision(w.receipt_path, inv_path, clock=at(6, 10, 0)), 78)   # now >= valid_until
        self.assertEqual(G.check_decision(w.receipt_path, inv_path, clock=at(5, 59, 59)), 78)  # written_at in future
        self.assertEqual(Path(inv_path).read_bytes(), before)          # the same bytes throughout

    def test_a_receipt_without_a_usable_validity_policy_is_rejected(self):
        w = World(self)
        self.assertTrue(w.go().admit)
        inv_path = os.path.join(w.dir, "inventory.json")
        rec = w.receipt()
        rec["policy"]["inventory_max_validity_s"]["value"] = "900"
        bad = os.path.join(w.dir, "receipt-bad.json")
        with open(bad, "w") as f:
            json.dump(rec, f)
        self.assertEqual(G.check_decision(bad, inv_path, clock=lambda: NOW), 78)
        del rec["policy"]
        with open(bad, "w") as f:
            json.dump(rec, f)
        self.assertEqual(G.check_decision(bad, inv_path, clock=lambda: NOW), 78)


class Walk(unittest.TestCase):
    """The default walker, over temporary trees this test creates (no other tree is walked)."""

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="capgate-walk-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def mk(self, rel, size):
        p = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(b"x" * size)
        return p

    def test_hardlinks_and_overlap_count_once_symlinks_not_followed(self):
        a = self.mk("r1/a.bin", 65536)
        os.link(a, os.path.join(self.root, "r1", "a-link.bin"))
        os.symlink("/", os.path.join(self.root, "r1", "escape"))
        os.makedirs(os.path.join(self.root, "r1", "sub"))
        r1 = os.path.join(self.root, "r1")
        out = G.walk_used([("r1", r1), ("r1b", os.path.join(r1, "sub"))], 30, 1000)
        used, flags = out[("r1", r1)]
        blocks = os.lstat(a).st_blocks * 512
        self.assertGreaterEqual(used, blocks)
        self.assertLess(used, 2 * blocks + 3 * 65536)        # the hard link is not counted twice
        self.assertIn("symlink_not_followed", flags)
        self.assertEqual(out[("r1b", os.path.join(r1, "sub"))][0], 0)   # already counted under r1

    def test_root_symlink_special_file_and_bounds_fail_to_full_cap(self):
        os.makedirs(os.path.join(self.root, "real"))
        os.symlink(os.path.join(self.root, "real"), os.path.join(self.root, "link"))
        out = G.walk_used([("x", os.path.join(self.root, "link"))], 30, 1000)
        self.assertEqual(out[("x", os.path.join(self.root, "link"))], (None, ["root_not_a_real_directory"]))
        os.mkfifo(os.path.join(self.root, "real", "fifo"))
        out = G.walk_used([("x", os.path.join(self.root, "real"))], 30, 1000)
        self.assertEqual(out[("x", os.path.join(self.root, "real"))][0], None)
        for i in range(3):
            self.mk(f"many/{i}", 1)
        out = G.walk_used([("x", os.path.join(self.root, "many"))], 30, 2)
        self.assertEqual(out[("x", os.path.join(self.root, "many"))], (None, ["entry_bound"]))
        ticks = iter([0.0, 100.0, 100.0, 100.0])
        out = G.walk_used([("x", os.path.join(self.root, "many"))], 30, 1000, monotonic=lambda: next(ticks))
        self.assertEqual(out[("x", os.path.join(self.root, "many"))], (None, ["time_bound"]))
        out = G.walk_used([("x", os.path.join(self.root, "absent"))], 30, 1000)
        self.assertEqual(out[("x", os.path.join(self.root, "absent"))], (None, ["lookup_failed"]))

    def racing_open(self, victim, swap):
        """An os.open that runs `swap()` just before it opens the directory named `victim`: the window between the
        walk listing a directory and opening it."""
        real = os.open
        done = []

        def opener(name, flags, *args, dir_fd=None, **kw):
            if not done and os.path.basename(name) == victim:
                done.append(1)
                swap()
            return real(name, flags, *args, dir_fd=dir_fd, **kw) if dir_fd is not None else real(name, flags)
        return opener

    def test_a_directory_swapped_for_a_symlink_mid_walk_is_not_followed_and_fails_closed(self):
        claim = os.path.join(self.root, "claim")
        os.makedirs(os.path.join(claim, "sub"))
        self.mk("elsewhere/big.bin", 262144)                 # blocks the walk must never count as the claim's

        def swap():
            os.rmdir(os.path.join(claim, "sub"))
            os.symlink(os.path.join(self.root, "elsewhere"), os.path.join(claim, "sub"))
        out = G.walk_used([("c", claim)], 30, 1000, _open=self.racing_open("sub", swap))
        self.assertEqual(out[("c", claim)], (None, ["open_refused"]))   # O_NOFOLLOW refuses it; the full cap is charged

    def test_a_directory_replaced_mid_walk_fails_closed_on_identity(self):
        claim = os.path.join(self.root, "claim")
        os.makedirs(os.path.join(claim, "sub"))
        self.mk("claim/sub/a.bin", 1)

        def swap():
            os.rename(os.path.join(claim, "sub"), os.path.join(self.root, "sub-moved"))
            os.makedirs(os.path.join(claim, "sub"))
        out = G.walk_used([("c", claim)], 30, 1000, _open=self.racing_open("sub", swap))
        self.assertEqual(out[("c", claim)], (None, ["identity_changed"]))

    def test_a_root_replaced_before_it_is_opened_fails_closed(self):
        claim = os.path.join(self.root, "claim")
        os.makedirs(claim)

        def swap():
            os.rename(claim, os.path.join(self.root, "claim-moved"))
            os.makedirs(claim)
        out = G.walk_used([("c", claim)], 30, 1000, _open=self.racing_open("claim", swap))
        self.assertEqual(out[("c", claim)], (None, ["identity_changed"]))


class DiskSampling(unittest.TestCase):
    """Free space is sampled before AND after the walks, and the smaller sample is used (review finding on 6d7e229f)."""

    def world(self, before, after):
        w = World(self)
        calls = []

        def statfs(path):
            calls.append(path)
            return 7, (before if len(calls) <= len(w.budget["disk"]) else after), 1
        w.statfs = statfs
        return w, calls

    def test_blocks_written_during_the_walk_are_not_counted_as_free(self):
        # The reviewer's example: 50 GiB free before; r1's 16 GiB claim fills during the walk, so the walk sees
        # used = 16 GiB (left 0) and only 34 GiB is free after. 19 + 0 + 16 + 2 = 37 GiB fits 50 but not 34.
        w, calls = self.world(50 * GIB, 34 * GIB)
        w.walk = {("r1-running", "/w/r1-running"): (16 * GIB, [])}
        v = w.go()
        self.assertEqual(v.exit_code, 75)
        self.assertEqual(len(calls), 4)                                  # 2 budget paths x 2 samples
        self.assertIn(("disk", "insufficient"), w.kinds())
        dev = w.receipt()["accounting"]["disk"]["devices"][0]
        self.assertEqual((dev["free_before"], dev["free_after"], dev["free"], dev["charged"]),
                         (50 * GIB, 34 * GIB, 34 * GIB, 37 * GIB))

    def test_the_smaller_sample_is_used_and_both_are_recorded(self):
        w, _ = self.world(50 * GIB, 60 * GIB)                            # space freed during the walk is not credited
        self.assertTrue(w.go().admit)
        dev = w.receipt()["accounting"]["disk"]["devices"][0]
        self.assertEqual((dev["free_before"], dev["free_after"], dev["free"]), (50 * GIB, 60 * GIB, 50 * GIB))

    def test_a_failed_or_moved_second_sample_fails_closed(self):
        w = World(self)
        calls = []

        def fails_second(path):
            calls.append(path)
            if len(calls) > 2:
                raise OSError("gone")
            return 7, FREE_S, 1
        w.statfs = fails_second
        v = w.go()
        self.assertEqual(v.exit_code, 75)
        self.assertEqual({f.code for f in v.failures if f.reading == "disk"}, {"D03"})
        w = World(self)
        calls2 = []

        def moves(path):
            calls2.append(path)
            return (7 if len(calls2) <= 2 else 8), FREE_S, 1
        w.statfs = moves
        v = w.go()
        self.assertEqual(v.exit_code, 75)
        self.assertEqual({f.code for f in v.failures if f.reading == "disk"}, {"D04"})
        w = World(self)
        calls3 = []

        def remounted(path):                                     # same st_dev, a different filesystem id
            calls3.append(path)
            return 7, FREE_S, (1 if len(calls3) <= 2 else 2)
        w.statfs = remounted
        v = w.go()
        self.assertEqual(v.exit_code, 75)
        self.assertEqual({f.code for f in v.failures if f.reading == "disk"}, {"D04"})


class ReservedId(unittest.TestCase):
    """'unknown' is the owner capacitygate reports for an unattributed container, so no reservation may take it."""

    def test_a_budget_named_unknown_is_refused(self):
        w = World(self)
        w.budget["reservation_id"] = "unknown"
        w.budget["disk"] = [{"path": "/w/unknown/work", "need_bytes": 18 * GIB}]
        self.assertEqual(w.go().exit_code, 76)

    def test_an_inventory_reservation_named_unknown_is_refused(self):
        w = World(self)
        w.inventory["reservations"][1]["id"] = "unknown"
        v = w.go()
        self.assertEqual(v.exit_code, 78)
        self.assertEqual([f.code for f in v.failures if f.reading == "inventory"], ["N10"])


if __name__ == "__main__":
    unittest.main()
