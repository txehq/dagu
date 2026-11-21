# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for runbudget.py (TXE-8043). runbudget_test.go runs this file; directly:
    python3 -I -B test_runbudget.py -v

Pure: no process, no network. The only file read is the schema document beside this file. Every value is synthetic.
"""
import copy
import importlib.util
import json
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("runbudget", HERE / "runbudget.py")
R = importlib.util.module_from_spec(spec)
spec.loader.exec_module(R)

GIB = 1024 ** 3


def base():
    return {
        "schema": "txe.runbudget/v1",
        "reservation_id": "res-example-01",
        "owner": {"ticket": "TXE-1", "session": "cc0-example", "grant": "msg_000000000001"},
        "containers": {"concurrent": 1, "cpus_milli": 2000, "memory_bytes": 4 * GIB},
        "time": {"run_bound_s": 7200, "kill_after_s": 10, "cleanup_reserve_s": 45},
        "disk": [{"path": "/w/res-example-01", "need_bytes": 18 * GIB}],
        "policy": {},
    }


def refused(doc):
    try:
        R.validate(doc)
    except R.BudgetError as e:
        return e.code, e.where
    return None


class Positive(unittest.TestCase):
    def test_base_is_valid_and_derived_values_are_exact(self):
        b = R.validate(base())
        self.assertEqual(b.need_memory_bytes, 4 * GIB)
        self.assertEqual(b.need_cpus_milli, 2000)
        self.assertEqual(b.deadline_s, 7255)
        self.assertEqual(b.disk, (R.DiskNeed("/w/res-example-01", 18 * GIB),))

    def test_concurrency_multiplies_both_caps(self):
        d = base()
        d["containers"]["concurrent"] = 3
        b = R.validate(d)
        self.assertEqual((b.need_memory_bytes, b.need_cpus_milli), (12 * GIB, 6000))

    def test_every_policy_key_is_accepted_at_its_minimum(self):
        d = base()
        d["policy"] = {k: lo for k, (lo, _) in R.POLICY_KEYS.items()}
        self.assertEqual(dict(R.validate(d).policy), d["policy"])

    def test_codex_session_form_is_accepted(self):
        d = base()
        d["owner"]["session"] = "cc-codex-0123456789ab"
        R.validate(d)


class Negative(unittest.TestCase):
    def test_each_missing_key_refuses_with_its_path(self):
        cases = [((), k) for k in R.TOP_KEYS if k != "schema"]
        cases += [(("owner",), k) for k in R.OWNER_KEYS] + [(("containers",), k) for k in R.CONTAINER_KEYS]
        cases += [(("time",), k) for k in R.TIME_KEYS]
        for parents, key in cases:
            with self.subTest(parents=parents, key=key):
                d = base()
                obj = d
                for p in parents:
                    obj = obj[p]
                del obj[key]
                self.assertEqual(refused(d)[0], "B04")
        d = base()
        del d["disk"][0]["need_bytes"]
        self.assertEqual(refused(d), ("B04", "disk[0].need_bytes"))

    def test_missing_schema_and_wrong_version_refuse(self):
        d = base()
        del d["schema"]
        self.assertEqual(refused(d)[0], "B02")
        d = base()
        d["schema"] = "txe.runbudget/v2"
        self.assertEqual(refused(d)[0], "B02")

    def test_extra_keys_refuse_at_every_level(self):
        for parents in ((), ("owner",), ("containers",), ("time",), ("policy",)):
            with self.subTest(parents=parents):
                d = base()
                obj = d
                for p in parents:
                    obj = obj[p]
                obj["extra"] = 1
                self.assertEqual(refused(d)[0], "B03")
        d = base()
        d["disk"][0]["extra"] = 1
        self.assertEqual(refused(d)[0], "B03")

    def test_zero_negative_float_bool_refuse(self):
        for key in ("concurrent", "cpus_milli", "memory_bytes"):
            for bad, code in ((0, "B06"), (-1, "B06"), (1.0, "B05"), (True, "B05"), ("1", "B05")):
                with self.subTest(key=key, bad=bad):
                    d = base()
                    d["containers"][key] = bad
                    self.assertEqual(refused(d)[0], code)
        d = base()
        d["time"]["run_bound_s"] = 0
        self.assertEqual(refused(d)[0], "B06")
        d = base()
        d["disk"][0]["need_bytes"] = -1
        self.assertEqual(refused(d)[0], "B06")
        d = base()
        d["policy"] = {"host_pressure_free_min_pct": 101}
        self.assertEqual(refused(d)[0], "B06")

    def test_paths_must_be_absolute_normalised_and_unique(self):
        for bad in ("w/x", "/w/../x", "/w/./x", "/w/x/", "//w/x", "/w//x", "", "/w/\x00"):
            with self.subTest(path=bad):
                d = base()
                d["disk"][0]["path"] = bad
                self.assertEqual(refused(d)[0], "B09")
        d = base()
        d["disk"].append(dict(d["disk"][0]))
        self.assertEqual(refused(d)[0], "B10")
        d = base()
        d["disk"] = []
        self.assertEqual(refused(d)[0], "B11")

    def test_identity_patterns(self):
        for key, bad in (("ticket", "TXE-0"), ("ticket", "txe-1"), ("session", "c0-x"), ("grant", "msg_00000000000g"),
                         ("grant", "msg_123")):
            with self.subTest(key=key, bad=bad):
                d = base()
                d["owner"][key] = bad
                self.assertEqual(refused(d)[0], "B08")
        for bad in ("ab", "Res-1", "-res", "r" * 65):
            d = base()
            d["reservation_id"] = bad
            self.assertEqual(refused(d)[0], "B07")

    def test_strict_json(self):
        text = json.dumps(base())
        with self.assertRaises(R.BudgetError) as e:
            R.loads(text.replace('"policy": {}', '"policy": {}, "policy": {}'))
        self.assertEqual(e.exception.code, "B12")
        with self.assertRaises(R.BudgetError) as e:
            R.loads(text.replace('"need_bytes": 19327352832', '"need_bytes": NaN'))
        self.assertEqual(e.exception.code, "B13")
        for bad in ("[]", "not json", b"\xff"):
            with self.assertRaises(R.BudgetError) as e:
                R.loads(bad)
            self.assertEqual(e.exception.code, "B01")

    def test_unreadable_file_is_b14(self):
        with self.assertRaises(R.BudgetError) as e:
            R.load(str(HERE / "testdata-does-not-exist.json"))
        self.assertEqual(e.exception.code, "B14")

    def test_a_refusal_never_carries_a_value(self):
        sentinel = "sekrit-value-7f3a91"
        d = base()
        d["owner"]["grant"] = sentinel
        with self.assertRaises(R.BudgetError) as e:
            R.validate(d)
        self.assertNotIn(sentinel, str(e.exception))


class CapsMatch(unittest.TestCase):
    def setUp(self):
        self.b = R.validate(base())

    def test_parsers(self):
        for text, v in (("4g", 4 * GIB), ("4G", 4 * GIB), ("4096m", 4 * GIB), ("1024k", 1024 ** 2), ("512", 512),
                        ("512b", 512)):
            self.assertEqual(R.parse_docker_memory(text), v, text)
        for text in ("4.5g", "4gb", "4GiB", "0", "0g", "", " 4g", "-4g", "04g", None):
            self.assertIsNone(R.parse_docker_memory(text), text)
        for text, v in (("2", 2000), ("1.5", 1500), ("0.25", 250), ("0.001", 1), ("16.125", 16125)):
            self.assertEqual(R.parse_docker_cpus(text), v, text)
        for text in ("0", "0.0", "1.2345", ".5", "1.", "-1", "01", "", None):
            self.assertIsNone(R.parse_docker_cpus(text), text)

    def test_match(self):
        self.assertEqual(R.caps_match(self.b, {"--cpus": "2", "--memory": "4g", "--memory-swap": "4096m"}), [])

    def test_mismatches(self):
        self.assertEqual(R.caps_match(self.b, {}), ["R01", "R04"])
        self.assertEqual(R.caps_match(self.b, {"--cpus": "two", "--memory": "4.0g"}), ["R02", "R05"])
        self.assertEqual(R.caps_match(self.b, {"--cpus": "4", "--memory": "8g"}), ["R03", "R06"])
        self.assertEqual(R.caps_match(self.b, {"--cpus": "2", "--memory": "4g", "--memory-swap": "8g"}), ["R07"])
        self.assertEqual(R.caps_match(self.b, {"--cpus": "2", "--memory": "4g", "--memory-swap": "-1"}), ["R07"])


class SchemaDocument(unittest.TestCase):
    """The JSON Schema document and the validator describe the same keys and bounds."""

    def setUp(self):
        self.s = json.loads((HERE / "runbudget.v1.schema.json").read_text(encoding="utf-8"))

    def test_keys_agree(self):
        p = self.s["properties"]
        self.assertEqual(set(self.s["required"]), R.TOP_KEYS)
        self.assertEqual(set(p["owner"]["required"]), R.OWNER_KEYS)
        self.assertEqual(set(p["containers"]["required"]), R.CONTAINER_KEYS)
        self.assertEqual(set(p["time"]["required"]), R.TIME_KEYS)
        self.assertEqual(set(p["disk"]["items"]["required"]), R.DISK_KEYS)
        self.assertEqual(p["schema"]["const"], R.SCHEMA)

    def test_policy_bounds_agree(self):
        props = self.s["properties"]["policy"]["properties"]
        self.assertEqual(set(props), set(R.POLICY_KEYS))
        for k, (lo, hi) in R.POLICY_KEYS.items():
            self.assertEqual(props[k]["minimum"], lo, k)
            self.assertEqual(props[k].get("maximum"), hi, k)

    def test_patterns_agree(self):
        p = self.s["properties"]
        self.assertEqual(p["reservation_id"]["pattern"], "^" + R.RESERVATION_ID_RE.pattern + "$")
        for key, rx in (("ticket", R.TICKET_RE), ("session", R.SESSION_RE), ("grant", R.GRANT_RE)):
            self.assertEqual(p["owner"]["properties"][key]["pattern"], "^" + rx.pattern + "$")


if __name__ == "__main__":
    unittest.main()
