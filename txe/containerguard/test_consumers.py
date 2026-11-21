# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for consumers.py (TXE-8041), the AST-heuristic consumer check. containerguard_test.go runs this file; directly:
    python3 -I -B test_consumers.py -v

The fixtures are Python and shell SOURCE TEXT, parsed and never run. Temporary trees hold only that text. The last
class scans this repository's real txe/ tree (reads only).
"""
import hashlib
import importlib.util
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
spec = importlib.util.spec_from_file_location("consumers", HERE / "consumers.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)

HEAD = "import subprocess\nimport sys\nfrom argv_guard import violations\n"
ARGV = '["docker", "create", "--name", "n", "--network", "none", "img", "true"]'


def codes(src, head=HEAD):
    return [f.code for f in C.scan_python("txe/x/launch.py", head + textwrap.dedent(src))]


GOOD = f"""
def launch(schema):
    argv = {ARGV}
    bad = violations(argv, schema)
    if bad:
        raise SystemExit("refused")
    subprocess.run(argv, check=True)
"""


class Recognised(unittest.TestCase):
    def test_the_fail_closed_pattern_passes(self):
        self.assertEqual(codes(GOOD), [])

    def test_return_and_sys_exit_aborts_pass(self):
        for abort in ("return None", "sys.exit(2)", "return bad"):
            with self.subTest(abort):
                self.assertEqual(codes(GOOD.replace('raise SystemExit("refused")', abort)), [])

    def test_a_builder_in_the_same_file_passes_when_its_caller_checks(self):
        src = f"""
        def build():
            return {ARGV}

        def launch(schema):
            argv = build()
            bad = violations(argv, schema)
            if bad:
                raise RuntimeError("refused")
            subprocess.Popen(argv)
        """
        self.assertEqual(codes(src), [])

    def test_a_builder_that_extends_then_returns_its_list_is_a_builder(self):
        src = f"""
        def build(extra):
            argv = {ARGV}
            argv += extra
            return argv + ["x"]

        def launch(schema):
            argv = build([])
            bad = violations(argv, schema)
            if bad:
                raise RuntimeError("refused")
            subprocess.Popen(argv)
        """
        self.assertEqual(codes(src), [])

    def test_an_attribute_qualified_check_passes(self):
        src = GOOD.replace("violations(argv", "argv_guard.violations(argv")
        self.assertEqual(codes(src, "import subprocess\nimport argv_guard\n"), [])


class Refused(unittest.TestCase):
    """Root's named negatives, and every unsupported or ambiguous form."""

    def test_an_ignored_return_fails(self):
        self.assertEqual(codes(GOOD.replace("bad = violations(argv, schema)", "violations(argv, schema)")
                               .replace("if bad:", "if False:")), ["C04"])

    def test_validation_of_a_different_argv_fails(self):
        src = f"""
        def launch(schema):
            argv = {ARGV}
            other = list(argv)
            bad = violations(other, schema)
            if bad:
                raise SystemExit(1)
            subprocess.run(argv)
        """
        self.assertIn("C07", codes(src))

    def test_every_mutation_after_the_check_fails(self):
        for change in ('argv.append("--privileged")', 'argv += ["-v", "/:/h"]', 'argv[1] = "run"',
                       'argv = argv + ["x"]', "del argv[2]", 'argv.insert(1, "-v")', "argv.extend([])",
                       "for argv in [[]]: pass", 'alias = argv\n    alias.append("--privileged")'):
            with self.subTest(change):
                src = GOOD.replace("    subprocess.run(argv, check=True)", f"    {change}\n    subprocess.run(argv, check=True)")
                self.assertIn("C06", codes(src), change)

    def test_a_check_without_a_fail_closed_abort_fails(self):
        for body in ('print("refused")', "pass", "logging.warning(bad)"):
            with self.subTest(body):
                self.assertIn("C05", codes(GOOD.replace('raise SystemExit("refused")', body)))
        self.assertIn("C05", codes(GOOD.replace("if bad:", "if not bad:")))
        self.assertIn("C05", codes(GOOD.replace("    if bad:\n        raise SystemExit(\"refused\")\n", "")))

    def test_an_else_or_elif_on_the_abort_fails(self):
        """PR 299 review (P2): an else branch runs after a PASSING check and was not inspected."""
        tail = '        raise SystemExit("refused")\n'
        for label, branch in (("else-mutation", '    else:\n        argv.insert(1, "--privileged")\n'),
                              ("else-harmless", "    else:\n        pass\n"),
                              ("elif", "    elif schema:\n        pass\n")):
            with self.subTest(label):
                self.assertIn("C15", codes(GOOD.replace(tail, tail + branch)), label)

    def test_using_the_argv_before_its_check_fails(self):
        src = f"""
        def launch(schema):
            argv = {ARGV}
            subprocess.run(argv)
            bad = violations(argv, schema)
            if bad:
                raise SystemExit(1)
        """
        self.assertIn("C03", codes(src))

    def test_dynamic_and_unsupported_launch_forms_fail(self):
        cases = {
            "inline-list": (f"def launch():\n    subprocess.run({ARGV})\n", "C01"),
            "list-in-tuple": (f"def launch():\n    a, b = {ARGV}, 1\n    subprocess.run(a)\n", "C01"),
            "builder-inline": (f"def build():\n    return {ARGV}\n\ndef launch():\n    subprocess.run(build())\n",
                               "C02"),
            "builder-uncalled": (f"def build():\n    return {ARGV}\n", "C11"),
            "check-in-branch": (f"def launch(s, x):\n    argv = {ARGV}\n    if x:\n        bad = violations(argv, s)\n"
                                f"        if bad:\n            raise SystemExit(1)\n    subprocess.run(argv)\n", "C09"),
            "launch-in-with": (f"def launch(s):\n    argv = {ARGV}\n    with open('x') as f:\n"
                               f"        subprocess.run(argv, stdout=f)\n", "C09"),
            "checked-escapes": (f"def launch(s):\n    argv = {ARGV}\n    bad = violations(argv, s)\n    if bad:\n"
                                f"        raise SystemExit(1)\n    subprocess.run(argv)\n    return argv\n", "C12"),
            "checked-never-launched": (f"def launch(s):\n    argv = {ARGV}\n    bad = violations(argv, s)\n"
                                       f"    if bad:\n        raise SystemExit(1)\n", "C13"),
            "unused": (f"def launch():\n    argv = {ARGV}\n", "C03"),
            "unparsable": ("def launch(:\n", "C10"),
        }
        for label, (src, code) in cases.items():
            with self.subTest(label):
                self.assertIn(code, codes(src), label)

    def test_a_check_without_importing_argv_guard_fails(self):
        self.assertIn("C14", codes(GOOD, "import subprocess\n\ndef violations(a, s):\n    return []\n"))

    def test_a_shell_launch_fails_and_a_comment_does_not(self):
        self.assertEqual([f.code for f in C.scan_shell("txe/x/a.sh", "docker run --rm img\n")], ["C08"])
        self.assertEqual(C.scan_shell("txe/x/a.sh", "# docker run is described here\necho ok\n"), [])

    def test_a_list_without_a_launch_verb_or_mark_is_not_a_launcher(self):
        self.assertEqual(codes('def f():\n    a = ["--mount", "x"]\n    b = ["run", "fast"]\n    return a, b\n'), [])


def tree(files):
    d = tempfile.TemporaryDirectory()
    root = Path(d.name)
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return d, root


ROW_HEAD = "\t".join(C.REGISTRY_COLUMNS)
DIFF = "launches its own argv and checks every mount structurally; adoption is its owner's call"
RUN_PY = (f"import subprocess\n\ndef check(m):\n    pass\n\ndef go():\n    argv = {ARGV}\n"
          f"    subprocess.run(argv)\n")                      # line 6 is `def go():`, line 8 the launch, line 2 blank
FULL_REF = "txe/m/run.py:check; tested by txe/m/run_test.go:TestCheck"
SHA = hashlib.sha256(RUN_PY.encode()).hexdigest()


def row(cls="ALTERNATE_GUARD", path="txe/m/run.py", sha=SHA, ticket="TXE-7549", difference=DIFF,
        use="through its pinned launcher", refs=FULL_REF, cites="-", owner="msg_ba9876543210",
        review="msg_0123456789ab"):
    return "\t".join((cls, path, sha, ticket, difference, use, refs, cites, owner, review))


def legacy(**kw):
    base = {"cls": "LEGACY_BOUNDARY", "use": "manual-only: acceptance demonstration only", "refs": "none",
            "cites": "txe/m/run.py:6;txe/m/run.py:8"}
    base.update(kw)
    return row(**base)


class Registry(unittest.TestCase):
    """UNGUARDED.tsv: two distinct classes, each row bound to its file's exact sha256."""

    def setUp(self):
        self.d, self.root = tree({"txe/m/run.py": RUN_PY,
                                  "txe/m/run_test.go": "package m\n\nfunc TestCheck(t *testing.T) {}\n",
                                  "txe/m/clean.py": "x = 1\n"})
        self.findings = C.scan(self.root)
        self.addCleanup(self.d.cleanup)

    def check(self, *rows):
        return C.check_registry(self.root, "\n".join((ROW_HEAD,) + rows) + "\n", self.findings)

    def test_the_fixture_tree_has_one_unguarded_launcher(self):
        self.assertEqual(sorted(self.findings), ["txe/m/run.py"])

    def test_a_complete_alternate_guard_row_classifies_its_path(self):
        self.assertEqual(self.check(row()), ([], {"txe/m/run.py"}))

    def test_a_complete_legacy_boundary_row_classifies_its_path_with_none_or_partial_refs(self):
        self.assertEqual(self.check(legacy()), ([], {"txe/m/run.py"}))
        self.assertEqual(self.check(legacy(refs=f"PARTIAL(mounts only) {FULL_REF}")), ([], {"txe/m/run.py"}))

    def test_each_bad_row_is_a_problem_and_classifies_nothing(self):
        cases = {
            "free-text-review": (row(review="approved by bob"), "E03"),
            "review-name-only": (row(review="cc3"), "E03"),
            "review-pending": (legacy(review="PENDING"), "E03"),
            "owner-pending": (legacy(owner="PENDING"), "E06"),
            "short-difference": (row(difference="ok"), "E02"),
            "bad-ticket": (row(ticket="7549"), "E02"),
            "unknown-class": (row(cls="EXEMPT"), "E08"),
            "other-sha": (row(sha="0" * 64), "E09"),
            "malformed-sha": (row(sha="152b1839"), "E09"),
            "alternate-with-partial": (row(refs=f"PARTIAL(mounts only) {FULL_REF}"), "E04"),
            "alternate-with-none": (row(refs="none"), "E04"),
            "legacy-claiming-full": (legacy(refs=FULL_REF), "E04"),
            "missing-symbol": (row(refs="txe/m/run.py:nope; tested by txe/m/run_test.go:TestCheck"), "E04"),
            "missing-test": (row(refs="txe/m/run.py:check; tested by txe/m/run_test.go:TestNope"), "E04"),
            "malformed-ref": (row(refs="check_mounts"), "E04"),
            "legacy-not-manual-only": (legacy(use="used by every agent"), "E10"),
            "legacy-without-cites": (legacy(cites="-"), "E11"),
            "cite-past-the-end": (legacy(cites="txe/m/run.py:99"), "E11"),
            "cite-blank-line": (legacy(cites="txe/m/run.py:2"), "E11"),
            "cite-malformed": (legacy(cites="run.py line 6"), "E11"),
            "stale-clean-file": (row(path="txe/m/clean.py", sha=hashlib.sha256(b"x = 1\n").hexdigest()), "E05"),
            "stale-missing-file": (row(path="txe/m/gone.py"), "E05"),
            "nine-columns": ("\t".join(row().split("\t")[:9]), "E01"),
            "padded-column": (row().replace("TXE-7549", " TXE-7549"), "E01"),
        }
        for label, (r, code) in cases.items():
            with self.subTest(label):
                problems, classified = self.check(r)
                self.assertIn(code, [p.code for p in problems], label)
                self.assertEqual(classified, set(), label)

    def test_a_duplicate_row_is_a_problem(self):
        problems, _ = self.check(row(), row())
        self.assertIn("E07", [p.code for p in problems])

    def test_a_wrong_header_is_a_problem(self):
        problems, classified = C.check_registry(self.root, "path\treason\n" + row() + "\n", self.findings)
        self.assertEqual(([p.code for p in problems], classified), (["E01"], set()))

    def test_an_edit_to_the_file_invalidates_its_row(self):
        self.assertEqual(self.check(legacy())[0], [])
        (self.root / "txe/m/run.py").write_text(RUN_PY + "# edited\n")
        self.findings = C.scan(self.root)
        problems, classified = self.check(legacy())
        self.assertEqual(([p.code for p in problems], classified), (["E09"], set()))


class Repository(unittest.TestCase):
    """This repository's real txe/ tree (reads only)."""

    def test_the_scan_finds_exactly_the_two_txe_7549_launchers(self):
        found = C.scan(REPO)
        self.assertEqual(sorted(found), ["txe/mutate/fixture-demo.py", "txe/mutate/mutate-sandboxed.py"])

    def test_both_rows_are_legacy_boundaries_bound_to_the_reviewed_bytes(self):
        rows = [r.split("\t") for r in (HERE / "UNGUARDED.tsv").read_text().splitlines()]
        self.assertEqual(tuple(rows[0]), C.REGISTRY_COLUMNS)
        by_path = {r[1]: r for r in rows[1:]}
        self.assertEqual(sorted(by_path), ["txe/mutate/fixture-demo.py", "txe/mutate/mutate-sandboxed.py"])
        for path, r in by_path.items():
            self.assertEqual((r[0], r[3]), ("LEGACY_BOUNDARY", "TXE-7549"), path)
            self.assertEqual(r[2], hashlib.sha256((REPO / path).read_bytes()).hexdigest(), path)
        self.assertTrue(by_path["txe/mutate/mutate-sandboxed.py"][6].startswith("PARTIAL(mounts only) "))
        self.assertEqual(by_path["txe/mutate/fixture-demo.py"][6], "none")
        self.assertIn("demonstration boundary, not enforcement", by_path["txe/mutate/fixture-demo.py"][4])

    def test_the_reviewed_rows_pass_every_registry_check_with_their_evidence(self):
        reg = (HERE / "UNGUARDED.tsv").read_text()
        problems, classified = C.check_registry(REPO, reg, C.scan(REPO))
        self.assertEqual([str(p) for p in problems], [])
        self.assertEqual(classified, {"txe/mutate/fixture-demo.py", "txe/mutate/mutate-sandboxed.py"})
        for r in [x.split("\t") for x in reg.splitlines()[1:]]:
            self.assertEqual((r[8], r[9]), ("msg_e244f71997d3", "msg_f5d1db2e4e66"), r[1])

    def test_the_repository_passes_the_consumer_check(self):
        """The gate: every launcher validates its argv or carries a complete reviewed, hash-bound registry row."""
        self.assertEqual([str(f) for f in C.report(REPO)], [])


if __name__ == "__main__":
    unittest.main()
