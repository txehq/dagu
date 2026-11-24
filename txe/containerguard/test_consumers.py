# SPDX-License-Identifier: GPL-3.0-or-later
"""Tests for consumers.py (TXE-8041), the AST-heuristic consumer check. containerguard_test.go runs this file; directly:
    python3 -I -B test_consumers.py -v

The fixtures are Python and shell SOURCE TEXT, parsed and never run. Temporary trees hold only that text. The last
class scans this repository's real txe/ tree (reads only). One exception: the README's supported recipe is executed
against the real argv_guard, with a fake `subprocess` that records its call (no process is ever started) and an
import hook that resolves only the recipe's two imports. Its filesystem check reads a fresh work dir the test makes
with tempfile.mkdtemp (and a symbolic link to it, only lstat'd), removed afterwards.
"""
import ast
import builtins
import dataclasses
import hashlib
import importlib.util
import os
import shutil
import types
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
spec = importlib.util.spec_from_file_location("consumers", HERE / "consumers.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)

HEAD = "import subprocess\nimport sys\nfrom txe.containerguard.argv_guard import check_mount_sources, violations\n"
PKG_AS = "import subprocess\nimport txe.containerguard.argv_guard as argv_guard\n"
ARGV = '["docker", "create", "--name", "n", "--network", "none", "img", "true"]'


def codes(src, head=HEAD):
    return [f.code for f in C.scan_python("txe/x/launch.py", head + textwrap.dedent(src))]


# C22: the filesystem floor, right after the argv check's abort. Its abort's text differs from the argv check's, so a
# test that replaces `raise SystemExit("refused")` changes the argv check's abort only.
FS = '    fs = check_mount_sources(schema)\n    if fs:\n        raise SystemExit("mounts refused")\n'
GOOD = f"""
def launch(schema):
    argv = {ARGV}
    bad = violations(argv, schema)
    if bad:
        raise SystemExit("refused")
{FS}    subprocess.run(argv, check=True)
"""


def qualify(src, prefix):
    """src with both guard calls spelled through prefix ("g.", "txe.containerguard.argv_guard.", or "")."""
    return src.replace("violations(argv", prefix + "violations(argv").replace(
        "check_mount_sources(schema)", prefix + "check_mount_sources(schema)")


GUARDED = qualify(GOOD, "argv_guard.")    # GOOD through `import … as argv_guard`


def readme_recipe():
    """The README's supported-recipe block, as source text."""
    text = (HERE / "README.md").read_text()
    start = text.index("```python\n# The supported recipe") + len("```python\n")
    return text[start:text.index("```", start)]


class Recognised(unittest.TestCase):
    def test_the_fail_closed_pattern_passes(self):
        self.assertEqual(codes(GOOD), [])

    def test_return_and_raise_aborts_pass(self):
        for abort in ("return None", "raise SystemExit(2)", "return bad"):
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
            fs = check_mount_sources(schema)
            if fs:
                raise RuntimeError("mounts refused")
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
            fs = check_mount_sources(schema)
            if fs:
                raise RuntimeError("mounts refused")
            subprocess.Popen(argv)
        """
        self.assertEqual(codes(src), [])

    def test_an_attribute_qualified_check_passes(self):
        src = GUARDED
        self.assertEqual(codes(src, "import subprocess\nimport txe.containerguard.argv_guard as argv_guard\n"), [])


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

    def test_a_python_shell_or_string_docker_launch_fails(self):
        """PR 299 review (P2): subprocess.run("docker run …", shell=True) produced no finding. Every recognised
        shell, string, -c or exec/spawn launch that names docker is C16, through any import alias."""
        cases = {
            "run-shell-string": 'import subprocess\n'
                                'subprocess.run("docker run --privileged alpine true", shell=True)\n',
            "run-shell-list": 'import subprocess\nsubprocess.run(["docker", "run", "alpine"], shell=True)\n',
            "run-args-keyword": 'import subprocess\nsubprocess.run(args="docker run x", shell=True)\n',
            "dynamic-shell-flag": 'import subprocess\n\ndef f(flag):\n'
                                  '    subprocess.run(["docker", "ps"], shell=flag)\n',
            "os-system": 'import os\nos.system("docker run alpine")\n',
            "os-popen-fstring": 'import os\nx = "a"\nos.popen(f"docker run {x}")\n',
            "module-alias": 'import subprocess as sp\nsp.call("docker create x", shell=True)\n',
            "from-import": 'from subprocess import check_output\ncheck_output("docker run x", shell=True)\n',
            "from-import-as": 'from os import system as sh\nsh("docker run x")\n',
            "asyncio-shell": 'import asyncio\n\nasync def f():\n'
                             '    await asyncio.create_subprocess_shell("docker run x")\n',
            "asyncio-subprocess-alias": 'from asyncio import subprocess as asp\n\nasync def f():\n'
                                        '    await asp.create_subprocess_shell("docker run x")\n',
            "asyncio-exec": 'import asyncio\n\nasync def f():\n'
                            '    await asyncio.create_subprocess_exec("docker", "run", "x")\n',
            "os-exec": 'import os\nos.execvp("docker", ["docker", "run", "x"])\n',
            "sh-dash-c-list": 'import subprocess\nsubprocess.run(["sh", "-c", "docker run x"])\n',
            "bash-path-dash-c-list": 'import subprocess\nsubprocess.run(["/bin/bash", "-c", "docker run x"])\n',
            "string-no-shell": 'import subprocess\nsubprocess.Popen("docker")\n',
            "dynamic-name-shell": 'import subprocess\ncmd = "docker run " + "x"\nsubprocess.run(cmd, shell=True)\n',
            "dynamic-fstring-no-shell": 'import subprocess\n\ndef f(y):\n    cmd = f"docker run {y}"\n'
                                        '    subprocess.run(cmd)\n',
        }
        cases["for-loop-shell"] = ('import subprocess\nfor c in ["docker run a", "docker run b"]:\n'
                                   '    subprocess.run(c, shell=True)\n')
        self.assertEqual(len(cases), 19)
        for label, src in cases.items():
            with self.subTest(label):
                self.assertIn("C16", codes(src, head=""), label)

    def test_forms_outside_c16_stay_clean(self):
        """C16's stated scope: a shell string with no docker word, and a docker list without a shell, are not C16;
        a guarded argv whose PAYLOAD runs `/bin/sh -c` (as the runners' does) is not a shell launch."""
        payload_argv = '["docker", "create", "--name", "n", "--network", "none", "img", "/bin/sh", "-c", "true"]'
        cases = {
            "non-docker-shell": 'import subprocess\nsubprocess.run("ls -l", shell=True)\n',
            "docker-list-no-shell": 'import subprocess\nsubprocess.run(["docker", "ps"])\n',
            "docker-list-shell-false": 'import subprocess\nsubprocess.run(["docker", "ps"], shell=False)\n',
            "guarded-argv-with-sh-c-payload": HEAD + textwrap.dedent(GOOD.replace(ARGV, payload_argv)),
            # PR 299 CG-r5: an item or attribute assignment on a name elsewhere is not a string bound to that name
            "item-assigned-argv-elsewhere": HEAD + textwrap.dedent(GOOD) + '\ndef other(argv):\n    argv[2] = "n2"\n',
            "attribute-on-argv-elsewhere": HEAD + textwrap.dedent(GOOD) +
                                           '\ndef other(argv):\n    argv.text = "docker run x"\n',
        }
        for label, src in cases.items():
            with self.subTest(label):
                self.assertEqual(codes(src, head=""), [], label)

    def test_a_list_without_a_launch_verb_or_mark_is_not_a_launcher(self):
        self.assertEqual(codes('def f():\n    a = ["--mount", "x"]\n    b = ["run", "fast"]\n    return a, b\n'), [])


class FilesystemRule(unittest.TestCase):
    """C22 (PR 299 security review of cdb78d1d): a launcher must run argv_guard's check_mount_sources on the check's
    schema, with a fail-closed abort, right after the argv check's abort. An optional helper would leave the symlinked
    bind source accepted for every new consumer that omits it. Inert source, parsed only."""

    def test_the_filesystem_check_must_follow_the_argv_check(self):
        launch = "    subprocess.run(argv, check=True)\n"
        cases = {
            "omitted": GOOD.replace(FS, ""),
            "result-ignored": GOOD.replace(FS, "    check_mount_sources(schema)\n"),
            "after-the-launch": GOOD.replace(FS, "").replace(launch, launch + FS),
            "before-the-argv-check": GOOD.replace(FS, "").replace("    bad = violations", FS + "    bad = violations"),
            "statement-between": GOOD.replace(FS, '    log("checked")\n' + FS),
            "other-schema": GOOD.replace("def launch(schema):", "def launch(schema, other):").replace(
                "check_mount_sources(schema)", "check_mount_sources(other)"),
            "keyword-schema": GOOD.replace("check_mount_sources(schema)", "check_mount_sources(schema=schema)"),
            "no-abort": GOOD.replace('raise SystemExit("mounts refused")', "print(fs)"),
            "abort-with-a-call": GOOD.replace('raise SystemExit("mounts refused")',
                                              "raise SystemExit(subprocess.run(argv))"),
            "inverted-test": GOOD.replace("    if fs:", "    if not fs:"),
            "else-branch": GOOD.replace('        raise SystemExit("mounts refused")\n',
                                        '        raise SystemExit("mounts refused")\n    else:\n        pass\n'),
            "result-reassigned-test": GOOD.replace("    if fs:", "    if bad:"),
        }
        for label, src in cases.items():
            with self.subTest(label):
                self.assertIn("C22", codes(src), label)

    def test_a_filesystem_check_not_bound_to_argv_guard_fails(self):
        local = "import subprocess\nfrom txe.containerguard.argv_guard import violations\n\n" \
                "def check_mount_sources(s):\n    return []\n"
        cases = {
            "local-definition": (local, GOOD, "C22"),
            "other-module": ("import subprocess\nfrom txe.containerguard.argv_guard import violations\n"
                             "from fake_guard import check_mount_sources\n", GOOD, "C22"),
            "passed-as-argument": (HEAD + "register(check_mount_sources)\n", GOOD, "C14"),
            "patched": (PKG_AS + "argv_guard.check_mount_sources = lambda s: []\n", GUARDED, "C14"),
        }
        for label, (head, src, code) in cases.items():
            with self.subTest(label):
                self.assertIn(code, codes(src, head), label)

    def test_the_launch_must_be_the_next_statement_with_a_pure_call(self):
        """PR 299 root review of 332681f4: C22 took the two statements after the argv abort, then accepted the launch
        as ANY later statement, so a filesystem-mutating helper between the host read and the create passed. The
        launch must be the statement right after the `if fs:` abort, and its callee and arguments may not call.
        Inert parsed source: nothing here is executed."""
        launch = "    subprocess.run(argv, check=True)\n"
        cases = {
            "intervening-filesystem-helper": GOOD.replace(FS, FS + "    replace_source(schema)\n"),
            "intervening-benign-call": GOOD.replace(FS, FS + '    log("x")\n'),
            "intervening-assignment": GOOD.replace(FS, FS + "    x = 1\n"),
            "launch-argument-calls": GOOD.replace(launch, '    subprocess.run(argv, stdout=open("log", "w"))\n'),
            "launch-callee-calls": GOOD.replace(launch, "    factory().run(argv)\n"),
            "launch-keyword-calls": GOOD.replace(launch, "    subprocess.run(args=argv, env=prepare())\n"),
        }
        for label, src in cases.items():
            with self.subTest(label):
                self.assertNotEqual(src, GOOD, label)
                self.assertIn("C22", codes(src), label)

    def test_the_complete_pattern_passes(self):
        self.assertEqual(codes(GOOD), [])
        self.assertEqual(codes(GUARDED, PKG_AS), [])


BUILDER = """
def build(x, log, CACHE):
    argv = {argv}
    {use}
    return argv

def launch(schema):
    argv = build(1, print, {{}})
    bad = violations(argv, schema)
    if bad:
        raise SystemExit(1)
    fs = check_mount_sources(schema)
    if fs:
        raise SystemExit(1)
    subprocess.run(argv)
"""


class Bindings(unittest.TestCase):
    """The two binding helpers have different jobs, and each is asserted against its own semantics, form by form
    (PR 299 CG-r5: _bindings read `argv[2] = "n2"` as argv being bound to a string). Inert source, parsed only."""

    def test_bindings_record_only_store_bound_names_with_their_values(self):
        cases = {
            "name": ("x = 'docker run'", {"x": ["'docker run'"]}),
            "tuple-unpack": ("a, b = v", {"a": ["v"], "b": ["v"]}),
            "list-unpack": ("[a, b] = v", {"a": ["v"], "b": ["v"]}),
            "starred": ("a, *rest = v", {"a": ["v"], "rest": ["v"]}),
            "chained": ("a = b = v", {"a": ["v"], "b": ["v"]}),
            "subscript": ("x[2] = 'n2'", {}),
            "attribute": ("x.text = 'docker run x'", {}),
            "subscript-of-attribute": ("x.y[0] = v", {}),
            "augassign": ("x += ' --rm'", {"x": ["' --rm'"]}),
            "annassign-value": ("x: str = 'docker'", {"x": ["'docker'"]}),
            "annassign-bare": ("x: str", {}),
            "walrus": ("(x := 'docker run')", {"x": ["'docker run'"]}),
            "walrus-in-subscript-target": ("x[(i := 1)] = v", {"i": ["1"]}),
            "for": ("for c in cmds:\n    pass", {"c": ["cmds"]}),
            "for-unpack": ("for a, b in pairs:\n    pass", {"a": ["pairs"], "b": ["pairs"]}),
            "async-for": ("async def f():\n    async for c in cmds:\n        pass", {"c": ["cmds"]}),
            "comprehension": ("[c for c in cmds]", {"c": ["cmds"]}),
            "with-as": ("with open(p) as f:\n    pass", {}),
            "import-def-param": ("import os\n\ndef f(a):\n    pass", {}),
        }
        for label, (src, want) in cases.items():
            with self.subTest(label):
                got = {k: [ast.unparse(v) for v in vs] for k, vs in C._bindings(ast.parse(src)).items()}
                self.assertEqual(got, want, label)

    def test_binding_counts_count_every_rebinding_but_never_a_target_base(self):
        cases = {
            "name": ("x = 1", {"x": 1}),
            "unpack-starred": ("a, *rest = v", {"a": 1, "rest": 1, "v": 0}),
            "subscript-base": ("x[0] = 1", {"x": 0}),
            "attribute-base": ("o.a = 1", {"o": 0}),
            "augassign": ("x += 1", {"x": 1}),
            "annassign-bare": ("x: int", {"x": 1}),
            "walrus": ("(x := 1)", {"x": 1}),
            "for-and-comprehension": ("for x in y:\n    pass\n[z for z in y]", {"x": 1, "z": 1, "y": 0}),
            "with-as": ("with c as x:\n    pass", {"x": 1, "c": 0}),
            "del": ("del x", {"x": 1}),
            "def-class-param": ("def f(a, *b, c=1, **d):\n    pass\n\nclass K:\n    pass",
                                {"f": 1, "a": 1, "b": 1, "c": 1, "d": 1, "K": 1}),
            "imports": ("import a.b\nimport m as n\nfrom p import q as r, s",
                        {"a": 1, "n": 1, "r": 1, "s": 1, "m": 0, "q": 0}),
            "except": ("try:\n    pass\nexcept E as e:\n    pass", {"e": 1, "E": 0}),
            "global": ("def f():\n    global g", {"g": 1, "f": 1}),
            "match": ("match v:\n    case [a, *r]:\n        pass\n    case {'k': b, **rest}:\n        pass",
                      {"a": 1, "r": 1, "b": 1, "rest": 1}),
            "rebinding-twice": ("x = 1\nx = 2", {"x": 2}),
        }
        for label, (src, want) in cases.items():
            with self.subTest(label):
                counts = C._binding_counts(ast.parse(src))
                self.assertEqual({k: counts.get(k, 0) for k in want}, want, label)


class ClosedPattern(unittest.TestCase):
    """PR 299 security and connector reviews of 6fd887bb and 9f83216a: an ACCEPTED shape must not launch, abort with a
    side effect, call a fake guard, or build and launch. Each reviewer's exact reproduction, plus negatives."""

    def test_an_abort_with_a_side_effect_fails(self):
        cases = {
            "return-launch": "return subprocess.run(argv)",
            "exit-launch": "sys.exit(subprocess.run(argv))",
            "raise-nested-launch": "raise SystemExit(str(subprocess.run(argv)))",
            "raise-helper-call": "raise RuntimeError(report(bad))",
            "return-mutation": 'return argv.append("--privileged")',
            "raise-from-call": "raise SystemExit(1) from launch_anyway()",
            "walrus": "return (n := bad)",
            # PR 299 security review of fa2183f1: a callable abort is never accepted, shadowable or not
            "sys-exit": "sys.exit(2)",
            "bare-exit": "exit(2)",
            "os-exit": "os._exit(2)",
        }
        for label, abort in cases.items():
            with self.subTest(label):
                self.assertIn("C05", codes(GOOD.replace('raise SystemExit("refused")', abort)), label)
        shadowed = HEAD + "\ndef exit(*a):\n    return None\n"     # the reviewer's repro: a local exit that returns
        self.assertIn("C05", codes(GOOD.replace('raise SystemExit("refused")', "exit(2)"), shadowed))

    def test_a_pure_abort_passes(self):
        for label, abort in (("fstring", 'raise SystemExit(f"refused: {bad}")'),
                             ("from-none", 'raise RuntimeError("refused") from None'), ("bare-return", "return"),
                             ("raise-systemexit", "raise SystemExit(2)")):
            with self.subTest(label):
                self.assertEqual(codes(GOOD.replace('raise SystemExit("refused")', abort)), [], label)

    def test_a_dynamic_launch_verb_is_a_launch_site(self):
        head = "def launch(verb, DOCKER, m, sub, rest):\n"
        cases = {
            "repro-docker-verb-network": '    argv = ["docker", verb, "--network", "host", "img"]\n',
            "name-binary-verb-mount": '    argv = [DOCKER, verb, "--mount", m]\n',
            "docker-dynamic-subcommand": '    argv = ["docker", sub, "x"]\n',
            "docker-starred": '    argv = ["docker", *rest]\n',
            # PR 299 security review of b3a9a422: a constant docker verb is a site with or without launch marks
            "mark-free-docker-run-repro": '    argv = ["docker", "run", "--privileged", "alpine"]\n',
            "mark-free-docker-create": '    argv = ["docker", "create", "alpine"]\n',
        }
        for label, line in cases.items():
            with self.subTest(label):
                self.assertIn("C03", codes(head + line + "    subprocess.run(argv)\n"), label)

    def test_non_docker_and_non_launch_lists_are_not_sites(self):
        """U3's boundary: a constant docker verb makes a site without marks, but neither a non-docker binary with a
        verb nor a docker command that is not run/create does, so neither needs a check."""
        cases = {
            "podman-run": '["podman", "run", "x"]',
            "docker-ps": '["docker", "ps"]',
            "docker-images": '["docker", "images", "-q"]',
            "bare-run": '["run", "x"]',
        }
        for label, lst in cases.items():
            with self.subTest(label):
                self.assertEqual(codes(f"def f():\n    argv = {lst}\n    subprocess.run(argv)\n"), [], label)

    def test_a_checked_dynamic_verb_launch_passes(self):
        src = GOOD.replace("def launch(schema):", "def launch(schema, verb):").replace(
            ARGV, '["docker", verb, "--network", "none", "img", "true"]')
        self.assertEqual(codes(src), [])

    def test_violations_must_be_argv_guards(self):
        host = GOOD.replace('"none"', '"host"')
        cases = {
            "repro-local-def-and-path-string": ("import subprocess\nGUARD = 'vendor/argv_guard.py'\n\n"
                                                "def violations(a, s):\n    return []\n", host),
            "shadowed-after-import": (HEAD + "violations = lambda a, s: []\n", GOOD),
            "parameter-shadow": (HEAD, GOOD.replace("def launch(schema):", "def launch(schema, violations):")),
            "try-fallback": ("import subprocess\ntry:\n    from txe.containerguard.argv_guard import violations\n"
                             "except ImportError:\n    def violations(a, s):\n        return []\n", GOOD),
            "suffix-module": ("import subprocess\nfrom evil.argv_guard import violations\n", GOOD),
            "other-module": ("import subprocess\nfrom fake_guard import violations\n", GOOD),
            "method-on-other-object": (PKG_AS,
                                       GOOD.replace("def launch(schema):", "def launch(schema, checker):")
                                       .replace("violations(argv", "checker.violations(argv")),
            "module-patched": (PKG_AS + "argv_guard.violations = lambda a, s: []\n",
                               GOOD.replace("violations(argv", "argv_guard.violations(argv")),
            "setattr-patch": (PKG_AS + "setattr(argv_guard, 'violations', lambda a, s: [])\n",
                              GOOD.replace("violations(argv", "argv_guard.violations(argv")),
            "star-import": (HEAD + "from helpers import *\n", GOOD),
            # PR 299 security review of fa2183f1: a bare `argv_guard` can resolve to a planted sibling argv_guard.py
            "top-level-from-import": ("import subprocess\nfrom argv_guard import violations\n", GOOD),
            "top-level-import": ("import subprocess\nimport argv_guard\n",
                                 GOOD.replace("violations(argv", "argv_guard.violations(argv")),
            "top-level-import-as": ("import subprocess\nimport argv_guard as g\n",
                                    GOOD.replace("violations(argv", "g.violations(argv")),
            # PR 299 review of b3a9a422: a patch hidden in an unpacking, a for target or a subscript of the module
            "tuple-unpack-patch": (PKG_AS + "(argv_guard.violations,) = (lambda *a: [],)\n", GUARDED),
            "list-unpack-patch": (PKG_AS + "[argv_guard.violations] = [lambda *a: []]\n", GUARDED),
            "starred-unpack-patch": (PKG_AS + "first, *argv_guard.violations = (1, 2)\n", GUARDED),
            "for-target-patch": (PKG_AS + "for argv_guard.violations in [lambda *a: []]:\n    pass\n", GUARDED),
            "module-dict-patch": (PKG_AS + "argv_guard.__dict__['violations'] = lambda *a: []\n", GUARDED),
            "nested-unpack-patch": (PKG_AS + "((argv_guard.violations, x), y) = ((lambda *a: [], 1), 2)\n", GUARDED),
            "with-target-patch": (PKG_AS + "with ctx() as argv_guard.violations:\n    pass\n", GUARDED),
            "annotated-patch": (PKG_AS + "argv_guard.violations: object = lambda *a: []\n", GUARDED),
            "augmented-patch": (PKG_AS + "argv_guard.violations += ()\n", GUARDED),
            "delete-patch": (PKG_AS + "del argv_guard.violations\n", GUARDED),
            "function-object-mutation": (PKG_AS + "argv_guard.violations.__code__ = (lambda *a: []).__code__\n",
                                         GUARDED),
            "globals-rebinding": (HEAD + "globals()['violations'] = lambda *a: []\n", GOOD),
            "exec-rebinding": (HEAD + "exec('violations = lambda *a: []')\n", GOOD),
            # PR 299 security review of 166b76cc: the guard may be referenced ONLY by its import and its check call
            "dict-update-repro": (PKG_AS + "argv_guard.__dict__.update({'violations': lambda *_: []})\n",
                                  GUARDED.replace(ARGV, '["docker", "run", "--privileged", "alpine"]')),
            "dict-setdefault": (PKG_AS + "argv_guard.__dict__.setdefault('violations', None)\n", GUARDED),
            "dict-setitem-method": (PKG_AS + "argv_guard.__dict__.__setitem__('violations', lambda *a: [])\n",
                                    GUARDED),
            "vars-update": (PKG_AS + "vars(argv_guard).update(violations=lambda *a: [])\n", GUARDED),
            "attribute-read-alias": (PKG_AS + "check = argv_guard.violations\n", GUARDED),
            "passed-as-argument": (HEAD + "register(violations)\n", GOOD),
            "sys-modules": (PKG_AS + "import sys\nsys.modules['x'].violations = lambda *a: []\n", GUARDED),
            "importlib-by-name": (PKG_AS + "import importlib\nimportlib.import_module('m').violations = None\n",
                                  GUARDED),
            "module-name-string": (PKG_AS + "NAME = 'txe.containerguard.argv_guard'\n", GUARDED),
            # PR 299 security review of 32dc13f1: a dotted target inside the module, and the patching library
            "mock-patch-decorator-repro": ("import subprocess\nimport unittest.mock\n"
                                           "from txe.containerguard.argv_guard import violations\n",
                                           GOOD.replace("\ndef launch(", "\n@unittest.mock.patch("
                                                        "'txe.containerguard.argv_guard.violations', new=lambda *_: [])"
                                                        "\ndef launch(")),
            "mock-patch-context": (HEAD + "from unittest import mock\n"
                                   "with mock.patch('txe.containerguard.argv_guard.violations'):\n    pass\n", GOOD),
            "dotted-target-constant": (HEAD + "TARGET = 'txe.containerguard.argv_guard.x'\n", GOOD),
            "from-unittest-mock-import": (HEAD + "from unittest.mock import patch\n", GOOD),
            "import-unittest-mock": (HEAD + "import unittest.mock\n", GOOD),
            "import-mock": (HEAD + "import mock\n", GOOD),
            "dynamic-load": ("import importlib.util\nimport subprocess\n"
                             "spec = importlib.util.spec_from_file_location('argv_guard', 'x/argv_guard.py')\n"
                             "G = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(G)\n",
                             GOOD.replace("violations(argv", "G.violations(argv")),
            "import-in-function": ("import subprocess\n", GOOD.replace(
                "    argv = ", "    from txe.containerguard.argv_guard import violations\n    argv = ")),
        }
        for label, (head, src) in cases.items():
            with self.subTest(label):
                self.assertIn("C14", codes(src, head), label)

    def test_strings_that_only_mention_the_guard_stay_clean(self):
        """W2's boundary: only the module's name, or a dotted target inside it, is access by name. A message or a
        GUARD_PIN-style path that merely mentions argv_guard is not (the README recipe, executed, is a third)."""
        cases = {
            "refusal-message": GOOD.replace('raise SystemExit("refused")',
                                            'raise SystemExit("argv_guard refused the launch")'),
            "guard-pin-path": "GUARD_PIN = ('c0ffee', 'txe/containerguard/argv_guard.py', 'ab12')\n" + GOOD,
        }
        for label, src in cases.items():
            with self.subTest(label):
                self.assertEqual(codes(src), [], label)

    def test_the_recognised_guard_bindings_pass(self):
        cases = {
            "import-as": ("import subprocess\nimport txe.containerguard.argv_guard as g\n", "g."),
            "package-from-import": ("import subprocess\nfrom txe.containerguard.argv_guard import "
                                    "check_mount_sources, violations\n", ""),
            "package-import": ("import subprocess\nimport txe.containerguard.argv_guard\n",
                               "txe.containerguard.argv_guard."),
        }
        for label, (head, prefix) in cases.items():
            with self.subTest(label):
                self.assertEqual(codes(qualify(GOOD, prefix), head), [], label)

    def test_a_use_outside_the_checked_block_fails(self):
        """PR 299 review of 8f848049: a block does not scope a Python name, so a later use is the same argv."""
        template = ("\ndef launch(schema, x, items):\n    {header}\n        argv = {argv}\n"
                    "        bad = violations(argv, schema)\n        if bad:\n            raise SystemExit(1)\n"
                    "        subprocess.run(argv)\n    {after}\n")
        cases = {
            "after-with-repro": ("with open('x') as f:", 'argv.insert(2, "--privileged")\n    subprocess.run(argv)'),
            "after-if": ("if x:", "subprocess.run(argv)"),
            "after-for": ("for _ in items:", 'argv.append("--privileged")'),
        }
        for label, (header, after) in cases.items():
            with self.subTest(label):
                self.assertIn("C20", codes(template.format(header=header, argv=ARGV, after=after)), label)

    def test_a_check_inside_a_try_fails(self):
        """PR 299 security review of 8f848049: a handler or finally runs after the abort, with the refused argv."""
        template = ("\ndef launch(schema):\n    try:\n        argv = {argv}\n        bad = violations(argv, schema)\n"
                    "        if bad:\n            {abort}\n        subprocess.run(argv)\n    {handler}\n")
        cases = {
            "except-relaunch-repro": ('raise RuntimeError("refused")',
                                      "except RuntimeError:\n        subprocess.run(argv)"),
            "finally-after-return": ("return", "finally:\n        done = 1"),
            "harmless-handler": ('raise RuntimeError("refused")', "except ValueError:\n        pass"),
        }
        for label, (abort, handler) in cases.items():
            with self.subTest(label):
                self.assertIn("C20", codes(template.format(argv=ARGV, abort=abort, handler=handler)), label)

    def test_a_site_not_directly_in_a_function_body_fails(self):
        cases = {
            "module-level": (f"\nargv = {ARGV}\nbad = violations(argv, None)\nif bad:\n    raise SystemExit(1)\n"
                             "subprocess.run(argv)\n"),
            "in-while": (f"\ndef launch(schema):\n    while True:\n        argv = {ARGV}\n"
                         "        bad = violations(argv, schema)\n        if bad:\n            raise SystemExit(1)\n"
                         "        subprocess.run(argv)\n        break\n"),
        }
        for label, src in cases.items():
            with self.subTest(label):
                self.assertIn("C20", codes(src), label)

    def test_the_argv_outside_the_recognised_sequence_fails(self):
        """The site's argv occurs exactly as its target, the check's argument and ONE launch argument; nothing else."""
        launch = "    subprocess.run(argv, check=True)\n"
        cases = {
            "second-launch": GOOD.replace(launch, launch + launch),
            "use-after-launch": GOOD.replace(launch, launch + "    print(argv)\n"),
            "earlier-binding": GOOD.replace("    argv = [", "    argv = None\n    argv = ["),
            "launch-in-nested-def": GOOD.replace(launch, "    def later():\n        subprocess.run(argv)\n"
                                                         "    later()\n"),
            "launch-in-lambda": GOOD.replace(launch, "    go = lambda: subprocess.run(argv)\n    go()\n"),
            "launch-in-generator": GOOD.replace(launch, "    list(subprocess.run(a) for a in [argv])\n"),
        }
        for label, src in cases.items():
            with self.subTest(label):
                self.assertIn("C21", codes(src), label)

    def test_the_launch_argument_contexts(self):
        """PR 299 CG-r7: each context the argv can take as the launch's argument, as an inert parsed fixture. Only a
        positional argument or the API's command keyword (`args=` on the subprocess launch APIs) of a call that is an
        Expr or Assign statement directly after the check is accepted; every other context is C21."""
        launch = "    subprocess.run(argv, check=True)\n"
        cases = {
            "positional": ("    subprocess.run(argv, check=True)\n", None),
            "command-keyword": ("    subprocess.run(args=argv, check=True)\n", None),
            "command-keyword-popen": ("    subprocess.Popen(args=argv)\n", None),
            "assigned-result": ("    proc = subprocess.run(argv)\n", None),
            "env-keyword": ("    subprocess.run(['true'], env=argv)\n", "C21"),
            "stdout-keyword": ("    subprocess.run(['true'], stdout=argv)\n", "C21"),
            "cwd-keyword": ("    subprocess.run(['true'], cwd=argv)\n", "C21"),
            "input-keyword": ("    subprocess.run(['true'], input=argv)\n", "C21"),
            "args-keyword-unknown-api": ("    runner(args=argv)\n", "C21"),
            "starred": ("    subprocess.run(*argv)\n", "C21"),
            "double-star": ("    subprocess.run(**argv)\n", "C21"),
            "attribute": ("    subprocess.run(argv.copy())\n", "C21"),
            "alias": ("    cmd = argv\n    subprocess.run(cmd)\n", "C21"),
            "lambda-command-keyword": ("    go = lambda: subprocess.run(args=argv)\n    go()\n", "C21"),
            "nested-def": ("    def later():\n        subprocess.run(argv)\n    later()\n", "C21"),
            "with-item": ("    with subprocess.Popen(argv) as proc:\n        proc.wait()\n", "C21"),
            "conditional-expression": ("    subprocess.run(argv) if schema else None\n", "C21"),
            "return": ("    return subprocess.run(argv)\n", "C21"),
            "comprehension": ("    [subprocess.run(argv) for _ in range(1)]\n", "C21"),
            "await": ("    await runner(argv)\n", "C21"),
            # PR 299 review of b3a9a422: the guard validates from "create", so the launch puts docker in front
            "docker-prefix": ("    subprocess.run(['docker'] + argv, check=True)\n", None),
            "docker-path-prefix": ("    subprocess.run(['/usr/bin/docker'] + argv)\n", None),
            "docker-prefix-command-keyword": ("    subprocess.run(args=['docker'] + argv)\n", None),
            "non-docker-prefix": ("    subprocess.run(['podman'] + argv)\n", "C21"),
            "two-element-prefix": ("    subprocess.run(['docker', 'run'] + argv)\n", "C21"),
            "argv-on-the-left": ("    subprocess.run(argv + ['docker'])\n", "C21"),
            "non-constant-prefix": ("    subprocess.run([DOCKER] + argv)\n", "C21"),
            "prefix-with-a-flag": ("    subprocess.run(['docker', '--debug'] + argv)\n", "C21"),
            "concatenation-after": ("    subprocess.run(['docker'] + argv + ['--rm'])\n", "C21"),
            "concatenation-before": ("    subprocess.run(['docker'] + ['--debug'] + argv)\n", "C21"),
            "conditional-prefix": ("    subprocess.run((['docker'] if schema else []) + argv)\n", "C21"),
            "aliased-prefix": ("    prefix = ['docker']\n    subprocess.run(prefix + argv)\n", "C21"),
            "aliased-command": ("    cmd = ['docker'] + argv\n    subprocess.run(cmd)\n", "C21"),
            "deferred-prefixed-launch": ("    go = lambda: subprocess.run(['docker'] + argv)\n    go()\n", "C21"),
        }
        self.assertEqual(len(cases), 34)
        for label, (block, code) in cases.items():
            with self.subTest(label):
                src = GOOD.replace(launch, block)
                if label == "await":
                    src = src.replace("def launch(schema):", "async def launch(schema):")
                if code is None:
                    self.assertEqual(codes(src), [], label)
                else:
                    self.assertIn(code, codes(src), label)

    def test_the_recorded_ast_chains_hold(self):
        """The parent chains C21 relies on, from the argv Name up to its function, asserted on Python's own parser
        rather than a hand trace (PR 299 CG-r7: a keyword value's parent is ast.keyword, not the Call)."""
        def chain(body, is_async=False):
            tree = ast.parse(("async def" if is_async else "def") + " f():\n    " + body + "\n")
            parent = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
            node = next(n for n in ast.walk(tree) if isinstance(n, ast.Name) and n.id == "argv")
            out = []
            while not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                node = parent[node]
                out.append(type(node).__name__)
            return out
        cases = {
            "positional": ("run(argv)", False, ["Call", "Expr", "FunctionDef"]),
            "command-keyword": ("run(args=argv)", False, ["keyword", "Call", "Expr", "FunctionDef"]),
            "assigned": ("p = run(argv)", False, ["Call", "Assign", "FunctionDef"]),
            "starred": ("run(*argv)", False, ["Starred", "Call", "Expr", "FunctionDef"]),
            "double-star": ("run(**argv)", False, ["keyword", "Call", "Expr", "FunctionDef"]),
            "attribute": ("run(argv.copy())", False, ["Attribute", "Call", "Call", "Expr", "FunctionDef"]),
            "await": ("await run(argv)", True, ["Call", "Await", "Expr", "AsyncFunctionDef"]),
            "lambda": ("go = lambda: run(argv)", False, ["Call", "Lambda", "Assign", "FunctionDef"]),
            "comprehension": ("[run(argv) for _ in x]", False, ["Call", "ListComp", "Expr", "FunctionDef"]),
            "with-item": ("with run(argv) as p:\n        pass", False, ["Call", "withitem", "With", "FunctionDef"]),
            "return": ("return run(argv)", False, ["Call", "Return", "FunctionDef"]),
            "conditional": ("run(argv) if c else None", False, ["Call", "IfExp", "Expr", "FunctionDef"]),
            "docker-prefix": ("run(['docker'] + argv)", False, ["BinOp", "Call", "Expr", "FunctionDef"]),
            "docker-prefix-keyword": ("run(args=['docker'] + argv)", False,
                                      ["BinOp", "keyword", "Call", "Expr", "FunctionDef"]),
        }
        for label, (body, is_async, want) in cases.items():
            with self.subTest(label):
                self.assertEqual(chain(body, is_async), want, label)

    def test_the_documented_recipe_runs_end_to_end_with_a_fake_launch(self):
        """PR 299 review of b3a9a422: the recipe's argv started with "docker", which the runtime guard always refuses
        (G01). The README's literal recipe is now EXECUTED against the real argv_guard, with a fake `subprocess` that
        records its call and never runs a process:
        - its argv starts with "create" and passes check_schema and violations for its schema;
        - launch(schema) calls subprocess.run exactly once, with ["docker"] + argv;
        - for a schema the argv does not match, launch raises SystemExit and never calls the fake;
        - PR 299 security review of cdb78d1d: the recipe's check_mount_sources runs for real against a fresh work dir
          made here; for a work dir reached through a symbolic link (only lstat'd), launch raises SystemExit and never
          calls the fake."""
        spec_g = importlib.util.spec_from_file_location("argv_guard_for_recipe", HERE / "argv_guard.py")
        G = importlib.util.module_from_spec(spec_g)
        spec_g.loader.exec_module(G)
        recipe = readme_recipe()
        launch = next(n for n in ast.walk(ast.parse(recipe)) if isinstance(n, ast.FunctionDef) and n.name == "launch")
        argv = ast.literal_eval(next(st.value for st in launch.body if isinstance(st, ast.Assign) and
                                     isinstance(st.targets[0], ast.Name) and st.targets[0].id == "argv"))
        self.assertEqual(argv[0], "create")
        scratch = os.path.realpath(tempfile.mkdtemp(prefix="cg-recipe-"))
        self.addCleanup(shutil.rmtree, scratch)
        os.mkdir(scratch + "/example")
        os.symlink(scratch + "/example", scratch + "/linked")
        schema = G.Schema(image=argv[-2], work_dir=scratch + "/example", scratch=scratch,
                          flags=frozenset({"--read-only"}),
                          single={"--name": "txe-example", "--pull": "never", "--network": "none", "--cap-drop": "ALL",
                                  "--security-opt": "no-new-privileges", "--user": "1000:1000",
                                  "--entrypoint": "/bin/true"},
                          repeated={}, last_option="--entrypoint", payload=(argv[-1],))
        self.assertEqual(G.check_schema(schema), [])
        self.assertEqual(G.violations(argv, schema), [])
        self.assertEqual(G.check_mount_sources(schema), [])
        linked = dataclasses.replace(schema, work_dir=scratch + "/linked")
        self.assertEqual((G.check_schema(linked), [v.code for v in G.check_mount_sources(linked)]), ([], ["F01"]))

        calls = []
        fake_subprocess = types.SimpleNamespace(run=lambda *a, **kw: calls.append((a, kw)))
        modules = {"subprocess": fake_subprocess, "txe.containerguard.argv_guard": G}

        def fake_import(name, globals=None, locals=None, fromlist=(), level=0):   # the recipe's two imports only
            if level or name not in modules:
                raise ImportError(f"the recipe imported {name!r}")
            return modules[name]
        ns: dict = {"__builtins__": {**builtins.__dict__, "__import__": fake_import}}
        exec(compile(recipe, "README.md supported recipe", "exec"), ns)
        ns["launch"](schema)
        self.assertEqual(calls, [((["docker"] + argv,), {"check": True})])
        calls.clear()
        with self.assertRaises(SystemExit):
            ns["launch"](dataclasses.replace(schema, single={**schema.single, "--user": "1001:1001"}))
        self.assertEqual(calls, [])
        with self.assertRaises(SystemExit):
            ns["launch"](linked)
        self.assertEqual(calls, [])

    def test_the_documented_recipe_passes(self):
        """The supported recipe, as the README documents it, and its accepted variants are clean. The README's own
        block is read from the file, so the documentation cannot drift from what the check accepts."""
        recipe = readme_recipe()
        builder = ("import subprocess\nfrom txe.containerguard.argv_guard import check_mount_sources, violations\n\n\n"
                   f"def build(extra):\n    argv = {ARGV}\n    argv += extra\n    return argv\n\n\n"
                   "def launch(schema):\n    argv = build([])\n    bad = violations(argv, schema)\n    if bad:\n"
                   '        raise SystemExit("argv_guard refused the launch")\n' + FS + "    subprocess.Popen(argv)\n")
        alias = qualify(GOOD, "guard.").replace(
            "subprocess.run(argv, check=True)", "subprocess.run(args=argv, check=True)")
        cases = {
            "readme-recipe": (recipe, ""),
            "builder": (builder, ""),
            "module-alias-keyword-launch": (alias,
                                            "import subprocess\nimport txe.containerguard.argv_guard as guard\n"),
        }
        for label, (src, head) in cases.items():
            with self.subTest(label):
                self.assertEqual(codes(src, head), [], label)

    def test_a_builder_may_only_construct_its_argv(self):
        cases = {
            "repro-launch-then-return": "subprocess.run(argv)",
            "launch-in-branch": "if x:\n        subprocess.run(argv)",
            "pass-to-helper": "log(argv)",
            "alias": "alias = argv",
            "store-elsewhere": 'CACHE["last"] = argv',
            "constructor-mentions-argv": "argv.extend(argv)",
        }
        for label, use in cases.items():
            with self.subTest(label):
                self.assertIn("C17", codes(BUILDER.format(argv=ARGV, use=use)), label)

    def test_a_builder_that_only_constructs_passes(self):
        use = 'argv.append("--rm")\n    if x:\n        argv.insert(1, "--init")\n    argv[2] = "n2"\n    argv += ["y"]'
        self.assertEqual(codes(BUILDER.format(argv=ARGV, use=use)), [])


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
        evidence = {  # each row's owner_ack and review_evidence, bound to that file's reviewed bytes
            "txe/mutate/fixture-demo.py": ("msg_47e1330eb699", "msg_8aa61a2eb4f7"),
            "txe/mutate/mutate-sandboxed.py": ("msg_e6ea429fa202", "msg_9d9d21e51448"),
        }
        for r in [x.split("\t") for x in reg.splitlines()[1:]]:
            self.assertEqual((r[8], r[9]), evidence[r[1]], r[1])

    def test_the_repository_passes_the_consumer_check(self):
        """The gate: every launcher validates its argv or carries a complete reviewed, hash-bound registry row."""
        self.assertEqual([str(f) for f in C.report(REPO)], [])


if __name__ == "__main__":
    unittest.main()
