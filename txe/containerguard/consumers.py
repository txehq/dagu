# SPDX-License-Identifier: GPL-3.0-or-later
"""The consumer check for argv_guard (TXE-8041): every container launcher under txe/ validates the argv it launches,
or is classified by a reviewed, hash-bound row in UNGUARDED.tsv, as ALTERNATE_GUARD (equivalent enforcement) or
LEGACY_BOUNDARY (a reviewed legacy boundary or different purpose, NOT certified against the floor).

THIS IS AN AST HEURISTIC, NOT A PROOF OF DATA FLOW. It recognises one written pattern and fails everything it cannot
recognise. Importing violations() and calling it somewhere does not show that the launched argv was validated or that
the findings were enforced. So the check demands this exact shape, in one function and one block:

    def launcher(...):                             # the site is a statement DIRECTLY in a function body (C20)
        argv = <a docker argv list literal>    or   argv = <a builder in this file>(...)
        bad = violations(argv, <schema>)           # txe.containerguard.argv_guard's: one module-level import (C14)
        if bad:
            raise ... | return ...                 # first statement of the branch, NO call or other side effect (C05)
        ... launch(argv) ...                       # argv's ONLY other occurrence in the function: one launch (C21)

A docker argv is a list literal with a launch verb and a launch mark, or a mark and a dynamic element, or a constant
"docker" followed by a dynamic verb (is_docker_list). A builder is a function in the same file that returns such a list
and does nothing else with it but construct it (C17). The abort is a raise or return whose expression may not call,
await, yield or assign (C05). violations() counts only when it resolves to txe.containerguard.argv_guard (the package
path; a bare argv_guard can resolve to a sibling file) through a module-level import bound once in the file; a dynamic
load, a fallback definition, a shadowing or a patch is C14. That is not cryptographic module identity: the runtime
guard is the enforcer, and this check is fail-closed for the forms it knows. A call to a builder outside an
assignment, a list used inline, a builder with no caller in its file (cross-module use is not analysed), a shell
`docker run/create`, an unparsable file, a check in a different block, an ignored result, a different argv checked,
the argv used before its check, a mutation after it, a checked argv that escapes or is never launched: each is a
finding. Anything ambiguous fails for review. The README lists what is recognised and validated, what is refused,
and what is not detected, and documents the supported recipe.

In Python, a known process-launch call (subprocess, os or asyncio, through any import alias) that names docker and
uses a shell (shell=True with a string or a list, os.system, os.popen, create_subprocess_shell), a shell's -c list, a
string command, or an exec/spawn call is C16, an unsupported launch: it fails for review, never passes. NOT covered:
a command that does not contain the word docker, an obfuscated or data-flow-built command, **kwargs, and launch
calls this recogniser does not know.

The scan covers *.py, *.sh and *.bash under txe/, except testdata/ directories and txe/containerguard/ itself (whose
test fixtures build inert argv that is never launched).

    python3 -I -B consumers.py <repo root>     # prints findings and registry problems; exit 1 if any
"""
import ast
import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path

LAUNCH_VERBS = frozenset({"create", "run"})
LAUNCH_MARKS = frozenset({"--network", "--mount", "--cidfile", "--entrypoint", "--cap-drop", "--security-opt"})
MUTATORS = frozenset({"append", "extend", "insert", "pop", "remove", "clear", "sort", "reverse", "__setitem__",
                      "__delitem__", "__iadd__"})
SHELL_LAUNCH = re.compile(r"\bdocker\s+(run|create)\b")
EVIDENCE = re.compile(r"msg_[0-9a-f]{12}|https://github\.com/txehq/[A-Za-z0-9_.-]+/pull/[0-9]+"
                      r"#(?:pullrequestreview-[0-9]+|discussion_r[0-9]+|issuecomment-[0-9]+)")
TICKET = re.compile(r"TXE-[0-9]+")
GUARD_REF = re.compile(r"(?:PARTIAL\((?P<scope>[a-z ]{3,40})\) )?(?P<src>txe/[A-Za-z0-9_./-]+\.py):"
                       r"(?P<sym>[A-Za-z_][A-Za-z0-9_]*); tested by (?P<test>txe/[A-Za-z0-9_./-]+\.(?:go|py)):"
                       r"(?P<tname>[A-Za-z_][A-Za-z0-9_]*)")
CITE = re.compile(r"(?P<file>txe/[A-Za-z0-9_./-]+):(?P<line>[1-9][0-9]*)")
HEX64 = re.compile(r"[0-9a-f]{64}")
# The registry of launchers that do NOT use the guard (UNGUARDED.tsv). A row is one of two DISTINCT classes:
#   ALTERNATE_GUARD  the launcher enforces the same properties another way: full guard and test references, none
#                    PARTIAL. It claims equivalence and is reviewed as such.
#   LEGACY_BOUNDARY  a reviewed legacy tool or a different purpose. It is NOT certification against the floor: it
#                    names its difference, its authorized manual-only use, any real but PARTIAL guard, and the exact
#                    lines it was reviewed at (cites). It never claims equivalence.
# Every row binds the file's exact sha256, so ANY edit to the file invalidates that file's classification (only its
# own row) until re-reviewed. "manual-only" is the permitted use under these source-row classifications; it neither
# revokes nor broadens separate CI or runtime authorizations. The evidence checks validate a record's SHAPE (a message
# id or review link), not the truth of the approval: reviewers still inspect the cited evidence.
REGISTRY_COLUMNS = ("class", "path", "sha256", "ticket", "difference", "authorized_use", "guard_refs", "cites",
                    "owner_ack", "review_evidence")
CLASSES = ("ALTERNATE_GUARD", "LEGACY_BOUNDARY")
SCOPE_EXCLUDE = ("txe/containerguard/",)

FINDINGS = {
    "C01": "a docker argv list is not assigned to a plain name (inline or dynamic form)",
    "C02": "a builder's argv is not assigned to a plain name (inline use)",
    "C03": "the argv is used before its check, or never after its assignment",
    "C04": "violations() is called on the argv but its result is ignored",
    "C05": "the check's result is not followed by a fail-closed abort (if <result>: raise/return/exit)",
    "C06": "the argv is changed after its check",
    "C07": "a different argv is checked than the one launched",
    "C08": "a shell docker run/create (shell launch forms are not analysed)",
    "C09": "the argv's first use after assignment is inside a compound statement (ambiguous)",
    "C10": "the file does not parse",
    "C11": "a builder has no caller in its own file (cross-module use is not analysed)",
    "C12": "the checked argv escapes the function (returned or stored); its launch is not analysed",
    "C13": "the checked argv is never passed to a call after the check",
    "C14": "the violations() call is not bound to argv_guard's: it is not imported exactly once, at module level, from "
           "argv_guard (a dynamic load is refused), or its name or module is rebound, shadowed or patched",
    "C15": "the abort conditional has an else or elif branch (it runs after a passing check, unanalysed)",
    "C16": "a Python process launch that names docker uses a shell, a shell's -c, a string command, or an exec/spawn "
           "call: an unsupported launch form, not analysed",
    "C17": "a builder uses its docker argv other than to construct and return it (a launch, call, alias or escape "
           "before any caller's check)",
    "C20": "the site is not a statement directly in a function body (a module-level site, or one nested in a with, "
           "try, if or loop, is not analysed)",
    "C21": "the argv's name occurs in its function other than as the site's target, the check's argument and ONE "
           "launch-call argument after the check (outside any nested def, lambda, class or comprehension)",
}
# C14: the only modules whose violations() counts, by import name. A module path suffix is not provenance: neither
# `evil.argv_guard` nor a file path ending argv_guard.py is trusted, and a dynamic load (importlib) is refused.
GUARD_MODULES = ("txe.containerguard.argv_guard",)   # package-qualified only: a bare `argv_guard` can resolve to a
                                                     # planted sibling argv_guard.py (PR 299 security review, fa2183f1)
GUARD_CALLS = frozenset(f"{m}.violations" for m in GUARD_MODULES)
CONSTRUCTORS = frozenset({"append", "extend", "insert"})
# C16: the process-launch calls the recogniser knows, by their canonical dotted name. Import aliases resolve to these
# (`import subprocess as sp`, `from os import system as sh`), and a bare `subprocess`, `os` or `asyncio` stands for
# itself. A call outside these names (exec(), importlib, a wrapper defined elsewhere) is not recognised (README).
SHELL_APIS = frozenset({"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput",
                        "asyncio.create_subprocess_shell", "asyncio.subprocess.create_subprocess_shell"})
PROCESS_APIS = frozenset({"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_call",
                          "subprocess.check_output"})
EXEC_APIS = frozenset({"asyncio.create_subprocess_exec", "asyncio.subprocess.create_subprocess_exec",
                       "os.posix_spawn", "os.posix_spawnp",
                       *(f"os.{p}{s}" for p in ("exec", "spawn")
                         for s in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe"))})
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash"})
DOCKER_WORD = re.compile(r"\bdocker\b")
EXEMPT_PROBLEMS = {
    "E01": "the row does not have exactly the registry's columns, or a column is empty or padded",
    "E02": "the difference is shorter than 30 characters, or the ticket is not TXE-<n>",
    "E03": "the review evidence is not a review message id or a PR review link",
    "E04": "the guard references are not valid for the class (ALTERNATE_GUARD: full references, none PARTIAL; "
           "LEGACY_BOUNDARY: 'none' or PARTIAL(<scope>) references) or name code that does not exist",
    "E05": "the path is not a scanned file with a finding (a stale row)",
    "E06": "the owner acknowledgment is not a message id or a PR review link",
    "E07": "the path is listed twice",
    "E08": "the class is not ALTERNATE_GUARD or LEGACY_BOUNDARY",
    "E09": "the file's sha256 is not the row's: it changed since the row was reviewed",
    "E10": "a LEGACY_BOUNDARY row's authorized use does not start 'manual-only: '",
    "E11": "the cites are not ';'-separated <txe path>:<line> lines that exist (a LEGACY_BOUNDARY row needs at least one)",
}


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    code: str

    def __str__(self):
        return f"{self.path}:{self.line}: {self.code} {FINDINGS.get(self.code) or EXEMPT_PROBLEMS.get(self.code, '')}"


def _strs(node):
    return {e.value for e in getattr(node, "elts", []) if isinstance(e, ast.Constant) and isinstance(e.value, str)}


def is_docker_list(node):
    """A list literal that launches a container. Any one of these makes it a launch site:
    - a constant launch verb and a launch mark;
    - a launch mark and any non-constant element: the verb may be dynamic (PR 299 security review,
      ['docker', verb, '--network', 'host', ...]);
    - a constant first element naming docker with a non-constant second element, which is a dynamic verb or subcommand;
    - a constant first element naming docker with a constant launch verb, with or without marks.
    An all-constant list without a verb or a mark (["--mount", "x"], ["docker", "ps"], ["docker"]) is not a launch."""
    if not isinstance(node, ast.List):
        return False
    s = _strs(node)
    marks = any(x in LAUNCH_MARKS or x.startswith("--network=") for x in s)
    dynamic = any(not (isinstance(e, ast.Constant) and isinstance(e.value, str)) for e in node.elts)
    first = node.elts[0] if node.elts else None
    docker_first = isinstance(first, ast.Constant) and isinstance(first.value, str) and \
        first.value.rsplit("/", 1)[-1] == "docker"
    dynamic_second = len(node.elts) > 1 and not (isinstance(node.elts[1], ast.Constant) and
                                                 isinstance(node.elts[1].value, str))
    return (bool(s & LAUNCH_VERBS) and marks) or (marks and dynamic) or (docker_first and dynamic_second) or \
        (docker_first and bool(s & LAUNCH_VERBS))      # PR 299 security review: ["docker", "run", "--privileged", …]


def _uses(node, name):
    return any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(node))


def _call_name(call):
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None


def _is_violations_call(node, name=None):
    if not (isinstance(node, ast.Call) and _call_name(node) == "violations"):
        return False
    return name is None or (bool(node.args) and isinstance(node.args[0], ast.Name) and node.args[0].id == name)


def _pure(expr):
    """No call, await, yield or assignment expression anywhere in expr: evaluating it has no side effect this
    heuristic can see (a property or __init__ with one is not detected; README)."""
    return expr is None or not any(isinstance(n, (ast.Call, ast.Await, ast.Yield, ast.YieldFrom, ast.NamedExpr))
                                   for n in ast.walk(expr))


def _pure_call(call):
    return _pure(call.func) and all(_pure(a) for a in call.args) and all(_pure(k.value) for k in call.keywords)


def _is_abort(stmt):
    """A fail-closed abort whose evaluation has no side effect (PR 299 security review: `return subprocess.run(argv)`
    launched the refused argv while aborting):
    - `return` with a pure value, or a bare `return`;
    - `raise`, bare, or of a pure exception, or of an exception class called with pure arguments.
    A CALL is never an abort (PR 299 security review of fa2183f1: `exit`, `sys.exit` and `os._exit` were accepted by
    spelling, and a local `def exit(...)` that returns passed). The AST cannot prove a callee terminates, while raise
    and return transfer control whatever they evaluate (raising a non-exception still raises TypeError). Use
    `raise SystemExit(n)`. Anything else, a nested launch included, is not an abort (C05)."""
    if isinstance(stmt, ast.Return):
        return _pure(stmt.value)
    if isinstance(stmt, ast.Raise):
        exc = stmt.exc
        ok = exc is None or (_pure_call(exc) if isinstance(exc, ast.Call) else _pure(exc))
        return ok and _pure(stmt.cause)
    return False


def _mutates(node, name):
    """True when node changes, or may change, the argv bound to `name`: rebinding, item assignment, deletion, an
    in-place method, a loop or with target, or an ALIAS (`x = argv`, which a later `x.append` would change unseen).
    A callee that mutates its argument is not visible to this heuristic (README)."""
    for n in ast.walk(node):
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and isinstance(n.value, ast.Name) and \
                n.value.id == name:
            return True
        if isinstance(n, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                for x in ast.walk(t):
                    if isinstance(x, ast.Name) and x.id == name:
                        return True
                    if isinstance(x, ast.Subscript) and isinstance(x.value, ast.Name) and x.value.id == name:
                        return True
        if isinstance(n, ast.Delete) and any(_uses(t, name) for t in n.targets):
            return True
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in MUTATORS and \
                isinstance(n.func.value, ast.Name) and n.func.value.id == name:
            return True
        if isinstance(n, (ast.For, ast.With)) and any(_uses(t, name) for t in
                                                      ([n.target] if isinstance(n, ast.For) else
                                                       [i.optional_vars for i in n.items if i.optional_vars])):
            return True
    return False


def _escapes(node, name):
    for n in ast.walk(node):
        if isinstance(n, (ast.Return, ast.Yield, ast.YieldFrom)) and n.value is not None and _uses(n.value, name):
            return True
        if isinstance(n, ast.Assign) and _uses(n.value, name) and any(
                isinstance(t, (ast.Attribute, ast.Subscript)) for t in n.targets):
            return True
    return False


def _binding_counts(tree):
    """How many times each name is bound anywhere in the file (C14's shadowing evidence), valued or not: assignment,
    augmented, annotated (even with no value: it makes the name local), unpacking, starred, loop, with, comprehension
    and walrus targets, del, def and class names, parameters, imports, except names, global/nonlocal and match
    captures. Only a Name in a Store or Del context counts, so the base of a Subscript or Attribute target is not a
    binding."""
    counts = {}

    def add(n):
        counts[n] = counts.get(n, 0) + 1
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            add(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            add(n.name)
        elif isinstance(n, ast.arg):
            add(n.arg)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                add(a.asname or a.name.split(".")[0])
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            for x in n.names:
                add(x)
        elif isinstance(n, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and n.name:
            add(n.name)
        elif isinstance(n, ast.MatchMapping) and n.rest:
            add(n.rest)
    return counts


def _written_bases(target):
    """Every object an assignment target writes into, through any unpacking (PR 299 review of b3a9a422:
    `(g.violations,) = (...)` hid the patch inside a tuple). An Attribute target writes into the attribute itself,
    and a Subscript target into its container (`g.__dict__["violations"] = ...`). A plain Name writes into no
    object, so it yields nothing (_binding_counts covers rebinding)."""
    if isinstance(target, (ast.Tuple, ast.List)):
        for e in target.elts:
            yield from _written_bases(e)
    elif isinstance(target, ast.Starred):
        yield from _written_bases(target.value)
    elif isinstance(target, ast.Attribute):
        yield target
    elif isinstance(target, ast.Subscript):
        yield target.value


def _guard_bindings(tree):
    """{local name: what it stands for} for argv_guard's violations, from MODULE-LEVEL `import M [as g]` and
    `from M import violations [as v]` (M in GUARD_MODULES) only, each local name bound exactly once in the file.
    Empty when any of these appears in the file:
    - a star import, which could shadow anything;
    - a write to the guard module or the guard function through ANY assignment target (plain, unpacked, nested,
      starred, augmented, annotated, deleted, or as a for, comprehension or with target), including an attribute of
      the function (`g.violations.__code__ = …`) or a subscript of the module (`g.__dict__[…] = …`);
    - setattr or delattr on either;
    - an unresolved rebinding: a write into globals(), vars() or locals(), or any exec or eval call.
    An import inside a try, if or def is not module level, so a fallback definition cannot stand in for the guard."""
    if any(isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names) for n in ast.walk(tree)):
        return {}
    out = {}
    for st in tree.body:
        if isinstance(st, ast.Import):
            for a in st.names:
                if a.name in GUARD_MODULES:
                    out[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(st, ast.ImportFrom) and not st.level and st.module in GUARD_MODULES:
            for a in st.names:
                if a.name == "violations":
                    out[a.asname or a.name] = f"{st.module}.violations"
    counts = _binding_counts(tree)
    out = {k: v for k, v in out.items() if counts.get(k) == 1}
    for n in ast.walk(tree):
        targets = n.targets if isinstance(n, (ast.Assign, ast.Delete)) else \
            [n.target] if isinstance(n, (ast.AugAssign, ast.AnnAssign, ast.For, ast.AsyncFor, ast.comprehension)) \
            else [n.optional_vars] if isinstance(n, ast.withitem) and n.optional_vars is not None else []
        bases = [b for t in targets for b in _written_bases(t)]
        if any(_dotted(b, out) is not None for b in bases):
            return {}
        # an unresolved rebinding refuses: a write into globals(), vars() or locals(), or any exec or eval
        if any(isinstance(b, ast.Call) and isinstance(b.func, ast.Name) and b.func.id in ("globals", "vars", "locals")
               for b in bases) or (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and
                                   n.func.id in ("exec", "eval")):
            return {}
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("setattr", "delattr") and \
                n.args and _dotted(n.args[0], out) is not None:
            return {}
    return out


def _uses_only_to_construct(stmts, name):
    """The line of the first use of `name` in stmts that is not pure argv construction, or None. Allowed:
    name.append/extend/insert(...) and `name += ...` whose arguments do not mention name; `name[i] = ...`;
    `return name` or `return name + ...`; and compound statements whose headers do not mention name and whose bodies
    follow the same rules. Anything else (a call taking name, an alias, a store elsewhere, a yield) is a use."""
    for st in stmts:
        if not _uses(st, name):
            continue
        if isinstance(st, ast.Expr) and isinstance(st.value, ast.Call) and \
                isinstance(st.value.func, ast.Attribute) and st.value.func.attr in CONSTRUCTORS and \
                isinstance(st.value.func.value, ast.Name) and st.value.func.value.id == name and \
                not any(_uses(a, name) for a in st.value.args) and \
                not any(_uses(k.value, name) for k in st.value.keywords):
            continue
        if isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name) and st.target.id == name and \
                isinstance(st.op, ast.Add) and not _uses(st.value, name):
            continue
        if isinstance(st, ast.Assign) and len(st.targets) == 1 and isinstance(st.targets[0], ast.Subscript) and \
                isinstance(st.targets[0].value, ast.Name) and st.targets[0].value.id == name and \
                not _uses(st.targets[0].slice, name) and not _uses(st.value, name):
            continue
        if isinstance(st, ast.Return) and st.value is not None and (
                (isinstance(st.value, ast.Name) and st.value.id == name) or
                (isinstance(st.value, ast.BinOp) and isinstance(st.value.op, ast.Add) and
                 isinstance(st.value.left, ast.Name) and st.value.left.id == name and
                 not _uses(st.value.right, name))):
            continue
        if isinstance(st, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
            headers = [getattr(st, "test", None), getattr(st, "iter", None), getattr(st, "target", None)] + \
                [i.context_expr for i in getattr(st, "items", [])] + \
                [i.optional_vars for i in getattr(st, "items", []) if i.optional_vars] + \
                [h.type for h in getattr(st, "handlers", []) if h.type]
            if not any(h is not None and _uses(h, name) for h in headers):
                bodies = [st.body, getattr(st, "orelse", []), getattr(st, "finalbody", [])] + \
                    [h.body for h in getattr(st, "handlers", [])]
                inner = next((ln for b in bodies for ln in [_uses_only_to_construct(b, name)] if ln is not None), None)
                if inner is None:
                    continue
                return inner
        return st.lineno
    return None


def _blocks(tree):
    """Every statement list in the tree, with its enclosing function (or None)."""
    out = []

    def visit(node, fn):
        for field in ("body", "orelse", "finalbody"):
            block = getattr(node, field, None)
            if isinstance(block, list) and block and isinstance(block[0], ast.stmt):
                out.append((block, fn))
                for st in block:
                    visit(st, st if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)) else fn)
        for h in getattr(node, "handlers", []):
            out.append((h.body, fn))
            for st in h.body:
                visit(st, fn)
    visit(tree, None)
    return out


def _import_names(tree):
    """Local name -> the dotted module or module.function it stands for, from this file's imports."""
    names = {m: m for m in ("subprocess", "os", "asyncio")}
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            for a in n.names:
                top = a.name.split(".")[0]
                names[a.asname or top] = a.name if a.asname else top
        elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
            for a in n.names:
                names[a.asname or a.name] = f"{n.module}.{a.name}"
    return names


def _dotted(node, names):
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name) or node.id not in names:
        return None
    return ".".join([names[node.id]] + parts[::-1])


def _bindings(tree):
    """Name -> the values this file gives it (C16's evidence), one level, no data flow. Only a name a statement BINDS
    counts: a Subscript or Attribute target (`x[i] = v`, `x.a = v`) changes an object and binds no name, so its base
    is never recorded (PR 299 CG-r5: `argv[2] = "n2"` was read as argv being the string "n2"). Per form:
    - `x = v`, `x: T = v`, `(x := v)`: v;
    - unpacking (`a, b = v`, `[a, *rest] = v`): v for each name;
    - `x += v`: v, an increment (a str increment makes x a string);
    - `for x in it` and a comprehension's `for x in it`: it (x takes its elements);
    - `x: T` with no value, `with … as x`, imports, except names, defs, classes and parameters: nothing, because the
      file shows no value for them.
    This differs from _binding_counts on purpose: that one counts every (re)binding, valued or not."""
    out = {}

    def bind(target, value):
        if isinstance(target, ast.Name):
            out.setdefault(target.id, []).append(value)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for e in target.elts:
                bind(e, value)
        elif isinstance(target, ast.Starred):
            bind(target.value, value)
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign):
            for t in n.targets:
                bind(t, n.value)
        elif isinstance(n, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)) and n.value is not None:
            bind(n.target, n.value)
        elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
            bind(n.target, n.iter)
    return out


def _consts(node):
    return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def _stringish(node, binds, depth=1):
    """True when node builds a command STRING: a str constant, an f-string, a %-format or a concatenation with a
    string, .format()/.join()/str(), or a name bound in this file to one of those."""
    if isinstance(node, ast.Constant):
        return isinstance(node.value, str)
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp):
        return isinstance(node.op, ast.Mod) or (isinstance(node.op, ast.Add) and
                                                 (_stringish(node.left, binds, 0) or _stringish(node.right, binds, 0)))
    if isinstance(node, ast.Call):
        f = node.func
        return (isinstance(f, ast.Attribute) and f.attr in ("format", "join")) or (isinstance(f, ast.Name) and
                                                                                   f.id == "str")
    if isinstance(node, ast.Name) and depth:
        return any(_stringish(v, binds, 0) for v in binds.get(node.id, ()))
    return False


def _shell_list(node):
    """A list or tuple literal that runs a shell's -c: ["sh", "-c", ...], ["/bin/bash", "-c", ...]."""
    if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
        return False
    first = node.elts[0]
    return isinstance(first, ast.Constant) and isinstance(first.value, str) and \
        first.value.rsplit("/", 1)[-1] in SHELLS and any(isinstance(e, ast.Constant) and e.value == "-c"
                                                          for e in node.elts)


def _unsupported_launches(rel, tree):
    """C16. A recognised launch call whose arguments (or the file's values for the names in them) name docker, in a
    form the argv pattern cannot analyse: a shell API, shell= anything but a constant False/None (a list argv
    included), a shell's -c list, a string command, or an exec/spawn call. Not covered, and so not claimed: a command
    that names no docker word, an obfuscated or data-flow-built one ("dock" + "er"), **kwargs, and calls this
    recogniser does not know (README)."""
    names, binds, out = _import_names(tree), _bindings(tree), []
    for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call)]:
        api = _dotted(call.func, names)
        if api not in SHELL_APIS | PROCESS_APIS | EXEC_APIS:
            continue
        texts = _consts(call) + [s for n in ast.walk(call) if isinstance(n, ast.Name)
                                 for v in binds.get(n.id, ()) for s in _consts(v)]
        if not any(DOCKER_WORD.search(t) for t in texts):
            continue
        cmds = list(call.args[:1]) + [k.value for k in call.keywords if k.arg == "args"]
        shell = any(k.arg == "shell" and not (isinstance(k.value, ast.Constant) and k.value.value in (False, None))
                    for k in call.keywords)
        shell_c = any(_shell_list(c) or (isinstance(c, ast.Name) and any(_shell_list(v) for v in binds.get(c.id, ())))
                      for c in cmds)
        if api in SHELL_APIS or api in EXEC_APIS or shell or shell_c or any(_stringish(c, binds) for c in cmds):
            out.append(Finding(rel, call.lineno, "C16"))
    return out


def scan_python(rel, text):
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        return [Finding(rel, e.lineno or 0, "C10")]
    found = _unsupported_launches(rel, tree)
    guard = _guard_bindings(tree)
    parent = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
    blocks = _blocks(tree)
    where = {id(st): (block, i, fn) for block, fn in blocks for i, st in enumerate(block)}
    builders, sites = set(), []
    for lst in [n for n in ast.walk(tree) if is_docker_list(n)]:
        p = parent.get(lst)
        if isinstance(p, ast.Return):
            fn = where.get(id(p), (None, None, None))[2]
            if fn is not None:
                builders.add(fn.name)
                continue
        if isinstance(p, ast.Assign) and len(p.targets) == 1 and isinstance(p.targets[0], ast.Name) and \
                id(p) in where:
            block, i, fn = where[id(p)]
            name = p.targets[0].id
            if fn is not None and any(_escapes(st, name) for st in block[i + 1:]) and \
                    not any(_is_violations_call(c, name) for st in block[i + 1:] for c in ast.walk(st)):
                builders.add(fn.name)      # it builds and returns the argv: the launch is at its callers
                impure = _uses_only_to_construct(block[i + 1:], name)
                if impure is not None:     # PR 299 review: a builder that launched before its caller's check
                    found.append(Finding(rel, impure, "C17"))
                continue
            sites.append((p, name))
            continue
        found.append(Finding(rel, lst.lineno, "C01"))
    changed = True
    while changed:                          # a function returning a builder's result is a builder too
        changed = False
        for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call) and _call_name(n) in builders]:
            p = parent.get(call)
            if isinstance(p, ast.Return) and id(p) in where and where[id(p)][2] is not None and \
                    where[id(p)][2].name not in builders:
                builders.add(where[id(p)][2].name)
                changed = True
    called = set()
    for call in [n for n in ast.walk(tree) if isinstance(n, ast.Call) and _call_name(n) in builders]:
        called.add(_call_name(call))
        p = parent.get(call)
        if isinstance(p, ast.Return):
            continue
        if isinstance(p, ast.Assign) and len(p.targets) == 1 and isinstance(p.targets[0], ast.Name) and id(p) in where:
            sites.append((p, p.targets[0].id))
            continue
        found.append(Finding(rel, call.lineno, "C02"))
    for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        if fn.name in builders and fn.name not in called:
            found.append(Finding(rel, fn.lineno, "C11"))
    for assign, name in sites:
        found += _site_place(rel, assign, where)
        found += _check_site(rel, assign, name, where, guard, tree, parent)
    return sorted(set(found), key=lambda f: (f.line, f.code))


def _site_place(rel, assign, where):
    """C20: the accepted site is a statement DIRECTLY in a function body (PR 299 reviews of 8f848049 and fa2183f1).
    A site nested in a with, try, if or loop has code around it that this check does not read: a use after the block
    (blocks do not scope Python names), a handler or finally that runs after the abort, or a with that suppresses it.
    A module-level site has no function to bound its uses. Both fail for review."""
    block, _, fn = where[id(assign)]
    return [] if fn is not None and block is fn.body else [Finding(rel, assign.lineno, "C20")]


DEFERRED = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef, ast.ListComp, ast.SetComp, ast.DictComp,
            ast.GeneratorExp)


# C21: the keyword that IS a launch API's command argument. Only these qualify as a keyword launch; the argv passed as
# env=, stdout=, cwd=, input= or any other keyword, or to an API not listed here by keyword, is not a launch of it.
COMMAND_KEYWORDS = {api: frozenset({"args"}) for api in PROCESS_APIS}


def _docker_prefix(node):
    """["docker"] or ["/path/to/docker"]: a list of exactly one constant string naming the docker binary."""
    return isinstance(node, ast.List) and len(node.elts) == 1 and isinstance(node.elts[0], ast.Constant) and \
        isinstance(node.elts[0].value, str) and node.elts[0].value.rsplit("/", 1)[-1] == "docker"


def _one_launch(rel, assign, check, after, name, fn, parent, names):
    """C21: within its function, the argv's name occurs exactly three times: as the site's target, as the check's
    argument, and as the command argument of ONE launch call after the check. Any other occurrence (a use before the
    site, a second launch, a mutation, an alias, an escape, a closure) is outside the recognised sequence.
    The supported contexts, with their AST chains (test_consumers.py asserts each chain on parsed source):
    - positional: Name -> Call (in Call.args) -> Expr | Assign -> the function;
    - command keyword: Name -> keyword (arg in COMMAND_KEYWORDS for the resolved API) -> Call -> Expr | Assign -> the
      function. ast.keyword sits between the value and the Call (PR 299 CG-r7);
    - the docker executable prefix, as either of those: Name -> BinOp(["docker"] + argv) -> ... The guard validates
      the `docker create` arguments starting at "create", so the launch puts the binary in front (PR 299 review of
      b3a9a422: a recipe argv starting with "docker" always failed the runtime guard);
    and the launch statement (that Expr, or that Assign whose value is the Call) is one of the statements after the
    check, directly in the function body. So nothing deferred can enclose the call. Refused, as not analysed:
    Starred (*argv), a **argv keyword (arg None), any other keyword, an attribute or call on argv, any other prefix
    or concatenation, Await, IfExp, BoolOp, a with item, return, and a lambda, def, class or comprehension."""
    occ = [n for n in ast.walk(fn) if isinstance(n, ast.Name) and n.id == name]
    later = [n for st in after for n in ast.walk(st) if isinstance(n, ast.Name) and n.id == name]
    known = {id(assign.targets[0]), id(check.args[0])}
    ok = len(later) == 1 and len(occ) == 3 and {id(n) for n in occ} == known | {id(later[0])}
    if ok:
        arg, p = later[0], parent.get(later[0])
        if isinstance(p, ast.BinOp) and isinstance(p.op, ast.Add) and p.right is arg and _docker_prefix(p.left):
            arg, p = p, parent.get(p)
        if isinstance(p, ast.keyword):
            call = parent.get(p)
            ok = isinstance(call, ast.Call) and p.arg in COMMAND_KEYWORDS.get(_dotted(call.func, names), ())
        else:
            call = p
            ok = isinstance(call, ast.Call) and arg in call.args
        stmt = parent.get(call)
        ok = ok and isinstance(stmt, (ast.Expr, ast.Assign)) and stmt.value is call and stmt in after
        node = call
        while ok and node is not None and node is not fn:      # kept as a second line: no deferred ancestor
            ok = not isinstance(node, DEFERRED)
            node = parent.get(node)
    return [] if ok else [Finding(rel, (later[0] if later else assign).lineno, "C21")]


def _check_site(rel, assign, name, where, guard, tree, parent):
    block, i, fn = where[id(assign)]
    rest = block[i + 1:]
    first = next((k for k, st in enumerate(rest) if _uses(st, name)), None)
    if first is None:
        return [Finding(rel, assign.lineno, "C03")]
    t = rest[first]
    if isinstance(t, ast.Expr) and _is_violations_call(t.value, name):
        return [Finding(rel, t.lineno, "C04")]
    if not (isinstance(t, ast.Assign) and len(t.targets) == 1 and isinstance(t.targets[0], ast.Name) and
            _is_violations_call(t.value, name)):
        if isinstance(t, (ast.If, ast.For, ast.While, ast.With, ast.Try)):
            return [Finding(rel, t.lineno, "C09")]
        scope = fn if fn is not None else tree
        other = any(_is_violations_call(c) and not _is_violations_call(c, name) for c in ast.walk(scope))
        return [Finding(rel, t.lineno, "C07" if other else "C03")]
    out = []
    if _dotted(t.value.func, guard) not in GUARD_CALLS:     # PR 299 security review: bind the call to the guard
        out.append(Finding(rel, t.lineno, "C14"))
    result = t.targets[0].id
    u = rest[first + 1] if first + 1 < len(rest) else None
    if not (isinstance(u, ast.If) and isinstance(u.test, ast.Name) and u.test.id == result and u.body and
            _is_abort(u.body[0])):
        return out + [Finding(rel, t.lineno, "C05")]
    if u.orelse:      # an else/elif runs after a PASSING check, outside the analysed path: refused, whatever it holds
        out.append(Finding(rel, u.lineno, "C15"))
    after = rest[first + 2:]
    if any(_mutates(st, name) for st in after):
        out.append(Finding(rel, u.lineno, "C06"))
    if any(_escapes(st, name) for st in after):
        out.append(Finding(rel, u.lineno, "C12"))
    # C13 asks only whether the argv reaches some call's argument after the check; C21 checks that argument's form
    launched = any(isinstance(c, ast.Call) and not _is_violations_call(c) and
                   any(_uses(a, name) for a in list(c.args) + [k.value for k in c.keywords])
                   for st in after for c in ast.walk(st))
    if not launched:
        out.append(Finding(rel, u.lineno, "C13"))
    if fn is not None:
        out += _one_launch(rel, assign, t.value, after, name, fn, parent, _import_names(tree))
    return out


def scan_shell(rel, text):
    return [Finding(rel, n, "C08") for n, line in enumerate(text.splitlines(), 1)
            if not line.lstrip().startswith("#") and SHELL_LAUNCH.search(line)]


def scan(root):
    """All findings under root/txe, as {relative path: [Finding]}."""
    root = Path(root)
    out = {}
    for p in sorted((root / "txe").rglob("*")):
        rel = p.relative_to(root).as_posix()
        if not p.is_file() or "testdata" in p.relative_to(root).parts or rel.startswith(SCOPE_EXCLUDE):
            continue
        if p.suffix == ".py":
            f = scan_python(rel, p.read_text(encoding="utf-8", errors="replace"))
        elif p.suffix in (".sh", ".bash"):
            f = scan_shell(rel, p.read_text(encoding="utf-8", errors="replace"))
        else:
            continue
        if f:
            out[rel] = f
    return out


def _defines(path, sym):
    text = path.read_text(encoding="utf-8", errors="replace")
    return re.search(rf"^\s*(?:def|class|func)\s+{re.escape(sym)}\b", text, re.M) is not None


def _guard_refs_ok(root, refs, cls):
    """ALTERNATE_GUARD: one or more full references, none PARTIAL. LEGACY_BOUNDARY: 'none', or PARTIAL ones only.
    Every reference must name a symbol and a test that exist."""
    if refs == "none":
        return cls == "LEGACY_BOUNDARY"
    for ref in refs.split(" | "):
        m = GUARD_REF.fullmatch(ref)
        if not m or (m["scope"] is None) != (cls == "ALTERNATE_GUARD"):
            return False
        src, test = root / m["src"], root / m["test"]
        if not (src.is_file() and test.is_file() and _defines(src, m["sym"]) and _defines(test, m["tname"])):
            return False
    return True


def _cites_ok(root, cites, cls):
    if cites == "-":
        return cls == "ALTERNATE_GUARD"
    for c in cites.split(";"):
        m = CITE.fullmatch(c)
        if not m or not (root / m["file"]).is_file():
            return False
        lines = (root / m["file"]).read_text(encoding="utf-8", errors="replace").splitlines()
        if int(m["line"]) > len(lines) or not lines[int(m["line"]) - 1].strip():
            return False
    return True


def check_registry(root, rows_text, findings, registry="UNGUARDED.tsv"):
    """Problems with the registry (header line first, TAB-separated), and the set of paths it validly classifies."""
    root = Path(root)
    problems, classified, seen = [], set(), set()
    lines = rows_text.splitlines()
    if not lines or tuple(lines[0].split("\t")) != REGISTRY_COLUMNS:
        return [Finding(registry, 1, "E01")], classified
    for n, line in enumerate(lines[1:], 2):
        cols = line.split("\t")
        if len(cols) != len(REGISTRY_COLUMNS) or any(c.strip() != c or not c for c in cols):
            problems.append(Finding(registry, n, "E01"))
            continue
        cls, path, digest, ticket, difference, use, refs, cites, owner, review = cols
        bad = []
        if cls not in CLASSES:
            bad.append("E08")
        if path in seen:
            bad.append("E07")
        seen.add(path)
        f = root / path
        if not HEX64.fullmatch(digest) or not f.is_file() or hashlib.sha256(f.read_bytes()).hexdigest() != digest:
            bad.append("E09")
        if len(difference) < 30 or not TICKET.fullmatch(ticket):
            bad.append("E02")
        if cls == "LEGACY_BOUNDARY" and not use.startswith("manual-only: "):
            bad.append("E10")
        if not _guard_refs_ok(root, refs, cls):
            bad.append("E04")
        if not _cites_ok(root, cites, cls):
            bad.append("E11")
        if not EVIDENCE.fullmatch(owner):
            bad.append("E06")
        if not EVIDENCE.fullmatch(review):
            bad.append("E03")
        if path not in findings:
            bad.append("E05")
        problems += [Finding(registry, n, code) for code in bad]
        if not bad:
            classified.add(path)
    return problems, classified


def report(root):
    """Every finding not validly classified, plus every registry problem. [] means the check passes."""
    root = Path(root)
    findings = scan(root)
    reg = Path(__file__).resolve().parent / "UNGUARDED.tsv"
    problems, classified = check_registry(root, reg.read_text(encoding="utf-8") if reg.is_file() else "", findings)
    return problems + [f for path, fs in sorted(findings.items()) if path not in classified for f in fs]


if __name__ == "__main__":
    bad = report(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[2])
    for f in bad:
        print(f)
    sys.exit(1 if bad else 0)
