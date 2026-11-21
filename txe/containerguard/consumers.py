# SPDX-License-Identifier: GPL-3.0-or-later
"""The consumer check for argv_guard (TXE-8041): every container launcher under txe/ validates the argv it launches,
or is classified by a reviewed, hash-bound row in UNGUARDED.tsv, as ALTERNATE_GUARD (equivalent enforcement) or
LEGACY_BOUNDARY (a reviewed legacy boundary or different purpose, NOT certified against the floor).

THIS IS AN AST HEURISTIC, NOT A PROOF OF DATA FLOW. It recognises one written pattern and fails everything it cannot
recognise. Importing violations() and calling it somewhere does not show that the launched argv was validated or that
the findings were enforced. So the check demands this exact shape, in one function and one block:

    argv = <a docker argv list literal>        or   argv = <a builder in this file>(...)
    bad = violations(argv, <schema>)               # argv_guard's, on the SAME name, result kept
    if bad:
        raise ... | return ... | sys.exit(...)     # fail closed, first statement of the branch
    ... launch(argv) ...                           # argv not reassigned, extended, item-set or deleted after the check

A docker argv is a list literal holding "create" or "run" and one of LAUNCH_MARKS. A builder is a function in the
same file that returns such a list. A call to a builder outside an assignment, a list used inline, a builder with no
caller in its file (cross-module use is not analysed), a shell `docker run/create`, an unparsable file, a check in a
different block, an ignored result, a different argv checked, the argv used before its check, a mutation after it, a
checked argv that escapes or is never launched: each is a finding. Anything ambiguous fails for review.

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
    "C14": "violations() is called but argv_guard is not imported in this file",
    "C15": "the abort conditional has an else or elif branch (it runs after a passing check, unanalysed)",
}
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
    if not isinstance(node, ast.List):
        return False
    s = _strs(node)
    return bool(s & LAUNCH_VERBS) and any(x in LAUNCH_MARKS or x.startswith("--network=") for x in s)


def _uses(node, name):
    return any(isinstance(n, ast.Name) and n.id == name for n in ast.walk(node))


def _call_name(call):
    f = call.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None


def _is_violations_call(node, name=None):
    if not (isinstance(node, ast.Call) and _call_name(node) == "violations"):
        return False
    return name is None or (bool(node.args) and isinstance(node.args[0], ast.Name) and node.args[0].id == name)


def _is_abort(stmt):
    if isinstance(stmt, (ast.Raise, ast.Return)):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        f = stmt.value.func
        return (isinstance(f, ast.Name) and f.id == "exit") or (
            isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and
            (f.value.id, f.attr) in (("sys", "exit"), ("os", "_exit")))
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


def scan_python(rel, text):
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        return [Finding(rel, e.lineno or 0, "C10")]
    found = []
    imports_guard = any(
        (isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[-1] == "argv_guard") or
        (isinstance(n, ast.Import) and any(a.name.split(".")[-1] == "argv_guard" for a in n.names)) or
        (isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.endswith("argv_guard.py"))
        for n in ast.walk(tree))
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
        found += _check_site(rel, assign, name, where, imports_guard, tree)
    return sorted(set(found), key=lambda f: (f.line, f.code))


def _check_site(rel, assign, name, where, imports_guard, tree):
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
    if not imports_guard:
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
    launched = any(isinstance(c, ast.Call) and not _is_violations_call(c) and
                   any(isinstance(a, ast.Name) and a.id == name for a in c.args)
                   for st in after for c in ast.walk(st))
    if not launched:
        out.append(Finding(rel, u.lineno, "C13"))
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
