# containerguard: one shared launch guard for container runners (TXE-8041)

Container runners that drive `docker create` copied a guard from `runner-final`. That guard joined the argv into one
string and searched it for substrings, which caused two problems:
- **It could not tell a Docker option from text inside the command it launches.** A reviewed payload holding
  `command -v` or `go test -v` read as Docker's `-v`. That is how TXE-8039's KG-r2 run failed 88/89.
- **Any option it did not list passed.**

`argv_guard.py` replaces it. It reads the options by position, against an exact schema of the run, and compares the
payload whole. `consumers.py` checks that the launchers in this tree use it, or carry a reviewed, hash-bound row in
`UNGUARDED.tsv`.

## The guard (`argv_guard.py`)

```python
from argv_guard import Schema, violations

schema = Schema(image="sha256:…", work_dir=W, scratch=SCRATCH, flags=frozenset({"--read-only", "--init"}),
                single={…}, repeated={"--label": (…), "--env": (…), "--mount": (…)},
                last_option="--entrypoint", payload=("-c", WRAPPED_SCRIPT))
argv = build_argv()
bad = violations(argv, schema)
if bad:
    raise Refused(f"argv: {[str(v) for v in bad]}")    # redacted codes only; never print argv
launch(argv)
```

**The schema is one run's exact argv:**
- each single-valued option with its value;
- each repeated option with its exact set;
- the boolean flags;
- the pinned image, and the option that comes right before it;
- the payload tokens.

**`check_schema` is a floor that no schema can loosen.** It is structural:
- paths are absolute and canonical with ONE leading `/`, and the work dir lies strictly inside scratch. A leading
  `//` is refused in every path input (scratch, work dir, mount source and target, tmpfs, writable target): POSIX
  `normpath` keeps it, but Linux resolves `//proc` as `/proc`, so the guard spells the rule out instead of relying on
  `normpath`. A declared writable target must also lie outside the system trees (`S19`);
- mounts are canonical bind mounts, sourced strictly inside the work dir, with unique targets outside the kernel and
  runtime trees, and read-only unless their target is declared writable;
- nothing is mounted from or onto a Docker socket;
- `--network none`, `--pull never`, `--cap-drop ALL`, `--security-opt no-new-privileges` and `--read-only` are fixed;
- the user is set and is not root;
- the image is a digest;
- env and label keys are well formed and unique, with credential-named env keys refused;
- each policy option has exactly one kind: `--mount`, `--env`, `--label` and `--tmpfs` are repeated; `--network`,
  `--pull`, `--cap-drop`, `--security-opt` and `--user` are single; `--read-only` is a flag. Declaring one in another
  kind would skip its rules, so it is refused;
- every schema option is listed in `CREATE_OPTIONS`: the canonical LONG `docker create` options the launchers use,
  each with docker/cli's own arity (v29.7.1: a boolean is a flag; a StringVar or single-value option is `single`; an
  accumulating list option may be `single` or `repeated`). A short alias (`-u`, `-w`, …) or any unlisted option is
  refused. So is an option in a kind its arity forbids: a docker boolean declared as taking a value would let the guard
  read the next token as its value while docker applied that token as an option. Widening the table is a reviewed
  change;
- no schema value starts with `-` (`S18`), which docker could read as an option.

**A value's text does not prove it holds no secret.** What makes the env safe is that it must equal the reviewed
schema, which is source.

**`violations` reads the argv by position:**
- options as tokens up to the image, each in the schema, with its exact value, once;
- a denied option, an `--opt=value` form or an unknown option refuses, and parsing STOPS;
- the image must follow the schema's last option;
- the payload must equal the schema's, compared whole and never parsed;
- the argv is never joined.

**Diagnostics are redacted.** A `Violation` is a stable code (see `CODES`), plus:
- an option name, only when it is a schema option or a denied one;
- a position;
- counts.

It never contains a value or an unknown token from the argv or the schema. This is a validator for a fixed, reviewed
argv. **It is not a safe logger of arbitrary argv**, and a caller must not print the argv it refuses.

## The consumer check (`consumers.py`): an AST HEURISTIC, not a data-flow proof

`consumers.py` scans `*.py`, `*.sh` and `*.bash` under `txe/`. It skips `testdata/` and this directory.

It sorts what it sees into three categories. **It does not claim complete coverage.** The runtime guard
(`argv_guard.violations`, called by the launcher) is what enforces the policy. This check is a fail-closed gate for
the forms it recognises, and it is incomplete outside its recogniser.

### The supported recipe

A launcher in this repository that wants the check to accept it is written exactly like this:

```python
# The supported recipe (consumers.py accepts exactly this shape; anything else fails for review).
import subprocess

from txe.containerguard.argv_guard import Schema, violations   # package-qualified, module level, bound once


def launch(schema: Schema) -> None:
    argv = ["docker", "create", "--name", "n", "--network", "none", "img", "true"]   # directly in the function body
    bad = violations(argv, schema)                     # the SAME name, the result kept
    if bad:                                            # no else or elif
        raise SystemExit("argv_guard refused the launch")   # raise or return, with no call in it
    subprocess.run(argv, check=True)                   # ONE launch: argv appears nowhere else in the function
```

`test_consumers.py` reads this block from the README and requires the check to accept it, so the recipe cannot drift
from the check. Accepted variants:
- the list built by a builder function in the same file, which only constructs and returns it, and whose result is
  assigned (`argv = build(...)`);
- `import txe.containerguard.argv_guard as guard` with `guard.violations(...)`;
- the launch taking the argv as a keyword argument (`subprocess.run(args=argv)`).

### 1. Recognised and validated

A **launch** is a list literal that has:
- a launch verb (`create` or `run`) and a launch mark (`--network`, `--mount`, `--cidfile`, `--entrypoint`,
  `--cap-drop`, `--security-opt`); or
- a launch mark and any dynamic element, since the verb may be in a variable; or
- a constant `docker` followed by a dynamic second element.

It is ACCEPTED only in the recipe's shape:
- the site (`argv = <list>` or `argv = build(...)`) is a statement **directly in a function body**;
- the next use is `bad = violations(argv, …)`, with `violations` bound to `txe.containerguard.argv_guard` by one
  module-level import. The name is bound once in the file and the module is never patched;
- the next statement is `if bad:` whose first statement is `raise …` or `return …`, with no call (other than an
  exception class), await, yield or walrus in it;
- after that, the argv's name appears in exactly ONE call argument, the launch. In the whole function it appears
  only as the site's target, the check's argument and that launch argument, and the launch is not inside a nested
  def, lambda, class or comprehension.

### 2. Unsupported, so refused (a finding, codes `C01`–`C21`)

A recognised launch in any other form fails for review. These forms include:
- a site not directly in a function body: module-level, or nested in a `with`, `try`, `if` or loop (`C20`);
- any other occurrence of the argv's name in its function (`C21`):
  - a use before the site or after the launch;
  - a second launch;
  - an alias;
  - a launch inside a nested def, lambda or comprehension;
- an ignored result, or a different argv checked;
- use before the check, or a change after it, including an alias (`x = argv`);
- an `else` or `elif` on the abort (`C15`);
- an abort with a side effect (`return subprocess.run(argv)`) (`C05`);
- a CALL as the abort (`sys.exit(…)`, `exit(…)`, `os._exit(…)`) (`C05`): a callee can be shadowed to return. Use
  `raise SystemExit(n)`;
- an inline list;
- a builder used inline, or never called in its file (cross-module use is not analysed);
- a builder that launches, passes, aliases, stores or yields its argv before returning it (`C17`);
- a check inside a branch;
- a checked argv that escapes or is never launched;
- a `violations` that is not argv_guard's (`C14`):
  - a local or fallback definition;
  - an import inside a `try`, `if` or `def`;
  - a name bound twice;
  - a star import;
  - a patched module;
  - a dynamic `importlib` load;
  - a module other than `txe.containerguard.argv_guard`. That includes the bare `argv_guard`, which can resolve to a
    sibling `argv_guard.py`. A path or name suffix is not provenance;
- a shell `docker run/create` in a `.sh` or `.bash` file;
- in Python, a process launch that names `docker` in an unsupported form (`C16`). The launch is a call to a known
  `subprocess`, `os` or `asyncio` function, through any import alias (`import subprocess as sp`,
  `from os import system as sh`). The forms are:
  - a shell: `shell=True`, with a string or a list; `os.system`; `os.popen`; `create_subprocess_shell`;
  - a shell's `-c` list (`["sh", "-c", …]`);
  - a string command, including one built from an f-string, a concatenation or `.format`, directly or through a name
    bound in the file;
  - an `exec*`, `spawn*` or `create_subprocess_exec` call;
- an unparsable file.

### 3. Not detected

The heuristic does not see these, so the code under it is unchecked, and reviewers still read the launch path:
- a launch whose argv is not a list literal of the shapes above: built in another module, read from data, or
  `[DOCKER, verb, *opts]` with no constant mark;
- a shell or string command without the word `docker`, and an obfuscated or data-flow-built command
  (`"dock" + "er"`);
- arguments passed through `**kwargs`, and launch functions the recogniser does not know (`exec()`, `importlib`, a
  wrapper in another module);
- a callee that changes its argument in place, and side effects inside a property or an exception's `__init__`;
- **module identity.** The package-qualified import reduces accidental resolution to a sibling module, but it is
  NOT cryptographic module identity. The check assumes the repository's source root is what Python imports
  `txe.containerguard.argv_guard` from. It makes no claim about an arbitrary Python path or arbitrary code.

These limits cover forms the AST cannot observe. They do not excuse a recognised shape: an accepted shape that
launches, aborts with a side effect, or calls a fake guard is a bug in this check, and is fixed rather than
documented.

### Launchers that do not use the guard (`UNGUARDED.tsv`)

A launcher that does not use the guard needs one row. Each row has one of two DISTINCT classes:

- **`ALTERNATE_GUARD`:** the launcher enforces the same properties another way. Its guard references are complete,
  and none is `PARTIAL`. It claims equivalence, and is reviewed as such.
- **`LEGACY_BOUNDARY`:** a reviewed legacy tool, or a tool with a different purpose. It is **NOT certification
  against the floor.** It states its difference and its authorized manual-only use. Its guard references are `none`
  or `PARTIAL(<scope>)` only, so it can never claim equivalence. It cites the exact lines it was reviewed at.

The row has ten TAB-separated columns:

| column | must be |
|---|---|
| `class` | `ALTERNATE_GUARD` or `LEGACY_BOUNDARY` |
| `path` | the exact file. The row is stale (`E05`), and fails, once that file has no finding |
| `sha256` | the file's exact sha256. ANY edit to the file invalidates the row (`E09`) until it is re-reviewed |
| `ticket` | `TXE-<n>` |
| `difference` | 30+ characters: what differs from the floor, and why |
| `authorized_use` | for `LEGACY_BOUNDARY`, starting `manual-only: ` |
| `guard_refs` | `<src>:<symbol>; tested by <test>:<name>` entries, separated by ` \| `, naming code and tests that exist. `LEGACY_BOUNDARY`: `none` or `PARTIAL(<scope>) …` only |
| `cites` | `<txe path>:<line>` entries separated by `;`, each an existing non-blank line. `-` only for `ALTERNATE_GUARD` |
| `owner_ack` | the owning ticket owner's acknowledgment: a review message id (`msg_<12 hex>`) or a txehq PR review link |
| `review_evidence` | the same form. A name is not approval |

There are no wildcard rows. A ticket id alone classifies nothing.

**The current rows:** `txe/mutate/mutate-sandboxed.py` and `txe/mutate/fixture-demo.py` (TXE-7549) are
`LEGACY_BOUNDARY`:
- the runner's `--network` is configurable; its `check_mounts` is a PARTIAL guard (mounts only);
- the demonstration's outer container intentionally runs with a writable root and the image's user. That is a
  demonstration boundary, not enforcement.

The evidence for both rows:
- `review_evidence` is the independent review that accepted both rows, `msg_f5d1db2e4e66`;
- `owner_ack` is the current custodian's acknowledgment, `msg_e244f71997d3`.

**Provenance:** TXE-7549's tools were written by cc7, then held by cc4-s246524. That contact is currently unreachable,
so the acknowledgment is the current custodian's.

### What these classifications do and do not mean

- **A hash change invalidates only that file's row.** Editing one file voids its own row until it is re-reviewed. Other
  rows are untouched.
- **"manual-only" is the permitted use under THESE source-row classifications.** It is not a claim that no reviewed,
  vendored copy runs in CI (TXE-8034's does). It neither revokes nor broadens any separate, explicit CI or runtime
  authorization. A classification authorizes no run, no network-enabled mutation, no adoption change and no edit to a
  pinned tool.
- **The checks validate a record's SHAPE, not the truth of an approval.** A well-formed message id says nothing about
  whether that message approved the row. Human or reviewer inspection of the cited evidence stays part of every registry
  review.

## Runners outside this repository

Evidence-tree runner packets (for example `~/Projects/txe-evidence/…/runner-kg-r3.py`) are **not covered by this
repository's CI.** A NEW runner revision adopts the guard like this:
- it loads `argv_guard.py` from a pinned commit of this repository, by blob sha256 (the `mutate-sandboxed` launcher
  pattern), and never vendors a copy;
- its packet's pure tests assert two things:
  1. the bytes it loaded hash to the pin;
  2. its launch path calls this module's `violations` on the argv it creates, and raises on any finding.

```python
GUARD_PIN = ("<commit>", "txe/containerguard/argv_guard.py", "<sha256>")

def test_the_launch_guard_is_the_pinned_shared_module(runner):
    assert hashlib.sha256(runner.GUARD_BYTES).hexdigest() == GUARD_PIN[2]
    assert runner.argv_violations.__module__ == "argv_guard" or runner.GUARD.violations is runner.check_with
```

The coordinator's packet review checks that both tests are there. The historical copies of the old guard in evidence
packets stay as they ran.
