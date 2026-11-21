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
- paths are absolute and normalised, and the work dir lies strictly inside scratch;
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

**It recognises a launch:** a list literal holding `create` or `run` and one of `--network`, `--mount`, `--cidfile`,
`--entrypoint`, `--cap-drop` or `--security-opt`. That list is either assigned directly, or returned by a builder in
the same file whose result is assigned.

**It accepts exactly one shape,** in the same function and block:

```python
argv = …                       # the docker list, or builder(...)
bad = violations(argv, schema) # argv_guard's, on the SAME name, result kept
if bad:                         # no else or elif
    raise … / return … / sys.exit(…)
… launch(argv) …               # argv never reassigned, extended, item-set, deleted or aliased after the check
```

**Everything else is a finding** (codes `C01`–`C15`), and ambiguity fails for review. That includes:
- an ignored result;
- a different argv checked;
- use before the check, or a change after it, including an alias (`x = argv`);
- an `else` or `elif` on the abort (it runs after a passing check);
- an inline or dynamic list;
- a builder used inline, or never called in its file (cross-module use is not analysed);
- a check inside a branch;
- a checked argv that escapes or is never launched;
- a missing `argv_guard` import;
- a shell `docker run/create`;
- an unparsable file.

Importing `violations` and calling it somewhere is NOT accepted as proof that the launched argv was validated. The
heuristic also cannot see a callee that changes its argument in place (for example `extend_args(argv)` after the
check). Reviewers still read the launch path.

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
