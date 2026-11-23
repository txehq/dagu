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
from argv_guard import Schema, check_mount_sources, violations

schema = Schema(image="sha256:…", work_dir=W, scratch=SCRATCH, flags=frozenset({"--read-only", "--init"}),
                single={…}, repeated={"--label": (…), "--env": (…), "--mount": (…)},
                last_option="--entrypoint", payload=("-c", WRAPPED_SCRIPT))
argv = build_argv()
bad = violations(argv, schema)
if bad:
    raise Refused(f"argv: {[str(v) for v in bad]}")    # redacted codes only; never print argv
fs = check_mount_sources(schema)                       # the filesystem floor, immediately before the create
if fs:
    raise Refused(f"mounts: {[str(v) for v in fs]}")
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
- the user is set to exactly `uid:gid`, BOTH required and both canonical positive decimals (`--user 1000:1000`).
  Refused (`S13`):
  - a bare uid (`--user 1000`): its primary group would resolve through the image's defaults;
  - a name, which resolves inside the image, where any name can be uid 0;
  - uid or gid 0 in any spelling (Docker's `strconv.Atoi` reads `00`, `+0` and `-0` as 0);
  - a leading zero, a sign or whitespace;
  - an empty uid or gid (`""`, `":"`, `"1000:"`);
  - an extra colon component (`1000:1000:1000`).

  This floor governs the REQUESTED container user only, not every privilege transition an image or runtime can
  make (a setuid binary inside the image, for example);
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
- a schema that fails `check_schema` is reported as such, and the argv is NOT parsed against it;
- options as tokens up to the image, each in the schema, with its exact value, once;
- a denied option, an `--opt=value` form or an unknown option refuses, and parsing STOPS;
- the image must follow the schema's last option;
- the payload must equal the schema's, compared whole and never parsed;
- the argv is never joined.

**`check_mount_sources` is the filesystem floor**, a preflight the launcher runs immediately before `docker create`
(the consumer check requires it, `C22`). `check_schema` and `violations` compare canonical path STRINGS, but Docker
resolves a bind source on the host and follows links: `work/innocent -> /var/run/docker.sock` passed both. This
function reads the host with `lstat` only and never follows a link:
- the work dir, every component from `/` down: a symbolic link anywhere (`F01`), a missing component or any other
  inspection error (`F03`), or a work dir that is not a directory (`F02`) refuses;
- EVERY bind source, readonly and writable, every component from `/` down: a symbolic link anywhere (`F01`), a
  missing component or any other inspection error (`F03`), or a source that is neither a directory nor a regular file,
  such as a socket, device or FIFO (`F02`), refuses;
- it adds no root of its own. `check_schema` already holds every source, readonly or writable, strictly inside the
  work dir (`S06`); this check narrows nothing further;
- the `--cidfile`, when the schema has one. The docker CLI creates and writes it on this host, so it is the same
  host-path class: it must be a canonical absolute path (`F05`); every component from `/` through its PARENT must be
  a directory chain with no symbolic link (`F01`), present and readable (`F03`), ending in a directory (`F02`); and
  the leaf must NOT exist in any form, a dangling link included, which is read with `lstat` and never followed
  (`F04`). Only "no such file" on the leaf is clean. Docker's own exclusive create of the cidfile (`O_EXCL`) remains
  a second, independent check at create time;
- a schema that fails `check_schema` is reported as such, and nothing is read.

Its limits, stated plainly:
- **This PR is source-only delivery. It is NOT an adoption or platform-compatibility approval.**
- **It is a preflight on the filesystem this process sees.** It establishes nothing about what a Docker daemon
  elsewhere mounts. A remote daemon (`DOCKER_HOST` over TCP or SSH) or a daemon in a different mount namespace is
  NOT supported.
- **VM-backed daemons are UNVERIFIED: Docker Desktop, OrbStack and any other daemon that runs in a VM.** Their bind
  sources are host paths served into the VM by the runtime's file sharing. That this preflight's view matches what
  such a daemon actually mounts is NOT measured (this PR runs no Docker probe), and the same path spelling on both
  sides does NOT establish that the same object is mounted. Adoption on these runtimes is unsupported until that
  equivalence is measured.
- **It is a point-in-time read, not proof against concurrent change.** Owning the work dir alone does not remove the
  race: the caller must ensure that no untrusted writer can create, replace or rename any source path, the cidfile's
  parent, or any of their ancestors from this check until `docker create` returns.
- **A hard link is not detected.** A hard link to a regular file elsewhere on the same filesystem is itself a regular
  file. (A hard-linked socket is still a socket, and is refused by `F02`.)
- **It governs the host side of a bind mount only.** Links INSIDE a mounted directory resolve in the container's own
  view at run time, and the requested-user limits above still apply.

**Diagnostics are redacted, by the `Violation` type itself.** A `Violation` is a stable code (see `CODES`), plus:
- an option name, only when it is in `NAMEABLE`: the listed create options and the denied ones, all module
  constants. Anything else is stored as `<unrecognised option>`, whatever the call site passes;
- a fixed detail phrase or a count template; anything else is stored as `<redacted>`;
- a position.

It never contains a value, a path, an unknown token from the argv, or a schema key. This is a validator for a fixed,
reviewed argv. **It is not a safe logger of arbitrary argv**, and a caller must not print the argv it refuses.

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

from txe.containerguard.argv_guard import Schema, check_mount_sources, violations   # package-qualified, module level


def launch(schema: Schema) -> None:
    # The `docker create` arguments argv_guard validates: from "create", every option the schema lists, the pinned
    # image, then the payload. The site is a statement directly in the function body.
    argv = ["create", "--name", "txe-example", "--pull", "never", "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--read-only", "--user", "1000:1000", "--entrypoint", "/bin/true",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "x"]
    bad = violations(argv, schema)                     # the SAME name, the result kept
    if bad:                                            # no else or elif
        raise SystemExit("argv_guard refused the launch")   # raise or return, with no call in it
    fs = check_mount_sources(schema)                   # the SAME schema, at once: the host filesystem floor
    if fs:                                             # no else or elif
        raise SystemExit("argv_guard refused the mounts")
    subprocess.run(["docker"] + argv, check=True)      # the NEXT statement, ONE launch: docker, then the argv
```

`test_consumers.py` reads this block from the README and checks it, so the recipe cannot drift:
- the consumer check must accept it;
- it is EXECUTED against the real runtime guard, with a fake `subprocess` that records its call and never starts a
  process:
  - for the matching schema, `check_schema` and `violations` return `[]`, and `launch` calls `subprocess.run` exactly
    once, with `["docker"] + argv`;
  - for a schema the argv does not match, `launch` raises `SystemExit` and calls nothing;
  - its `check_mount_sources` runs for real, against a fresh work dir the test makes; for a work dir reached through
    a symbolic link, `launch` raises `SystemExit` and calls nothing.

**A separate prerequisite: the executable.** `"docker"` is resolved by the launcher's `PATH`, or the absolute path
given in the prefix. Neither this check nor the guard verifies which binary that is: making it the reviewed Docker
client is the launcher's environment's job.

Accepted variants:
- the list built by a builder function in the same file, which only constructs and returns it, and whose result is
  assigned (`argv = build(...)`);
- `import txe.containerguard.argv_guard as guard` with `guard.violations(...)`;
- the launch taking the argv as the API's own command keyword: `args=` on `subprocess.run`, `Popen`, `call`,
  `check_call` or `check_output` (`subprocess.run(args=argv)`), through any import alias of `subprocess`;
- the launch's result assigned (`proc = subprocess.run(["docker"] + argv)`);
- the argv itself as the argument (`subprocess.run(argv)`). The AST check accepts this, but the runtime guard only
  passes an argv that starts with `create`, so this form launches nothing useful. Use the docker prefix.

### 1. Recognised and validated

A **launch** is a list literal that has:
- a launch verb (`create` or `run`) and a launch mark (`--network`, `--mount`, `--cidfile`, `--entrypoint`,
  `--cap-drop`, `--security-opt`); or
- a launch mark and any dynamic element, since the verb may be in a variable; or
- a constant `docker` followed by a dynamic second element; or
- a constant `docker` with a constant launch verb, with or without marks (`["docker", "run", "--privileged", …]`).

It is ACCEPTED only in the recipe's shape:
- the site (`argv = <list>` or `argv = build(...)`) is a statement **directly in a function body**;
- the next use is `bad = violations(argv, …)`, with `violations` bound to `txe.containerguard.argv_guard` by one
  module-level import. The name is bound once in the file, the module is never patched, and the guard name occurs
  ONLY in that import and as the check call's callee;
- the next statement is `if bad:` whose first statement is `raise …` or `return …`, with no call (other than an
  exception class), await, yield or walrus in it;
- the two statements right after that abort are `fs = check_mount_sources(<the check's schema>)`, bound to
  `txe.containerguard.argv_guard` exactly as `violations` is, and `if fs:` with the same kind of abort and no `else`
  (`C22`);
- the launch is the statement IMMEDIATELY after that `if fs:` abort, with no statement between them (`C22`), and
  its callee and arguments contain no call, await, yield or walrus (`C22`). That bounds what the check can see. It
  does not prove that evaluating the launch's callee and arguments has no effect: an attribute read can run a
  property or `__getattr__`. The caller must keep that evaluation free of filesystem changes;
- after that, the argv's name appears exactly ONCE, as the launch's command argument. That is a positional argument
  or the API's command keyword above, either as `argv` itself or with the docker binary in front (`["docker"] + argv`,
  a one-element list naming docker). In the whole function it appears only as the site's target, the check's
  argument and that one argument. The launch call is an expression statement, or the value of an assignment,
  directly in the function body after the check. `test_consumers.py` asserts the AST chain of each supported and
  refused context on parsed source:
  - `f(argv)`: Name → Call → Expr / Assign;
  - `f(args=argv)`: Name → keyword → Call → Expr / Assign;
  - `f(["docker"] + argv)`: Name → BinOp → Call (or → keyword → Call) → Expr / Assign.

### 2. Unsupported, so refused (a finding, codes `C01`–`C22`)

A recognised launch in any other form fails for review. These forms include:
- a site not directly in a function body: module-level, or nested in a `with`, `try`, `if` or loop (`C20`);
- any other occurrence of the argv's name in its function (`C21`):
  - a use before the site or after the launch;
  - a second launch;
  - an alias;
  - a launch inside a nested def, lambda or comprehension;
  - the argv as any other keyword (`env=`, `stdout=`, `cwd=`, `input=`, or `args=` on an API not listed);
  - `*argv`, `**argv`, an attribute or call on it (`argv.copy()`), or any prefix or concatenation other than a
    one-element list naming docker (`["podman"] + argv`, `argv + […]`, `[DOCKER] + argv`);
  - a launch that is awaited, conditional (`… if … else …`), a `with` item or returned;
- an ignored result, or a different argv checked;
- the filesystem check omitted, its result ignored, run anywhere but right after the argv check's abort (after the
  launch, before the argv check, or with a statement between), on another schema or by keyword, not bound to
  argv_guard's, or without a fail-closed abort, or with an `else`; ANY statement between its abort and the launch
  (a helper such as `replace_source()`, a `log(…)` call, an assignment); or a launch whose callee or arguments call
  something (`subprocess.run(argv, stdout=open(…))`, `factory().run(argv)`) (`C22`);
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
  - a patched module or guard function. That covers any assignment target, including unpacking
    (`(g.violations,) = …`), nesting, starred, augmented, annotated, deleted, or a for or with target. It also covers
    an attribute of the function (`g.violations.__code__ = …`) and a subscript of the module
    (`g.__dict__[…] = …`);
  - an unresolved rebinding: a write into `globals()`, `vars()` or `locals()`, or any `exec` or `eval`;
  - ANY other reference to the guard name: a read or alias (`h = g.violations`), an argument (`f(violations)`,
    `vars(g)`), or a namespace mutation through any API (`g.__dict__.update(…)`, `.setdefault`, `.__setitem__`).
    Only the import and the check call are allowed;
  - the guard module reached by name: a string naming it, `sys.modules`, `importlib` or `__import__`;
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
  `txe.containerguard.argv_guard` from. It makes no claim about an arbitrary Python path or arbitrary code;
- **executable identity.** Which `docker` binary `PATH` resolves is outside both this check and the guard;
- arbitrary Python effects in general. The check refuses the unresolved rebindings it can see (`exec`, `eval`, a
  write into `globals()`, `vars()` or `locals()`), but it does not claim completeness against every way Python code
  can change behaviour at run time;
- **guard tampering beyond this file.** The closed-use rule is a static rule over the recognised forms in one file:
  the guard's own module-level import and its check call, with any other reference to the guard name or module in
  that file refused. It does not make tampering impossible. Another module, an import-time side effect, a
  monkeypatch from a test harness, or other run-time state can still change the guard. The runtime
  `argv_guard.violations` call remains the enforcer.

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

The evidence for each row is bound to that row's exact bytes (TXE-8053):
- `txe/mutate/fixture-demo.py` (836458c6): `review_evidence` is root's scoped exact-byte source review,
  `msg_8aa61a2eb4f7`, and `owner_ack` is the current custodian's (cc3-s975c73) acknowledgment of the same,
  `msg_47e1330eb699`.
- `txe/mutate/mutate-sandboxed.py` (c76ed2f7, the bytes with `--diagnostic`, `--ro-mount`, chunked file
  hashing and the mount-field refusal): REVIEW PENDING. The row still cites `msg_590f75e91493` (root's scoped
  review) and `msg_e8ac8fe99474` (the custodian's acknowledgment), which cover the previous bytes, 7803b411. Both
  are replaced by the review and acknowledgment of c76ed2f7 before this merges.
Each review accepts the classification and the declared partial guards only. It is not a fixed-argv floor
attestation, not behavioural acceptance and not adoption or a global pin.

**Historical evidence, kept apart:**
- `msg_8aa61a2eb4f7` and `msg_47e1330eb699` also covered the runner's earlier TXE-8053 bytes (e9d6e717), which this
  branch no longer has.
- `msg_f5d1db2e4e66` and `msg_e244f71997d3` covered the TXE-7549 bytes, which no longer exist on this branch either,
  so the TXE-7549 acceptance the rows cite is historical.

Any executable change to either file voids its row.

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
  2. its launch path calls this module's `violations` on the argv it creates, then `check_mount_sources` on the same
     schema immediately before the create, and raises on any finding of either.

**A pin is a snapshot.** A consumer pinned to an older `argv_guard.py` digest keeps that version's rules. It is NOT
upgraded, or validated, by any later change to this module or by the tests that validate it. That includes the
numeric-user rule (`S13`): a consumer gets it only by moving its pin and re-running its own packet. It also includes
the filesystem floor: an older consumer gets neither `check_mount_sources` nor its rules until it moves its pin AND
adds the call to its launch path, and it is not protected against a symlinked bind source until then.

```python
GUARD_PIN = ("<commit>", "txe/containerguard/argv_guard.py", "<sha256>")

def test_the_launch_guard_is_the_pinned_shared_module(runner):
    assert hashlib.sha256(runner.GUARD_BYTES).hexdigest() == GUARD_PIN[2]
    assert runner.argv_violations.__module__ == "argv_guard" or runner.GUARD.violations is runner.check_with
```

The coordinator's packet review checks that both tests are there. The historical copies of the old guard in evidence
packets stay as they ran.
