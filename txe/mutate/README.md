# mutate-sandboxed: mutation tests that cannot reach the host (TXE-7549)

A mutant breaks a guard on purpose. On 2026-11-16 a hand-written mutant runner ran one with the
session's real environment, and the code under test deleted the Mac's shared Go module cache
(postmortem TXE-7547: txehq/txe `docs/postmortems/2026-11-16-shared-gomodcache-deletion.md`).
Mutation tests run only through this runner, never through a per-ticket script.

```sh
mutate-sandboxed --mutants mutants.json --tree . --image sha256:<local image id> -- go test ./internal/intg/machineauth/...
# ~/.coding_global/bin/mutate-sandboxed runs main's copy of txe/mutate/mutate-sandboxed.py
```

`mutants.json` is a list of `{"name", "file", "old", "new"}` objects, with an optional `count`
(default 1). `old` must occur exactly `count` times in `file`, relative to the tree.

## What it guarantees

- **A fresh copy per mutant.** The live tree is copied once (without `.git`, `node_modules` and
  `.local`; `--exclude` adds names), and each run gets its own copy of that. The live tree is
  never edited. Every file a mutant names is read before the copy, and a change to any of them
  after any run (baselines included) stops the run.
- **A container per run.** It has two mounts, both inside the work directory this run created:
  the run's own directory (read-write, at `/work`) and the seeded module proxy (read-only, at
  `/goproxy`), plus, only when `--ro-mount` is given, one read-only copy the runner made at
  `/work/src/.git` (below). It has no network (`--network none` unless `--network` says otherwise), no Docker
  socket, no capabilities, a read-only root, `--memory`/`--cpus`/`--pids` limits (8g, 4, 4096 by
  default) and no variable from the caller's environment. Its host footprint is bounded too: a
  run whose captured output passes `--max-output-mib` (64), whose own directory (its only writable
  host path) passes `--max-disk-mib` (16384), or that leaves less than `--min-free-mib` (2048)
  free beside the work directory is stopped as ERROR and its container removed. The size checks
  poll (output every second, the directory every 5 s, and both once more before a normal exit is
  accepted), so a run can overshoot a bound by what it writes in that interval. `/work` is not
  quota-backed storage: the bounds detect and stop a writer, they cannot refuse a fast burst. Runs
  do not accumulate either: each run's directory is discarded once its result is recorded (its
  log is kept outside it), and before every copy into the work directory its total size is
  checked against `--max-work-mib` (32768) and the free space beside it against `--min-free-mib`,
  with the copy's full size added first (a sparse file counts at its apparent size, which is what
  a copy writes out); either failing stops the run (exit 6). GOPATH, GOMODCACHE, GOCACHE, TMPDIR,
  XDG_CACHE_HOME and XDG_CONFIG_HOME point under `/work/sandbox`. HOME is never set, here or
  anywhere in the runner: the container keeps its image user's default. Every `docker run` has
  `--pull never`, and an image that is not present locally is refused: name it by its id. An
  image that declares a `VOLUME` is refused too: Docker would give every run an anonymous
  writable host volume outside the sandbox's bounds. Every run has `--log-driver none`, so Docker keeps no second,
  unbounded copy of the output on its data root (the attached stream the runner captures and
  bounds is unaffected; with no real container run since this change, that is from Docker's
  documentation, not observed here). A mount
  that would be, contain or lie inside the shared caches, GOPATH, HOME, the Docker socket or the
  live tree is refused before docker runs.
- **Mount paths must be plain enough for docker's `--mount`.** Its value is comma-separated fields, and the runner
  does not quote them. A `--workdir-root` (or any mount source or target) containing a comma, a double quote, or a
  line break (LF or CR) is refused with exit 2 before any docker call, never passed to docker split or corrupted.
  Every other path character, spaces included, is passed as is.
- **The shared module cache is only read, and only before any mutant runs.** On the host, `go mod
  download` fills an owned cache from the unmutated copy with
  `GOPROXY=file://<shared GOMODCACHE>/cache/download,<your GOPROXY>`. Go never writes to a file
  proxy, and `go mod download` runs no project code. The seed's environment is built from
  nothing: PATH, HOME (unchanged, never overridden), the standard proxy variables, the caller's
  resolved GOPROXY/GOSUMDB/GOPRIVATE/GONOPROXY/GONOSUMDB/GOINSECURE/GOTOOLCHAIN, the owned caches,
  and `GOWORK=off`, `GOENV=off`, so no caller variable can point Go at a live file. `--no-seed` skips
  this for a tree with no module dependencies.
- **Host checks after every run.** The identity (device, inode and, on macOS, birth time) of the
  shared GOMODCACHE, its `cache/download`, GOCACHE, GOPATH, HOME and the live tree; that no entry
  directly inside the shared GOMODCACHE, its `cache/download` or GOCACHE disappeared or was
  replaced (new entries are fine: other sessions fill the caches); the content of a fixture
  sentinel file where one exists; and the content of each live-tree file a mutant names. Any
  change stops the run at once with exit 3 and a banner; the work directory is kept as evidence
  and that run gets no verdict.
- **Kills must repeat.** The unmutated tree must pass first (exit 4 otherwise) and again at the
  end. Each killed mutant runs again in a new sandbox; a kill that does not repeat is reported as
  `UNREPEATED-KILL`, a finding (exit 5), never a flake. docker's own failures (exit 125 to 127)
  and timeouts are findings too, never kills.
- **Cleanup deletes only what it created.** The work directory is removed only when its identity
  and the ownership token written into it at creation still match.

Exit codes: 0 done with no finding (survivors are listed, not failures); 2 refused or bad input;
3 shared state changed; 4 the unmutated tree failed; 5 findings; 6 stopped by `--deadline` (every
run, settlement and integrity check; cooperative bounds, no process-exit guarantee: see "The bounds" below) or
by SIGTERM, SIGINT or SIGHUP; 7 a `--diagnostic` run
completed and was recorded (below). Any exit from 3 to 7 keeps the work directory as evidence.

## Diagnostic runs and the read-only git view (TXE-8053)

```sh
mutate-sandboxed --ro-manifest /abs/view                       # prints the view's digest; runs nothing
mutate-sandboxed --diagnostic --tree . --image sha256:<id> \
  --ro-mount /abs/view:/work/src/.git:<digest> -- python3 -I -B ops/ci/mutant-consumers-check.py --static-only
```

**`--diagnostic`** runs the unmutated tree once, with the same boundary, bounds and host checks as
any run, and records the command's result as evidence. It takes no mutant list (`--mutants` with
it is refused). The command's stdout and stderr go to `<work>/logs/001.stdout` and
`001.stderr`, outside every mount; the report holds each one's path, size, sha256 and tail, and
`"mode": "diagnostic", "gate": "never"`. The stderr file is the docker client's: it also carries
anything docker itself prints. The two streams' interleaving is not recorded. The work directory
is always kept.

- **Exit 7 means evidence complete, not command success.** The container ran to its own exit with
  a code N that is not docker's own (125 to 127), every host check held, the run's container was
  confirmed removed or absent by the owner-checked cleanup call (docker's `--rm` is not taken on
  trust), and the end-of-run checks held. Only then is the `DIAGNOSTIC: command exit N` line
  printed. The outcome is `DIAGNOSTIC`, never PASSED, SURVIVED, KILLED or FAILED. A diagnostic
  never exits 0, so it never passes a gate that reads exit 0. Read the report; do not chain on the
  exit status, and never treat `command_exit` 0 as a gate success (`gate: never`).
- **Separate facts, never merged.** `report["diagnostic"]` keeps:
  - `command_exit`: the docker client's raw exit status, ALWAYS kept as evidence (null only when
    the client was stopped or died before returning), with `command_exit_attribution`: `command`,
    `ambiguous: docker-or-command` for 125 to 127, or `none: ...`;
  - `settlement`: `confirmed` (the container removed or absent), `unconfirmed`, or `not checked`;
  - `integrity`: `held`, `failed` (exit 3) or `incomplete` (the final check could not finish);
  - `evidence`: `complete` only with exit 7, else `incomplete`; and `status`, a summary.
  The overall exit is `report["exit"]`.
- **7 never masks a failure.** A run that did not complete (docker's 125 to 127, the timeout, an
  output or disk bound, the client killed by a signal, a container not confirmed removed) is exit
  5 with `status: not-completed: ...`. A shared-state or read-only-mount change is exit 3: during
  the run no diagnostic is recorded, and after it (in cleanup or the final check) the recorded one
  is marked `integrity: failed`, `status: invalid: shared state changed`. Refusals are 2 and the
  deadline or a signal 6, as in any run.
- **Ambiguity: 125, 126 and 127 are attributed to neither side.** docker run reports its own
  failures with those codes and the client cannot tell them from the command's, so the runner
  does not claim either: such a run is exit 5, `not-completed`, with the value kept in
  `command_exit` and `command_exit_attribution: ambiguous: docker-or-command`.
- **Anything unexpected is a finding.** An exception the runner does not expect (a host-side step
  failing, such as removing a run directory the command made unremovable) is exit 5 with
  `report["error"]`; whenever a report is written, its `exit` equals the process's exit status.
- **Reports first, terminal output last.** At the end the runner writes `--report` and, when the
  work directory stays, `<work>/report.json`; only then removes the work directory; and only
  then writes its held stderr lines and the `DIAGNOSTIC` line. A report that cannot be written
  (`report_error`; the work directory is then kept as the evidence that survives), a work
  directory that cannot be removed (`cleanup_error`), and a terminal write that fails for any
  reason but a broken stream (`stream_errors`) each turn 0 or 7 into 5, and the reports are
  written again with that exit. A broken pipe or a closed stdout or stderr, the expected case of a
  reader that went away, is only noted (`broken_streams`) and changes nothing. No report can be
  promised on a filesystem that refuses every write: then the exit is 5 and stderr says why.
- **The bounds under `--deadline D`, none extended, all COOPERATIVE** (the report's `budgets`):
  they bound what the runner checks a clock around. They are not a process-exit guarantee: see
  the last item.
  - **D, the active and integrity deadline.** Runs end a reserve before it: min(45, D/3) s,
    chosen to hold settlement and the read-only mount checks after a run and at the end, each a
    full re-hash of the view (with a view, the reserve has to cover two hashes; a large view or a
    small D makes the end check run out). The reserve's adequacy is not measured. A run, a
    settlement or an integrity check that cannot finish by D is exit 6 (integrity `incomplete`
    when it is the end check), never 7; an earlier 2, 4 or 5 also becomes 6, the report keeping its
    findings and results.
  - **Emergency cleanup: 10 s after D,** one budget that every container-removal call past D
    consumes (each call's timeout is what is left of it; none restarts its own); once it is spent
    no call starts and the container is reported as not confirmed removed.
  - **A 5 s termination margin** for the local steps left: the end-of-run host check (identities
    and one-level listings of the watched directories), the report writes, the work directory's
    removal and terminal output. These do host I/O with NO deadline of their own, and the
    finalizer ignores SIGTERM, SIGINT and SIGHUP so that cleanup is not cut short. The margin is
    an allowance for a caller to add, not something the runner enforces or has measured.
  - **No process-exit guarantee; the caller owns the hard deadline and custody.** A caller that
    needs the process gone by a time must enforce it from outside (SIGKILL, a job timeout), no
    earlier than D + 15 s (`budgets.least_external_hard_deadline_s`), and keep custody of what a
    kill leaves: the work directory, whose `cids/` holds each started container's id (and whose
    name and owner label carry the run's token) for removal by hand. txe's CI launcher and
    `fixture-demo.py` are such callers; the global launcher (`~/.coding_global/bin/mutate-sandboxed`)
    is not: it execs the runner and adds no bound.
- **Settlement after "removal already in progress".** When `rm -f` fails, the runner inspects the
  same owner-checked container once more, within the emergency cleanup budget; only docker's own
  "no such" counts as absent. Anything else, "in progress" included, is unconfirmed: exit 5.

**`--ro-mount SRC:DST:SHA256`** gives the container a read-only view of a directory, in either
mode. SRC is only read on the host and never mounted: the runner copies it into
`<work>/ro/<n>` and mounts that copy.

- **SRC** is absolute and equal to its own realpath (on macOS `/private/tmp/...`, not `/tmp/...`),
  a plain directory, and does not equal, contain or lie inside the shared module or build cache,
  GOPATH, the Docker socket, the live tree or the run's work directory; it may lie inside HOME but
  not contain it. It holds only directories and regular files with names in `[A-Za-z0-9._-]`, no
  two in one directory equal ignoring case.
- **Bounds:** `--ro-max-files` (100000 entries), `--ro-max-depth` (32 levels), `--ro-max-mib`
  (4096 MiB in all) and `--ro-max-file-mib` (2048 MiB per file). Bytes are counted as read, so a
  file that grows during the copy is still bounded.
- **Races:** every directory is opened relative to its parent's descriptor with `O_NOFOLLOW`, and
  every file with `O_NOFOLLOW | O_NONBLOCK` and checked to be regular, so a directory or file
  replaced mid-walk by a link or a FIFO is refused, not followed. The copy, not the source, is
  hashed: a writer racing on the source can only cause a refusal.
- **The copy** is new files and directories whose modes the runner sets explicitly (0644 and
  0755, whatever the umask or the source's modes, on Linux and macOS alike) and checks, owned by
  the runner's uid, which is the uid the container runs as (so git's ownership check holds);
  times are not kept. Its manifest must equal SHA256. It is checked again (manifest, one link per file,
  owner, and the git view's shape) immediately before every mount and after every run; a failure
  then is exit 3.
- **The manifest:** every entry below the root, sorted by its relative path as bytes,
  `D <rel>\n` per directory (empty ones included) and `F <size> <sha256> <rel>\n` per file; its
  digest is the sha256 of those lines joined. It covers names, types, sizes and contents, not
  modes, owners or times. `--ro-manifest DIR` prints it with the same code. That mode takes no
  `--deadline` (refused, exit 2): the walk is bounded by the `--ro-max-*` limits, and a caller that
  needs a time bound wraps the command; a digest it cannot deliver (stdout gone or failing) is 5.
- **DST** must be exactly `/work/src/.git`, a named exception to "no mount overlaps `/work`".
  Any other destination, a second `--ro-mount`, two mounts on one target, or a read-only source
  that a read-write mount source contains or lies inside is refused. There is no option field: a
  writable form does not exist. Two separate checks guard the mountpoint:
  - **No source data is shadowed.** The tree copy never holds `.git` (excluded at every depth),
    and after each run's copy the runner refuses if anything exists at `src/.git`, before it
    creates the mountpoint.
  - **The mountpoint is the runner's.** The runner then creates it as an empty plain directory,
    and immediately before building the argv checks that no link lies on its path and that it is
    still an empty directory, so docker neither creates it nor resolves it through a link.
- **The git view's contents.** Byte integrity says nothing about what the bytes are, so the copy
  must also be the TXE-8047 view: `HEAD` (a detached object id), `config` (only `[core]` with
  `repositoryformatversion`, `filemode`, `bare`, `logallrefupdates`, `ignorecase`,
  `precomposeunicode`, `symlinks`, plain values), `objects/` (packs, idx and rev files, loose
  objects, an empty `info/`), `refs/` (directories only), and optionally `index` and `shallow`.
  Anything else (hooks, alternates, refs, `packed-refs`, reflogs, remotes, credential helpers,
  includes, `commondir`, `description`) is refused. The runner does not check which commit the
  objects hold or that the index matches it: that binding is the view builder's.
- With the view mounted the container gets `GIT_OPTIONAL_LOCKS=0`, so git skips its optional
  index refresh instead of trying `.git/index.lock`; a command that needs a lock fails on the
  read-only mount.

Limits: the read-only bind is enforced by Docker (on macOS by the VM's file sharing); the tests'
fake docker cannot enforce it, so the per-run re-check is the alarm if it fails. Teardown: the
mountpoint goes with the run's directory; the copy goes with the work directory under its
ownership check, and stays as evidence whenever the work directory is kept.

**Containers the runner started, and only those, are removed when it stops.** Each `docker run`
records its container id with `--cidfile` in the work directory, outside every mount, and carries
a unique name and an owner label holding the run's random token. **A container leaves the
runner's custody only when an owner-checked inspect or removal confirms it gone**, in every mode
and outcome: a docker client that returned normally proves nothing (`--rm` is not taken on
trust). After each run the runner settles it (removed, or confirmed absent) by the deadline before
the next run starts or its directory is discarded; if a check after the run raises first (an
integrity incident, the deadline), it stays pending and the finalizer's emergency removal settles
it, or reports it in `containers_left`. Removal happens only when docker reports that exact name and
token on the container. Runs stop the reserve (a third of `--deadline`, at most 45 s) before the
deadline; settlement and the clearing of a stopped run draw on the deadline itself, and only the
finalizer's emergency removal draws on the one budget that ends 10 s after it (above). A cleanup
that fails is reported as `cleanup error` on stderr and in the report.

The build cache: the baseline's GOCACHE is copied (copy-on-write on APFS) into each mutant's
sandbox so a mutant does not rebuild from nothing; `--no-warm-gocache` gives each an empty one.
The sandbox sets `GOFLAGS=-modcacherw -count=1`, so that copied cache never replays a cached test
result: every baseline and mutant run executes its tests.

## Limits

- Tests that need `.git` in the tree, network access or a host service do not run unchanged.
- Host-side copies of a tree a container wrote (the baseline's build cache) copy only
  directories, regular files and symlinks: a special file (a FIFO would block the copy) is refused.
  The source path may hold no symlink and must resolve inside the run's own directory; links
  nested below it are copied as links, never followed. The host reads a run's directory only
  after confirming its container is gone or stopped.
- A tree holding a symlink that resolves outside it is refused: a host-side step (the seed's
  `go mod download` updating `go.sum`, say) could write through it into live files.
- **Seeding trusts the tree.** The seed's `go mod download` fetches every module the tree's
  `go.mod` requires from the shared cache (private modules included), and code in the sandbox can
  read them, and could encode them into its verdicts. The runner's threat is its own mutants
  breaking guards in the caller's own tree, not a hostile tree. For a tree you do not trust, run
  with `--no-seed`: nothing is read from the shared module cache and the sandbox has
  `GOPROXY=off`.
- On Linux the identity is device and inode only: Python's `os.stat` has no birth time there.
- **The host checks are an alarm, not proof that nothing changed.** They see a watched directory
  replaced, an entry one level inside a shared cache removed or replaced, and a sentinel's content
  changed. They do not see a deletion deeper inside a cache (one module's files, one build-cache
  object), a change to files outside the watched paths, or a change made and undone between two
  checks. Device and inode alone would miss an in-place deletion that keeps the root directory,
  which is why the entry and sentinel checks exist. The container's mounts are the boundary; the
  checks are how you learn the boundary failed.
- The guard hook (below) is a heuristic over command text, not complete enforcement: a script
  with an ordinary name, a command built at run time, or a run from inside a script the command
  calls gets past it.

## The forgotten-wrapper check

`guard-hook.py` is a PreToolUse hook for Claude Code and Codex. It refuses (exit 2, reason on
stderr) a shell command that runs a mutation tool, or a script whose name says mutant or
mutation, any way other than through `mutate-sandboxed`. It catches the habit that caused the
incident; the rule in `~/.coding_global/AGENTS.md` is the policy.

It reads the command the way a shell does (quotes, escapes, pipelines, lists, subshells, command
and process substitution, redirections, here-documents) and judges only what would execute
(TXE-7641):

- **Refused:** a mutation tool or a mutant-named file as the program (`mutmut run`,
  `./mutants.py`, `source run-mutations.sh`), also behind wrappers and runners (`timeout`, `env`,
  `nohup`, `xargs`, `uv run`, `uvx`, `poetry run`, `find -exec`); an interpreter whose script is
  one (`python3 -I tools/mutants.py`, `python3 -I <(git show x:mutants.py)`, `python3 -m mutmut`,
  `python3 - < mutants.py`, `cat mutants.py | python3`, `go run ./tools/mutate`); and shell code
  that does any of these (`bash -c '...'`, `eval`, a here-document or here-string to `bash`,
  `$(...)` and backticks anywhere, an unquoted here-document's substitutions); and code for a
  non-shell interpreter (`python3 -c`, `node -e`, `perl -e`, a here-document on python3's
  stdin) that imports a mutant module, or names a mutant script or tool and calls something that
  runs a file or a process (`runpy`, `exec`, `subprocess`, `os.system`, `require`, `load`, ...),
  also when the mutant is one of the code's own arguments (`python3 -c '...' mutants.py`: the
  guard does not follow data flow, so it errs toward refusing).
- **Python data reads versus execution (TXE-8183).** The shared run-call list above has
  other-language words (`load`, `system`, `require`), so `json.load(...)` used to count as running
  a file. Python code is now parsed with `ast.parse`, which builds a tree and runs nothing. It can
  be cleared as data only in one supported form, and only when it fits a deliberately small grammar.

  The supported form:
  - the isolated interpreter, `python3 -I` (plus only `-B`/`-u`), with the code given by `-c` or
    on stdin;
  - not interactive: no `-i` and no PYTHONINSPECT;
  - at the top level of the command, either directly or behind
    timeout/nice/nohup/command/`env` without `-S`. Not inside eval, `env -S`, `bash -c`, go
    `-exec`, sudo or `uv run`;
  - with no `PYTHON*` variable set.

  The grammar, in one module scope:
  - `import` of `json`, `ast` and `sys` only, with no alias that shadows a builtin or a binding;
  - plain `NAME = ...` assignments, where NAME is never a module or a builtin name;
  - `with open(...) as NAME:`;
  - expression statements;
  - calls only to a few builtins (`print`, `len`, `open` in a literal read mode, ...), to
    `json.load`/`loads`/`dumps`, `ast.parse`/`dump`/`literal_eval`, and to a few methods (`read`,
    `get`, `split`, ...), each with only its listed keywords. No callback keyword: `key=`,
    `object_hook=`, `opener=` and the like are refused;
  - a module only as `module.attr`, and never assigned or deleted;
  - no def, lambda, comprehension, loop, class, `del`, `_` name or attribute, `*args`/`**kwargs`,
    coding comment, `\r` or BOM.

  The code must also reach Python exactly as written. It must come from single quotes, a quoted
  here-document or a single-quoted here-string. Code that the shell expands first is never
  cleared: `"...$X..."`, `"...$(cmd)..."`, `$'...'`, an unquoted `<<EOF` or an expanded `<<<`.

  Code in any other form or shape is not cleared. A json.load of a mutant-named input without `-I`
  is therefore still refused, as it was before TXE-8183: a documented false positive, pending
  explicit review. With `-i`, the stdin that Python reads after the code is judged as a program.

  Cleared code is data, whatever its arguments, variables or tokens name. That includes
  `mutants.json` and a `mutate-sandboxed-*` work directory, so a runner's `report.json` can be
  read. Code that is not cleared is judged as before, with two additions:
  - executable deserialization and dynamic access count as run calls (`pickle`, `marshal`,
    `importlib`, `getattr`, `__builtins__`, ...): `pickle.load` is execution and `json.load` is
    not;
  - an input names a mutant when ANY path component does, whatever its extension. So
    `exec(open("mutants.json").read())`, `runpy` on `mutants` or on a `.txt` file, and execution of
    a file under a `mutate-sandboxed-*` work directory are refused.

  No extension or path is exempt. A pathname alone proves neither execution nor its absence;
  only code shown not to execute makes its inputs data. Every newly allowed read in `guardAllowed`
  has executing counterparts in `guardRefused`.

  Trusted, not checked:
  - `python3` on PATH is CPython, with an unmodified standard library;
  - its site-packages `.pth` files, which `-I` does not disable, and anything installed system-wide
    are state outside the command.
- **Python string literals are data (TXE-8351).** An editing script carries the text it writes
  as string literals. On 2026-11-24 two such scripts were refused: a Markdown spec edit and an OKR
  web `domains.ts` edit, both on a quoted here-document to `python3`. Their replacement text held
  both halves of the run-call rule: a backtick (a code span) counted as the run call, and
  `mutation` (TanStack Query's word for a write) counted as the name. Uncleared Python code now
  looks for its run call in the code only, via a view of the source with every string literal and
  comment blanked. `tokenize` builds that view and runs nothing. Names are still read from the full
  text, strings included, because a string is what names the file a real run call runs:
  `subprocess.run(["python3", "mutants.py"])` is refused, and so is a here-document program that
  writes a mutated file and runs `go test` or `pytest`.

  The view is used only when blanking a string cannot hide how a string becomes a call. Otherwise
  the code is judged on its full text, as before. It needs all of these:
  - Python runs the text exactly as written, and imports nothing it does not show. That excludes:
    - shell-expanded text (`"...$X..."`, an unquoted `<<EOF`, `$'...'`), including an unquoted
      `*`, `?`, `[`, `{` or `~`. Pathname, brace or tilde expansion can replace the word, so a file
      named like code becomes the program;
    - any interpreter flag outside `-BbdEIOPqRsSuv`: `-x` skips the first source line, `-W`
      imports a warning category's module, and `-X` and `-i` are not modelled;
    - a `PYTHON*` variable in the command (`PYTHONPATH`, `PYTHONWARNINGS`);
    - code that is not at the top level of the command: inside `bash -c`, `eval`, `env -S`, go
      `-exec`, a subshell or a substitution. An outer shell may expand that text first. In
      `bash -c "python3 -c 'print(\"$X\")'"`, `$X` can close the Python string and add code;
    - a wrapper or runner other than timeout, nice, nohup, `command` or `env` without `-S`. `watch`
      runs its words through `sh -c`, `xargs -I` rewrites them, `sudo -s` starts a shell, and
      `uv run`, `find -exec` and the like are not modelled;
  - every import comes first, before any other statement, at module level. Otherwise a statement
    could write `json.py` and a later `import json` would run it;
  - the code tokenizes and parses, with no coding comment, `\r` or BOM;
  - no from-import of a private name or `*`: `from os import _execvpe` runs a process under a
    name no run rule lists;
  - every import is absolute and of a text-handling module: `os`, `sys`, `re`, `json`, `pathlib`,
    `io`, `shutil`, `textwrap`, `difflib`, `glob`, `fnmatch`, `hashlib` or `tempfile`. A module
    such as `timeit`, `string`, `operator` or `pkgutil` can run a string or look up a callable by
    its name, so it keeps the strings;
  - `sys` is used only as `sys.argv`, `sys.stdin`, `sys.stdout`, `sys.stderr`, `sys.exit` or a few
    read-only facts. `sys.breakpointhook` resolves a callable named by `PYTHONBREAKPOINT`, and
    `sys.modules` reaches any loaded module, so any other use keeps the strings. So do `os.sys`,
    and `sys` passed on or rebound;
  - before Python 3.12 an f-string is one token, so an `f`/`t`-prefixed string is never blanked.
    From 3.12 only its literal text is blanked, and its `{...}` expressions are code.

  On the view, these also count as run calls, since each can look a callable up by a name only a
  string holds: a dunder (`os.__dict__["system"]`), a private attribute, a frame or code attribute
  (`gi_frame`, `f_builtins`), `help()` (it imports a module by name) and `sys.modules`. The view is
  read in NFKC form, as Python reads identifiers, so a fullwidth `ｅｘｅｃ` is `exec`. `os`'s
  process calls imported by name (`from os import popen, execvp`) are run calls too.

- **A hand mutation run in one command (TXE-8351).** A mutant applied by hand and tested over the
  live tree in the same command is the TXE-7547 shape: `python3 - <<'PY' ... PY && go test ./...`.
  No program in it is named for mutation. One command is refused when all three hold:
  1. it writes `.go`, `.py` or `.sh` source. That means an output redirection or `tee` to such a
     file, an in-place `sed -i`, `perl -i` or `ruby -i` of one, or interpreter code that names
     one and writes a file (`open(p, "w")`, `write_text`, `os.replace`, `writeFileSync`, ...);
  2. it runs `go test`, `pytest`, `python -m pytest` or `bazel test`;
  3. its text names a mutant or a mutation (comments included; `mutate-sandboxed` itself does not
     count).

  These stay allowed:
  - an edit of `.md` or `.ts` files, even followed by a test;
  - a source edit with no mutation word;
  - an edit with no test;
  - a test that `mutate-sandboxed` runs.

  A warning filter's category is imported when Python starts. So a `-W` or `PYTHONWARNINGS` whose
  category is in a mutant-named module (`-W ignore::mutants.Warning`) is refused, whatever the
  code, isolated or not.
- **Descriptors:** each command's redirections are tracked per descriptor, left to right (`<`,
  `<>`, output redirections, `<&N`, here-documents, here-strings), so `python3 3< mutants.py <&3`
  and `python3 /dev/fd/3 3< mutants.py` are judged on what they read. A descriptor path the
  command does not set (`/dev/fd/$N`, one opened by an earlier `exec 3<`, any `/proc` path) fails
  closed, as does nesting deeper than the reader follows and any internal error.
- **Allowed, because the words are only data:** grep and sed patterns, echo and printf
  arguments, `--body`/`--text`/`-m` messages, paths given to cat, ls or shasum, a here-document
  written to a file, comments, and interpreter code that only mentions the names (prints them,
  counts them, edits text that contains them). `mutate-sandboxed` itself, and the guard's own
  files (`mutant-run-guard`, `guard-hook.py`), are never refused.
- **File-edit tools (TXE-8344).** Codex sends a patch to its hooks as
  `{"tool_name": "apply_patch", "tool_input": {"command": "<patch>"}}`. That is the canonical name
  in openai/codex rust-v0.171.0 `core/src/tools/hook_names.rs`, where `Write` and `Edit` are
  matcher aliases that never reach the hook. A patch is file content, not a command, and read as
  shell text its prose lines become programs (a line `+Mutant file ...` names a program
  `+Mutant`). So a call whose harness-supplied `tool_name` is exactly `apply_patch` is not judged.
  - **What stays judged as a command, as before:** the same text under any other name — `Bash`,
    `exec_command`, `shell`, an unknown, missing or non-string name, or a case or spelling variant
    such as `APPLY_PATCH` or `apply-patch`.
  - **Never exempted:** nothing is exempt because of what the payload text looks like (a command
    can begin with `*** Begin Patch`), and the hook registration's matcher is unchanged.
  - **Limit:** a patch that writes a mutant script is allowed, because writing runs nothing.
    Running that script afterwards is judged like any other command.

The case lists in `mutate_test.go` (`guardRefused`, `guardAllowed`) hold the v3 rollout's
acceptance cases and every false positive observed since, in their observed shape. The reader
never fails: input it cannot follow (unbalanced quotes, unknown syntax) is read as words.

### Documented limits (TXE-7658)

The guard reads command text; it does not run a shell. These get past it, by design, and are not
covered by parser work: the AGENTS.md rule, the sandboxed runner and the runner's host checks are
the controls for them.

- A renamed script, or a program or file name assembled at run time (`python3 "$f"` inside a
  loop, `$(printf ./mutants.py)`, a name read from a file).
- A mutation run started from inside a script the command calls, or by a tool the guard does not
  know.
- **Substitutions in go's exec flags.** `-exec "$(printf ./mutants.py)"` leaves no `$` in the word
  the guard sees, so it is judged as the empty string. A literal `$VAR` or backtick in an
  `-exec`/`-toolexec`/`-vettool` value is refused.
- **Go environment state the command does not show.** A go env file reached through HOME,
  XDG_CONFIG_HOME, GOROOT or GOTOOLCHAIN, or written by an earlier command, can set
  `GOFLAGS=-exec=...`. Only a visible GOENV assignment and GOFLAGS on the command line are read.
- **Redirections on compound commands.** `while`/`until … done`, `if … fi` and `case … esac` bodies
  do not inherit the redirections or pipe written after the closing keyword
  (`while read l; do python3; done < mutants.py`). `( … )` and `{ …; }` groups do.
- State set outside the command: an exported variable, an alias or function from the shell's rc
  files, an `exec 3<` in an earlier call.
- **Python's startup state outside the command (TXE-8183).** Clearance requires `-I`, so neither
  the current directory nor a PYTHON* variable can redirect `import json`. Two kinds of state
  remain trusted, not checked:
  - an exported PYTHON* variable is ignored under `-I`, but an unusual `python3` on PATH is not;
  - a system site-packages `.pth` file runs at startup even under `-I`.
- **Stdin continuation is judged only from what the command shows.** With `-i` (or
  PYTHONINSPECT), the stdin that Python reads after the code, module or script is judged as a
  program, so `< mutants.py` and `cat mutants.py |` are refused. A stdin the command does not
  show, such as a terminal or an inherited descriptor, cannot be judged.
- **Other languages keep the shared run-call list.** `node -e`, `perl -e` and `ruby -e` code are
  judged as before, and no read-only grammar clears them. Their string literals are not blanked
  either (TXE-8351 covers Python only), so they can still be refused for a word like `load` or
  `require` used as data.
- **Lazy imports in non-isolated Python.** Without `-I` the current directory is on `sys.path`.
  A standard-library call made after the program writes a file can import a module by name, and
  that file can be it: an uncaught exception imports `traceback`, and the `idna` codec imports
  `stringprep`. The code view cannot see such an import. Only imports the program states are
  required to come first. Code meant to be read as data is safest under `python3 -I`.
- **Edit, then test, in two commands.** The hand-mutation rule (above) judges one command. An edit
  of `.go`, `.py` or `.sh` source in one Bash call followed by `go test` in the next is not refused,
  and neither is a write the rule does not model (`cp`, `mv`, `git apply`). The same applies to a
  runner it does not list (`make test`, `npm test`).
- **Python's path-component rule over-refuses.** Uncleared Python code that may run something
  is refused when any word names a mutant in any component, for example
  `subprocess.run(["go", "test", "./txe/mutate/..."])`. That code is not a data read; ask your
  coordinator.

A shape gets a parser fix only when an agent would plausibly write it by accident while running a
mutant, with a fixture in `guardRefused` that shows it.

## The acceptance demonstration

`fixture-demo.py` runs `testdata/fixture` (a module with no dependencies, whose one mutant runs
`go clean -modcache` with its environment), one step per call, each against sentinel-only fake
caches. Neither step reads the real module cache, and the image is named by its id (never
pulled).

- `fixture-demo.py sandboxed <evidence> <image-id> [--deadline 300]`: through the real sandbox.
  Expected: exit 0, the mutant SURVIVED, the fake caches and sentinels unchanged, and, from the
  fixture test's own `go test -v` lines kept in the report (each result's `output_tail`), the
  mutant's `go clean` returned nil and its sandbox GOMODCACHE is gone while the baseline's is
  still there. Those lines are what was observed inside the sandbox, not an inference.
- `fixture-demo.py outer-negative <evidence> <image-id> [--deadline 180]`: the alarm, with the
  boundary removed, proven inside an outer container with no network, no capabilities, no Docker
  socket, no credentials and no mount but a read-only copy of this directory. There
  `negative-in-outer.sh` plays the host with fake caches and gives the runner
  `testdata/leaky-docker.py`, which runs the mutant with the caller's environment. Expected: the
  runner inside exits 3. A boundary-off run never happens on a real host: there is no flag for it.

`--deadline` bounds the whole demo, every container, error handling and cleanup included. Past
it, or on SIGTERM, SIGINT or SIGHUP, the demo stops the runner and both force-remove only the
containers recorded as started (docker's `--cidfile`, kept outside every mount), each only when
docker reports that container's own name and owner token. The demo works inside one directory it
creates exclusively and stamps with a token; it removes it only when the token and the
directory's identity still match, and keeps it as evidence after any unexpected result.

Tests: `go test ./txe/mutate/`. They start no container, download nothing and run no
destructive mutant: a fake docker plays the container on a temporary directory, and the alarm
tests change sentinel-only fake caches from that fake docker, at paths the test names.
