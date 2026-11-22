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
  `/goproxy`). It has no network (`--network none` unless `--network` says otherwise), no Docker
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
3 shared state changed; 4 the unmutated tree failed; 5 findings; 6 stopped by `--deadline` (the
whole run, every container included) or by SIGTERM, SIGINT or SIGHUP. Any exit from 3 to 6 keeps
the work directory as evidence.

**Containers the runner started, and only those, are removed when it stops.** Each `docker run`
records its container id with `--cidfile` in the work directory, outside every mount, and carries
a unique name and an owner label holding the run's random token. On a timeout, the deadline or a
signal, the runner force-removes each container whose docker client had not returned, and only
when docker reports that exact name and token on it. Runs stop a cleanup reserve (a third of `--deadline`, at most
45 s) before the deadline, and each cleanup call is cut to what remains, with a 1 s floor: a
container left running is still removed when the deadline has just passed, so cleanup can overrun
the deadline by about 2 s per such container (at most one: runs are sequential). A cleanup that
fails is reported as `cleanup error` on stderr and in the report.

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
  judged as before, and no read-only grammar clears them. They can still be refused for a word
  like `load` or `require` used as data.
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
