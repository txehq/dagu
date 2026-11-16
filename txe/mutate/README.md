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
  never edited, and a change to a file a mutant names stops the run.
- **A container per run.** It has two mounts, both inside the work directory this run created:
  the run's own directory (read-write, at `/work`) and the seeded module proxy (read-only, at
  `/goproxy`). It has no network (`--network none` unless `--network` says otherwise), no Docker
  socket, no capabilities, a read-only root, `--memory`/`--cpus`/`--pids` limits (8g, 4, 4096 by
  default) and no variable from the caller's environment. GOPATH, GOMODCACHE, GOCACHE, TMPDIR,
  XDG_CACHE_HOME and XDG_CONFIG_HOME point under `/work/sandbox`. HOME is never set, here or
  anywhere in the runner: the container keeps its image user's default. Every `docker run` has
  `--pull never`, and an image that is not present locally is refused: name it by its id. A mount
  that would be, contain or lie inside the shared caches, GOPATH, HOME, the Docker socket or the
  live tree is refused before docker runs.
- **The shared module cache is only read, and only before any mutant runs.** On the host, `go mod
  download` fills an owned cache from the unmutated copy with
  `GOPROXY=file://<shared GOMODCACHE>/cache/download,<your GOPROXY>`. Go never writes to a file
  proxy, and `go mod download` runs no project code. HOME is not overridden. `--no-seed` skips
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
3 shared state changed; 4 the unmutated tree failed; 5 findings.

The build cache: the baseline's GOCACHE is copied (copy-on-write on APFS) into each mutant's
sandbox so a mutant does not rebuild from nothing; `--no-warm-gocache` gives each an empty one.

## Limits

- Tests that need `.git` in the tree, network access or a host service do not run unchanged.
- On Linux the identity is device and inode only: Python's `os.stat` has no birth time there.
- **The host checks are an alarm, not proof that nothing changed.** They see a watched directory
  replaced, an entry one level inside a shared cache removed or replaced, and a sentinel's content
  changed. They do not see a deletion deeper inside a cache (one module's files, one build-cache
  object), a change to files outside the watched paths, or a change made and undone between two
  checks. Device and inode alone would miss an in-place deletion that keeps the root directory,
  which is why the entry and sentinel checks exist. The container's mounts are the boundary; the
  checks are how you learn the boundary failed.
- The guard hook (below) is a heuristic over command text, not complete enforcement: a script
  with an ordinary name, or a command built at run time, gets past it.

## The forgotten-wrapper check

`guard-hook.py` is a PreToolUse hook for Claude Code and Codex. It refuses (exit 2, reason on
stderr) a shell command that runs a mutation tool, or a script whose name says mutant or
mutation, any way other than through `mutate-sandboxed`. It does not parse shell and a renamed
script gets past it; it catches the habit that caused the incident, and the rule in
`~/.coding_global/AGENTS.md` is the policy.

## The acceptance demonstration

`fixture-demo.sh` runs `testdata/fixture` (a module with no dependencies, whose one mutant runs
`go clean -modcache` with its environment), one step per call, each against sentinel-only fake
caches. Neither step reads the real module cache.

- `fixture-demo.sh sandboxed <evidence> <image-id>`: through the real sandbox. Expected: exit 0,
  the mutant SURVIVED, the fake caches and sentinels unchanged.
- `fixture-demo.sh outer-negative <evidence> <image-id>`: the alarm, with the boundary removed,
  proven inside an outer container with no network, no capabilities, no Docker socket, no
  credentials and no mount but a read-only copy of this directory. There `negative-in-outer.sh`
  plays the host with fake caches and gives the runner `testdata/leaky-docker.py`, which runs the
  mutant with the caller's environment. Expected: the runner inside exits 3. A boundary-off run
  never happens on a real host: there is no flag for it.

Tests: `go test ./txe/mutate/`. They start no container, download nothing and run no
destructive mutant: a fake docker plays the container on a temporary directory, and the alarm
tests change sentinel-only fake caches from that fake docker, at paths the test names.
