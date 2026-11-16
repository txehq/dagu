# mutate-sandboxed: mutation tests that cannot reach the host (TXE-7549)

A mutant breaks a guard on purpose. On 2026-11-16 a hand-written mutant runner ran one with the
session's real environment, and the code under test deleted the Mac's shared Go module cache
(postmortem TXE-7547: txehq/txe `docs/postmortems/2026-11-16-shared-gomodcache-deletion.md`).
Mutation tests run only through this runner, never through a per-ticket script.

```sh
mutate-sandboxed --mutants mutants.json --tree . -- go test ./internal/intg/machineauth/...
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
  socket, no capabilities, a read-only root and no variable from the caller's environment. HOME,
  GOPATH, GOMODCACHE, GOCACHE, TMPDIR and XDG_CACHE_HOME point under `/work/sandbox`. A mount
  that would be, contain or lie inside the shared caches, GOPATH, HOME, the Docker socket or the
  live tree is refused before docker runs.
- **The shared module cache is only read, and only before any mutant runs.** On the host, `go mod
  download` fills an owned cache from the unmutated copy with
  `GOPROXY=file://<shared GOMODCACHE>/cache/download,<your GOPROXY>`. Go never writes to a file
  proxy, and `go mod download` runs no project code. HOME is not overridden. `--no-seed` skips
  this for a tree with no module dependencies.
- **Identity checks.** The device, inode and (on macOS) birth time of the shared GOMODCACHE, its
  `cache/download`, GOCACHE, GOPATH, HOME and the live tree are read before the run and after
  every sandboxed command. Any change stops the run at once with exit 3 and a banner; the work
  directory is kept as evidence and that run gets no verdict.
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
- The identity check sees a watched directory replaced or deleted, not a file deleted inside it.
  The container boundary is what keeps those files out of reach; the check is the alarm if the
  boundary is ever bypassed.

## The forgotten-wrapper check

`guard-hook.py` is a PreToolUse hook for Claude Code and Codex. It refuses (exit 2, reason on
stderr) a shell command that runs a mutation tool, or a script whose name says mutant or
mutation, any way other than through `mutate-sandboxed`. It does not parse shell and a renamed
script gets past it; it catches the habit that caused the incident, and the rule in
`~/.coding_global/AGENTS.md` is the policy.

## The acceptance demonstration

`fixture-demo.sh <evidence-dir>` runs `testdata/fixture` (a module with no dependencies, whose
one mutant runs `go clean -modcache`) twice against sentinel-only fake caches it creates: once
sandboxed (exit 0, the mutant survives, the fake caches unchanged) and once with
`--unsafe-host-run-for-fixture` (exit 3 on the identity check). That flag is refused unless both
caches are given explicitly and each holds `.mutate-sandboxed-fixture-sentinel`.

Tests: `go test ./txe/mutate/`. They start no container and download nothing: a fake docker
plays the container on a temporary directory.
