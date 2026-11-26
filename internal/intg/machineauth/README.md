# Machine-authentication release check

The matrix a `dagu` build must pass as real processes before it is called good for
machine authentication: a hub (`start-all`) with `coordinator.auth.mode: enforce` and
`txe.authz.mode: enforce`, workers and the CLI, against a synthetic identity provider on
loopback. It is the committed form of the TXE-6193 acceptance (txehq/dagu, 2026-11-07),
which ran the same cells against `txe-v2.18.2-19`, main and #230 in an isolated container.

Everything here is test code. Nothing reaches outside the machine it runs on: the issuer,
the hub, the TLS edge and the workers listen on ephemeral loopback ports; every process
gets its own HOME, DAGU_HOME and TXE home under the test's temporary directory; the
persons, owners, machines, clients and secrets are minted for the run; no token, secret
or URL with a query is ever logged.

## The three tests

**Light, always on (CI):**

- `TestMatrixNamesEveryRefusalReason` — every `transportauth.Reason` is either provoked by
  a refusal class of the matrix or named in `unreachableReasons` with why. A reason added
  to the contract fails here until it is classified.
- `TestMatrixCoversEverySurface` — every coordinator method has a surface (the contract's
  rule) and every surface is covered or named by the matrix.
- `TestVerify*` — the result verifier fails closed on every way a result can fall short.

- `TestRequiredHubCellsFollowTheScope`, `TestStageOneShapeStillDerives78Cells`,
  `TestNativeOnlyHubConfigHoldsToItsSource` — the required set per hub scope (28 full, 26
  native-only), stage 1's shape still at 78 cells, and -17's configuration held to its keys.

These check the definition, not that a negative path ran: that is the heavy test's job,
and its results file is the only record of it.

**Heavy, opt-in (`TestMachineAuthReleaseMatrix`, Linux):**

```sh
# the current source, built by the harness (a smoke: the long cells are off)
DAGU_MACHINEAUTH_MATRIX=source go test ./internal/intg/machineauth -run ReleaseMatrix -v -timeout 30m

# named builds, as a release proof (long cells on in the manifest)
DAGU_MACHINEAUTH_MATRIX=/path/manifest.json go test ./internal/intg/machineauth -run ReleaseMatrix -v -timeout 90m
```

The manifest names each build exactly: the binary's path, its full sha256, the version
it must report (`dagu version`, and `/health` for a hub), and its provenance record by
path and sha256 (below). `long: true` asks for the long cells. Unknown fields are
refused. Before any cell the test checks each binary's digest, its provenance record,
its version and whether its worker lists `--worker.hub-url`. A build that does not hold
stops the run.

```json
{
  "builds": [
    {"name": "c", "path": "/abs/c/dagu", "sha256": "<64 hex>", "version": "2.25.8-txe.1",
     "provenance": {"record": "/abs/c/provenance.json", "sha256": "<64 hex>"}},
    {"name": "w18", "path": "/abs/w18/dagu", "sha256": "<64 hex>", "version": "2.18.2-txe.18",
     "roles": ["worker"], "routes": ["native"],
     "provenance": {"record": "/abs/w18/provenance.json", "sha256": "<64 hex>"}}
  ],
  "long": true,
  "results_dir": "/abs/results"
}
```

**Scope.** A build runs the full scope: hub and worker, over native gRPC, the channel and
the channel through TLS. Only a build listed in `narrowedScopes` (`scope_test.go`, keyed by
the version it reports) may declare `roles` and `routes`, and only exactly as listed: a
listed version declared with the full scope is refused too. The reason is the file's,
reviewed with it; a manifest cannot give one. Each entry names its source commit and the
**provenance kind** its record must be. There are two entries, and both predate the worker
channel (#197, #198 and #213 landed in -19):

| Version | Scope | Provenance |
|---|---|---|
| `2.18.2-txe.18` | worker only, native gRPC: the worker the Mac runs | `source`: a record of the controlled build of commit `5b011eba…`, module `github.com/dagucloud/dagu/v2` |
| `2.18.2-txe.17` | hub and worker, native gRPC only: the hub's fallback (TXE-7523 R9, TXE-8590) | `image`: a record read out of index `sha256:d625b509…` (commit `4d164866…`) |

-17's source has no `--worker.hub-url` and no `coordinator.worker_channel`. A hub rolled
back to -17 therefore serves native-gRPC workers only; a worker configured with
`--worker.hub-url` cannot work against it.

The capability probe corroborates a scope but never sets one. A full build whose worker
lacks `--worker.hub-url` fails, and a narrowed one whose worker has it fails too.

**A native-only hub** runs every hub cell under the same name except the two that exist
only to prove a route it lacks, `pos-channel-http` and `pos-channel-tls`: 26 cells with the
long ones, against a full hub's 28. `pos-probe-control` and each refusal class run over gRPC
only. Setup's `txe enrol check` runs without `--hub-url` and is held to the machine id. A
cell of a route the hub lacks is not run and not recorded: it is absent from the result, never
a pass, and the verifier derives the same set from the scope. The hub's configuration has no
`coordinator.worker_channel` block and no TLS edge is started. The configuration is held to
the keys the entry lists from the build's own source (`HubConfigKeys`), before any cell: an
older build ignores a key it does not know rather than refusing it, so the harness refuses
instead. A narrowed hub entry without that list is refused.

For each hub build the test runs the cells below with that build as hub and as worker,
and the pair cell (`pair-native`) with every other build as worker. A worker-only build
gets a machine of its own, owner B, under every hub build. It is enrolled through **its
own CLI**, and runs `w-setup`, `pos-native`, `neg-worker-start`, `neg-worker-nocred`,
`cancel`, `revoke-owner`, `reenrol`, and with `long: true` `stale` and `revoke-issuer`.
Its issuer revocation refuses only its own machine's client.

The test writes `machineauth-results-<utc>.json` (schema 2): the manifest's sha256; for
each build its digest, version, scope, the binary's own account, its provenance reference
and, for a narrowed build, what it excludes and why; and the status of every cell: `pass`,
`fail` or `not_run`. It prints one `SCOPE` line per build before the first cell and again at
the end, NARROWED with its exclusions where they apply, so a narrowed scope heads the result. "FULL" means full **for the manifest's scope**. The test fails
on any failed cell. With `long: false` the long cells are recorded `not_run` and the result
is **partial**: a smoke of the build, never release acceptance. The source mode is a smoke
too, because it has no manifest or provenance.

To run it inside a Linux container without a Go toolchain, cross-compile the test and copy
it in: `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -c -o machineauth.test
./internal/intg/machineauth` (the architecture of the builds under test), then
`DAGU_MACHINEAUTH_MATRIX=manifest.json ./machineauth.test -test.run ReleaseMatrix -test.v
-test.timeout 150m`. `DAGU_MACHINEAUTH_PORTS=<lo>-<hi>` keeps every port the rig listens on
inside an assigned block. `DAGU_MACHINEAUTH_MANIFEST_SHA256` refuses any manifest other than
the approved one.

**Provenance (`TestMachineAuthExtract`, `TestMachineAuthSourceRecord`):**

```sh
# a binary out of a published image: pull the index by digest into an OCI layout first
# (crane pull --format=oci <repo>@<index digest> <layout>); nothing is run from the image
DAGU_MACHINEAUTH_EXTRACT=/abs/extract-c.json go test ./internal/intg/machineauth -run MachineAuthExtract -v
#   {"name":"c","layout":"/abs/layout-c","ref":"ghcr.io/…","index":"sha256:…","platform":"linux/amd64",
#    "manifest":"sha256:<the platform manifest the publication recorded>","path":"/usr/local/bin/dagu","out_dir":"/abs/c"}

# a build from source, done by the command itself from a fresh, verified clone of the tag
DAGU_MACHINEAUTH_SOURCE_RECORD=/abs/source-w18.json go test ./internal/intg/machineauth -run MachineAuthSourceRecord -v
#   {"name":"w18","repo":"/abs/dagu","tag":"txe-v2.18.2-18","commit":"5b011eba…","module":"github.com/dagucloud/dagu/v2",
#    "package":"./cmd","version":"2.18.2-txe.18","goos":"linux","goarch":"amd64","parallel":2,"out_dir":"/abs/w18",
#    "installed":{"tag":"…","commit":"…","version":"…","read_from":"…"}}   (optional)
```

The extraction follows the chain index → the platform's manifest (exactly one; the
expected digest when given) → config (the platform, one diff id per layer) → every layer
(blob digest, and uncompressed diff id over every byte including the tar's padding) → the
file's last state across layers. Whiteouts of the file or of any directory above it, and
opaque directories, delete what lower layers had. A layer's own file survives its own
whiteouts. A link at the path, or a non-directory above it, is refused. The extraction
stops at the first link that does not hold, leaves no binary or record behind, and never
overwrites.

The source record is written only by a build the command does itself; it has no field for
a binary, because a VCS stamp can be borrowed. A module built in an ignored directory of a
checkout carries the checkout's revision and `vcs.modified=false`. The command:

- clones the tag afresh, with no user or system git configuration;
- checks that the tag and HEAD are the spec's commit;
- checks that `git status --porcelain --ignored` is empty before and after the build;
- builds the package the way the worker kit builds dagu: `go build -ldflags "-X
  'main.version=<version>'"` for the spec's platform, with cgo off, `-mod=readonly`,
  `GOENV=off` and no `GOFLAGS`, bounded by the spec's required `parallel` (`go build -p` and
  `GOMAXPROCS`);
- checks the binary's build information: the module and package, the platform, the
  version flag, and a git stamp of that commit on a clean tree.

The caller's environment reaches the build only through a fixed list of variables: tools,
temporary files, the module proxy and the module cache. The list's names are recorded and
its values are not.

Neither of the caller's caches is used by the build. A writer of a shared module cache
could change an extracted file during the build and restore it afterwards, and a writer of
a shared build cache could plant compiled packages. Each build gets a fresh private
`GOCACHE` and a fresh private `GOMODCACHE`. The module cache is filled only through Go's
download path, which checks every zip against go.sum. Modules come from the caller's module
cache downloads, served as a read-only file proxy, then from the caller's proxy. Extracted
files in the shared cache are never read, so the build works offline when the caller's cache
already holds the downloads. `go mod verify` must report every module matching before and
after the build. The first build compiles cold.

The build never sets `HOME`. It names owned `GOPATH`, `GOMODCACHE` and `GOCACHE` directories,
which it creates exclusively inside one work directory, itself made inside the spec's `out_dir`, so nothing about where it lives comes from the environment, not even `TMPDIR`. Before every go command it checks
that each of the three resolves to its own directory; a value that is missing or points
elsewhere refuses the command. It removes the work directory by the identity recorded at
creation: the directory and its parent, by device and inode, plus the path. It refuses a
target that is unknown, replaced, turned into a link, or has a different parent. Nothing in
the package cleans a module cache through go, or derives a path to remove from the
environment or from `go env`, and `TestNoModuleCacheCleanOrHomeOverride` enforces that
(TXE-7538).

The record names the clone's commit and tree, the command,
the variables the command set, and the Go version. A narrowed build's record must come from
this builder (`machineauth-controlled-clone-v1`), for the module `narrowedScopes` lists.

The record's scope says it is **not** the installed binary of any machine. An installed record
(the worker kit's `dagu-<version>.json`) corroborates the tag, commit and version only, not
the bytes.

**Verify (`TestMachineAuthVerify`, the release gate's command):**

```sh
DAGU_MACHINEAUTH_VERIFY=/abs/results/machineauth-results-….json \
DAGU_MACHINEAUTH_MATRIX=/path/manifest.json \
DAGU_MACHINEAUTH_MANIFEST_SHA256=<the approved manifest's sha256> \
go test ./internal/intg/machineauth -run MachineAuthVerify -v
```

It holds a recorded run to the approved manifest, to the binaries and records on disk now,
and to `narrowedScopes`. It fails on any of these:

- a manifest that is not the approved one, or results recorded under another;
- a build the manifest does not name, or a build missing from the results;
- a recorded digest that is not the manifest's, or a binary whose digest is no longer the
  recorded one (or cannot be read);
- a reported version, a recorded scope, its exclusions or reason, or the binary's own
  account that does not agree with the manifest and `narrowedScopes`;
- a provenance record that is not the bound one, or not for the build's binary;
- a narrowed build whose record is not the listed provenance kind for the listed commit: a
  source record of that commit from the controlled build, or an image record of the listed
  index;
- a hub build with a cell its scope does not have (a native-only hub's `pos-channel-*`), or
  without a cell its scope derives;
- a cell that failed or was not run;
- a missing, unknown or duplicated cell, a cell attributed to two builds, or a missing pair;
- a worker-only build recorded as a hub, or a missing worker-only cell under any hub;
- a status that is not `pass`/`fail`/`not_run`;
- a results schema it does not read;
- a manifest with `long: false`.

A pass cannot be carried by hand. It prints the `SCOPE` lines and each build's provenance
scope.

## The cells

Positive: `setup` (the real enrolment protocol: browser-SSO persons, binding requests and
the administrator's approvals, `txe login`, `txe machine create`, `txe enrol` for the
worker and reviewer classes through the issuer, the persons' approvals, `txe enrol check`
over the channel, or without it for a native-only hub), `pos-native`, `pos-channel-http`, `pos-channel-tls` (through a TLS edge
whose CA the worker trusts by `SSL_CERT_FILE`), `pos-two-owners`, `pos-probe-control`,
`cancel`, `revoke-owner` (the step stops at the worker's bound, every late write refused),
`reenrol` (a new generation; the revoked one stays), `neg-worker-start` (the binary refuses a
reviewer credential, another machine's id or label), `neg-worker-nocred`.

Negative, each over gRPC and the channel (gRPC only for a native-only hub), each held to the
reason the hub logs:
`neg-no-credential`, `neg-hub-scheme-with-token`, `neg-garbage-token`, `neg-cli-token`,
`neg-reviewer-token`, `neg-other-machine-id`, `neg-other-machine-label`,
`neg-expired-token`, `neg-not-yet-valid-token`, `neg-wrong-audience`,
`neg-unknown-client`, `neg-long-lifetime`, `neg-other-identity-on-client`,
`neg-dispatch-as-machine`, `neg-cancel-as-machine`.

Long (`long: true`): `stale` (a frozen worker's attempt expires at the production lease
threshold; its late status and streams are refused as stale) and `revoke-issuer` (the
provider refuses the refresh; the worker presents nothing more). Each takes minutes.

Budget: about 3 minutes per build without the long cells, about 15 with them, plus a few
seconds per pair. A worker-only build adds about 13 minutes under each hub build with the long
cells. These are native-speed figures, and emulation is slower.

## What it does not cover

A real identity provider, person onboarding in a browser, the live hub and its tunnel,
Cloudflare, Windows (a machine credential is refused there), threats from the same user on
the machine, and the bytes of an installed worker on another platform: a source build of its
tag stands for its source, not for its binary.
