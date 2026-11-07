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

These check the definition, not that a negative path ran: that is the heavy test's job,
and its results file is the only record of it.

**Heavy, opt-in (`TestMachineAuthReleaseMatrix`, Linux):**

```sh
# the current source, built by the harness (a smoke: the long cells are off)
DAGU_MACHINEAUTH_MATRIX=source go test ./internal/intg/machineauth -run ReleaseMatrix -v -timeout 30m

# named builds, as a release proof (long cells on in the manifest)
DAGU_MACHINEAUTH_MATRIX=/path/manifest.json go test ./internal/intg/machineauth -run ReleaseMatrix -v -timeout 90m
```

The manifest names each build exactly, with the binary's path, its full sha256 and
(optionally) the version it must report; `long: true` asks for the two slow cells.
The test refuses to start if a binary's digest is not the manifest's.

```json
{
  "builds": [
    {"name": "release", "path": "/abs/dagu-release", "sha256": "<64 hex>", "version": "2.18.2-txe.20"},
    {"name": "previous", "path": "/abs/dagu-previous", "sha256": "<64 hex>"}
  ],
  "long": true,
  "results_dir": "/abs/results"
}
```

For each build it runs the cells below with that build as hub and as worker, and with
several builds the pair cell (`pair-native`) for every ordered pair. It writes
`machineauth-results-<utc>.json` with each binary's digest and reported version and the
status of every cell: `pass`, `fail` or `not_run`. The test fails on any failed cell. With
`long: false` the long cells are recorded `not_run` and the result is **partial**: a
smoke of the build, never release acceptance.

To run it inside a Linux container without a Go toolchain, cross-compile the test and copy
it in: `GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o machineauth.test
./internal/intg/machineauth`, then `DAGU_MACHINEAUTH_MATRIX=manifest.json ./machineauth.test
-test.run ReleaseMatrix -test.v -test.timeout 90m`.

**Verify (`TestMachineAuthVerify`, the release gate's command):**

```sh
DAGU_MACHINEAUTH_VERIFY=/abs/results/machineauth-results-….json \
DAGU_MACHINEAUTH_MATRIX=/path/manifest.json \
go test ./internal/intg/machineauth -run MachineAuthVerify -v
```

It holds a recorded run to the manifest and to the binaries on disk now, and fails on: a
build the manifest does not name, a build missing from the results, a recorded digest that
is not the manifest's, a binary whose digest is no longer the recorded one (or cannot be
read), a reported version that is not the manifest's, a cell that failed or was not run, a
missing or unknown or duplicated cell, a cell attributed to two builds, a missing pair, a
status that is not `pass`/`fail`/`not_run`, a results schema it does not read, and a
manifest with `long: false`. A pass cannot be carried by hand.

## The cells

Positive: `setup` (the real enrolment protocol: browser-SSO persons, binding requests and
the administrator's approvals, `txe login`, `txe machine create`, `txe enrol` for the
worker and reviewer classes through the issuer, the persons' approvals, `txe enrol check`
over the channel), `pos-native`, `pos-channel-http`, `pos-channel-tls` (through a TLS edge
whose CA the worker trusts by `SSL_CERT_FILE`), `pos-two-owners`, `pos-probe-control`,
`cancel`, `revoke-owner` (the step stops at the worker's bound, every late write refused),
`reenrol` (a new generation; the revoked one stays), `neg-worker-start` (the binary refuses a
reviewer credential, another machine's id or label), `neg-worker-nocred`.

Negative, each over gRPC and the channel, each held to the reason the hub logs:
`neg-no-credential`, `neg-hub-scheme-with-token`, `neg-garbage-token`, `neg-cli-token`,
`neg-reviewer-token`, `neg-other-machine-id`, `neg-other-machine-label`,
`neg-expired-token`, `neg-not-yet-valid-token`, `neg-wrong-audience`,
`neg-unknown-client`, `neg-long-lifetime`, `neg-other-identity-on-client`,
`neg-dispatch-as-machine`, `neg-cancel-as-machine`.

Long (`long: true`): `stale` (a frozen worker's attempt expires at the production lease
threshold; its late status and streams are refused as stale) and `revoke-issuer` (the
provider refuses the refresh; the worker presents nothing more). Each takes minutes.

Budget: about 3 minutes per build without the long cells, about 15 with them, plus a few
seconds per pair.

## What it does not cover

A real identity provider, person onboarding in a browser, the live hub and its tunnel,
Cloudflare, Windows (a machine credential is refused there), and threats from the same
user on the machine.
