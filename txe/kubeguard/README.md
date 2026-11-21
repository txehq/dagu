# kubeguard: kube-run and kubectl-context-guard (TXE-8039)

On 2026-11-21 an agent's `kubectl get ... -A`, with no `--context` and no `--kubeconfig`, read the
production cluster, because that workstation's default kubeconfig context was production. Naming a context
does not fix that: a context is a local alias, the same name can mean another cluster in another file, and
a context can be repointed inside its file. This directory holds the source of the class fix:

- **`kube_run.py`, kube-run**: the one identity-bound path for an agent's cluster API call.
  `kube-run [--authorization FILE] [--timeout SECONDS] <cluster-id> -- <kubectl arguments>`. It checks, in
  order:
  - a registered cluster id (fixed registry path);
  - no target, identity or TLS override (KR04);
  - an authorization policy (KR06 to KR09);
  - server and CA sha256 pins before any contact (KR10 to KR14);
  - static credentials only (KR23);
  - a TLS-verified kube-system Namespace UID probe (KR15, KR16);
  - a kubeconfig re-hash (KR17).
  Only then does it make the request, under B5 host custody. Diagnostics are stable codes with values
  withheld. The full contract is in its docstring.
  Authorization covers every part of a request that selects scope:
  - every resource operand (`get pods/a secrets/b` is pods and secrets), including those after `--`;
  - an attached or clustered `-s` (`-sURL`, `-its`) is a server override, refused like `--server`;
  - every true spelling of `--all-namespaces` and `-A`;
  - a `cp` operand that names its own namespace is refused;
  - `auth` and `rollout` are authorized with their subcommand (`auth can-i`, `rollout restart`), from an
    allowlist;
  - only options kube-run knows are forwarded. Any other option, and any attached or clustered short option
    (`-wA`, `-inother`, `-ojson`), is refused: write each option and its value separately;
  - file-based and create requests (`apply`, `create`, `replace`, `diff`, `-f`, `-k`; `logs -f` excepted) are
    refused, because the kinds and namespaces they act on cannot be read from the arguments before contact;
  - discovery verbs take no operand, so `cluster-info dump` is refused, and `--subresource=<s>` is authorized
    as `<resource>/<s>`.
  The registry entry must pin kubectl by absolute path. kube-run never looks kubectl up on the caller's PATH.
- **`b5_custody.py`**: the reviewed B5 host-process custody, copied byte for byte (provenance below) and
  pinned by sha256 in `kube_run.py`.
- **`kubectl-context-guard.py`**: a PreToolUse hook that lets an agent's cluster API call through only on the
  installed kube-run path:
  - direct kubectl API calls are refused (H01), and so are helm, flux, k9s and stern API calls (H07);
  - anything it cannot read fails closed (H02 to H05, H12 to H14);
  - local version, help, config-read and kustomize commands pass.

## What state this is in

- **Unwired source is inert.** Nothing in this directory installs itself. Nothing here changes a
  kubeconfig, a current-context, a credential, a settings file or a hook configuration.
- **Once wired, the hook BLOCKS calls.** With no cluster registered, every agent cluster API call is
  refused. An unconfigured kube-run refuses every call too (KR02 with no registry, KR06 with no policy).
  Wiring the hook therefore changes agent behaviour at once. It is a deployment decision with its own plan,
  not part of this change.
- **An authorization record is a declaration of scope, not tamper-proof authority.** kube-run checks a
  record's shape, cluster, expiry and scope against the request. It does not check who wrote the record: a
  caller who can write a file can write one. KR06, the refusal of every call to an entry with no policy
  configured, is a default-deny, not authentication of a configured record. Who may issue records, and how
  they are protected, is a decision for any install plan; signing is out of scope here.
- The rules that need a decision before any install are compatibility proposals, not approved policies:
  static credentials only, the direct-client and helm/flux refusals, which clusters are registered and who
  writes authorization records.

## Event shapes: guarded, unsupported, not installed

| Shape | Status |
|---|---|
| Claude Code PreToolUse, `tool_name == "Bash"`, `tool_input.command` a string | **Guarded.** Parsed by the hook's lexer and checked by H01 to H13. Tested with synthetic events in Claude Code's documented shape. Not yet observed in a live harness |
| Any other tool or harness with a command-like field (`tool_input.command` or `tool_input.cmd`, a string or an argv list), for example a Codex shell call | **Unsupported, NOT guarded.** It is refused (H14) when the text names a cluster client, and allowed otherwise. Nothing in it is parsed, so a kube-run call in this shape passes unchecked by the hook (kube-run still runs its own checks). No Codex payload has been captured or tested; the shapes in the tests are hand-written |
| Events with no command-like field (Read, Edit, MCP tools, ...) | Allowed, not guarded. MCP cluster tools are out of scope (TXE-7874) |
| Script files (`bash ops/x.sh` that runs kubectl inside), client-go programs, and interpreter code that builds a client's name at run time (`python3 -c '...execlp("kube"+"ctl", ...)'`) | **Not visible to the hook.** It is a heuristic over command text, and it refuses interpreter payloads only when they name a client. Keeping such calls off a production cluster needs the agent's environment to hold no usable default credential. That is a deployment decision, not something this hook can enforce |
| Any harness where the hook is not wired | **Not installed**: no protection at all |

Only the first row is positive protection. An H14 refusal is a fail-closed stop, not a claim of coverage.

## Platform and syscall constraints

- B5 needs **macOS**. It reads group membership through libproc `proc_listpids(PROC_PGRP_ONLY)` and observes
  the leader without reaping it through `os.waitid(..., WNOWAIT)`, which needs Python 3.13 on macOS. It
  spawns with `posix_spawn(setsid=True)` and blocks TERM, INT and HUP with `pthread_sigmask` around the
  spawn.
- On any other platform (Linux included), B5's `bounded_run` refuses **before it creates any pipe or child**,
  and kube-run refuses the call as **KR26** (exit 3). The argument, registry, authorization and pin checks still
  run first. A Linux implementation would need a reviewed `/proc`-based membership reader: new code and a new
  pin, not a change to the copied section.
- **B5's stated limit:** it settles the owned process group only. A descendant that calls `setsid()` leaves
  the group, and is neither seen nor signalled. That is why kube-run refuses credential helpers (exec,
  auth-provider, impersonation: KR23). kube-run is not containment for arbitrary exec plugins or client-go
  programs, and it is not ready for real auth plugins.
- The hook never runs a client, never opens a kubeconfig and never contacts a cluster.

## Provenance of `b5_custody.py`

Everything from the line `# ---------- B5` to the end of `b5_custody.py` is copied byte for byte from:
- **Source:** `runner-final.py`, the reviewed container-stage-1 runner of TXE-7974 (file sha256 `c7c97084…`,
  lines 294-640). TXE wrote it, and it is kept as TXE-7974 evidence rather than in this repository.
- **Pin:** the section's sha256 is `074c8f65f57b987118079e99ef92c9ec86929111679605a2552c9c8fd1ff94d8`.
  `test_kube_run.py` fails when it differs.
- **Whole file:** `kube_run.py` pins the whole file's sha256 (`B5_SHA256`), and refuses to run (KR25) on any
  other copy.
- **Licence:** the same as this repository (`GPL-3.0-or-later`).

Do not edit below the marker. A change is a new reviewed revision, then new pins in both places.

## Tests

`go test ./txe/kubeguard/` runs both suites with `python3 -I -B`, in pure mode (`kubeguard_test.go`). They are
skipped on Windows.

- **`test_kube_run.py`.**
  - kube-run is driven through `main()` with a stub transport, a fixed clock and inert fixtures.
  - The tests cover the pre-contact pins, authorization, overrides, value-free diagnostics, settlement
    outcomes, credential helpers and the B5 pins.
  - Off macOS they also check that the real transport refuses with KR26 before any child.
  - On macOS with `KUBEGUARD_REAL_CHILDREN=1`, run directly (`python3 -I -B test_kube_run.py -v
    RealChildrenThroughB5`), 8 more cases run real, bounded, self-expiring children through B5. The fixtures
    signal no child; B5 runs its own TERM/KILL cleanup. That mode keeps its fixture root as evidence. CI never
    runs it.
- **`test_kubectl_context_guard.py`.**
  - Synthetic events on stdin cover the refusals, the allowed local and kube-run forms, value-free
    diagnostics, and the event shapes above.
  - **PairingWithKubeRun** checks the hook against this directory's `kube_run.py`:
    - every kube-run form the hook allows parses in kube-run;
    - an argument form the hook refuses is refused by kube-run too;
    - the two override lists are the same list.
