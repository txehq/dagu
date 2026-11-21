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
  **kube-run is read-only.** It runs only these verbs:
  - `get`, `describe`, `top`, `logs` and `events`;
  - `rollout status` and `rollout history`;
  - `auth can-i` and `auth whoami`;
  - the discovery verbs `api-resources`, `api-versions`, `explain`, `version` and `cluster-info` (with no
    operand, so `cluster-info dump` is refused).
  Every mutating, interactive or tunnelling verb is refused before contact: `delete`, `edit`, `patch`, `label`,
  `annotate`, `scale`, `wait`, `apply`, `create`, `replace`, `diff`, `exec`, `cp`, `attach`, `port-forward`,
  `run`, `debug`, `proxy`, `expose`, `autoscale`, `set`, `drain`, `cordon`, `uncordon`, `taint`, `certificate`,
  `rollout restart|undo|pause|resume`, and any plugin or unknown verb.
  A read is still authorized by cluster, resources and namespace, because a read can widen too:
  - every resource operand counts (`get pods/a secrets/b` is pods and secrets), including those after `--`;
  - every true spelling of `--all-namespaces` and `-A` means all namespaces;
  - `--subresource=<s>` is authorized as `<resource>/<s>`;
  - `auth` and `rollout` are authorized with their subcommand (`auth can-i`, `rollout status`);
  - an attached or clustered `-s` (`-sURL`, `-its`) is a server override, refused like `--server`;
  - options follow a per-verb arity table (`VERB_OPTIONS` in `kube_run.py`): for each read verb, the options
    that take a value and the options that take none. In `logs`, `-f` (follow) and `-p` (previous) take no
    value. Only the options in that table, plus a few global ones, are forwarded. Any other option (`--raw`
    included), and any attached or clustered short option (`-wA`, `-ojson`), is refused: write each option and
    its value separately;
  - a value is never another option, so `-o --namespace x` and `-l -A` are refused. A value that looks like an
    option (`--tail=-1`, `--tail -1`) is refused rather than reinterpreted. `--opt=value` is read explicitly,
    and after `--` every token is an operand;
  - `-f`/`--filename`/`-k`/`--kustomize` (file or kustomization reads) are refused on every verb.
  The registry entry must pin kubectl by absolute path. kube-run never looks kubectl up on the caller's PATH.
  Example: `kube-run --authorization rec.json txe-onprem-ci -- get pods -n arc-runners -o wide`.
- **`b5_custody.py`**: the reviewed B5 host-process custody, copied byte for byte (provenance below) and
  pinned by sha256 in `kube_run.py`.
- **`kubectl-context-guard.py`**: a PreToolUse hook that lets an agent's cluster API call through only on the
  installed kube-run path:
  - direct kubectl API calls are refused (H01), and so are helm, flux, k9s and stern API calls (H07);
  - anything it cannot read fails closed (H02 to H05, H12 to H14);
  - a client's name is allowed only in a position the hook understands: a client's own argv (classified), the
    installed kube-run's argv (H09 to H11), or an argument or input of the small closed data set (`echo`,
    `printf`, `cat`, `grep`, `which`, `test`) with its listed options only. Anywhere else it is refused (H15). An interpreter's code, arguments or input
    naming a client, and a shell or interpreter reading a pipe while the command names a client, are refused
    as H03. `watch` without `--exec` runs its words as shell text, and they are checked as such;
  - wrapper options follow per-wrapper arity tables. An option whose value is optional and attached only
    (`watch -d`/`--differences`, GNU `xargs -i`/`--replace`, `-e`/`--eof`, `-l`/`--max-lines`) consumes no
    word, and its attached short form (`-d1`, `-ifoo`) is unsupported: unknown, so refused when a client
    follows. A word consumed as a REQUIRED value never names a client (`watch -n kubectl ...` is H03), so a
    wrong table entry fails closed;
  - the installed kube-run is accepted only as a BARE command word, with no wrapper before it (`env`, `sudo`,
    `timeout`, `nohup`, `command`, `time`, ...). It must also sit in a line whose every other command, at any
    depth, is in a SMALL CLOSED SET of environment-neutral commands, with no assignment of any form (`NAME=`,
    `NAME+=`, `NAME[i]=`) (H16). The set is:
    - the data set above, used as data;
    - `[ ... ]` and `cd`;
    - `set` with only `-e`, `-u`, `-x` (and `+`, clustered as in `-euo pipefail`) and `-o`/`+o` `pipefail`,
      `errexit`, `nounset` or `xtrace`;
    - a kubectl-family client's local forms;
    - a shell in `-c` mode, whose text is held to this same set;
    - keyword structure (`if`/`then`/`fi`, `while`/`do`/`done`, `!`, `{ }`, `( )`).
  - Anything else is refused. That includes:
    - every other external command or builtin, known or unknown: `export`, `read`, `printf -v`, `mapfile`,
      `let`, `getopts`, `eval`, `source`, interpreters, `helm`/`flux`/`kustomize` local forms, every wrapper
      (`command -v` included), `time`, and `set -k`/`-o keyword`/`-a`;
    - a shell given a script file;
    - an output redirection to anything but `/dev/null` or an fd duplicate (`2>&1`);
    - an upper-case assignment-shaped kube-run argument (`PATH=/tmp/bin`), which an inherited keyword mode
      would move into kube-run's environment.
  - Syntax H16 does not model is refused in such a line: `${...}` (its `:=` and `=` forms assign), `$((..))`,
    `((..))`, `$[..]`, `[[ ]]`, a function definition `name()`, and `for`/`select`/`case`/`function`.
  - It is an allowlist because any environment change could choose the interpreter of kube-run's
    `#!/usr/bin/env python3`, and the builtins that make one cannot be enumerated safely. It holds the text of
    the line to this set. It is not proof of a trusted pre-existing environment: that is the installation
    contract below;
  - standard input fed to a shell (`bash -s x <<< '...'`, a here-document, a script reading its input) is
    always checked as a program;
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
| Claude Code PreToolUse, `tool_name == "Bash"`, `tool_input.command` a string | **Guarded.** Parsed by the hook's lexer and checked by H01 to H13 and H15. Tested with synthetic events in Claude Code's documented shape. Not yet observed in a live harness |
| Any other tool or harness with a command-like field (`tool_input.command` or `tool_input.cmd`, a string or an argv list), for example a Codex shell call | **Unsupported, NOT guarded.** It is refused (H14) when the text names a cluster client, and allowed otherwise. Nothing in it is parsed, so a kube-run call in this shape passes unchecked by the hook (kube-run still runs its own checks). No Codex payload has been captured or tested; the shapes in the tests are hand-written |
| Events with no command-like field (Read, Edit, MCP tools, ...) | Allowed, not guarded. MCP cluster tools are out of scope (TXE-7874) |
| Script files (`bash ops/x.sh` that runs kubectl inside), client-go programs, and interpreter code that builds a client's name at run time (`python3 -c '...execlp("kube"+"ctl", ...)'`) | **Not visible to the hook.** It is a heuristic over command text, and it refuses interpreter payloads only when they name a client. Keeping such calls off a production cluster needs the agent's environment to hold no usable default credential. That is a deployment decision, not something this hook can enforce |
| Any harness where the hook is not wired | **Not installed**: no protection at all |

Only the first row is positive protection. An H14 refusal is a fail-closed stop, not a claim of coverage.

## Shell parsing: its scope and its cost

The hook reads Bash command text with its own lexer. That covers quoting, `$(...)`, backticks, `<(...)`,
here-documents and here-strings, `sh -c`/`eval`/stdin fed to a shell, and wrappers. Here-document delimiters
follow Bash's quote removal (`<<EOF`, `<<'EOF'`, `<<"EOF"`, `<<\EOF`, `<<-EOF`). It is **not** a full Bash
parser, and it does not parse interpreter code.

**A command the hook cannot parse is refused (H05), whatever it names.** That is the conservative choice for
an unwired prototype, and its effect is broad. Once wired, some legitimate NON-cluster Bash commands that this
lexer cannot read would be refused as well, for example a partly quoted here-document delimiter (`<<"E"OF`) or
other constructs outside the forms above. Such a refusal says H05; the remedy is to write the command in a
form the lexer reads. The extra raw-text check, which also matches a client name with its backslashes removed
(`kube\ctl`), is a second line only, never the parser.

## Positive classification: where a client's name is accepted

Every cluster-client name in a guarded command must sit in a context the hook understands. Any other mention is
refused:
- H15 in an unclassified command;
- H03 in an interpreter, or in a shell or interpreter that reads a pipe or generated text;
- H02 after a run-time command word.

| Accepted context | Exact conditions |
|---|---|
| A client's own argv (kubectl, oc, kubecolor, helm, flux, k9s, stern) | It is a LOCAL form whose options are fully understood (`version --client`, help, `config` reads without `--raw`/`--flatten`, kustomize, helm template without `--validate` or `--dry-run=server`, ...). Any other form is H01 or H07 |
| The installed kube-run's argv | H09 to H11 hold, and kube-run repeats every check at run time |
| The SMALL closed data set (`DATA_OPTIONS`) | `echo` with `-n` `-e` `-E` only; `printf` and `cat` with NO options; `grep` with `-r` `-R` `-n` `-i` `-l` `-c` `-v` `-w` `-x` `-E` `-F` `-o` and `-e <pattern>` (`egrep`/`fgrep` the same, without `-E`/`-F`); `which` with `-a`; `test`, `true`, `false` and `:` with any token; `[` ... `]`, the EXACT word `[` with `]` as its last argument, classified before the glob check with the rules of `test` (a `[` without its `]` is H05; words merely containing `[`, such as `[a-z]` or `x[`, stay run-time command words, H02). Operands and input are then data, but only while that output does not reach code: a shell or interpreter reading its pipe is refused, and so is an output process substitution `>(...)` (checked as a pipe receiver) or a redirection into a process substitution |
| `command -v` / `command -V` | A lookup, not a run |
| The inner text of `$(...)`, backticks and `<(...)` | It is classified recursively by these same rules |

Why no operand of the data set carries execution: `echo`, `printf` and `cat` print text or file contents;
`grep` matches a pattern over files (this set has no pager, preprocessor or exec option); `which` prints paths;
`test`/`[` evaluate an expression; `true`/`false`/`:` ignore their arguments. Rejected forms: any option not
listed, any attached or clustered short form outside the listed letters, `--long=value` for an unlisted name, and
every other command.

**Unsupported, and refused when a client is named:** every other command, including `man` (it runs a pager:
`man -P`, `--pager`, `MANPAGER`), `git` (configured hooks, pagers, diff drivers and textconv helpers run without any
flag in the command, and `grep -O`/`--open-files-in-pager`, `--ext-diff` and `--textconv` run programs), `head`,
`tail`, `tee`, `rg`, `ag`, `sort`, `less`, `more`, `gh`, `orca`, `awk`, `sed`, `make` and scripts. A prefix
assignment whose value names a client (`MANPAGER='kubectl ...' man ls`, `GIT_PAGER=...`) is refused as H04.
Also:
- `source` or `.` of generated text;
- an interpreter whose code, arguments or input name a client;
- `watch` (its words are shell text unless `--exec` is given);
- a shell or interpreter reading a pipe;
- the forms the lexer cannot parse (H05).

**Expected false refusals, documented:** text that only QUOTES a client name, inside a command that is not a data
context, is refused too. Examples: an orchestration message (`orca orchestration ask --question 'run kubectl get
pods?'`), a `gh` comment, an `rg` search, a `git commit -m` message, `git log --grep` and `man kubectl`. Write such
text with a data command (`echo`, `cat` to a file), or without the client's name.

**Scope and prerequisites:** this is not containment of arbitrary scripts or interpreters. The hook cannot infer
commands that are absent from the command text: a script file's contents, or a program that builds a client's
name at run time. Its classification also ASSUMES things it cannot see:
- that the command words resolve to the standard programs, so no shell alias or function and no `PATH` entry
  shadows `echo`, `cat`, `grep` and the rest;
- that no external configuration turns them into launchers (an alias file, a `BASH_ENV`, a pager or driver
  setting).
These are deployment prerequisites, not things the hook proves. It does not guard every way a shell can execute a
command: it refuses the ones it can see that it does not understand.

H16 also refuses legitimate lines. Examples are setting a variable for a kube-run call (`NS=arc-runners;
kube-run ... -n "$NS"`), wrapping it (`timeout 60 kube-run ...`), combining it with any command outside the
neutral set (`date; kube-run ...`), writing its output to a file (`kube-run ... > out.txt`), and `"${NS}"`. Pass
values literally, use kube-run's own `--timeout`, pipe to `grep`, and run other commands in a separate tool call.

**Installation contract for kube-run (a prerequisite of any install; nothing here installs it):** the installed
kube-run must start through an ABSOLUTE, pinned interpreter in isolated mode. For example, it can be a small
launcher at the installed path that execs `<absolute python3.13> -I -B <absolute kube_run.py> "$@"`. The
`#!/usr/bin/env python3` shebang is for running it from source. Through `env`, it lets the caller's `PATH` choose
the interpreter, and a program posing as Python would receive kube-run's full argv before any check. H16 keeps
the hook from accepting a line that changes that environment. But the hook cannot see an environment the agent's
shell already inherited, which is why the pinned interpreter is the install's job. Relative entries in an inherited
`PATH` (which `cd` would then change) are excluded by the same contract.

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
