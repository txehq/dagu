# Developer CLI and skill install

`install.sh` puts the TXE developer CLI on this machine's `PATH` as `dagu`. It also gives every Claude Code and Codex profile the `txe-dagu-jobs` skill that binary carries. It runs on macOS and Linux and needs no Kubernetes access and no API key.

```sh
txe/developer/install.sh --tag <accepted tag>          # build the fork tag, such as txe-v2.18.2-14 (needs git and go)
txe/developer/install.sh --tag <accepted tag> --binary /abs/dagu-<its version>   # install an accepted build of that tag
txe/developer/install.sh --check                       # read back; changes nothing
dagu txe login --hub https://dag.txeinternal.com        # then sign in, in the browser
dagu txe whoami                                         # bound, and to which owner
dagu txe machine create                                 # once per machine: record it in the hub
```

Use a tag that has passed acceptance; ask the hub's operators which one is current. `dagu txe machine create` needs `txe-v2.18.2-14` or later. `--binary` must report exactly the tag's version (`dagu version`), such as `2.18.2-txe.14` for `txe-v2.18.2-14`.

## Where things go

| Path | What | Owner |
|---|---|---|
| `~/.local/share/txe-dagu-cli/bin/dagu-<version>` | the binary; earlier versions are kept | this script |
| `~/.local/share/txe-dagu-cli/bin/dagu` | wrapper: a `dagu txe` command uses the developer's context store, whatever flags come before `txe` | this script |
| `~/.local/share/txe-dagu-cli/client/data` | the developer's context store: the `txe` context `dagu txe login --hub` creates, sign-in only, no API key | `dagu txe login` |
| `~/.local/bin/dagu` | link to the wrapper | this script |
| `~/.local/share/txe-dagu/` | the TXE home: machine identity, packages, receipts, sign-ins, the unpacked skill | the worker and the CLI |
| `~/.local/share/txe-dagu/client/` | the machine's own context store, which this machine's jobs run with | the worker installer |
| `~/.local/share/txe-dagu/bin/dagu` | the binary this machine's worker and its jobs run | `txe/worker/install.sh` |

The developer's sign-in and the machine's store are kept apart. On a machine with a worker, the machine's `txe` context reaches the hub over the local tunnel with the machine's credential, and `dagu txe login --hub` would refuse to replace it. A job a signed-in developer registers still runs its steps with the machine's own store. Registration checks that store first: the sign-in must be bound to the machine's owner, and both stores must reach the same registry (TXE-4706).

## Recording this machine in the hub

The hub has to know a machine before it can enrol the machine's worker or register a job from it. `dagu txe machine create` records it, once, with the developer's sign-in. It sends nothing else: no API key and no administrator step.

- The owner is the sign-in's owner, as the hub reports it. `--owner-id` only checks that; the command stops if it names another owner.
- The machine's identity is `machine.json` in the TXE home. If it exists, its machine id is used and the file is never changed, and if it belongs to another owner, the command stops. If it does not exist, the command mints the id and writes the file first, the way the worker installer does, so the worker installer later keeps it (`--display-name` names it, default this computer's name).
- Running it again is safe: the hub returns the record it already has for the same machine and owner.
- The hub, not this command, decides: it holds a person's or CLI sign-in to its own owner in every mode. The command checks first only so that it sends nothing the hub would refuse. A machine's worker or reviewer credential cannot create a machine.

On a new machine the order is:

1. `txe/developer/install.sh`, then `dagu txe login --hub <the hub's address>` as a person of the owner;
2. `dagu txe machine create`, which mints the machine id and writes `machine.json`;
3. the worker installer, which keeps that `machine.json`, so it needs no `--owner-id`;
4. `dagu txe enrol` (below).

## Enrolling this machine's worker

`dagu txe enrol` is the machine's, not the developer's. The wrapper leaves it on the machine's own store, the TXE home's `client`. The hub the enrolment records is therefore the one this machine's job steps reach. A step presents the machine credential only to that hub (TXE-4707), so an enrolment made through the developer's store would leave the steps refusing to run.

Order on a machine with a worker:

1. **Hub:** `dagu txe machine create` has recorded the machine, and the hub's administrator lists the machine's worker client in `txe.authn.clients`.
2. **Enrol:** `dagu txe enrol --client-id <this machine's worker client> --wait 15m`. A person of the owner signs in, then approves in the hub.
3. **Upgrade the worker:** its jobs' steps run `~/.local/share/txe-dagu/bin/dagu`.

Until step 2 completes, the steps keep the context's API key, and say so.

## Skill links

`dagu txe skill install` unpacks the binary's skill under the TXE home and points `skill/current` at it. Then:

- `~/.coding_skills/txe-dagu-jobs` links to `skill/current`, when `~/.coding_skills` exists.
- Each `~/.claude*/skills`, `~/.codex*/skills` and `$CODEX_HOME/skills`, plus `~/.agents/skills` (which Codex also reads), gets `txe-dagu-jobs`. It links to `~/.coding_skills/txe-dagu-jobs`, or to `skill/current` when there is no `~/.coding_skills`.
- A real directory, or any link other than exactly that one, is someone's own copy. That includes a link pinned to one revision. It is reported and kept, and the readback fails until it is moved away.
- A profile home that is a link is followed, and each real home is visited once.

An upgrade moves `skill/current`, so every profile reads the new revision with no link changed.

## Readback

`--check` changes nothing outside a temporary directory it removes, and reads no context store: the skill status runs with a Dagu home and store of its own there. It checks three things:

- the wrapper is byte for byte what this script writes for its tag, and its binary is `dagu-<that tag's version>` and reports that version;
- `dagu` on PATH is the link to the wrapper;
- every location is exactly the managed link, and resolves to the binary's skill revision.

A build from a tag uses `-trimpath`, so rebuilding the same tag with the same toolchain gives the same file.

## What it never does

- It never changes the worker's binary, its launchd agents or its context store.
- It never replaces a `~/.local/bin/dagu` it cannot name. It replaces only its own link, or the link the worker installer makes to `~/.local/share/txe-dagu/bin/dagu`.
- It never reads, copies or writes a credential.
- It never installs into the TXE home: a developer root that is, or leads into, the TXE home is refused.
- It writes nothing through a fixed temporary name, or through a link at a destination. Every staged file is created for the run and renamed onto exactly its pathname. A versioned binary is published only where nothing exists yet.
- It runs one install at a time, using a lock directory in the CLI root. That lock serialises this script, not other programs: one that replaces `~/.local/bin/dagu` between this script's check and its swap would lose its file.
- It refuses a developer bin, client or store directory that resolves to, or into, the worker's. That covers the TXE home, its `bin`, `client`, `client/data` and `client/data/contexts`.
