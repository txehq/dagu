# Developer CLI and skill install

`install.sh` puts the TXE developer CLI on this machine's `PATH` as `dagu`. It also gives every Claude Code and Codex profile the `txe-dagu-jobs` skill that binary carries. It runs on macOS and Linux and needs no Kubernetes access and no API key.

```sh
txe/developer/install.sh --tag txe-v2.18.2-12          # build the fork tag (needs git and go)
txe/developer/install.sh --tag txe-v2.18.2-12 --binary /abs/dagu-2.18.2-txe.12   # install an accepted build of that tag
txe/developer/install.sh --check                       # read back; changes nothing
dagu txe login --hub https://dag.txeinternal.com        # then sign in, in the browser
dagu txe whoami
```

Use a tag that has passed acceptance. `--binary` must report exactly the tag's version (`dagu version`).

## Where things go

| Path | What | Owner |
|---|---|---|
| `~/.local/share/txe-dagu-cli/bin/dagu-<version>` | the binary; earlier versions are kept | this script |
| `~/.local/share/txe-dagu-cli/bin/dagu` | wrapper: `dagu txe ...` uses the developer's context store | this script |
| `~/.local/share/txe-dagu-cli/client/data` | the developer's context store: the `txe` context `dagu txe login --hub` creates, sign-in only, no API key | `dagu txe login` |
| `~/.local/bin/dagu` | link to the wrapper | this script |
| `~/.local/share/txe-dagu/` | the TXE home: machine identity, packages, receipts, sign-ins, the unpacked skill | the worker and the CLI |
| `~/.local/share/txe-dagu/client/` | the machine's own context store, which this machine's jobs run with | the worker installer |
| `~/.local/share/txe-dagu/bin/dagu` | the binary this machine's worker and its jobs run | `txe/worker/install.sh` |

The developer's sign-in and the machine's store are kept apart. On a machine with a worker, the machine's `txe` context reaches the hub over the local tunnel with the machine's credential, and `dagu txe login --hub` would refuse to replace it. A job a signed-in developer registers still runs its steps with the machine's own store. Registration checks that store first: the sign-in must be bound to the machine's owner, and both stores must reach the same registry (TXE-4706).

## Skill links

`dagu txe skill install` unpacks the binary's skill under the TXE home and points `skill/current` at it. Then:

- `~/.coding_skills/txe-dagu-jobs` links to `skill/current`, when `~/.coding_skills` exists.
- Each `~/.claude*/skills`, `~/.codex*/skills` and `$CODEX_HOME/skills`, plus `~/.agents/skills` (which Codex also reads), gets `txe-dagu-jobs`. It links to `~/.coding_skills/txe-dagu-jobs`, or to `skill/current` when there is no `~/.coding_skills`.
- A real directory, or a link that resolves elsewhere, is someone's own copy. It is reported and kept, and the readback fails until it is moved away.
- A profile home that is itself a link to another home is covered by that home.

An upgrade moves `skill/current`, so every profile reads the new revision with no link changed.

## What it never does

- It never changes the worker's binary, its launchd agents or its context store.
- It never replaces a `~/.local/bin/dagu` it cannot name. It replaces only its own link, or the link the worker installer makes to `~/.local/share/txe-dagu/bin/dagu`.
- It never reads, copies or writes a credential.
