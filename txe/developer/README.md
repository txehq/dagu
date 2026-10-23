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

The fork publishes no release downloads, so on a new machine get the script from the tag and let it build that tag. It needs git, go, python3 and bash, and `~/.local/bin` on `PATH`:

```sh
git clone --depth 1 --branch <accepted tag> https://github.com/txehq/dagu.git txe-dagu-<accepted tag>
cd txe-dagu-<accepted tag>
txe/developer/install.sh --tag <accepted tag>
```

The hub's dashboard gives the same steps, with this hub's address filled in, under Integrations, "Developer setup". A person signed in through single sign-on finds them under "Developer setup" in their own dashboard. The page shows commands to copy and the output to expect; it runs nothing, and it cannot see the machine.

Signing in ends at a one-time listener on `127.0.0.1` on the machine that runs `dagu txe login`, on a port it picks, and gives up after five minutes. `--no-browser` only stops the CLI from opening a browser: the address it prints must still be opened in a browser on that machine. On a remote machine over SSH, take the port from the `127.0.0.1` address in the printed `redirect_uri`, and forward that same port from your own computer in a second terminal (`ssh -L <port>:127.0.0.1:<port> <you>@<that machine>`). Then open the address in your own browser.

## Checking that it works

Four stages, each checked on the machine, in order:

| Stage | Proof |
|---|---|
| CLI and skill installed | `install.sh --check` ends with `ok.` |
| Identity bound | `dagu txe whoami` says `bound, owner own_…`; `unbound` or `pending` waits on an administrator |
| Machine and worker ready | `dagu txe doctor` says ok on every line, `machine on hub` included, and the machine's page in the hub shows an active enrolment. The worker install and its enrolment need an administrator today: the tunnel credential, and the worker client listed in the hub |
| A job ran and its result reached the hub | the smoke test below |

`smoke/` is the smoke test. The page writes it into a new directory under `~/txe-dev-setup-smoke`. The shell that runs the page's command fills in `{{STAMP}}` and `{{EXPIRES_AT}}`: the job key, and a lifetime of fifteen minutes from then. The job runs every minute. Each run prints one line and writes only its `result.json`, which is published to the hub; it calls no external service. Then:

1. `dagu txe register -f job.yaml --session dev-setup-smoke --dry-run`: `The spec is complete. Nothing was registered.`
2. `dagu txe register -f job.yaml --session dev-setup-smoke` registers a real job, which runs every minute on this machine until it expires: `Registered job_… version 1. The hub has marked it ready.`
3. `dagu txe package verify <job id>`: the package is intact and the job is ready. It has not run yet.
4. `dagu txe inspect <job id>` within a minute or two: `Recent runs` lists a run with status `succeeded`, and the job's page in the hub shows the run and its `result.json`.

When the lifetime ends, the registry retires the job (`Lifecycle: retired`), and the hub runs it no more. Its runs stay readable. To end it sooner: `dagu txe retire <job id> --session dev-setup-smoke --detail "smoke test done"`. `dagu txe complete` is for a job whose purpose is met. `TestTXEDeveloperSmokeJob` registers these files with the built CLI against a hub with the real registry. The page's own tests check that it prints exactly these files.

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
