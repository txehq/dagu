# Local Dagu worker (macOS)

Runs Connor's jobs on his machine for the Dagu service in the TXE staging cluster
(`capso-txe-development`, namespace `dagu`). The service schedules a job; this worker runs its
scripts locally with local tools and credentials, and returns status, logs and artifacts to the
service. Two launchd agents keep it running whether or not a coding session is open.

| Agent | What it runs |
|---|---|
| `com.txe.dagu.tunnel` | `kubectl port-forward` from `127.0.0.1:18080` to the UI/API and from `127.0.0.1:50055` to the coordinator, using a credential that can only port-forward in `dagu` |
| `com.txe.dagu.worker` | `dagu worker`. Its id is this machine's `mch_` id, its labels are `txe.machine` and `txe.owner`, and it reaches the coordinator at `127.0.0.1:50055`. Once the machine is enrolled, it presents the machine credential (see "Machine credential") |

## Layout

Everything lives under `~/.local/share/txe-dagu`, outside every git worktree.

| Path | Contents | Lifetime |
|---|---|---|
| `machine.json` | `machine_id`, `owner_id`, display name | written once; a reinstall never changes it |
| `bin/dagu-<version>`, `bin/dagu` | every installed binary with its build record; `dagu` points at the current one | kept across upgrades |
| `packages/` | job packages (written by the CLI, TXE-3408) | kept |
| `outputs/` | job outputs and deliverables, `outputs/<job id>/` | kept |
| `receipts/`, `client/`, `skill/` | registration receipts, the CLI's context store with its API key, the shared skill (all owned by the CLI, TXE-3408) | kept |
| `tunnel/kubeconfig` | the tunnel's ServiceAccount token, mode 0600 | renewed by `tunnel-credential.sh` |
| `worker-credential.json`, `worker-credential.json.lock` | the worker's machine credential, mode 0600, and the lock the worker holds while renewing it | written by `dagu txe enrol`; the worker rewrites it when the provider rotates the refresh token |
| `worker-home/` | the worker's `DAGU_HOME` | kept |
| `logs/` | agent logs | kept |

## Install

The cluster side (namespace, Service, the `dagu-tunnel` ServiceAccount and its Role) comes from
txehq/txe `kubernetes/dagu` and must exist first.

```sh
txe/worker/tunnel-credential.sh                     # uses your own context once
txe/worker/install.sh --tag txe-v2.18.2-2 --owner-id own_...
txe/worker/status.sh
```

The owner id is minted once for the installation (`txe/worker/mint-id.sh own`) and recorded with
the service. Pass it only on the first install.

The installer links `~/.local/bin/dagu` to `bin/dagu`, so shells and coding-agent sessions run
this install as `dagu` (set `TXE_DAGU_LINK_DIR` for another directory). If a `dagu` the installer
did not create is already there, it is left alone and named in the output; run
`~/.local/share/txe-dagu/bin/dagu` instead. The installer also says when the link's directory is
not on your PATH.

A job script can read Linear through the Orca CLI without a Linear key. A job's Linear target check
is different, and needs one. The skill sets out both: `txe/skill/SKILL.md`, "Linear: the target check
and your script are two things".

Once the hub knows the machine, install its periodic resource check on the hub. The hub schedules
that check, and this worker runs it.

```sh
~/.local/share/txe-dagu/bin/dagu txe hub install --dry-run   # shows what would change
~/.local/share/txe-dagu/bin/dagu txe hub install
```

Run it again after an upgrade. It rewrites the hub's copy only when the rendered DAG differs.
Version 2 of that DAG declares `hist_retention_days: 36500`, so its runs are kept with their logs
rather than getting Dagu's 30-day default; a hub copy at version 1 declares nothing until it is
installed again.

The installer manages that DAG: it restores its own rendered spec, so do not edit the hub's copy.

It also has limits. Installs from this machine's TXE home run one at a time. The lock does not
cover a copy of the home on another machine, or another API client writing the DAG.

After it creates or updates the DAG, the installer reads it back. That catches a different write
landing after the installer's own write: the install then reports an error. An edit landing between
the installer's first read and its write is overwritten without notice, because the hub's spec API
has no conditional write.

Keep one owner for installs and updates of this machine's hub DAG. Nothing here prevents
conflicting writes atomically.

## Machine credential

When the hub verifies its workers (`coordinator.auth`), the worker must present this machine's own
credential. Enrolment happens after the first install, because `dagu txe enrol` reads `machine.json`:

```sh
dagu txe enrol --client-id <this machine's worker client> --wait 15m   # a person of the owner signs in;
                                                                       # a person approves in the hub
txe/worker/install.sh --tag <the installed tag>                        # the worker agent now passes it
txe/worker/status.sh                                                   # shows the credential it passes
```

The install uses `--credential-file <absolute path>` if given, or else `worker-credential.json` in
the TXE home, where enrol writes it, when that file exists. With neither, the worker agent is
exactly that of an unenrolled machine.

Before anything is written, the install checks the credential and refuses it, rather than
installing without it, when:
- it is not an absolute path to a regular file, or it is a symlink;
- it is not owned by you, or not mode 0600 or tighter;
- its directory is not yours alone, or not writable: the worker saves rotated tokens and its lock
  file there;
- it does not hold exactly the machine credential's fields, with class `worker`;
- it is another machine's.

After building, the install also has the new binary load the credential exactly as the worker will
(`dagu txe enrol check`), and stops if it cannot. A tag from before TXE-4366 has no such check,
so an enrolled machine needs a tag that includes it.

The agent gets the file's path only, in `DAGU_WORKER_AUTH_CREDENTIAL_FILE`. No token is in the plist,
an argument or a log. The install never reads the token beyond checking that it is present.

To roll back to a worker that presents no credential, install again with `--no-credential`. It
writes the worker agent of an unenrolled machine and keeps `worker-credential.json` where it is;
the next install without `--no-credential` passes it again. Do not delete the credential to roll
back: it cannot be recreated without enrolling again. Revoking the enrolment in the hub does not
change what the agent passes either. The installer still finds the file, and the worker then
presents a revoked credential and is refused; the coordinator decides that, not the install.

## Upgrade

Use the same tag as the server image: server and worker must run the same version.

```sh
txe/worker/install.sh --tag txe-v<next>
```

Upgrade while no job is running, because restarting the worker ends its running tasks.

## Limits

- **Sleep or offline.** Once the service has noticed the worker is gone, a run that comes due waits
  in the service's queue, and further ticks of that job are skipped until the worker reconnects. A
  run handed to the worker just before it went away is different. If no worker claims its task
  within 90 seconds, the task expires. A claim that is never confirmed is released after about 90
  seconds, and the task then expires after another 90 seconds if nobody claims it. Once the hand-out
  is 10 minutes old, the service's next check (every 45 seconds) marks the run failed with the
  reason "not dispatched". Nothing ran, so start it again. There is no guarantee that queued work
  survives hours offline.
- **Tunnel drop.** If the tunnel is down for more than 90 seconds, the worker cancels any task it
  is running. launchd restarts the tunnel within seconds after a Pod replacement or network change.
- **Credential expiry.** The tunnel credential expires (`status.sh` shows when). Rerun
  `tunnel-credential.sh` before then.
- **Spot node replacement.** The service Pod is rescheduled against the same volume. Runs wait
  until it is back.
- **No high availability.** There is one service Pod and one worker.

## Stop

```sh
txe/worker/stop.sh
```

This stops both agents. All data is kept.
