# Local Dagu worker (macOS)

Runs Connor's jobs on his machine for the Dagu service in the TXE staging cluster
(`capso-txe-development`, namespace `dagu`). The service schedules a job; this worker runs its
scripts locally with local tools and credentials, and returns status, logs and artifacts to the
service. Two launchd agents keep it running whether or not a coding session is open.

| Agent | What it runs |
|---|---|
| `com.txe.dagu.tunnel` | `kubectl port-forward` from `127.0.0.1:18080` to the UI/API and from `127.0.0.1:50055` to the coordinator, using a credential that can only port-forward in `dagu` |
| `com.txe.dagu.worker` | `dagu worker`. Its id is this machine's `mch_` id, its labels are `txe.machine` and `txe.owner`, and it reaches the coordinator at `127.0.0.1:50055` |

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

Once the hub knows the machine, install its periodic resource check on the hub. The hub schedules
that check, and this worker runs it.

```sh
~/.local/share/txe-dagu/bin/dagu txe hub install --dry-run   # shows what would change
~/.local/share/txe-dagu/bin/dagu txe hub install
```

Run it again after an upgrade. It rewrites the hub's copy only when the rendered DAG differs.

## Upgrade

Use the same tag as the server image: server and worker must run the same version.

```sh
txe/worker/install.sh --tag txe-v<next>
```

Upgrade while no job is running, because restarting the worker ends its running tasks.

## Limits

- **Sleep or offline.** Scheduled runs wait in the service's queue, and further ticks of that job
  are skipped until the worker reconnects.
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
