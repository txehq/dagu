# TXE integration contract, v1

Status: **agreed direction, not yet frozen.** The program coordinator approved the shape below on
2026-10-09 (TXE-3401). The registry's exact records, transactions and endpoints are CC3's to write and
freeze after the consuming workers (CC2, CC4, CC5) review them. Until then this file is the
reference for identities, the DAG mapping and who edits what.

This tree (`txe/`) and the `internal/txe` packages hold everything the TXE fork adds to Dagu. Keep
upstream files untouched unless a change cannot live here, so the fork stays a small patch set.

## Pinned Dagu facts this contract relies on

Read from v2.18.2-13 (9bb941da0a31). Re-read them before relying on a newer pin.

- A worker connects to the coordinator; the coordinator never connects to a worker. The worker
  returns status, logs and artifacts over gRPC, and their durable copies live on the server.
- Each task carries the DAG's YAML. `run:`/`command:` paths and `working_dir` are resolved on the
  worker, so job packages must sit at absolute paths on the assigned machine.
- Without a connected matching worker, scheduled and enqueued runs wait in the queue, and later
  ticks of that DAG are skipped meanwhile. A direct `start` fails, so clients enqueue.
- A worker cancels a running task when it cannot reach the task's coordinator for more than 90s.
- DAGs have no owner, annotation or version field; unknown keys are rejected. Labels are limited to
  keys `^[a-zA-Z0-9][a-zA-Z0-9_.-]*$` (≤63) and values `^[a-zA-Z0-9][a-zA-Z0-9_./-]*$` (≤255).
- Remote CLI contexts need `builtin` auth and a `dagu_` API key. The community edition allows two
  keys. RBAC, OIDC and the audit log are licence-gated upstream; phase two adapts them (TXE-3415).

## Identities

Every id is opaque and minted once: `<prefix>_<ULID>` (`txe/worker/mint-id.sh`). None is derived
from a name, path, host, email, session or login.

| Record | Id | Minted by |
|---|---|---|
| Owner | `own_…` | the installer, once per installation (Connor in phase one) |
| Project | `prj_…` | the CLI, on a repository's first registration |
| Machine | `mch_…` | `txe/worker/install.sh`, once per machine; it is also the Dagu worker id |
| Job | `job_…` | the CLI at registration; it is also the Dagu DAG name |
| Job version | integer, +1 per accepted change | the registry |
| Package | `sha256:<64 hex>`, the full digest of the package manifest | the CLI packager |
| Review claim | `clm_…` | the reviewer, through the registry |
| Decision | `dec_…`, bound to job id + job version + action digest | the dashboard, through the registry |
| Action | `act_…` plus an idempotency key | the reviewer, through the registry |

Owner is separate from every actor: creating session (`cc<n>-<ws>`), creating machine, reviewer,
approver and executing machine are recorded in their own fields. Reviewing or running a job never
changes its owner.

## Mapping a job onto Dagu

- One DAG per job, named by its job id. The human title goes in `description`; `group` is the
  project's display name.
- Labels, all display and filter aids:
  - `txe.schema=1`
  - `txe.owner`, `txe.project`, `txe.job`, `txe.machine` (the ids)
  - `txe.version` (the job version)
  - `txe.package=sha256-<first 32 hex>`

  **The registry's full digest is authoritative; the label is only for display.** Dagu lowercases
  DAG labels when it loads them, so an id read from a label is not the id; read ids from the
  registry.
- `worker_selector: {txe.machine: mch_…}` routes every run to the assigned machine's worker.
- `working_dir` is the package's `files/` directory on that machine,
  `~/.local/share/txe-dagu/packages/<job id>/<digest>/files`. The job's outputs go to
  `~/.local/share/txe-dagu/outputs/<job id>/`, passed as `TXE_OUTPUT_DIR`. Validation refuses any
  execution path inside a git worktree or a temporary directory.
- Schedules use `CRON_TZ=<zone> <cron>`. Overlap defaults to skip. `timeout_sec` is required and
  retries are bounded. `catchup_window` is set only when the job's missed-run policy asks for it.
- The review cadence is its own reviewer DAG, not the job's schedule.
- Retiring a job records it in the registry and suspends the DAG. The DAG file and its run history
  are kept.

## Registry (CC3)

The records Dagu cannot hold live in a file-backed store inside the service's existing `DAGU_HOME`
on its persistent volume (`data/txe/v1/`). It is exposed at `/api/v1/txe/…` behind Dagu's own auth.
Every record carries `schema`, `id`, `owner_id`, `version`, `created_at/by` and `updated_at/by`.
Every write is compare-and-swap on the expected version; a conflict is HTTP 409. Clients never
write the store's files.

Constraints the coordinator set for the freeze:

1. **Registration is one transaction.** A job is ready only after its package exists on the
   assigned machine, its full digest is recorded, and its registry record and DAG are both saved.
   A partial registration stays visibly incomplete and yields no receipt.
2. **Lifecycle is checked immediately before every effect.** Suspending a DAG does not stop a run
   that is already queued. So each job run, follow-up action and reviewer action re-reads the
   registry for lifecycle, job version and decision just before it acts, and stops if any changed.
3. **Decisions are bound to a revision.** An approval names the job version and action digest it
   approved. Any change to either invalidates it.
4. **Credentials are named precisely.** Resource credentials (kubeconfigs, Linear tokens, cloud
   logins used by job scripts) stay on the machine and are referenced by name, never copied. They
   are distinct from service-issued state: the Dagu API keys, the admin login and the tunnel's
   ServiceAccount token. The machine keeps the admin password in the Keychain, the CLI's API key
   in Dagu's own encrypted context store under `~/.local/share/txe-dagu/client`, and the tunnel
   token under `~/.local/share/txe-dagu/tunnel`. The server keeps its own builtin auth state and,
   in the cluster, the image pull Secret. Phase one has two API keys, `cli` (shared by Connor's
   Claude sessions) and `reviewer`. A job's credential refs are file locators resolved on the
   worker; the worker passes no extra environment variables to jobs.

Lifecycle values are `active`, `paused`, `needs-human`, `completed` and `retired`. They are separate
from run status, and from machine availability (`ready`, `offline`, `auth-required`).

## Who edits what

One editor per path. A change outside your rows goes through that row's owner.

| Owner | Paths in txehq/dagu |
|---|---|
| CC1 (TXE-3407) | `.github/workflows/txe-*.yaml`; `txe/worker/**`; `txe/contract/**`; worker or coordinator transport code only for a transport defect |
| CC2 (TXE-3408) | `txe/skill/**`; the `dagu txe` CLI in `internal/cmd/txe*.go`, `internal/txe/client/**`, `internal/txe/pkg/**`; the one line registering it in the root command |
| CC3 (TXE-3409) | `internal/txe/registry/**`; `internal/service/frontend/api/v1/txe*.go`; the `/txe` part of `api/v1/api.yaml` and the code generated from it; sole OpenAPI editor |
| CC4 (TXE-3410) | `ui/**` additions, preferably under `ui/src/features/txe/**`; UI API types regenerated after CC3's change merges |
| CC5 (TXE-3411, TXE-3412) | `txe/reviewer/**`; `internal/txe/review/**`; `txe/it/**` |

In txehq/txe, CC1 alone edits `kubernetes/dagu/**`, `ops/dagu/**` and their delivery-ledger rows.
