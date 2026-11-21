# capacitygate: one capacity preflight for Mac container launchers (TXE-8043, design r3)

**Status: source written. Not yet run.** A pure test run, a validation packet and any live read each need their own
grant. Until this module is merged *and* a consumer adopts it (TXE-8044), the coordinator keeps verifying every reading
by hand before each START.

**Decisions** are root's rulings recorded in TXE-8043:
- Q1–Q6: the floor, the reserve, reservations, the host estimate, CPU, and the module/adoption split;
- D1–D4: disk accounting, CPU for unknown foreign containers, inventory validity, and public sanitization.

[`DESIGN-r1.md`](DESIGN-r1.md) is design r1, published as a **sanitized derivative** (D4; transform in §7). Its §1
(the inventory of gates that existed) and §2 (consumers) still hold. **This file replaces r1's §3–§6.**

## 1. What it is, and what it is not

- **A point-in-time preflight.** One pass of reads, one comparison, one receipt, then exit.
  - It starts, stops and signals nothing.
  - It never retries a read; v1 has no retry policy. An inconsistent snapshot refuses, and a later pass may succeed.
  - It never polls, and it adds no monitoring, daemon or hook.
- **Not a lease and not a lock.**
  - Another admission can follow a second later, and the inventory can go stale.
  - **One named coordinator owns the inventory and serializes admissions.** An atomic file replace alone does not.
  - Each decision is bound to the inventory's `generation` and sha256. A later caller rejects a superseded decision,
    or an inventory that has gone stale since the preflight even when its bytes are unchanged (`check-decision`,
    §4.4).
- **Not cleanup authority.**
  - An unknown owner stays unknown.
  - Every container's ownership is `UNVERIFIED`: a label or a listed id is a claim.
  - Every container is marked `cleanup_authority: "none"`.
- **Not guaranteed CPU availability.** CPU admission is *managed-reservation admission* over declared and configured
  allocations. Load is informational.
- **Grant ids are audit references, not cryptographic approval.**
- **Not runtime isolation and not Kubernetes CI admission.**

## 2. The admission formula

### 2.1 Terms

**Units.** All memory and disk values are integer bytes, and CPU is integer millicpus (`m`). A decimal reading is
converted with exact decimal arithmetic and **rounded up**.

**Readings.** Containers are identified by their **full 64-hex id** everywhere (D2 clarification 1):
- `T_mem` and `T_cpu` = `docker info` MemTotal, and NCPU × 1000.
- `C`: the running containers. `docker ps` gives each id its name and its `txe.capacity.reservation` label.
  `docker stats` gives each id its `use(c)`. `docker inspect` gives each id its CPU configuration.
- **The snapshot must agree:** ContainersRunning = #ps = #stats, with the ps id set equal to the stats id set (else
  exit 74, `inconsistent`), and the inspect id set equal to the ps id set (else exit 79, `inconsistent`).
- `free(d)`: `statvfs` free space for an unprivileged writer, on each device `d` the run's paths use (or their nearest
  existing ancestor's device). It is sampled before AND after the walks, and `free(d)` is the smaller sample. A block a
  running reservation writes during its walk is then never both deducted from its remaining claim and counted as
  free. A failed second sample (D03), or a path whose device or filesystem id changed (D04), fails the disk check
  closed (75). **The two samples reserve no capacity:** a writer may still allocate after the second sample, so this
  is not an atomic admission snapshot, and the inventory and concurrent-writer limits still apply.

**Inventory** (§4.2). A running or pending reservation `r` has:
- its total caps `cap_mem(r)` and `cap_cpu(r)`;
- its disk claims `cap_disk(r, p)`;
- its containers `C(r)`, matched by label or by listed id. `C_res` is their union over running reservations.
`C_foreign = C − C_res` covers unreserved containers and every container whose owner is unknown.
`Pend` = the pending reservations **minus the new run's own entry**.

**Budget** (txe/runbudget):
- `N_mem = concurrent × memory_bytes`;
- `N_cpu = concurrent × cpus_milli`;
- `N_disk(d)` = the sum of `need_bytes` over the budget paths on device `d`.

**Policy** (§3): `R_vm`, `R_cpu`, `F_disk` and `P_min`.

**One owner per container (no overlap).**
- Each container id has exactly one owner: one running reservation, or `unknown`.
- Two claimed owners, a pending reservation with a container, or a container of the new run itself are all inventory
  `conflict` (exit 78).
- So each id is charged **once for memory** (inside its reservation's `max`, or in `U_mem`) and **once for CPU**
  (inside its reservation's `max`, or as one foreign term). `test_every_container_charged_once_per_resource` checks
  this.

### 2.2 Memory (exit 74)

```
A_mem(r) = max( Σ_{c ∈ C(r)} use(c) , cap_mem(r) )     r running   (an idle or absent container never erases the cap)
U_mem    = Σ_{c ∈ C_foreign} use(c)
P_mem    = Σ_{p ∈ Pend} cap_mem(p)
charged_mem = Σ A_mem + U_mem + P_mem + N_mem + R_vm  ≤  T_mem
```

### 2.3 CPU (exit 79)

**Each container's configured upper bound `q(c)`** (D2 clarification 2) is the **minimum over every applicable known
constraint**, so no rule order matters:

| Constraint | Applies when | Bound |
|---|---|---|
| NanoCpus | > 0 | ceil(NanoCpus / 10⁶) |
| CpuQuota / CpuPeriod | quota > 0 and period > 0 | ceil(quota × 1000 / period) |
| CpusetCpus | non-empty and valid | (number of CPUs) × 1000 |
| the VM | whenever any of the above applies | NCPU × 1000 |

**Each container gets one of four classes:**
- **`KNOWN`** has `q(c)` = that minimum.
- **`VALID_UNLIMITED`:** nothing is set. NanoCpus is 0, CpuQuota is 0 or −1, and CpusetCpus is empty.
- **`UNKNOWN_CONFIG`:** CpuQuota > 0 with CpuPeriod 0, and no other known constraint. Docker's default period is
  **not** assumed. With another known constraint present, the class is `KNOWN`.
- **`MALFORMED`:** a non-integer field, a negative NanoCpus or CpuPeriod, or a CpuQuota below −1. Also a cpuset that
  has bad syntax, a reversed range, a duplicate or overlapping CPU, or a CPU outside `0..NCPU−1`.

```
A_cpu(r)  = max( cap_cpu(r) , Σ_{c ∈ C(r), KNOWN} q(c) )        r running
            (an unbounded matched container is charged inside cap_cpu(r) and flagged reserved_container_unbounded:
             an ADMISSION POLICY, not an enforced CPU limit)
F_known   = Σ_{c ∈ C_foreign, KNOWN} q(c)
F_policy  = |{c ∈ C_foreign : VALID_UNLIMITED}| × foreign_cpu_policy.milli
P_cpu     = Σ_{p ∈ Pend} cap_cpu(p)
charged_cpu = Σ A_cpu + P_cpu + F_known + F_policy + N_cpu + R_cpu  ≤  T_cpu      and   cpus_milli ≤ T_cpu
```

**What refuses with exit 79, whatever the totals** (D2 clarification 3):
- **`VALID_UNLIMITED` foreign with no `foreign_cpu_policy`:** kind `unbounded`, code C11. This default refusal is
  deliberate. The existing foreign containers are not pre-approved at any value.
- **`UNKNOWN_CONFIG` foreign:** kind `unknown_config`, code C12. **No policy covers it.** It needs an explicit,
  documented classification in a later version.
- **`MALFORMED`, reserved or foreign:** kind `malformed`, code C10. **No policy covers it.** Neither does a failed or
  inconsistent inspect read.

**The foreign-CPU policy:**
- It lives in the **inventory** (§4.2), not in the budget: a run may not waive other people's containers.
- `milli` must be > 0. There is no implicit zero.
- It names a `grant`, and its `generation` must equal the inventory's.

Load (`sysctl -n vm.loadavg`) is recorded and never gates.

### 2.4 Disk (exit 75), per device `d` the new run uses

```
left(r, p) = max( cap_disk(r, p) − used(r, p) , 0 )     r running; used(r, p) is already out of free(d)
           = cap_disk(r, p)                              when the walk or the lookup fails (flagged; conservative)
charged_disk(d) = N_disk(d) + Σ_{r running, p on d} left(r, p) + Σ_{p ∈ Pend, on d} cap_disk(p) + F_disk  ≤  free(d)
```

**The walk** (D1). `used(r, p)` comes from a bounded `lstat` walk of the claim's path:
- **The path NAMES its reservation:** one of its components is the reservation id, or the inventory refuses (78,
  N14). This is a name check only. **The root directory's identity is NOT bound:** nothing records which directory
  the coordinator meant.
- **The walk works on directory descriptors, because the claim tree may be written while it is walked** (the
  `txe/mutate` `dir_usage` pattern). The root, and each directory below it, is opened with `O_NOFOLLOW`, each child
  relative to its parent's descriptor. Each opened directory's `(st_dev, st_ino)` must equal the `lstat` taken when it
  was listed. A directory swapped for a symlink (`open_refused`) or replaced (`identity_changed`) fails closed.
- **What `O_NOFOLLOW` does NOT give.** It applies to the final component only.
  - Every component ABOVE the root is resolved normally, following symlinks, by both the `lstat` and the `open`.
  - An ancestor changed before the walk starts redirects both calls consistently. The walk then measures whatever
    tree the path now names, undetected; a swap between the `lstat` and the `open` is caught as `identity_changed`.
  - So no protection is claimed for the path prefix. Its parent directories must not be writable by the reservation,
    and binding the root's `(st_dev, st_ino)` in the inventory is a pending contract decision.
- **The root must be a real directory, not a symlink.**
  - Symlinks below the root are never followed or counted.
  - A FIFO, socket or device file fails the walk.
  - A different `st_dev` is not descended.
  - `..` cannot appear, because paths are normalised.
- **Every `(st_dev, st_ino)` is counted once across all walks,** so hard links and overlapping paths never count twice.
- **The bounds are `disk_walk_max_s`, `disk_walk_max_entries`, and 256 levels deep** (dir_usage's `max_depth`).
  Exceeding any of them fails that walk.

**Fallbacks:**
- **Any failure charges the full remaining cap, flagged `fallback_full_remaining_cap`.** That over-reserves on purpose;
  it does not show that the disk is available.
- A claim whose device cannot be found is charged to every device the run uses, flagged.
- A claim on another device is recorded in `other_device_claims` and not charged.

**No live walk has been authorized.** The tests walk only temporary directories they create.

### 2.5 Host

- **Pressure (exit 72):** `memory_pressure -Q` free % ≥ `P_min`. This is a policy floor, not a measured guarantee (Q1).
- **The vm_stat estimate (exit 73 only when missing or unreadable):** **log-only.** Its page classes may overlap. The
  receipt records it as `host_model: {gating: false, status: "heuristic_pending_evidence"}`, beside `N_mem + P_mem`.

### 2.6 Worked example: the S run's readings (sanitized fixtures) with a synthetic inventory

**The readings:**
- `T_mem` = 33669160960 B;
- NCPU 18;
- 7 containers using 3953785834 B in total (per-container figures in `test_capacity_gate.py` `USE`);
- one device with 199161080 KiB free.

**The inventory:**
- **r1, running:** 2 GiB / 2000 m. It holds `ctr-03` (99048489 B; NanoCpus 2e9, so 2000 m), and it claims 16 GiB at
  `/w/r1-running`, of which 6 GiB is used.
- **r2, running:** 1 GiB / 1000 m. It holds `ctr-05` (1297080124 B, **over** its cap; CPU unlimited).
- **p1, pending:** 8 GiB / 4000 m / 16 GiB.
- **The new run:** `--cpus 2 --memory 4g`, with disk needs of 18 + 1 GiB. It is listed as pending under its own id.
- **Foreign containers:**
  - `ctr-01`: NanoCpus, 1000 m;
  - `ctr-02`: quota 50000 / period 100000, 500 m;
  - `ctr-04`: cpuset 0-1, 2000 m;
  - `ctr-06` and `ctr-07`: `VALID_UNLIMITED`, under a policy of 1000 m each.

| Resource | Terms | Charged | Total |
|---|---|---|---|
| Memory | A(r1) = max(99048489, 2147483648) = 2147483648; A(r2) = max(1297080124, 1073741824) = 1297080124; U = 2557657221; P = 8589934592; N = 4294967296; R_vm = 2147483648 | **21034606529** | 33669160960: admit |
| CPU | A(r1) = max(2000, 2000); A(r2) = max(1000, 0), flagged; P = 4000; F_known = 3500; F_policy = 2 × 1000; N = 2000; R = 0 | **14500 m** | 18000 m: admit |
| Disk | N = 19 GiB; left(r1) = 16 − 6 = 10 GiB; P = 16 GiB; F = 2 GiB | **47 GiB** | 189.9 GiB: admit |

**The double-count traps.** Each sits between the right sum and a wrong one:

| Wrong implementation | Its memory sum | Trap | Right result |
|---|---|---|---|
| all measured + all caps | 22207396842 (over by 99048489 + 1 GiB) | `T_mem` = 21000 MiB | admit |
| counting the new run again | 25329573825 | 21000 MiB | admit |
| cap only (r2 at 1 GiB) | 20811268229 | `T_mem` = 20000 MiB | refuse |
| measured only (r1 at its idle use) | 18986171370 | 20000 MiB | refuse |

The CPU and disk traps:
- **CPU:** r1 holds 2 containers and NCPU is 13. The right sum is 13000, so it admits; charging per container gives
  15000.
- **Disk:** with 50 GiB free, the right sum of 47 admits, while charging r1's full cap gives 53. With 40 GiB free, the
  right sum refuses, while ignoring r1 gives 37.

## 3. Policy values (each reported as `{value, origin, lineage}`; a budget may override, with origin `budget`)

| Key | Default | Lineage |
|---|---|---|
| `host_pressure_free_min_pct` | 40 | The TXE-8034 I9c r4 proposal. Kept by Q1 as a configurable, conservative policy floor, not a measured safety guarantee |
| `vm_reserve_bytes` | 2 GiB | The I9c r4 proposal. Approved by Q2 as the initial default. TXE-8034's prior acceptance was not recovered. Not universally sufficient |
| `vm_cpu_reserve_milli` | 0 | D2: an explicit initial policy, not proof that every CPU is available |
| `disk_floor_bytes` | 2 GiB | mutate-sandboxed `--min-free-mib 2048`, TXE-7549 |
| `inventory_max_validity_s` | 900 | D3: a configurable policy cap. It is not shown to be safe by any cadence |
| `disk_walk_max_s` | 30 | **proposed here** (the I9c docker read bound); pending review |
| `disk_walk_max_entries` | 1000000 | **proposed here**; pending review |

## 4. The interface

### 4.1 The budget

The budget is `txe.runbudget/v1`, a separate data contract with no import between guards. It is documented in
[`../runbudget/README.md`](../runbudget/README.md).

### 4.2 The reservation inventory: `txe.capacity.inventory/v1`

```json
{"schema": "txe.capacity.inventory/v1", "generation": 41,
 "owner": {"session": "cc<n>-<ws>", "run": "run_<12 hex>"},
 "written_at": "2026-11-21T06:00:00Z", "valid_until": "2026-11-21T06:10:00Z",
 "foreign_cpu_policy": {"milli": 1000, "grant": "msg_<12 hex>", "generation": 41},
 "reservations": [{"id": "r1-running", "state": "running",
   "owner": {"ticket": "TXE-<n>", "session": "cc<n>-<ws>", "grant": "msg_<12 hex>"},
   "cpus_milli": 2000, "memory_bytes": 2147483648,
   "disk": [{"path": "/w/r1-running", "cap_bytes": 17179869184}],
   "match": {"kind": "ids", "ids": ["<64 hex>"]}, "deadline": "2026-11-21T09:00:00Z"}]}
```

**Who writes it.** Only the coordinator that owns Mac admission.
- It increments `generation` on every change.
- It **refreshes the inventory at every actual admission and ownership change**, not only at checkpoints.
- It writes by atomic replace.
- The gate, launchers and workers only read it.

**Matching:**
- `match.kind: "label"` matches containers whose `txe.capacity.reservation` label equals the reservation id. The
  launcher sets the label in its reviewed argv.
- `match.kind: "ids"` lists the full ids the owner started.
- **Do not register unrelated foreign containers as reservations just to avoid a refusal** (D2 clarification 4).
- A label naming an unregistered id gives no ownership, and is flagged `label_unregistered`.
- **`unknown` is a reserved id** (`runbudget.RESERVED_IDS`). It is the owner the receipt reports for an unattributed
  container, so neither a budget nor an inventory reservation may take it (76 / 78).

**Refusals (exit 78):**

| Kind | Cause |
|---|---|
| `missing` | the file is absent |
| `unreadable` | not strict JSON; an unknown or missing key; a bad type or timestamp; a duplicate id; a disk path that does not name its reservation; a policy `milli` < 1 |
| `stale` | `written_at` > now; now ≥ `valid_until`; or a validity window > `inventory_max_validity_s` |
| `conflict` | the new run is not `pending` with equal owner, caps and disk; one container id under two reservations; a pending reservation with a container; a container of the new run; a policy bound to another generation |

A running reservation past its deadline, or with no matched container, is still charged its cap and flagged
(`past_deadline`, `unmatched`).

### 4.3 Module API (`capacity_gate.py`, stdlib only)

```python
verdict = preflight(budget_path, inventory_path, receipt_path, docker="/abs/docker")   # seams: run, statfs, stat_fn,
if not verdict.admit:                                                                   # walker, clock, monotonic
    sys.exit(verdict.exit_code)            # never print the argv or the environment
if check_decision(verdict.receipt_path, inventory_path) != 0:   # immediately before the first container
    sys.exit(78)
launch(argv)
```

- `Verdict(admit, exit_code, failures, receipt_path, inventory_generation, inventory_sha256)`.
- `Failure(reading, kind, code, detail)`. `detail` holds stable codes and numbers only.
- **The pure parts are tested directly:** `account_memory`, `account_cpu` and `classify_cpu`; the parsers; and
  `parse_inventory` and `check_inventory`. `account_disk` and `walk_used` are tested through injected seams and
  temporary trees.

**The commands are constants:**

| Command | Bound |
|---|---|
| `/usr/bin/memory_pressure -Q` | 15 s |
| `/usr/bin/vm_stat` | 10 s |
| `/usr/sbin/sysctl -n vm.loadavg` | 10 s |
| `docker info --format '{{.MemTotal}} {{.NCPU}} {{.ContainersRunning}}'` | 30 s |
| `docker ps --no-trunc --format '{{.ID}}\t{{.Names}}\t{{.Label "txe.capacity.reservation"}}'` | 30 s |
| `docker stats --no-stream --no-trunc --format '{{.ID}}\t{{.MemUsage}}'` | 30 s |
| `docker inspect --format '{{.Id}}\t{{.HostConfig.NanoCpus}}\t{{.HostConfig.CpuQuota}}\t{{.HostConfig.CpuPeriod}}\t{{.HostConfig.CpusetCpus}}' <ids>` | 30 s |

**Assumptions the validation packet must confirm on the real Docker CLI**, since nothing has been run:
- `docker stats --no-trunc` prints the full id under `{{.ID}}`;
- the HostConfig fields render as shown;
- `vm.loadavg` prints `{ a b c }`.

### 4.4 CLI and exit codes

```
python3 -I capacity_gate.py preflight --budget B --inventory I --receipt R --docker /abs/docker [--pin COMMIT,BLOB,SHA256]
python3 -I capacity_gate.py check-budget B                    # 0 or 76
python3 -I capacity_gate.py check-inventory I [--budget B]    # 0 or 78: the coordinator's own check before a grant
python3 -I capacity_gate.py check-decision R --inventory I    # 0, or 78 when superseded or the inventory is now stale
```

**Exit codes:**

| Code | Meaning |
|---|---|
| 0 | admit |
| 2 | usage |
| 72 | host pressure |
| 73 | host estimate missing or unreadable |
| 74 | VM memory, or the snapshot (info, ps, stats) |
| 75 | disk |
| 76 | budget |
| 77 | the receipt or its raw directory could not be claimed or written |
| 78 | inventory, attribution or decision |
| 79 | VM CPU, or inspect |

- **Every reading is taken once,** and the exit is the first failing code in the order **77, 76, 78, 72, 73, 74, 79,
  75**.
- **The receipt path and its `.raw/` directory are claimed exclusively before any read.** If either is taken, the gate
  exits 77 having read nothing.

### 4.5 Receipt: `txe.capacitygate.receipt/v1`

**The top-level fields:**
- `module` (self sha256, claimed pin), `started_at`, `finished_at` and `deadline`;
- `verdict` (admit, exit code, every failure);
- **`decision_binding`** (inventory generation and sha256);
- `budget`, `inventory` (owner, written_at, valid_until, age) and `policy` (value, origin, lineage);
- `readings`: per reading, its time, command, bound, exit status, raw sha256 and status. The raw bytes are under
  `<receipt>.raw/`;
- `accounting`: every term of §2, per-container CPU `basis`, flags and the disk walks;
- `host_model`, `load` and `disclaimers`.

**One row per container id:**
- `id`, `name`, `owner`, and `owner_verification: "UNVERIFIED"`;
- `matched_by` and `flags`;
- `mem_use_bytes` and `mem_basis`;
- `cpu_class`, `cpu_bound_milli`, `cpu_constraints` and `cpu_basis`;
- `cleanup_authority: "none"`.

**The receipt is private admission evidence.** It keeps the exact ids for reconciliation. It never contains an
environment value.

## 5. Adoption

Adoption is TXE-8044, which is blocked. It has two concrete blockers: this module's reviewed merge, and an explicit,
pinned consumer-adoption approval.
- This change grants no pin bump.
- It edits no frozen packet or installed launcher.
- It does not touch `txe/mutate/`.

A pinned consumer loads `runbudget.py` and `capacity_gate.py` by their own blob hashes, putting `runbudget` into
`sys.modules` first.

## 6. Tests, consumer check, CI

- **`test_capacity_gate.py`:**
  - the S-run fixtures and their hashes;
  - every parser;
  - CPU classification;
  - the formula with exact bytes;
  - each trap;
  - the unknown-owner case and charged-once checks;
  - the reading matrix (missing, unreadable and insufficient per reading);
  - the inventory refusals, the exit order, the receipt and decision binding, and the walker.
- **`../runbudget/test_runbudget.py`:** the contract and its schema document.
- **The Go wrappers** `capacitygate_test.go` and `runbudget_test.go` run both with `python3 -I -B` in dagu's CI Go job,
  whose path filter covers `txe/**`. A missing python3 fails them, and only Windows skips.
- **Waiting for PR 299 (containerguard) to merge:**
  - `consumers.py`, which imports containerguard's launch recogniser at test time only, so there is one definition of
    "a launch";
  - `UNGATED.tsv`. Its rows need their own scope-specific review, never recycled approval ids.
  - The plan: after 299 merges, rebase onto `main`, add both, then push. Never stack on 299's branch.

## 7. Public-repository sanitization (D4)

**Everything published here is derived data.** Internal names, hostnames, paths, ids and URLs are neutralized, and the
arithmetic and structure are preserved. The raw originals, the literal mapping and the raw-to-sanitized hash map are
kept only in the private TXE-8043 evidence.

| Published file | sha256 | Transform |
|---|---|---|
| `DESIGN-r1.md` | `c0bb19952760680e1c049b45eabfc2a73541a96ba76933c32319ce84ff8151c1` | a literal map applied in one pass, longest first. Evidence paths → `<evidence:TXE-n>/…`; message ids → `msg-ref-NN`; session and run ids → roles; instance labels → `worker-A`/`worker-B`/`coordinator-C`/`worker-W`; private-file hashes → `<sha256-…>`; internal repository paths, a PR number and project names → `<…>` placeholders. The raw r1 hash is recorded privately |
| `testdata/s-run/*` | see [`testdata/README.md`](testdata/README.md) | identity for three files; renamed and re-keyed ids for stats; synthetic ps |

Raw design r1 was never published. The local commit that held it is replaced before any push.
