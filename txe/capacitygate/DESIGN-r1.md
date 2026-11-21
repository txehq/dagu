# Mac container capacity preflight: design (TXE-8042, r1)

Status: DESIGN ONLY, for review. No code, no probe, no run. Manual pre-START verification of every reading
stays the rule until a reviewed module is adopted.
Author: <worker-session-W> (implementation worker), coordinator <coordinator-session-C>, root <root-run>.
Written 2026-11-21 from reads only: `git show` of txe and txehq/dagu branches, and the frozen evidence packets
under `<evidence>/`, which were read and never edited.

## 0. The problem in one paragraph

TXE-8041's container run (stage 0 at 14:22:13Z, 2026-11-21) started on a receipt that checked CPU load
only. Memory and disk were read 14 s after the start. TXE-8034's host-run launchers already had a reviewed
pre-start capacity gate (I9c, exits 72-75), but it lives as a hand-copied block inside eleven frozen
`host-run.sh` files, and nothing else calls it. The TXE-7974 `prelude.sh` that the TXE-8039 and TXE-8041
wrappers source has an `idle_gate`, which checks process names, not capacity. This is the "a hand edit in N
places is a hotfix" case. The class fix is one maintained module that every Mac container launcher calls, plus a
check that fails when a new launcher does not call it.

## 1. Inventory of the existing gates

### 1.1 TXE-8034 I9c capacity gate (the one to reuse)

The same block is in every TXE-8034 host-run packet from r4 on. It first appeared in packet r4
(`<packet-r4>/host-run.sh`, sha256 `<sha256-packet-r4>`). Root asked for it in msg-ref-01, relayed as
coordinator-C msg-ref-02. worker-A proposed the thresholds in `<evidence:TXE-8034>/<threshold-proposal-r4>`.

| Run | Packet (sha256) | Gate passed | Readings logged | Approval |
|---|---|---|---|---|
| S | `<evidence:TXE-8034>/<packet-S>/host-run.sh` (`<sha256-packet-S>`), OUT `<run-S>` | 06:02:02Z | free 56 %; VM 32109 MiB, 7 containers using 3770 MiB, available 26290 MiB; disk 189 GiB | root GO msg-ref-03 |
| M1 | `<evidence:TXE-8034>/<packet-M1>/host-run.sh` (`<sha256-packet-M1>`), OUT `<run-M1>` | 06:23:23Z | free 55 %; VM available 26297 MiB; disk 187 GiB | root msg-ref-04; START msg-ref-05 |

M1 is the same capacity block. Its "headroom gate" differs from S's "capacity gate" in one way: the idle check
(62/71) and the foreign-gtimeout check (63) are logged as information and no longer stop the run.

What the block measures, and how. Every command runs under `gtimeout -k 5 N` and keeps its raw output in OUT.

| Exit | Reading | Command | Threshold | Where the threshold came from |
|---|---|---|---|---|
| 72 | Host memory pressure | `/usr/bin/memory_pressure -Q`, parse `System-wide memory free percentage: N%` | ≥ 40 % | worker-A's r4 proposal. A fixed number, not derived from the run |
| 73 | Host available-memory estimate | `/usr/bin/vm_stat`: (free + inactive + speculative + purgeable) × page size | **none** (logged; it fails only when unreadable) | r4: logged, not thresholded |
| 74 | Docker VM headroom | `docker info --format '{{.MemTotal}} {{.NCPU}} {{.ContainersRunning}}'` and `docker stats --no-stream --format '{{.Name}}\t{{.MemUsage}}'`. available = MemTotal − Σ MemUsage − 2 GiB. The stats row count must equal ContainersRunning, and an unknown unit fails | ≥ 6 GiB | worker-A's r4 proposal. The 2 GiB reserve is "my addition" (worker-A-ask-r4.txt, "DECISION FOR ROOT … Recommendation: keep it"). I found no message that accepts it explicitly; the r4–r6 GOs went ahead with it |
| 75 | Disk free | `/bin/df -Pk $BASE /private/tmp $OUT`; the lowest free must pass, and the row count must be 3 | ≥ 40 GiB | worker-A's r4 proposal. A fixed number |

What fails closed: a command's non-zero exit or timeout, a value that will not parse, a count mismatch, an
unknown unit, and a value below its threshold. Each gets its own exit before the launcher starts. Swap is
deliberately not a threshold (root msg-ref-01).

What it does **not** do:
- **No threshold comes from the run's budget.** The run's caps (`--cpus 2 --memory 4g` in r4 to <packet-r4b>) and its
  disk caps (`--max-disk-mib`, default 16384) never enter the comparison. 6 GiB and 40 GiB are constants.
- The host estimate (73) is not compared with anything.
- There is no CPU reading. NCPU is read but not used.
- It is a sequential read, not a lease: another coordinator can start work a second later.
- The readings are timestamped only by the log line around them.

Reviewed by: root, through the GO on each packet (msg-ref-01 for r4; msg-ref-06 and
msg-ref-07 for r6; msg-ref-03 for S; msg-ref-04 for M1). coordinator-C reviewed each packet before
relaying it. I found no separate source review of the block as a reusable unit.

The hand-copy count: the I9c block is in **11** `host-run*.sh` files under `<evidence>/<evidence:TXE-8034>/`, from
`<packet-S>` through `<packet-safepoint>`.

### 1.2 TXE-7974 `prelude.sh` idle_gate (sourced by the TXE-8039 KG-r3 and TXE-8041 CG-r1 wrappers)

- **Files:**
  - `<evidence:TXE-7974>/prelude.sh` (`<sha256-prelude>`)
  - `<evidence:TXE-8039>/kg-run.sh` (`<sha256-kg-wrapper>`)
  - `<evidence:TXE-8041>/cg-run.sh` (`<sha256-cg-wrapper>`)
- **What it measures:** `mac-idle-check.sh` under `gtimeout -k 5 90`, checking process names at one instant.
  Any non-zero exit stops the wrapper with exit 9.
- **What it does not measure:** memory, the Docker VM or disk.
- **The caps:** the runners set them (`runner-cg-r1.py`: `LIMITS = {"cpus": "4", "memory": "8g", …}`, with
  `--memory-swap` equal to `--memory`). They are never compared with any reading.
- **Where capacity came from:** the TXE-8041 receipt was coordinator-C's hand check ("capacity load 8/18", coordination
  log 14:21:16Z), plus a <project-B> agreement for 4 CPU / 8 GiB × 1450+10 s.
- **Reviewed by:** root's GO msg-ref-08 for the CG run. coordinator-C verified the wrapper hash `<sha256-cg-wrapper>`.

### 1.3 Run-time disk floors inside the runner (runtime, not admission)

dagu `txe/mutate/mutate-sandboxed.py` (origin/main) has `--min-free-mib` (default 2048, :904) and
`--max-disk-mib` (default 16384). They are checked before each container (:603) and by the watchdog (:802).
These are **runtime** limits. They stop a run that is already going. They are listed here because the
preflight's disk need can reuse the same declared numbers (§4.2), not because they are an admission check.

### 1.4 Summary

| Gate | Memory | VM headroom | Reserve | Disk | Budget-derived | Reusable unit |
|---|---|---|---|---|---|---|
| TXE-8034 I9c | yes (40 %) | yes (6 GiB) | 2 GiB VM | yes (40 GiB) | **no** | no: copied 11× |
| TXE-7974 idle_gate | no | no | no | no | no | yes, but it is not a capacity check |
| mutate-sandboxed floors | no | no | no | runtime only | partly (its own flags) | n/a |

## 2. Consumers: launchers that start a capped container on this Mac

| Launcher | Repo | Runs where | Capped how | Calls a capacity gate today |
|---|---|---|---|---|
| `txe/mutate/mutate-sandboxed.py`, run through `<installed mutate-sandboxed launcher>` (pinned commit, blob and sha256) | txehq/dagu | Mac | `--cpus`, `--memory` flags | **no**. Its outer TXE-8034 host-run packets run I9c |
| `txe/mutate/fixture-demo.py` | txehq/dagu | Mac, manual, TXE-7549 acceptance only | yes | no |
| Evidence-packet runners: `runner-kg-r3.py`, `runner-cg-r1.py` and their wrappers | outside both repos (`<evidence>`) | Mac | `LIMITS` dict | no (idle_gate only) |
| TXE-8034 `host-run.sh` packets | outside both repos (`<evidence>`) | Mac | caps passed to mutate-sandboxed | yes: an I9c copy |

**Not consumers. These are Kubernetes CI, and out of scope (§4.4):**
- txe `<txe-ci-file-1>` and the vendored `<txe-ci-file-2>` (<txe-PR-A>, not
  merged): these run on ARC runner pods.
- txe `<txe-ci-test-3>` (`docker run … --memory 1g --cpus 2`): runs on ARC.
- txe `<txe-ci-test-4>`: <broker>'s own `--memory`, inside a
  testcontainer.

**Result: the txe repo has no Mac container launcher on origin/main today.** Every Mac launcher is either in
dagu `txe/` or in an evidence packet.

How I found them: `git grep` for `--cpus` / `--memory` / `docker run|create` over txe origin/main, txe <txe-PR-A>
and dagu origin/main and PR 299 (`d9c4d5fc`), plus the packets named in the brief. This is a text search. A
launcher that builds its flags at run time would escape it, and §5.2's check has the same limit.

## 3. Home: dagu `txe/capacitygate/`, beside `txe/containerguard/`

**Recommendation:** one stdlib-only Python module, `txe/capacitygate/capacity_gate.py`, in txehq/dagu.

Why there:
1. **The consumers are there.** Both Mac launchers in a repository are in dagu `txe/mutate/`. txe has none
   (§2).
2. **The adoption mechanism is already there and already reviewed.** `<installed mutate-sandboxed launcher>`
   runs a dagu blob by pinned commit, blob id and sha256. containerguard's README prescribes the same pattern for
   out-of-repo runners: "loads `argv_guard.py` from a pinned commit … by blob sha256, and never vendors a copy".
3. **The consumer-check model is there.** `txe/containerguard/consumers.py` and its Go test wrapper run in
   dagu's `ci.yaml`, whose paths filter includes `txe/**`.
4. **It pairs with argv_guard.** The argv_guard `Schema` already holds the run's `--cpus` and `--memory`. The
   budget can be read from the schema, so the caps have one source (§4.1).

How each consumer adopts it:

| Consumer | Mechanism |
|---|---|
| dagu `txe/mutate/mutate-sandboxed.py` | In-repo `import` (sibling path), called in `main()` before the first container. Its `--cpus`, `--memory`, `--max-disk-mib`, `--min-free-mib` and `--deadline` flags are the budget. Editing it changes its blob, so the `<global config dir>` pin and the UNGUARDED.tsv row get the reviewed update they already require |
| dagu `txe/mutate/fixture-demo.py` | A row in `UNGATED.tsv` (§5.2) as `LEGACY_BOUNDARY`, manual-only. It runs only under TXE-7549 acceptance |
| Evidence-packet Python runners (the next `runner-*.py`) | Load `capacity_gate.py` from a pinned dagu commit by blob sha256, the argv_guard pattern. The packet's pure tests assert the hash and that the launch path calls `preflight()` and refuses on a failing verdict |
| Evidence-packet shell launchers (the next `host-run.sh`) | **The adapter:** `python3 -I <(git -C $DAGU cat-file blob $PIN) --budget budget.json --receipt OUT/capacity.json` with a pinned blob, the same form as the mutate-sandboxed launcher. A non-zero exit stops the launcher. This replaces the copied I9c block |
| A future txe-repo Mac launcher | The same pinned-blob load from dagu. No vendored copy; txe's <txe-PR-A> vendoring precedent is for CI, which is out of scope |

Frozen packets are never edited. The 11 existing I9c copies stay as they ran.

## 4. The contract

### 4.1 Input: the declared budget (JSON, schema `capacitygate.budget/v1`)

```json
{
  "schema": "capacitygate.budget/v1",
  "owner": {"ticket": "TXE-NNNN", "session": "cc<n>-<ws>", "grant": "msg_<12 hex>"},
  "containers": {"concurrent": 1, "cpus": 4, "memory_bytes": 8589934592},
  "time": {"run_bound_s": 1450, "kill_after_s": 10, "cleanup_reserve_s": 45},
  "disk": [{"path": "/abs/work", "need_bytes": 17179869184}],
  "reserves": {"vm_bytes": 2147483648, "host_bytes": 0, "disk_floor_bytes": 2147483648}
}
```

- **`containers`** describes the most the run holds at once. Its `cpus` and `memory_bytes` must equal the
  launch argv's `--cpus` / `--memory`. Python consumers build the budget from the argv_guard `Schema` (or the
  runner's own flags), so the caps have one source. Shell consumers pass their caps to both the budget and the
  launcher from one variable. The consumer check (§5.2) verifies that only where both are literals.
- **`time`** gives the deadline: the start plus `run_bound_s + kill_after_s`, with the cleanup reserve
  included. The receipt records it, so a reader can see what the run claimed and until when. It is **not** a lease
  and reserves nothing.
- **`disk[].need_bytes`** is the declared worst case for that path. For mutate-sandboxed that is
  `max_disk_mib × concurrent` + the snapshot size + `max_output_mib`. Paths on the same volume (same `st_dev`)
  are summed.
- **`reserves`** are the only fixed numbers, and each carries its lineage in the receipt:
  - `vm_bytes` = 2 GiB: TXE-8034 r4, worker-A-ask-r4.txt. It needs an explicit acceptance (Q2).
  - `disk_floor_bytes` = 2 GiB: mutate-sandboxed `--min-free-mib` 2048, reviewed under TXE-7549.
  - `host_bytes` defaults to 0 until root sets it (Q3).
- **Schema violations refuse (exit 76):** an unknown key, a missing key, a non-positive number, a relative or
  non-normalised path, `concurrent` < 1, or `cpus` above the VM's NCPU (found once the VM is read).

### 4.2 Readings

Each reading records: `name`, `taken_at` (UTC, from the clock at the read), the command (absolute path), its
bound, its exit status, the sha256 of its raw output (the raw output itself is kept in the receipt directory),
the parsed value with its unit, the computed `need`, and a `status`.

| Reading | Source (the reviewed I9c command, reused) | Need (from the budget) | Exit |
|---|---|---|---|
| `host_pressure` | `memory_pressure -Q`, free % | ≥ 40 %. The reviewed I9c floor; this is a pressure state, not a size (Q1) | 72 |
| `host_available` | `vm_stat`, (free + inactive + speculative + purgeable) × page size | ≥ `concurrent × memory_bytes + reserves.host_bytes`. The OrbStack VM takes host pages as it grows, so the run's cap must fit in what the host can give | 73 |
| `vm_headroom` | `docker info` MemTotal / NCPU / ContainersRunning, and `docker stats --no-stream` MemUsage. **Every** running container counts as foreign, because the preflight runs before the run's first container | MemTotal − Σ MemUsage − `reserves.vm_bytes` ≥ `concurrent × memory_bytes`. Also `cpus` ≤ NCPU | 74 |
| `reserve` | recorded, not read: the reserves in force and their lineage | n/a | (76 if malformed) |
| `disk:<path>` | `os.statvfs` per declared path, grouped by `st_dev`. Replaces the `df -Pk` parse | free ≥ Σ need on that volume + `disk_floor_bytes` | 75 |

The parsers are the I9c awk and sed logic ported verbatim in meaning: four page classes plus a page size; the
row count equals ContainersRunning; the unit table B/KiB/kB/MiB/MB/GiB/GB, with anything else unreadable. Each
parser is fixtured with a captured real sample (§5.1).

CPU load is recorded as a reading (`sysctl vm.loadavg`) but **not** thresholded in r1 (Q4).

### 4.3 The verdict

`admit` is true only when every reading has `status: ok`. Otherwise every failing reading is listed with one of:
- `missing`: the command was absent, exited non-zero or timed out;
- `unreadable`: the output did not parse, a count did not match, or a unit was unknown;
- `insufficient`: the value is below the need, with both numbers.

**All readings are taken and reported, and the CLI exits with the first failing code in the order 76, 72, 73,
74, 75.** One run of the gate therefore names every shortfall. The receipt (`capacitygate.receipt/v1`) holds:
- the owner and lineage: the module's commit, blob and sha256, and the budget file's sha256;
- the budget, the readings, the needs, the reserves and the deadline;
- the verdict.

It is written with `O_EXCL` to a path the caller names, and a receipt that cannot be persisted is a refusal
(exit 77). The gate never starts, stops or signals anything, and never polls: one pass, then exit.

### 4.4 What it is not

- **Not Kubernetes CI admission.** ARC jobs are admitted by the scheduler from pod requests and limits, and by
  the runner scale sets (<runner-ops-repository>). The readers are macOS-only (`memory_pressure`, `vm_stat`) and fail
  `missing` on Linux by construction. The consumer check scans dagu `txe/` only. txe's `<txe-ci-directory>/` and workflows
  are never consumers.
- **Not runtime isolation.** The argv floor (containerguard), the cgroup caps, the OOM handling and
  mutate-sandboxed's watchdog (time, output, disk) stay where they are. The preflight decides whether to start,
  and nothing after that. It adds no monitoring.
- **Not a lease, and not cross-coordinator admission.** It is a sequential read. Root's rule still applies on
  top: admission is the combined declared budgets plus running work, serial by default. The coordinator owns that
  decision, and the receipt is its evidence.

## 5. Tests

### 5.1 Schema and negative fixtures (pure, no process started)

**Positive fixtures** are copies of the captured files `cap-memory-pressure.txt`, `cap-vm-stat.txt`,
`cap-docker-info.txt` and `cap-docker-stats.txt` from `<evidence:TXE-8034>/<run-S>/` (copied, never moved;
provenance and sha256 noted in `testdata/README`). The disk reading uses an injected `statvfs` result.

**Negative fixtures:** at least one per (reading × failure kind), each asserting the reading's name, the kind
and the exit:

| Reading | missing | unreadable | insufficient |
|---|---|---|---|
| host_pressure | exit 1 / timeout | no `free percentage` line; a non-integer | 39 % |
| host_available | exit 1 | no page size; only 3 of the 4 page classes | 1 byte under the need |
| vm_headroom | `docker info` fails; `docker stats` fails | unknown unit `TiB`; the row count ≠ ContainersRunning; a non-integer MemTotal | 1 byte under; `cpus` > NCPU |
| disk | `statvfs` raises | a path is not absolute | volume sum + floor exceeds free by 1 byte; two paths on one `st_dev` that pass alone but fail together |

**Budget schema negatives:** each key missing, an extra key, a zero or negative number, a relative path,
`concurrent` 0, and a caps mismatch against a given argv_guard Schema.

**Verdict tests:**
- all failures are listed in one pass;
- the exit order is as stated;
- a receipt-write failure gives 77;
- the receipt never contains an environment value.

### 5.2 Consumer check: `txe/capacitygate/consumers.py`, modelled on containerguard's

- **It reuses containerguard's launch recogniser by import, not by copy.** That keeps one definition of "a
  launch": a list literal holding `create` or `run` plus a Docker isolation option, assigned directly or through
  a same-file builder.
- **The accepted shape**, in the same function, before the launch, and on the straight-line path:
  `verdict = preflight(budget)`, then `if not verdict.admit: raise/return/sys.exit`. The budget must be built in
  that function (or by a same-file builder) from the same caps the argv uses. Where both are literals, they must be
  equal.
- **Shell:** a `.sh` that invokes the gate CLI must test its exit before any later `docker` or launcher line.
- **The registry:** `UNGATED.tsv` has the same ten columns and the same rules as `UNGUARDED.tsv`:
  `ALTERNATE_GUARD` or `LEGACY_BOUNDARY`, the sha256 pin, cites, `owner_ack` and `review_evidence`.
  `fixture-demo.py` starts there.

**Honest limits:** it is an AST and text heuristic, not a data-flow proof.
- It does not follow cross-module builders, dynamic argv, the Docker SDK, or a launch through another process.
- It cannot see evidence-packet runners outside the repository. Those rely on the pinned-blob packet tests and
  the coordinator's packet review, as in containerguard.
- It cannot prove the budget is truthful, only that a gate call has the shape.
- It cannot close the gap between the read and the launch. The gate is a read.

### 5.3 Where the tests run in CI

A `txe/capacitygate/capacitygate_test.go` wrapper runs the Python suites with `python3 -I -B`, exactly like
`containerguard_test.go`. It runs in dagu's `ci.yaml` Go test job, whose paths filter already includes
`txe/**`. A missing python3 fails the test rather than skipping it. No Bazel suite is involved, because no txe
code changes.

## 6. Open questions, each with a recommendation

- **Q1. Is the host-pressure floor 40 % kept?** It is a pressure state, not a size, and cannot come from a
  budget. **Recommend:** keep the reviewed 40 % as a recorded floor with its lineage, and make the
  budget-derived `host_available` check the binding size test. *What would change this:* root preferring the
  kernel's `kern.memorystatus_vm_pressure_level` (normal or not) as the state test.
- **Q2. Is the 2 GiB VM reserve accepted explicitly?** I found no message that accepts it; it rode through the
  r4–r6 GOs. **Recommend:** root accepts it once by message id, and the receipt cites that id.
- **Q3. Should the host get a reserve beyond the run's cap?** **Recommend:** 0 in r1, so no new number is
  introduced. Root sets a value if it wants one.
- **Q4. Should CPU load be thresholded?** **Recommend:** record it, and do not gate on it in r1. Root's
  combined-budget admission already covers CPU, and load average is a lagging average. *What would change
  this:* root asking for `cpus ≤ NCPU − load1`.
- **Q5. Ticket shape.** The code belongs in dagu and this note is in txe, which would be two merges.
  **Recommend:** TXE-8042 becomes the parent with two sub-issues:
  - **(a)** the dagu PR: `txe/capacitygate/` (module, CLI adapter, fixtures, consumer check, Go wrapper), with
    this design moved into its README;
  - **(b)** the dagu PR that adopts it in `mutate-sandboxed.py`, plus the reviewed pin bump in
    `<installed mutate-sandboxed launcher>`.

  This txe commit is then not pushed. Alternatively, it merges here as a spec bundle under a third sub-issue.
- **Q6. The order relative to PR 299.** The consumer check imports containerguard's recogniser, so (a) depends
  on dagu PR 299 merging. **Recommend:** (a) waits for 299. Until then, the coordinator keeps verifying every
  reading by hand before each START.
