# runbudget: the run budget data contract, `txe.runbudget/v1` (TXE-8043)

A budget is one container run's declared caps. The launcher writes it once per run, from the same values it passes to
the container argv. It is a **data contract, not a code dependency**:
- `txe/capacitygate` reads it to admit or refuse the run;
- `txe/containerguard`, or any runner, can compare it with its own argv through `caps_match`, which takes a plain
  `{option: value}` mapping.

Neither guard imports the other. This directory imports nothing from either.

| File | Purpose |
|---|---|
| `runbudget.v1.schema.json` | JSON Schema 2020-12: the documentation and a test oracle |
| `runbudget.py` | the stdlib, pure reference validator: `load`, `loads`, `validate`, `caps_match`, the docker cap parsers |
| `test_runbudget.py` | its suite. `runbudget_test.go` runs it in CI with `python3 -I -B` |

## Fields

See the schema document. In short:
- **`reservation_id`:** the key into the coordinator's reservation inventory.
- **`owner`:** `{ticket, session, grant}`. The grant is an audit reference, not cryptographic approval.
- **`containers`:** `{concurrent, cpus_milli, memory_bytes}`. The caps are **per container**.
- **`time`:** `{run_bound_s, kill_after_s, cleanup_reserve_s}`. Their sum is the receipt's claimed deadline, which
  reserves nothing.
- **`disk`:** `[{path, need_bytes}]`.
- **`policy`:** optional overrides of capacitygate's policy values. The receipt reports each override with origin
  `budget`.

## Rules

- **Strict.** These all refuse with a stable code (`CODES`) and the JSON path of the field, never its value:
  - an unknown or missing key;
  - a duplicate JSON key;
  - NaN or Infinity;
  - a float or bool where an integer belongs;
  - a non-normalised or relative path;
  - a repeated path.
- **Versioning.** Any added, removed or re-meant field is a new schema string (`txe.runbudget/v2`). v1 is frozen once
  merged. A reader accepts exactly the versions it names. A migration ships the new reader before any writer emits the
  new version.
- **The argv tie.** `caps_match(budget, single)` returns redacted codes (`CAPS_CODES`) when `--cpus`, `--memory` or
  `--memory-swap` disagree with the per-container caps.
  - `--memory` accepts an integer with an optional `b`/`k`/`m`/`g` suffix (binary). Anything else is unreadable, never
    a guess.
  - `--cpus` accepts at most three decimals.

**Loading by pinned blob.** A runner outside this repository that loads `capacity_gate.py` by blob hash loads
`runbudget.py` the same way, by its own pinned hash, and puts it in `sys.modules["runbudget"]` first.
