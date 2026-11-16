# The rollback floor (TXE-7557, TXE-7559)

A hub or a worker can be rolled back to a **floor release**. The floor's registry code then reads
the stores the current code wrote. Action parameters are decoded strictly (`decodeParams`,
`DisallowUnknownFields`), so one field the current code writes and a floor does not know makes the
floor refuse the whole record, and every path that decodes it. TXE-7553 found that for the explicit
rerun's `rerun: true`: on -17 and -19 it blocked authorizing the decision, settling the action,
ending moved-on retries and any later person's retry on the same job. Nothing caught it before
merge. TXE-7629 (R2) now stores a rerun as `step: "run"`, a field every floor knows, so the floors
read its records and refuse none of them (the nine documented refusals went to zero).
`knownFloorFailures` is empty.

Records the registry rewrites (jobs, resource events, artifact manifests, the resource index
marker) are decoded leniently (`json.Unmarshal`). A floor reads a field it does not know without
error, and its next rewrite of the record drops it: after a rollback and a roll forward the field is
gone, with no error anywhere. TXE-7559 compares every field of every rewritten record.

## The source of truth

All in `rollback_floor_test.go`:

| Declaration | What it holds |
|---|---|
| `rollbackFloors` | the floor releases, each pinned by commit; a present tag must point at that commit |
| `strictParamTypes` | every parameter type `decodeParams` decodes, by action |
| `strictParamFields` | one entry per JSON field of those types: `Floor` (every floor's type has it) or `Breaks: "<ticket>"` (a floor refuses records carrying it; the ticket records the decision) |
| `knownFloorFailures` | every path a floor is documented to refuse, by fixture record and path, and the `Breaks` field it names |
| `rollbackFloorIntents`, `rollbackFloorScenarios` | the retry intents and the persisted lifecycle states the fixture writes a job for |

In `rollback_floor_rewrite_test.go`:

| Declaration | What it holds |
|---|---|
| `rewrittenRecordKinds` | every record kind the registry reads, changes and writes back: its key, current type, the functions that rewrite it, and the fields the rewrite itself sets |
| `acceptedFloorDrops` | every field a floor's rewrite is known to lose: the kind, the field's path, exactly the floors that lose it, why the loss is safe, and the ticket that accepted it |

## The tests

Every test job (no floor is built):

- `TestStrictParamsFieldsHaveRollbackFloorEntries`: a strictly decoded field with no entry, an entry
  for a field that is gone, or a documented failure of a field that is not `Breaks`, fails.
- `TestStrictParamTypesAreDeclared`: a type passed to `decodeParams` that is not in
  `strictParamTypes`, or strict decoding outside `decodeParams`, fails.
- `TestRollbackFloorFixtureCarriesEveryStrictField`: a strictly decoded field that no fixture record
  carries fails, so the floors always read it.
- `TestRollbackFloorChecksRefuse`: the comparison refuses each way a report can disagree with the
  declarations, on synthetic reports.
- `TestRollbackFloorRewrittenKindsAreDeclared`: a function that writes back a record
  (`CompareAndSwap`, `putJSON`, `Put`) and is not a declared site of a rewritten kind fails.
- `TestRollbackFloorSyntheticRecordsCarryEveryField`: the synthetic record of each kind must set
  every field of the current type, so a new field is compared from the commit that adds it.
- `TestRollbackFloorCurrentRewriteKeepsEveryField`: the current code's own rewrite loses no field
  and changes only the ones it sets (a job's `revision` and `updated`, the marker's `at`).
- `TestAcceptedFloorDropsAreReviewed`: an accepted loss with no reason, no ticket, no floor, an
  unknown floor or kind, or a field the current type does not have, fails.
- `TestRollbackFloorRewriteChecksRefuse`: the rewrite comparison refuses a dropped field, a changed
  field, a planted field, a lost record, a failed or missing rewrite, a loss accepted only for
  another floor, and an accepted loss that no longer happens, on synthetic snapshots.

CI job **Test rollback floor** (`DAGU_ROLLBACK_FLOOR=1`, full history):

- `TestRollbackFloorReadersReadCurrentRecords` writes a temporary FileStore with the current code:
  one job per intent and lifecycle state (decided, executing, succeeded, not_applied, uncertain,
  escalated, moved_on, abandoned), plus owner, machine and project. For each floor it extracts the
  tree at the pinned commit (`git archive`), adds `testdata/rollbackfloor/floor_reader_test.go` to
  that tree's registry package, and runs it over a **copy** of the store. The reader drives the
  floor's own code: every store-wide and per-job read, a job transaction, `EndMovedOnRetries`, the
  state's own path (authorize a decided retry, settle an executing or uncertain action, answer an
  escalation), a later person's retry on the same job, and whether the parameters and binding the
  current code wrote survive. It also reports the floor's own strict fields.
- Every path must succeed, except the documented failures, which must fail with `decodeParams`'
  exact refusal. A documented failure that no longer happens fails too, so the list cannot go stale.
  A `Floor` field the floor's type lacks, or a `Breaks` field it has, fails.
- The rewrite check (TXE-7559). The test adds to a copy of the store one synthetic record of each
  rewritten kind, with every field of the current type set, and rewrites a copy of that with the
  current code. Each floor rewrites two more copies with its own code: each job by a job
  transaction that only marks it changed, each resource event and artifact manifest through the
  floor's own type and a compare-and-swap (as its `applyPending` and `CheckHubArtifacts` do), and
  the index marker by its `RebuildResourceIndex`. Every JSON field of every record is compared
  before and after. A field the floor's rewrite drops or changes, and the current code's rewrite
  of the same record does not, fails unless `acceptedFloorDrops` names it for that floor. An
  accepted loss that no longer happens on a floor it names fails too.
- The negative case runs in the same job: on the second copy, `zz_planted_txe7559` is planted on
  every job, on every job's proposals, on every resource event, on every artifact record and on the
  index marker. No type has it, so every floor drops it. The losses the check reports there must
  be exactly the planted fields, which proves a field a floor drops fails the job.

Only temporary stores are used. No live store or shared hub is touched.

## Adding a field to a strictly decoded type

1. Add the field's entry to `strictParamFields`. It is `Floor` only if every floor's type already
   has it; a new field is not.
2. If a new intent carries it, add the intent to `rollbackFloorIntents`. Otherwise the fixture must
   still write a record that carries it.
3. Run the CI job. Every path the floors refuse is named in its failure. Either make the encoding
   one the floors accept (as TXE-7629 did for the rerun), or record the incompatibility: a `Breaks` entry naming the
   ticket with the decision (a writer gate, or a raised floor), and each refused path in
   `knownFloorFailures`.

Raising the floor (removing a release from `rollbackFloors`) is a release decision, recorded in its
ticket. When the floor is above every release lacking a `Breaks` field, that field becomes `Floor`
and its documented failures go; the job tells you which.

## Adding a field to a rewritten record

Nothing to declare: the synthetic record carries the field, and the job compares it. When the CI
job reports `rewrite loses <kind> <path>`, either keep the field on the floors (it cannot be, for
a released floor), raise the floor, or add an `acceptedFloorDrops` entry: the floors that lose it,
why losing it after a rollback and roll forward is safe, and the ticket that accepted it.

A new record kind that the registry rewrites fails `TestRollbackFloorRewrittenKindsAreDeclared`
until it is in `rewrittenRecordKinds`, and both rewrite procedures (`rewriteCurrent` here,
`floorReaderRewrite` in the reader) rewrite it.

## Accepted losses

| Kind | Field | Floors | Ticket | Why it is safe |
|---|---|---|---|---|
| resource event | `reporter_job_id`, `reporter_job_version` | -17 | TXE-7559 | added by TXE-3993 after -17. A pending event -17 rewrites loses its reporting job; the current code then applies an observer-relative observation to no job (`notTheObserver`). It fails closed, and the next check reports again. |

## Not covered

- A floor's rewrite of a record kind it has and the current code no longer writes is not compared;
  nothing reads such records after a roll forward.
- A field a floor's rewrite adds is not a loss and is not reported.
- Records written once and never rewritten (owners, machines, projects, history, evidence, index
  entries, dedupe keys) cannot lose a field to a floor and are not compared.
