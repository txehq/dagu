# The rollback floor (TXE-7557)

A hub or a worker can be rolled back to a **floor release**. The floor's registry code then reads
the stores the current code wrote. Action parameters are decoded strictly (`decodeParams`,
`DisallowUnknownFields`), so one field the current code writes and a floor does not know makes the
floor refuse the whole record, and every path that decodes it. TXE-7553 found that for the explicit
rerun's `rerun: true`: on -17 and -19 it blocks authorizing the decision, settling the action,
ending moved-on retries and any later person's retry on the same job. Nothing caught it before
merge.

## The source of truth

All in `rollback_floor_test.go`:

| Declaration | What it holds |
|---|---|
| `rollbackFloors` | the floor releases, each pinned by commit; a present tag must point at that commit |
| `strictParamTypes` | every parameter type `decodeParams` decodes, by action |
| `strictParamFields` | one entry per JSON field of those types: `Floor` (every floor's type has it) or `Breaks: "<ticket>"` (a floor refuses records carrying it; the ticket records the decision) |
| `knownFloorFailures` | every path a floor is documented to refuse, by fixture record and path, and the `Breaks` field it names |
| `rollbackFloorIntents`, `rollbackFloorScenarios` | the retry intents and the persisted lifecycle states the fixture writes a job for |

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

Only temporary stores are used. No live store or shared hub is touched.

## Adding a field to a strictly decoded type

1. Add the field's entry to `strictParamFields`. It is `Floor` only if every floor's type already
   has it; a new field is not.
2. If a new intent carries it, add the intent to `rollbackFloorIntents`. Otherwise the fixture must
   still write a record that carries it.
3. Run the CI job. Every path the floors refuse is named in its failure. Either make the encoding
   one the floors accept (TXE-7553's R2), or record the incompatibility: a `Breaks` entry naming the
   ticket with the decision (a writer gate, or a raised floor), and each refused path in
   `knownFloorFailures`.

Raising the floor (removing a release from `rollbackFloors`) is a release decision, recorded in its
ticket. When the floor is above every release lacking a `Breaks` field, that field becomes `Floor`
and its documented failures go; the job tells you which.

## Not covered

Job documents are decoded leniently (`json.Unmarshal`). A floor reads a new field there without
error, but every floor transaction rewrites the job and drops it. The reader's
`8_params_and_binding_preserved` check catches that for the retry's parameters and binding; it
does not cover other new fields of lenient records.
