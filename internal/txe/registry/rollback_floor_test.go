package registry

// The rollback floor (TXE-7557). A hub or worker can be rolled back to a
// floor release, and the floor's registry code then reads the stores the
// current code wrote. Action parameters are decoded strictly
// (decodeParams), so a field the current code writes and a floor reader does
// not know makes that reader refuse the whole record, and with it every path
// that decodes it: TXE-7553 found the explicit rerun's `rerun: true` locking
// jobs on -17 and -19 that way, and nothing had caught it before merge.
// TXE-7629 (R2) now stores the rerun as `step: "run"`, a field every floor
// knows, so no path is documented to fail.
//
// One source of truth, declared here:
//
//   - rollbackFloors: the floor releases, pinned by commit;
//   - strictParamFields: one compatibility entry per field of every strictly
//     decoded parameter type, either known to every floor reader or naming
//     the ticket that records the incompatibility;
//   - knownFloorFailures: every path a floor reader is documented to refuse,
//     and on which record.
//
// Two tests hold it:
//
//   - the guards below run in every test job, with no floor built: a field
//     added to a strict type without an entry, a strictly decoded type not
//     declared, or a field no fixture record carries, fails at once;
//   - TestRollbackFloorReadersReadCurrentRecords (CI job "Test rollback
//     floor", DAGU_ROLLBACK_FLOOR=1) extracts each floor's tree at its pinned
//     commit, writes a temporary FileStore with the current code holding a
//     job per retry intent and lifecycle state, and runs the floor's own
//     registry code over a copy of it (testdata/rollbackfloor). Every path
//     must succeed, except the documented failures, which must fail exactly
//     as documented; a documented failure that no longer happens fails too,
//     so the list never goes stale. Only temporary stores are used.
//
// rollback_floor_rewrite_test.go adds the rewrite check (TXE-7559): every
// field of every record a floor rewrites. rollback-floor.md has the rules for
// changing any of this.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dag"
)

// rollbackFloor is a release the hub or a worker may be rolled back to.
type rollbackFloor struct {
	// Name is the release tag. When the tag is present it must point at
	// Commit; the commit, never the tag, is what is built.
	Name   string
	Commit string
}

// rollbackFloors are the declared rollback floors (TXE-7553). Removing one
// is a release decision, recorded where the floor was raised.
var rollbackFloors = []rollbackFloor{
	{Name: "txe-v2.18.2-17", Commit: "4d164866b07195346610588a37390a38960e5bb7"},
	{Name: "txe-v2.18.2-19", Commit: "8d2f1f20624c36d6921742984a63a8f1578530ef"},
}

// strictParamTypes are the parameter types decodeParams decodes, by action.
// TestStrictParamTypesAreDeclared fails when the package decodes another.
var strictParamTypes = map[string]reflect.Type{
	ActionRetryRun:        reflect.TypeFor[RetryRunParams](),
	ActionUncertainEffect: reflect.TypeFor[UncertainEffectParams](),
}

// fieldCompat is one strictly decoded field's compatibility with the floors.
type fieldCompat struct {
	// Floor: every floor reader's type has the field, so records carrying
	// it decode there.
	Floor bool
	// Breaks is the ticket that records why a floor reader refuses a record
	// carrying the field, and what is decided about it. Every path that
	// refuses must be in knownFloorFailures.
	Breaks string
}

var floorField = fieldCompat{Floor: true}

// strictParamFields has an entry for every JSON field of every type in
// strictParamTypes, and none for a field that does not exist.
var strictParamFields = map[string]map[string]fieldCompat{
	ActionRetryRun: {
		"run_id":          floorField,
		"attempt_id":      floorField,
		"queued_at":       floorField,
		"run_spec_sha256": floorField,
		"package_digest":  floorField,
		// A person's rerun is `step: "run"` since TXE-7629: the floors know
		// the field, so they read the record. Their own code carries out
		// only a republish by step, so they refuse to run a rerun (the
		// binding and the reviewer's step switch), and refuse nothing else.
		"step": floorField,
	},
	ActionUncertainEffect: {
		"action_id": floorField,
		"attempt":   floorField,
	},
}

// knownFloorFailure is a path a floor reader is documented to refuse.
type knownFloorFailure struct {
	// Record is "<intent>/<scenario>" of the fixture job.
	Record string
	// Op is the path, as the floor reader names it.
	Op string
	// Field is the strictly decoded field the refusal names. It must have a
	// Breaks entry: a refusal is documented only as a field's consequence.
	Field string
}

// knownFloorFailures are the documented refusals, the same on every floor.
// TXE-7553's proof (rollback-proof, 147/156) found nine on -17 and -19, all
// for the `rerun` field; TXE-7629 removed that field and with it every one.
// The CI job fails if a floor refuses any path now.
var knownFloorFailures = []knownFloorFailure{}

// floorRefusal is how a floor reader reports a record it refuses for an
// unknown strictly decoded field: decodeParams' own error.
func floorRefusal(field string) string {
	return fmt.Sprintf(`ERR %s: registry: %s: action params: json: unknown field %q`, CodeInvalid, CodeInvalid, field)
}

// rollbackFloorIntents are the retry intents a person or reviewer can ask
// for, by the parameters that carry them. An intent carried by a new field
// is added here; TestRollbackFloorFixtureCarriesEveryStrictField fails until
// some record carries every field.
var rollbackFloorIntents = []struct {
	Name string
	Set  func(*RetryRunParams)
}{
	{Name: "unspecified", Set: func(*RetryRunParams) {}},
	{Name: "republish", Set: func(p *RetryRunParams) { p.Step = RetryStepPublish }},
	{Name: "rerun", Set: func(p *RetryRunParams) { p.Step = RetryStepRun }},
}

// rollbackFloorScenarios are the lifecycle states a retry is persisted in:
//
//   - decided: approved, not carried out;
//   - executing: carried out under a live grant;
//   - succeeded: settled, proposal and action archived;
//   - not_applied: settled not applied, proposal still decided;
//   - uncertain: the outcome is unknown;
//   - escalated: uncertain, and a reviewer asked a person about it
//     (txe.uncertain_effect);
//   - moved_on: the run moved on before the retry, so it was superseded;
//   - abandoned: Dagu admitted the execution and abandoned it, settled not
//     applied with the admitted execution.
var rollbackFloorScenarios = []string{"decided", "executing", "succeeded", "not_applied", "uncertain", "escalated", "moved_on", "abandoned"}

// floorJob is one fixture job, as the floor reader receives it.
type floorJob struct {
	Record       string          `json:"record"`
	Intent       string          `json:"intent"`
	Scenario     string          `json:"scenario"`
	JobID        string          `json:"job_id"`
	RunID        string          `json:"run_id"`
	ProposalID   string          `json:"proposal_id"`
	DecisionID   string          `json:"decision_id"`
	ActionID     string          `json:"action_id,omitempty"`
	GrantID      string          `json:"grant_id,omitempty"`
	ClaimID      string          `json:"claim_id,omitempty"`
	Fence        int64           `json:"fence,omitempty"`
	EscalationID string          `json:"escalation_id,omitempty"`
	Version      int             `json:"version"`
	Package      string          `json:"package"`
	Spec         string          `json:"spec"`
	Params       json.RawMessage `json:"params"`
	Binding      string          `json:"binding"`
}

// floorManifest is what the fixture writer leaves beside the store.
type floorManifest struct {
	Now      time.Time                 `json:"now"`
	Owner    string                    `json:"owner"`
	Machine  string                    `json:"machine"`
	Project  string                    `json:"project"`
	Jobs     []floorJob                `json:"jobs"`
	Attempts map[string]RunAttempt     `json:"attempts"`
	Retries  map[string]RetryExecution `json:"retries"`
}

// floorReport is what a floor reader returns.
type floorReport struct {
	// Fields are the JSON fields of the floor's own strict types, by action.
	Fields map[string][]string `json:"fields"`
	// Results are each path's outcome by record ("store" for the store-wide
	// reads): "ok", or "ERR <code>: <error>".
	Results map[string]map[string]string `json:"results"`
	// Rewrites are each rewritten record's outcome by store ("real",
	// "planted") and key: "ok", or "ERR ..." (TXE-7559).
	Rewrites map[string]map[string]string `json:"rewrites"`
}

// floorStoreRecord is the report's record for the store-wide reads.
const floorStoreRecord = "store"

func jsonFieldNames(t reflect.Type) []string {
	var names []string
	for f := range t.Fields() {
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		switch name {
		case "-":
			continue
		case "":
			name = f.Name
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// newFloorFixture opens a FileStore under dir, the way newFixture does under
// a test's own temporary directory.
func newFloorFixture(t *testing.T, dir string) *fixture {
	t.Helper()
	f := &fixture{t: t, ctx: context.Background(), now: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	f.dagsDir = filepath.Join(dir, "dags")
	f.dags = NewDAGStore(persis.NewDAGRepository(dag.NewStore(f.dagsDir), persis.DAGRepositoryOptions{}))
	s, err := NewFileStore(filepath.Join(dir, "data"), WithClock(f.clock), WithDAGStore(f.dags))
	require.NoError(t, err)
	f.store = s
	f.owner = f.mint(PrefixOwner)
	f.machine = f.mint(PrefixMachine)
	_, err = s.CreateOwner(f.ctx, Owner{OwnerID: f.owner, DisplayName: "Connor Wang"}, cli)
	require.NoError(t, err)
	_, err = s.CreateMachine(f.ctx, Machine{MachineID: f.machine, OwnerID: f.owner, DisplayName: "laptop"}, cli)
	require.NoError(t, err)
	p, err := s.EnsureProject(f.ctx, f.owner, "github.com/txehq/txe", "txe", cli)
	require.NoError(t, err)
	f.project = p.ProjectID
	require.NoError(t, s.RebuildResourceIndex(f.ctx))
	return f
}

// writeRollbackFloorFixture writes, with the current code's own calls, a
// FileStore under dir holding one job per intent and scenario, and the
// manifest the floor reader drives it with. It returns the manifest and the
// store's fixture.
func writeRollbackFloorFixture(t *testing.T, dir string) (floorManifest, *fixture) {
	t.Helper()
	f := newFloorFixture(t, dir)
	rc := withRuns(f)
	rc.attempts = map[string]RunAttempt{}
	rc.retries = map[string]RetryExecution{}
	man := floorManifest{Owner: f.owner, Machine: f.machine, Project: f.project}

	for _, intent := range rollbackFloorIntents {
		for _, sc := range rollbackFloorScenarios {
			key := intent.Name + "-" + sc
			job := f.ready(key)
			r := &retryFixture{f: f, rc: rc, job: job}
			run := "run-" + key
			rc.attempts[run] = failedAttempt("a1", job.DAGSpecSHA256)
			params := r.params(run, "a1")
			intent.Set(&params)
			j := floorJob{Record: intent.Name + "/" + sc, Intent: intent.Name, Scenario: sc, JobID: job.JobID, RunID: run,
				Version: job.Version, Package: job.PackageDigest, Spec: job.DAGSpecSHA256}

			p, d, err := r.propose(params, "key-"+key)
			require.NoError(t, err, key)
			j.ProposalID, j.DecisionID, j.Binding = p.ProposalID, d.DecisionID, p.BindingDigest
			switch sc {
			case "decided":
			case "moved_on":
				rc.attempts[run] = RunAttempt{AttemptID: "a2", SpecSHA256: job.DAGSpecSHA256, Status: "succeeded", Finished: true, Succeeded: true}
				_, err := f.store.EndMovedOnRetries(f.ctx, job.JobID)
				require.NoError(t, err, key)
			default:
				ec := acquire(t, f, job.JobID, ClaimExecution, time.Hour)
				act, g, err := r.authorize(p, d, ec)
				require.NoError(t, err, key)
				j.ActionID, j.GrantID, j.ClaimID, j.Fence = act, g.GrantID, ec.ClaimID, ec.Fence
				switch sc {
				case "executing":
				case "succeeded":
					rc.attempts[run] = RunAttempt{AttemptID: "a2", SpecSHA256: job.DAGSpecSHA256, Status: "queued"}
					r.admit(t, act, params, ExecutionRef("a2", ""), false, false)
					require.NoError(t, r.settle(act, g, ec, ActionSucceeded, ExecutionRef("a2", "")), key)
				case "not_applied":
					require.NoError(t, r.settle(act, g, ec, ActionNotApplied, ""), key)
				case "uncertain":
					require.NoError(t, r.settle(act, g, ec, ActionUncertain, ""), key)
				case "escalated":
					require.NoError(t, r.settle(act, g, ec, ActionUncertain, ""), key)
					_, err := f.tx(job.JobID, agent, func(tx *JobTx) error { return tx.ReleaseClaim(ec.ClaimID, ec.Fence) })
					require.NoError(t, err, key)
					j.EscalationID = escalateFloorAction(t, f, job, act)
				case "abandoned":
					r.admit(t, act, params, ExecutionRef("a2", ""), true, false)
					require.NoError(t, r.settleOutcome(act, g, ec, ActionNotApplied, "", admittedOutcome(ExecutionRef("a2", ""))), key)
				default:
					t.Fatalf("scenario %s is not written", sc)
				}
			}
			stored := floorProposal(t, f, job.JobID, j.ProposalID)
			j.Params, j.Binding = stored.Action.Params, stored.BindingDigest
			man.Jobs = append(man.Jobs, j)
		}
	}
	man.Now = f.clock()
	man.Attempts, man.Retries = rc.attempts, rc.retries
	b, err := json.MarshalIndent(man, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "manifest.json"), b, 0o600))
	return man, f
}

// escalateFloorAction files the reviewer's question about the uncertain
// action actionID under a review claim, as the reviewer does; the execution
// claim is released first.
func escalateFloorAction(t *testing.T, f *fixture, job *Job, actionID string) string {
	t.Helper()
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	a := got.Actions[actionID]
	require.NotNil(t, a, "action %s", actionID)
	id, err := EscalationProposalID(actionID, a.Attempt, job.Version)
	require.NoError(t, err)
	c := acquire(t, f, job.JobID, ClaimReview, time.Hour)
	_, err = f.tx(job.JobID, agent, func(tx *JobTx) error {
		_, err := tx.PutProposal(c.ClaimID, c.Fence, Proposal{ProposalID: id,
			Action: ActionSpec{Name: ActionUncertainEffect, Params: json.RawMessage(fmt.Sprintf(`{"action_id":%q,"attempt":%d}`, actionID, a.Attempt))}})
		return err
	})
	require.NoError(t, err, "escalate %s", actionID)
	return id
}

// floorProposal is the proposal as stored, on the job or in its archive.
func floorProposal(t *testing.T, f *fixture, jobID, proposalID string) *Proposal {
	t.Helper()
	job, err := f.store.GetJob(f.ctx, jobID)
	require.NoError(t, err)
	if p := job.Proposals[proposalID]; p != nil {
		return p
	}
	archived, err := f.store.ListArchivedProposals(f.ctx, jobID, 0)
	require.NoError(t, err)
	for _, p := range archived {
		if p.ProposalID == proposalID {
			return p
		}
	}
	t.Fatalf("proposal %s of job %s is on neither the job nor its archive", proposalID, jobID)
	return nil
}

// storedParamFields is, by action, every parameter field some proposal or
// action of the fixture's jobs carries, on the job or in its archive.
func storedParamFields(t *testing.T, f *fixture, man floorManifest) map[string]map[string]bool {
	t.Helper()
	seen := map[string]map[string]bool{}
	note := func(spec ActionSpec) {
		var raw map[string]json.RawMessage
		if len(spec.Params) == 0 || json.Unmarshal(spec.Params, &raw) != nil {
			return
		}
		if seen[spec.Name] == nil {
			seen[spec.Name] = map[string]bool{}
		}
		for k := range raw {
			seen[spec.Name][k] = true
		}
	}
	for _, j := range man.Jobs {
		job, err := f.store.GetJob(f.ctx, j.JobID)
		require.NoError(t, err)
		for _, p := range job.Proposals {
			note(p.Action)
		}
		for _, a := range job.Actions {
			note(a.Spec)
		}
		ap, err := f.store.ListArchivedProposals(f.ctx, j.JobID, 0)
		require.NoError(t, err)
		for _, p := range ap {
			note(p.Action)
		}
		aa, err := f.store.ListArchivedActions(f.ctx, j.JobID, 0)
		require.NoError(t, err)
		for _, a := range aa {
			note(a.Spec)
		}
	}
	return seen
}

// checkRollbackFloorDeclarations checks the source of truth against the
// current code's strict types. It returns every problem found.
func checkRollbackFloorDeclarations(types map[string]reflect.Type, fields map[string]map[string]fieldCompat, known []knownFloorFailure) []string {
	var problems []string
	for _, action := range sortedKeys(types) {
		entries, ok := fields[action]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: no compatibility entries", action))
			continue
		}
		names := jsonFieldNames(types[action])
		for _, name := range names {
			e, ok := entries[name]
			switch {
			case !ok:
				problems = append(problems, fmt.Sprintf("%s.%s: strictly decoded and has no compatibility entry: declare it Floor only if every rollback floor's type has it, else Breaks with the ticket that records the incompatibility, and list the paths it breaks", action, name))
			case e.Floor == (e.Breaks != ""):
				problems = append(problems, fmt.Sprintf("%s.%s: an entry is exactly one of Floor or Breaks", action, name))
			}
		}
		for _, name := range sortedKeys(entries) {
			if !slices.Contains(names, name) {
				problems = append(problems, fmt.Sprintf("%s.%s: entry for a field %s does not have", action, name, types[action]))
			}
		}
	}
	for _, action := range sortedKeys(fields) {
		if _, ok := types[action]; !ok {
			problems = append(problems, fmt.Sprintf("%s: entries for an action that is not strictly decoded", action))
		}
	}
	seen := map[string]bool{}
	for _, k := range known {
		id := k.Record + " " + k.Op
		if seen[id] {
			problems = append(problems, "known failure listed twice: "+id)
		}
		seen[id] = true
		breaking := false
		for _, entries := range fields {
			if e, ok := entries[k.Field]; ok && e.Breaks != "" {
				breaking = true
			}
		}
		if !breaking {
			problems = append(problems, fmt.Sprintf("known failure %s names field %q, which has no Breaks entry", id, k.Field))
		}
	}
	return problems
}

// checkFloorReport compares what floor read with the declarations. records
// are the fixture's records, each of which the floor must have read.
func checkFloorReport(floor string, rep floorReport, fields map[string]map[string]fieldCompat, known []knownFloorFailure, records []string) []string {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, floor+": "+fmt.Sprintf(format, args...)) }
	for _, action := range sortedKeys(fields) {
		have, ok := rep.Fields[action]
		if !ok {
			add("%s: the floor reader reported no fields for it", action)
			continue
		}
		for _, name := range sortedKeys(fields[action]) {
			e, in := fields[action][name], slices.Contains(have, name)
			switch {
			case e.Floor && !in:
				add("%s.%s is declared Floor, but this floor's type does not have it: a record carrying it is refused here", action, name)
			case e.Breaks != "" && in:
				add("%s.%s is declared Breaks (%s), but this floor's type has it: correct the entry and its known failures", action, name, e.Breaks)
			}
		}
	}
	want := map[string]string{}
	for _, k := range known {
		want[k.Record+" "+k.Op] = floorRefusal(k.Field)
	}
	for _, rec := range append([]string{floorStoreRecord}, records...) {
		ops, ok := rep.Results[rec]
		if !ok {
			add("record %s was not read", rec)
			continue
		}
		if len(ops) == 0 {
			add("record %s: no path ran", rec)
		}
		for _, op := range sortedKeys(ops) {
			got := ops[op]
			id := rec + " " + op
			exp, documented := want[id]
			delete(want, id)
			switch {
			case documented && got != exp:
				add("%s: documented to fail with %q, got %q", id, exp, got)
			case !documented && !strings.HasPrefix(got, "ok"):
				add("%s: fails and is not documented: %s", id, got)
			}
		}
	}
	for _, id := range sortedKeys(want) {
		add("%s: documented failure did not happen (the path did not run): remove it, or restore the path", id)
	}
	for rec := range rep.Results {
		if rec != floorStoreRecord && !slices.Contains(records, rec) {
			add("record %s is not in the fixture", rec)
		}
	}
	sort.Strings(problems)
	return problems
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Every field of every strictly decoded type has exactly one compatibility
// entry, and every documented failure is a Breaks field's consequence.
func TestStrictParamsFieldsHaveRollbackFloorEntries(t *testing.T) {
	require.Empty(t, checkRollbackFloorDeclarations(strictParamTypes, strictParamFields, knownFloorFailures))
}

// strictlyDecodedTypes is the set of types this package passes to
// decodeParams, read from its source.
func strictlyDecodedTypes(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	found := map[string]bool{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			vars := map[string]string{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.ValueSpec:
					if id, ok := n.Type.(*ast.Ident); ok {
						for _, v := range n.Names {
							vars[v.Name] = id.Name
						}
					}
				case *ast.SelectorExpr:
					if id, ok := n.X.(*ast.Ident); ok && id.Name == "dec" && n.Sel.Name == "DisallowUnknownFields" && fn.Name.Name != "decodeParams" {
						t.Errorf("%s: %s decodes strictly outside decodeParams: route it through decodeParams so the rollback floor covers it", fset.Position(n.Pos()), fn.Name.Name)
					}
				case *ast.CallExpr:
					if id, ok := n.Fun.(*ast.Ident); !ok || id.Name != "decodeParams" || len(n.Args) != 2 {
						return true
					}
					var typ string
					if u, ok := n.Args[1].(*ast.UnaryExpr); ok && u.Op == token.AND {
						switch x := u.X.(type) {
						case *ast.Ident:
							typ = vars[x.Name]
						case *ast.CompositeLit:
							if id, ok := x.Type.(*ast.Ident); ok {
								typ = id.Name
							}
						}
					}
					if typ == "" {
						t.Errorf("%s: cannot tell what decodeParams decodes here: pass &v of a `var v T`", fset.Position(n.Pos()))
						return true
					}
					found[typ] = true
				}
				return true
			})
		}
	}
	return found
}

// Every type decodeParams decodes is declared in strictParamTypes, so a new
// strictly decoded parameter type is covered by the floor from its first
// field.
func TestStrictParamTypesAreDeclared(t *testing.T) {
	declared := map[string]bool{}
	for _, typ := range strictParamTypes {
		declared[typ.Name()] = true
	}
	require.Equal(t, declared, strictlyDecodedTypes(t))
}

// Every strictly decoded field is carried by some record the fixture writes,
// so the floor readers read it: an intent carried by a new field gets its
// jobs in every lifecycle state through rollbackFloorIntents.
func TestRollbackFloorFixtureCarriesEveryStrictField(t *testing.T) {
	man, f := writeRollbackFloorFixture(t, t.TempDir())
	require.Len(t, man.Jobs, len(rollbackFloorIntents)*len(rollbackFloorScenarios))
	seen := storedParamFields(t, f, man)
	for _, action := range sortedKeys(strictParamTypes) {
		for _, name := range jsonFieldNames(strictParamTypes[action]) {
			require.True(t, seen[action][name], "%s.%s is in no record the fixture writes: add the intent that sets it to rollbackFloorIntents", action, name)
		}
	}
}

// The checks fail on each way the floor can be broken. Synthetic reports;
// the real ones come from the floor readers.
func TestRollbackFloorChecksRefuse(t *testing.T) {
	fields := map[string]map[string]fieldCompat{"a": {"old": floorField, "new": {Breaks: "TXE-0"}}}
	known := []knownFloorFailure{{Record: "x/s", Op: "op1", Field: "new"}}
	records := []string{"x/s", "y/s"}
	good := func() floorReport {
		return floorReport{
			Fields: map[string][]string{"a": {"old"}},
			Results: map[string]map[string]string{
				floorStoreRecord: {"get": "ok"},
				"x/s":            {"op1": floorRefusal("new"), "op2": "ok"},
				"y/s":            {"op1": "ok (job)", "op2": "ok"},
			},
		}
	}
	require.Empty(t, checkFloorReport("f", good(), fields, known, records))

	cases := map[string]func(*floorReport) []knownFloorFailure{
		"an undocumented failure": func(r *floorReport) []knownFloorFailure {
			r.Results["y/s"]["op1"] = floorRefusal("new")
			return known
		},
		"a documented failure that stopped happening": func(r *floorReport) []knownFloorFailure {
			r.Results["x/s"]["op1"] = "ok"
			return known
		},
		"a documented failure with another error": func(r *floorReport) []knownFloorFailure {
			r.Results["x/s"]["op1"] = "ERR invalid: something else"
			return known
		},
		"a documented path that did not run": func(r *floorReport) []knownFloorFailure {
			delete(r.Results["x/s"], "op1")
			return known
		},
		"a record not read": func(r *floorReport) []knownFloorFailure {
			delete(r.Results, "y/s")
			return known
		},
		"store reads missing": func(r *floorReport) []knownFloorFailure {
			delete(r.Results, floorStoreRecord)
			return known
		},
		"a Floor field the floor lacks": func(r *floorReport) []knownFloorFailure {
			r.Fields["a"] = nil
			return known
		},
		"a Breaks field the floor has": func(r *floorReport) []knownFloorFailure {
			r.Fields["a"] = []string{"old", "new"}
			return known
		},
		"no fields reported": func(r *floorReport) []knownFloorFailure {
			delete(r.Fields, "a")
			return known
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := good()
			k := mutate(&r)
			require.NotEmpty(t, checkFloorReport("f", r, fields, k, records))
		})
	}

	type decl struct{ RunID, Added string }
	types := map[string]reflect.Type{"a": reflect.TypeFor[struct {
		Old string `json:"old"`
		New bool   `json:"new,omitempty"`
	}]()}
	require.Empty(t, checkRollbackFloorDeclarations(types, fields, known))
	require.NotEmpty(t, checkRollbackFloorDeclarations(map[string]reflect.Type{"a": reflect.TypeFor[struct {
		Old   string `json:"old"`
		New   bool   `json:"new,omitempty"`
		Added string `json:"added,omitempty"`
	}]()}, fields, known), "a field added with no entry")
	require.NotEmpty(t, checkRollbackFloorDeclarations(map[string]reflect.Type{"a": reflect.TypeFor[decl]()}, fields, known), "entries for fields that are gone")
	require.NotEmpty(t, checkRollbackFloorDeclarations(types, map[string]map[string]fieldCompat{"a": {"old": floorField, "new": {}}}, known), "an entry that is neither")
	require.NotEmpty(t, checkRollbackFloorDeclarations(types, fields, []knownFloorFailure{{Record: "x/s", Op: "op1", Field: "old"}}), "a failure of a Floor field")
	require.NotEmpty(t, checkRollbackFloorDeclarations(types, fields, append(slices.Clone(known), known...)), "a failure listed twice")
}

func floorGit(t *testing.T, root string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// extractFloorTree writes the tree of commit into dir.
func extractFloorTree(t *testing.T, root, commit, dir string) {
	t.Helper()
	archive := exec.Command("git", "-C", root, "archive", "--format=tar", commit)
	untar := exec.Command("tar", "-x", "-C", dir)
	pipe, err := archive.StdoutPipe()
	require.NoError(t, err)
	untar.Stdin = pipe
	var aerr, uerr bytes.Buffer
	archive.Stderr, untar.Stderr = &aerr, &uerr
	require.NoError(t, untar.Start())
	require.NoError(t, archive.Run(), "git archive %s: %s", commit, aerr.String())
	require.NoError(t, untar.Wait(), "tar: %s", uerr.String())
}

// The floor readers read every record the current code writes, and refuse
// exactly the documented paths. CI's "Test rollback floor" job runs it with
// the repository's full history; anywhere else it is skipped.
func TestRollbackFloorReadersReadCurrentRecords(t *testing.T) {
	if os.Getenv("DAGU_ROLLBACK_FLOOR") != "1" {
		t.Skip("builds every rollback floor at its pinned commit: set DAGU_ROLLBACK_FLOOR=1 (CI's rollback-floor job does)")
	}
	reader, err := os.ReadFile(filepath.Join("testdata", "rollbackfloor", "floor_reader_test.go"))
	require.NoError(t, err)
	root, err := floorGit(t, ".", "rev-parse", "--show-toplevel")
	require.NoError(t, err)

	fixtureDir := t.TempDir()
	man, _ := writeRollbackFloorFixture(t, fixtureDir)
	records := make([]string, 0, len(man.Jobs))
	for _, j := range man.Jobs {
		records = append(records, j.Record)
	}
	rewriteBase, rewriteBefore, rewriteCur := prepareRewriteStores(t, fixtureDir, man.Now)

	for _, floor := range rollbackFloors {
		t.Run(floor.Name, func(t *testing.T) {
			t.Parallel()
			got, err := floorGit(t, root, "rev-parse", "--verify", "--quiet", floor.Commit+"^{commit}")
			require.NoError(t, err, "floor %s: commit %s is not in this clone (CI checks out with fetch-depth 0)", floor.Name, floor.Commit)
			require.Equal(t, floor.Commit, got)
			if tag, err := floorGit(t, root, "rev-parse", "--verify", "--quiet", "refs/tags/"+floor.Name+"^{commit}"); err == nil {
				require.Equal(t, floor.Commit, tag, "tag %s moved off the pinned floor commit", floor.Name)
			}

			tree := t.TempDir()
			extractFloorTree(t, root, floor.Commit, tree)
			require.NoError(t, os.WriteFile(filepath.Join(tree, "internal", "txe", "registry", "zz_rollback_floor_reader_test.go"), reader, 0o600))
			in := t.TempDir()
			require.NoError(t, os.CopyFS(in, os.DirFS(fixtureDir)), "the floor reads a copy of the store, never the one written")
			out := filepath.Join(t.TempDir(), "report.json")
			dirs := floorRewriteCopies(t, rewriteBase)
			rewrite, err := json.Marshal(dirs)
			require.NoError(t, err)

			cmd := exec.Command("go", "test", "-count=1", "-run", "^TestRollbackFloorReader$", "./internal/txe/registry/")
			cmd.Dir = tree
			cmd.Env = append(os.Environ(), "DAGU_ROLLBACK_FLOOR_IN="+in, "DAGU_ROLLBACK_FLOOR_OUT="+out, "DAGU_ROLLBACK_FLOOR_REWRITE="+string(rewrite))
			output, err := cmd.CombinedOutput()
			require.NoError(t, err, "floor %s reader:\n%s", floor.Name, output)

			b, err := os.ReadFile(out)
			require.NoError(t, err, "floor %s wrote no report:\n%s", floor.Name, output)
			var rep floorReport
			require.NoError(t, json.Unmarshal(b, &rep))
			for _, rec := range sortedKeys(rep.Results) {
				for _, op := range sortedKeys(rep.Results[rec]) {
					t.Logf("%s %-24s %-34s %s", floor.Name, rec, op, rep.Results[rec][op])
				}
			}
			require.Empty(t, checkFloorReport(floor.Name, rep, strictParamFields, knownFloorFailures, records))
			checkFloorRewrites(t, floor.Name, dirs, rewriteBefore, rewriteCur, rep.Rewrites)
		})
	}
}
