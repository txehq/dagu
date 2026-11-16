package registry

// The rollback floor's rewrite check (TXE-7559). Records the registry
// rewrites are decoded leniently (json.Unmarshal): a floor reads a field it
// does not know without error, and its next rewrite of the record drops it.
// After a rollback and a roll forward the field is gone, with no error
// anywhere. TXE-7557's reader checked that only for a retry's parameters and
// binding.
//
// Here each floor rewrites every record of every rewritten kind
// (rewrittenRecordKinds) in a temporary store the current code wrote, and the
// current code rewrites a copy of the same store the same way. Every JSON
// field of every record is compared before and after: a field the floor's
// rewrite drops or changes, and the current code's does not, fails, unless
// acceptedFloorDrops names it, why losing it on rollback is safe, and the
// ticket that accepted it. Besides the lifecycle fixture, the store holds one
// synthetic record of each kind with every field of the current type set, so
// a new field is compared from the commit that adds it, whether or not any
// path sets it yet.

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dag"
)

// rewrittenKind is a record kind the registry reads, changes and writes
// back, so a floor rewrites it too.
type rewrittenKind struct {
	// Name is the kind, as the report and acceptedFloorDrops name it.
	Name string
	// Prefix is the records' key prefix; Key, when set, is the one record's
	// key instead.
	Prefix, Key string
	// Type is the current code's type of the record.
	Type reflect.Type
	// Sites are the functions of this package that write a record of the
	// kind back: TestRollbackFloorRewrittenKindsAreDeclared fails on a
	// rewrite anywhere else.
	Sites []string
	// Sets are the fields the rewrite itself replaces (a job transaction's
	// revision and updated stamp): the only ones the current code's own
	// rewrite may drop or change.
	Sets []string
}

// rewrittenRecordKinds are every record kind the registry rewrites. Records
// created once and never written again (owners, machines, projects, history,
// evidence, index entries, dedupe keys) are not rewritten, so no floor can
// drop their fields.
var rewrittenRecordKinds = []rewrittenKind{
	{Name: "job", Prefix: jobsPrefix, Type: reflect.TypeFor[Job](), Sites: []string{"commit"}, Sets: []string{"revision", "updated"}},
	{Name: "resource_event", Prefix: resourceEventsPrefix, Type: reflect.TypeFor[ResourceEvent](), Sites: []string{"applyPending"}},
	{Name: "artifact_manifest", Prefix: artifactsPrefix, Type: reflect.TypeFor[ArtifactManifest](), Sites: []string{"CheckHubArtifacts"}},
	{Name: "resource_index_ready", Key: resourceIndexReady, Type: reflect.TypeFor[indexReady](), Sites: []string{"RebuildResourceIndex"}, Sets: []string{"at"}},
}

// acceptedFloorDrop is a field a floor's rewrite is known to drop or change,
// and why that is safe.
type acceptedFloorDrop struct {
	// Kind is a rewrittenRecordKinds name.
	Kind string
	// Path is the field's path in the current type: map entries are "*" and
	// slice elements "[]", as in "proposals.*.decision.verdict".
	Path string
	// Floors are exactly the floors that drop it.
	Floors []string
	// Why losing the field on a rollback and roll forward is safe.
	Why string
	// Ticket is the ticket that accepted the loss.
	Ticket string
}

// acceptedFloorDrops are the reviewed losses. Each entry must still happen on
// every floor it names, so the list cannot go stale.
var acceptedFloorDrops = []acceptedFloorDrop{
	{
		Kind: "resource_event", Path: "reporter_job_id", Floors: []string{"txe-v2.18.2-17"}, Ticket: "TXE-7559",
		Why: "added by TXE-3993 after -17. A pending event -17 rewrites loses the reporting job; when the current code applies it " +
			"after a roll forward, an observer-relative observation then names no reporting job and changes no job's availability " +
			"(notTheObserver). The loss fails closed: no job is changed on another job's credential, and the next check reports again.",
	},
	{
		Kind: "resource_event", Path: "reporter_job_version", Floors: []string{"txe-v2.18.2-17"}, Ticket: "TXE-7559",
		Why: "added with reporter_job_id by TXE-3993 and read only with it; losing it with reporter_job_id fails closed the same way.",
	},
}

// plantedField is the field the negative case plants on the floor's copy
// only. No type has it, so the current code never writes it and every floor
// drops it.
const plantedField = "zz_planted_txe7559"

// plantedPaths are where the negative case plants it, by kind: every rewrite
// must report each one.
var plantedPaths = map[string][]string{
	"job":                  {plantedField, "proposals.*." + plantedField},
	"resource_event":       {plantedField},
	"artifact_manifest":    {"artifacts[]." + plantedField},
	"resource_index_ready": {plantedField},
}

// rewriteSnapshot is a store's rewritten records, decoded generically, by key.
type rewriteSnapshot map[string]any

// floorDrop is one field a floor's rewrite lost.
type floorDrop struct {
	Kind, Path, Record, Change string
}

func (d floorDrop) String() string {
	return fmt.Sprintf("%s %s %s (record %s)", d.Kind, d.Path, d.Change, d.Record)
}

// kindOf returns the rewritten kind a key belongs to.
func kindOf(key string) (rewrittenKind, bool) {
	for _, k := range rewrittenRecordKinds {
		if (k.Key != "" && key == k.Key) || (k.Prefix != "" && strings.HasPrefix(key, k.Prefix)) {
			return k, true
		}
	}
	return rewrittenKind{}, false
}

// openRewriteStore opens the store under dir with a fixed clock.
func openRewriteStore(t *testing.T, dir string, now time.Time) *fixture {
	t.Helper()
	f := &fixture{t: t, ctx: context.Background(), now: now}
	f.dagsDir = filepath.Join(dir, "dags")
	f.dags = NewDAGStore(persis.NewDAGRepository(dag.NewStore(f.dagsDir), persis.DAGRepositoryOptions{}))
	s, err := NewFileStore(filepath.Join(dir, "data"), WithClock(f.clock), WithDAGStore(f.dags))
	require.NoError(t, err)
	f.store = s
	return f
}

// listKeys lists every key under prefix.
func listKeys(ctx context.Context, col persis.Collection, prefix string) ([]string, error) {
	var keys []string
	cursor := ""
	for {
		page, err := col.List(ctx, persis.ListQuery{Prefix: prefix, Cursor: cursor, Limit: 500})
		if err != nil {
			return nil, err
		}
		for _, rec := range page.Records {
			keys = append(keys, rec.ID)
		}
		if page.NextCursor == "" {
			return keys, nil
		}
		cursor = page.NextCursor
	}
}

// snapshotRewritten reads every rewritten record of the store under dir.
func snapshotRewritten(t *testing.T, dir string) rewriteSnapshot {
	t.Helper()
	f := openRewriteStore(t, dir, time.Time{})
	snap := rewriteSnapshot{}
	for _, k := range rewrittenRecordKinds {
		keys := []string{k.Key}
		if k.Key == "" {
			var err error
			keys, err = listKeys(f.ctx, f.store.col, k.Prefix)
			require.NoError(t, err)
		}
		for _, key := range keys {
			rec, err := f.store.col.Get(f.ctx, key)
			require.NoError(t, err, key)
			var v any
			require.NoError(t, json.Unmarshal(rec.Data, &v), key)
			snap[key] = v
		}
	}
	return snap
}

// rewriteRoundTrip decodes every record under prefix into T and writes it
// back, the way the registry's compare-and-swap rewrites do.
func rewriteRoundTrip[T any](f *fixture, prefix string, res map[string]string) {
	keys, err := listKeys(f.ctx, f.store.col, prefix)
	if err != nil {
		res[prefix] = "ERR list: " + err.Error()
		return
	}
	for _, key := range keys {
		res[key] = func() string {
			rec, err := f.store.col.Get(f.ctx, key)
			if err != nil {
				return "ERR get: " + err.Error()
			}
			var v T
			if err := json.Unmarshal(rec.Data, &v); err != nil {
				return "ERR decode: " + err.Error()
			}
			data, err := json.Marshal(&v)
			if err != nil {
				return "ERR encode: " + err.Error()
			}
			if err := f.store.col.CompareAndSwap(f.ctx, key, rec.Data, data); err != nil {
				return "ERR write: " + err.Error()
			}
			return "ok"
		}()
	}
}

// rewriteCurrent rewrites, with the current code, every rewritten record of
// the store under dir, exactly as testdata/rollbackfloor's floorReaderRewrite
// does with a floor's.
func rewriteCurrent(t *testing.T, dir string, now time.Time) map[string]string {
	t.Helper()
	f := openRewriteStore(t, dir, now)
	res := map[string]string{}
	keys, err := listKeys(f.ctx, f.store.col, jobsPrefix)
	require.NoError(t, err)
	for _, key := range keys {
		_, err := f.tx(strings.TrimPrefix(key, jobsPrefix), agent, func(tx *JobTx) error { tx.touch(); return nil })
		res[key] = floorResult(err)
	}
	rewriteRoundTrip[ResourceEvent](f, resourceEventsPrefix, res)
	rewriteRoundTrip[ArtifactManifest](f, artifactsPrefix, res)
	res[resourceIndexReady] = floorResult(f.store.RebuildResourceIndex(f.ctx))
	return res
}

func floorResult(err error) string {
	if err == nil {
		return "ok"
	}
	return fmt.Sprintf("ERR %s: %v", ErrorCode(err), err)
}

// fillAll sets every exported JSON field reachable from v to a non-zero
// value: one element in every slice, one entry in every map. A type already
// being filled further up is left zero, so recursive types end.
func fillAll(v reflect.Value, at time.Time, filling map[reflect.Type]bool) {
	t := v.Type()
	switch {
	case t == reflect.TypeFor[time.Time]():
		v.Set(reflect.ValueOf(at))
		return
	case t == reflect.TypeFor[json.RawMessage]():
		v.Set(reflect.ValueOf(json.RawMessage(`{"filled":true}`)))
		return
	}
	switch t.Kind() { //nolint:exhaustive // every other kind is left zero; the field check catches a field that goes missing.
	case reflect.Pointer:
		if filling[t.Elem()] {
			return
		}
		p := reflect.New(t.Elem())
		fillAll(p.Elem(), at, filling)
		v.Set(p)
	case reflect.Struct:
		filling[t] = true
		defer delete(filling, t)
		for i := range t.NumField() {
			if f := t.Field(i); f.IsExported() && f.Tag.Get("json") != "-" {
				fillAll(v.Field(i), at, filling)
			}
		}
	case reflect.Slice:
		if filling[t.Elem()] {
			return
		}
		s := reflect.MakeSlice(t, 1, 1)
		fillAll(s.Index(0), at, filling)
		v.Set(s)
	case reflect.Map:
		if filling[t.Elem()] {
			return
		}
		m := reflect.MakeMapWithSize(t, 1)
		key := reflect.New(t.Key()).Elem()
		fillAll(key, at, filling)
		val := reflect.New(t.Elem()).Elem()
		fillAll(val, at, filling)
		m.SetMapIndex(key, val)
		v.Set(m)
	case reflect.String:
		v.SetString("x")
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(1)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(1)
	default:
		// Left zero: TestRollbackFloorSyntheticRecordsCarryEveryField fails
		// if a field of such a kind goes missing from the record.
	}
}

// schemaPaths lists every field path of t, in acceptedFloorDrop's form. A
// type met again further down is not walked again.
func schemaPaths(t reflect.Type, prefix string, walking map[reflect.Type]bool, out map[string]bool) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch {
	case t == reflect.TypeFor[time.Time](), t == reflect.TypeFor[json.RawMessage]():
		return
	}
	switch t.Kind() { //nolint:exhaustive // every other kind is a leaf.
	case reflect.Struct:
		if walking[t] {
			return
		}
		walking[t] = true
		defer delete(walking, t)
		for f := range t.Fields() {
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if !f.IsExported() || name == "-" {
				continue
			}
			if name == "" {
				name = f.Name
			}
			p := joinPath(prefix, name)
			out[p] = true
			schemaPaths(f.Type, p, walking, out)
		}
	case reflect.Slice, reflect.Array:
		schemaPaths(t.Elem(), prefix+"[]", walking, out)
	case reflect.Map:
		schemaPaths(t.Elem(), joinPath(prefix, "*"), walking, out)
	default:
		// A leaf.
	}
}

func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

// jsonPaths lists every field path of a decoded record, in schema form, using
// t to tell a map's keys from a struct's fields.
func jsonPaths(t reflect.Type, v any, prefix string, out map[string]bool) {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			seg, ct := descend(t, k)
			p := joinPath(prefix, seg)
			out[p] = true
			jsonPaths(ct, child, p, out)
		}
	case []any:
		var et reflect.Type
		if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) && t != reflect.TypeFor[json.RawMessage]() {
			et = t.Elem()
		}
		for _, child := range x {
			jsonPaths(et, child, prefix+"[]", out)
		}
	}
}

// descend returns the schema segment of key under t and the type below it;
// a key t does not know keeps its name and has no type.
func descend(t reflect.Type, key string) (string, reflect.Type) {
	if t == nil || t == reflect.TypeFor[json.RawMessage]() {
		return key, nil
	}
	switch t.Kind() { //nolint:exhaustive // every other kind is a leaf.
	case reflect.Map:
		return "*", t.Elem()
	case reflect.Struct:
		for f := range t.Fields() {
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			if name == "" {
				name = f.Name
			}
			if f.IsExported() && name == key {
				return key, f.Type
			}
		}
	default:
		// A leaf has no fields.
	}
	return key, nil
}

// schemaOf converts a concrete path (map keys, slice indexes) to schema form.
func schemaOf(t reflect.Type, path []string) string {
	out := ""
	for _, seg := range path {
		for t != nil && t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		if strings.HasPrefix(seg, "[") {
			out += "[]"
			if t != nil && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) && t != reflect.TypeFor[json.RawMessage]() {
				t = t.Elem()
			} else {
				t = nil
			}
			continue
		}
		var s string
		s, t = descend(t, seg)
		out = joinPath(out, s)
	}
	return out
}

type fieldDiff struct {
	Path   []string
	Change string // "dropped" or "changed"
}

func (d fieldDiff) id() string { return strings.Join(d.Path, "\x00") + "\x00" + d.Change }

// diffJSON lists every field of before that after lacks or holds differently.
// A field only after has is not a loss and is not listed.
func diffJSON(path []string, before, after any, out *[]fieldDiff) {
	switch b := before.(type) {
	case map[string]any:
		a, ok := after.(map[string]any)
		if !ok {
			*out = append(*out, fieldDiff{Path: slices.Clone(path), Change: "changed"})
			return
		}
		for _, k := range sortedKeys(b) {
			p := append(slices.Clone(path), k)
			av, ok := a[k]
			if !ok {
				*out = append(*out, fieldDiff{Path: p, Change: "dropped"})
				continue
			}
			diffJSON(p, b[k], av, out)
		}
	case []any:
		a, ok := after.([]any)
		if !ok {
			*out = append(*out, fieldDiff{Path: slices.Clone(path), Change: "changed"})
			return
		}
		for i := range b {
			p := append(slices.Clone(path), "["+strconv.Itoa(i)+"]")
			if i >= len(a) {
				*out = append(*out, fieldDiff{Path: p, Change: "dropped"})
				continue
			}
			diffJSON(p, b[i], a[i], out)
		}
	default:
		if !reflect.DeepEqual(before, after) {
			*out = append(*out, fieldDiff{Path: slices.Clone(path), Change: "changed"})
		}
	}
}

// floorRewriteDrops compares a floor's rewrite with the current code's. before
// is the store the floor rewrote and floor the floor's rewrite of it; base is
// the store the current code rewrote, without anything planted, and current
// that rewrite. A difference the current code's rewrite makes to its own
// input too is the transaction's own (revision, updated stamp) and is not a
// loss; one it does not make is. It returns the losses and the problems that
// are not losses (a record lost, a rewrite that failed).
func floorRewriteDrops(before, floor, base, current rewriteSnapshot, results map[string]string) ([]floorDrop, []string) {
	var drops []floorDrop
	var problems []string
	for _, key := range sortedKeys(results) {
		if !strings.HasPrefix(results[key], "ok") {
			problems = append(problems, fmt.Sprintf("rewrite of %s failed: %s", key, results[key]))
		}
	}
	for _, key := range sortedKeys(before) {
		kind, ok := kindOf(key)
		if !ok {
			problems = append(problems, "record "+key+" is of no rewritten kind")
			continue
		}
		if _, rewritten := results[key]; !rewritten {
			problems = append(problems, "record "+key+" was not rewritten")
		}
		after, ok := floor[key]
		if !ok {
			problems = append(problems, "record "+key+" is gone after the rewrite")
			continue
		}
		excused := map[string]bool{}
		var cur []fieldDiff
		diffJSON(nil, base[key], current[key], &cur)
		for _, d := range cur {
			excused[d.id()] = true
		}
		var got []fieldDiff
		diffJSON(nil, before[key], after, &got)
		for _, d := range got {
			if !excused[d.id()] {
				drops = append(drops, floorDrop{Kind: kind.Name, Path: schemaOf(kind.Type, d.Path), Record: key, Change: d.Change})
			}
		}
	}
	return drops, problems
}

// unacceptedDrops removes the losses acceptedFloorDrops names for floor, and
// reports each entry naming floor that did not happen.
func unacceptedDrops(floor string, drops []floorDrop, accepted []acceptedFloorDrop) (left []floorDrop, stale []string) {
	seen := map[int]bool{}
	for _, d := range drops {
		i := slices.IndexFunc(accepted, func(a acceptedFloorDrop) bool {
			return a.Kind == d.Kind && a.Path == d.Path && slices.Contains(a.Floors, floor)
		})
		if i < 0 {
			left = append(left, d)
			continue
		}
		seen[i] = true
	}
	for i, a := range accepted {
		if slices.Contains(a.Floors, floor) && !seen[i] {
			stale = append(stale, fmt.Sprintf("accepted loss %s %s (%s) no longer happens on %s: remove %s from its Floors", a.Kind, a.Path, a.Ticket, floor, floor))
		}
	}
	return left, stale
}

// dropProblems renders the losses no entry accepts, one per field.
func dropProblems(floor string, left []floorDrop) []string {
	byField := map[string]floorDrop{}
	for _, d := range left {
		if _, ok := byField[d.Kind+" "+d.Path]; !ok {
			byField[d.Kind+" "+d.Path] = d
		}
	}
	var problems []string
	for _, k := range sortedKeys(byField) {
		problems = append(problems, fmt.Sprintf("%s: rewrite loses %s: make the floor keep it, or add it to acceptedFloorDrops "+
			"with why losing it on rollback is safe and the ticket that accepts it", floor, byField[k]))
	}
	return problems
}

func dropFields(drops []floorDrop) []string {
	set := map[string]bool{}
	for _, d := range drops {
		set[d.Kind+" "+d.Path] = true
	}
	return sortedKeys(set)
}

// checkAcceptedFloorDrops checks each entry is reviewed and well formed.
func checkAcceptedFloorDrops(accepted []acceptedFloorDrop, floors []rollbackFloor) []string {
	var problems []string
	names := map[string]bool{}
	for _, f := range floors {
		names[f.Name] = true
	}
	seen := map[string]bool{}
	for _, a := range accepted {
		id := a.Kind + " " + a.Path
		kind := slices.IndexFunc(rewrittenRecordKinds, func(k rewrittenKind) bool { return k.Name == a.Kind })
		switch {
		case kind < 0:
			problems = append(problems, id+": no rewritten kind "+a.Kind)
		case !schemaPathKnown(rewrittenRecordKinds[kind].Type, a.Path):
			problems = append(problems, id+": the current type has no such field")
		}
		if seen[id] {
			problems = append(problems, id+": listed twice")
		}
		seen[id] = true
		if strings.TrimSpace(a.Why) == "" {
			problems = append(problems, id+": says not why losing it is safe")
		}
		if !strings.HasPrefix(a.Ticket, "TXE-") {
			problems = append(problems, id+": names no accepting ticket")
		}
		if len(a.Floors) == 0 {
			problems = append(problems, id+": names no floor")
		}
		for _, f := range a.Floors {
			if !names[f] {
				problems = append(problems, id+": "+f+" is not a rollback floor")
			}
		}
	}
	return problems
}

func schemaPathKnown(t reflect.Type, path string) bool {
	all := map[string]bool{}
	schemaPaths(t, "", map[reflect.Type]bool{}, all)
	return all[path]
}

// syntheticRecords returns one record of each rewritten kind with every field
// of the current type set, by key. The job's one version is versionRef, a
// real version record, so the floors' RebuildResourceIndex reads it.
func syntheticRecords(t *testing.T, at time.Time, versionRef string) map[string]any {
	t.Helper()
	jobID, err := NewID(PrefixJob, at)
	require.NoError(t, err)
	out := map[string]any{}
	for _, k := range rewrittenRecordKinds {
		v := reflect.New(k.Type)
		fillAll(v.Elem(), at, map[reflect.Type]bool{})
		key := k.Key
		switch rec := v.Interface().(type) {
		case *Job:
			rec.JobID = jobID
			rec.Version, rec.VersionRefs = 1, []string{versionRef}
			key = jobsPrefix + jobID
		case *ResourceEvent:
			id, err := NewID(PrefixEvent, at)
			require.NoError(t, err)
			rec.EventID = id
			key = resourceEventsPrefix + id
		case *ArtifactManifest:
			rec.JobID = jobID
			key = artifactKey(jobID, "run-synthetic", "execution-synthetic")
		}
		require.NotEmpty(t, key, "kind %s: the synthetic record has no key", k.Name)
		out[key] = v.Interface()
	}
	return out
}

// writeSyntheticRecords writes the synthetic records into the store under
// dir, whose jobs give the synthetic job its version.
func writeSyntheticRecords(t *testing.T, dir string, at time.Time) {
	t.Helper()
	f := openRewriteStore(t, dir, time.Time{})
	jobs, err := f.store.ListJobs(f.ctx, JobFilter{})
	require.NoError(t, err)
	require.NotEmpty(t, jobs, "the synthetic job takes a real job's version")
	recs := syntheticRecords(t, at, jobs[0].VersionRefs[0])
	for _, key := range sortedKeys(recs) {
		data, err := json.Marshal(recs[key])
		require.NoError(t, err)
		require.NoError(t, f.store.col.Put(f.ctx, &persis.Record{ID: key, Data: data}), key)
	}
}

// plantFields adds plantedField at every plantedPaths path of every
// rewritten record of the store under dir.
func plantFields(t *testing.T, dir string) {
	t.Helper()
	f := openRewriteStore(t, dir, time.Time{})
	planted := map[string]int{}
	for key, v := range snapshotRewritten(t, dir) {
		kind, _ := kindOf(key)
		for _, p := range plantedPaths[kind.Name] {
			planted[kind.Name+" "+p] += plantAt(kind.Type, v, strings.TrimSuffix(strings.TrimSuffix(p, plantedField), "."), "")
		}
		data, err := json.Marshal(v)
		require.NoError(t, err)
		require.NoError(t, f.store.col.Put(f.ctx, &persis.Record{ID: key, Data: data}), key)
	}
	for kind, paths := range plantedPaths {
		for _, p := range paths {
			require.Positive(t, planted[kind+" "+p], "no %s record has %s to plant under", kind, p)
		}
	}
}

// plantAt sets plantedField in every object of v at schema path parent
// (relative to prefix) and returns how many it set.
func plantAt(t reflect.Type, v any, parent, prefix string) int {
	n := 0
	if prefix == parent {
		if m, ok := v.(map[string]any); ok {
			m[plantedField] = "planted"
			n++
		}
	}
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if k == plantedField {
				continue
			}
			seg, ct := descend(t, k)
			n += plantAt(ct, child, parent, joinPath(prefix, seg))
		}
	case []any:
		var et reflect.Type
		if t != nil && t.Kind() == reflect.Slice {
			et = t.Elem()
		}
		for _, child := range x {
			n += plantAt(et, child, parent, prefix+"[]")
		}
	}
	return n
}

// Every function that writes back a record it read is a declared rewrite
// site of a rewritten kind, so a new rewrite is compared from its first
// commit.
func TestRollbackFloorRewrittenKindsAreDeclared(t *testing.T) {
	declared := map[string]bool{}
	for _, k := range rewrittenRecordKinds {
		for _, s := range k.Sites {
			declared[s] = true
		}
	}
	found := map[string]bool{}
	fset := token.NewFileSet()
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Name.Name == "putJSON" {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				var name string
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					name = fun.Sel.Name
				case *ast.Ident:
					name = fun.Name
				}
				switch name {
				case "CompareAndSwap", "putJSON", "Put":
					found[fn.Name.Name] = true
					if !declared[fn.Name.Name] {
						t.Errorf("%s: %s rewrites a record (%s) and is no rewrittenRecordKinds site: declare the kind, or add the site to its kind", fset.Position(call.Pos()), fn.Name.Name, name)
					}
				}
				return true
			})
		}
	}
	for _, s := range sortedKeys(declared) {
		require.True(t, found[s], "rewrittenRecordKinds names site %s, which rewrites nothing", s)
	}
}

// The synthetic records carry every field of the current types, so no field
// escapes the comparison for want of a fixture that sets it.
func TestRollbackFloorSyntheticRecordsCarryEveryField(t *testing.T) {
	recs := syntheticRecords(t, time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC), "x")
	require.Len(t, recs, len(rewrittenRecordKinds))
	for key, rec := range recs {
		kind, ok := kindOf(key)
		require.True(t, ok, key)
		want := map[string]bool{}
		schemaPaths(kind.Type, "", map[reflect.Type]bool{}, want)
		b, err := json.Marshal(rec)
		require.NoError(t, err)
		var v any
		require.NoError(t, json.Unmarshal(b, &v))
		got := map[string]bool{}
		jsonPaths(kind.Type, v, "", got)
		var missing []string
		for _, p := range sortedKeys(want) {
			if !got[p] {
				missing = append(missing, p)
			}
		}
		require.Empty(t, missing, "kind %s: the synthetic record lacks these fields: make fillAll set them", kind.Name)
	}
}

// The current code's own rewrite keeps every field of every record, and
// changes only the fields the rewrite sets, so the comparison's baseline
// loses nothing.
func TestRollbackFloorCurrentRewriteKeepsEveryField(t *testing.T) {
	dir := t.TempDir()
	_, f := writeRollbackFloorFixture(t, dir)
	writeSyntheticRecords(t, dir, f.clock())
	before := snapshotRewritten(t, dir)
	res := rewriteCurrent(t, dir, f.clock())
	after := snapshotRewritten(t, dir)
	var dropped []string
	for key := range before {
		var diffs []fieldDiff
		diffJSON(nil, before[key], after[key], &diffs)
		for _, d := range diffs {
			kind, _ := kindOf(key)
			path := schemaOf(kind.Type, d.Path)
			if !slices.ContainsFunc(kind.Sets, func(set string) bool { return path == set || strings.HasPrefix(path, set+".") }) {
				dropped = append(dropped, key+" "+path+" "+d.Change)
			}
		}
	}
	for _, key := range sortedKeys(res) {
		require.Equal(t, "ok", res[key], key)
	}
	require.Empty(t, dropped)
}

// Every reviewed loss names a known kind, an existing field, the floors, why
// it is safe and the accepting ticket.
func TestAcceptedFloorDropsAreReviewed(t *testing.T) {
	require.Empty(t, checkAcceptedFloorDrops(acceptedFloorDrops, rollbackFloors))
}

// The rewrite checks fail on each way a floor's rewrite can lose data.
// Synthetic snapshots; the real ones come from the floor readers.
func TestRollbackFloorRewriteChecksRefuse(t *testing.T) {
	key := jobsPrefix + "job_x"
	before := rewriteSnapshot{key: map[string]any{"revision": 1.0, "job_id": "job_x",
		"proposals": map[string]any{"prp_1": map[string]any{"state": "decided", "question": "q"}}}}
	current := rewriteSnapshot{key: map[string]any{"revision": 2.0, "job_id": "job_x",
		"proposals": map[string]any{"prp_1": map[string]any{"state": "decided", "question": "q"}}}}
	ok := map[string]string{key: "ok"}

	drops, problems := floorRewriteDrops(before, current, before, current, ok)
	require.Empty(t, drops, "the transaction's own change is not a loss")
	require.Empty(t, problems)

	lost := rewriteSnapshot{key: map[string]any{"revision": 2.0, "job_id": "job_x",
		"proposals": map[string]any{"prp_1": map[string]any{"state": "decided"}}}}
	drops, _ = floorRewriteDrops(before, lost, before, current, ok)
	require.Equal(t, []string{"job proposals.*.question"}, dropFields(drops), "a dropped nested field")

	changed := rewriteSnapshot{key: map[string]any{"revision": 2.0, "job_id": "job_y",
		"proposals": map[string]any{"prp_1": map[string]any{"state": "decided", "question": "q"}}}}
	drops, _ = floorRewriteDrops(before, changed, before, current, ok)
	require.Len(t, drops, 1, "a changed field")
	require.Equal(t, "changed", drops[0].Change)

	planted := rewriteSnapshot{key: map[string]any{"revision": 1.0, "job_id": "job_x", plantedField: "planted",
		"proposals": map[string]any{"prp_1": map[string]any{"state": "decided", "question": "q"}}}}
	drops, _ = floorRewriteDrops(planted, current, before, current, ok)
	require.Equal(t, []string{"job " + plantedField}, dropFields(drops), "a planted field the floor drops, though the current code's rewrite of its own input never had it")

	_, problems = floorRewriteDrops(before, rewriteSnapshot{}, before, current, ok)
	require.NotEmpty(t, problems, "a record gone")
	_, problems = floorRewriteDrops(before, current, before, current, map[string]string{key: "ERR invalid: no"})
	require.NotEmpty(t, problems, "a rewrite that failed")
	_, problems = floorRewriteDrops(before, current, before, current, map[string]string{})
	require.NotEmpty(t, problems, "a record not rewritten")

	accepted := []acceptedFloorDrop{{Kind: "job", Path: "proposals.*.question", Floors: []string{"f1"}, Why: "safe", Ticket: "TXE-0"}}
	drops, _ = floorRewriteDrops(before, lost, before, current, ok)
	left, stale := unacceptedDrops("f1", drops, accepted)
	require.Empty(t, left, "an accepted loss")
	require.Empty(t, stale)
	left, _ = unacceptedDrops("f2", drops, accepted)
	require.NotEmpty(t, dropProblems("f2", left), "a loss accepted for another floor only")
	_, stale = unacceptedDrops("f1", nil, accepted)
	require.NotEmpty(t, stale, "an accepted loss that no longer happens")

	floors := []rollbackFloor{{Name: "f1"}}
	good := acceptedFloorDrop{Kind: "job", Path: "proposals.*.question", Floors: []string{"f1"}, Why: "safe", Ticket: "TXE-0"}
	require.Empty(t, checkAcceptedFloorDrops([]acceptedFloorDrop{good}, floors))
	for name, mutate := range map[string]func(*acceptedFloorDrop){
		"no why":        func(a *acceptedFloorDrop) { a.Why = " " },
		"no ticket":     func(a *acceptedFloorDrop) { a.Ticket = "" },
		"no floor":      func(a *acceptedFloorDrop) { a.Floors = nil },
		"unknown floor": func(a *acceptedFloorDrop) { a.Floors = []string{"f9"} },
		"unknown kind":  func(a *acceptedFloorDrop) { a.Kind = "nope" },
		"unknown field": func(a *acceptedFloorDrop) { a.Path = "proposals.*.nope" },
	} {
		bad := good
		mutate(&bad)
		require.NotEmpty(t, checkAcceptedFloorDrops([]acceptedFloorDrop{bad}, floors), name)
	}
	require.NotEmpty(t, checkAcceptedFloorDrops([]acceptedFloorDrop{good, good}, floors), "listed twice")
}

// rewriteDirs are the stores each floor rewrites: the real one, and one with
// plantedField planted (the negative case).
type rewriteDirs struct {
	Real    string `json:"real"`
	Planted string `json:"planted"`
	// planted is the planted store before the floor rewrote it.
	planted rewriteSnapshot
}

// prepareRewriteStores copies the fixture under fixtureDir, adds the
// synthetic records, and rewrites one copy with the current code. It returns
// the store each floor's copies are made from, its snapshot, and the current
// code's rewrite of it.
func prepareRewriteStores(t *testing.T, fixtureDir string, now time.Time) (base string, before, current rewriteSnapshot) {
	t.Helper()
	base = t.TempDir()
	require.NoError(t, os.CopyFS(base, os.DirFS(fixtureDir)))
	writeSyntheticRecords(t, base, now)
	before = snapshotRewritten(t, base)
	cur := t.TempDir()
	require.NoError(t, os.CopyFS(cur, os.DirFS(base)))
	for key, res := range rewriteCurrent(t, cur, now) {
		require.Equal(t, "ok", res, "the current code's rewrite of %s", key)
	}
	return base, before, snapshotRewritten(t, cur)
}

// floorRewriteCopies makes the floor's two copies of base: the real one, and
// the planted one.
func floorRewriteCopies(t *testing.T, base string) rewriteDirs {
	t.Helper()
	d := rewriteDirs{Real: t.TempDir(), Planted: t.TempDir()}
	require.NoError(t, os.CopyFS(d.Real, os.DirFS(base)))
	require.NoError(t, os.CopyFS(d.Planted, os.DirFS(base)))
	plantFields(t, d.Planted)
	d.planted = snapshotRewritten(t, d.Planted)
	return d
}

// checkFloorRewrites checks a floor's rewrites: on the real store, every loss
// must be accepted and every accepted loss must happen; on the planted store,
// exactly the planted fields are the unaccepted losses, which proves the
// check fails when a floor drops a field the current code writes.
func checkFloorRewrites(t *testing.T, floor string, dirs rewriteDirs, before, current rewriteSnapshot, results map[string]map[string]string) {
	t.Helper()
	drops, problems := floorRewriteDrops(before, snapshotRewritten(t, dirs.Real), before, current, results["real"])
	left, stale := unacceptedDrops(floor, drops, acceptedFloorDrops)
	problems = append(problems, stale...)
	problems = append(problems, dropProblems(floor, left)...)
	for _, field := range dropFields(drops) {
		t.Logf("%s rewrite loses %s", floor, field)
	}
	require.Empty(t, problems, "%s: rewrite of the current code's records", floor)

	drops, problems = floorRewriteDrops(dirs.planted, snapshotRewritten(t, dirs.Planted), before, current, results["planted"])
	require.Empty(t, problems, "%s: rewrite of the planted records", floor)
	left, _ = unacceptedDrops(floor, drops, acceptedFloorDrops)
	var want []string
	for kind, paths := range plantedPaths {
		for _, p := range paths {
			want = append(want, kind+" "+p)
		}
	}
	sort.Strings(want)
	require.Equal(t, want, dropFields(left), "%s: the planted fields are exactly the losses the check reports", floor)
}
