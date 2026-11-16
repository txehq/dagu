// The rollback floor reader (TXE-7557). TestRollbackFloorReadersReadCurrentRecords
// copies this file into the registry package of each rollback floor's tree,
// extracted at its pinned commit, and runs it there over a COPY of a
// temporary store the current code wrote. It compiles only against a floor's
// registry code and its test helpers, never the current ones: testdata is
// never built here.
//
// It drives the floor's own paths over every record and reports each one's
// outcome and the floor's strict parameter fields; it asserts nothing about
// the outcomes. The current code's test compares them with the declared
// contract.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/file/dag"
)

type floorReaderJob struct {
	Record       string          `json:"record"`
	Scenario     string          `json:"scenario"`
	JobID        string          `json:"job_id"`
	RunID        string          `json:"run_id"`
	ProposalID   string          `json:"proposal_id"`
	DecisionID   string          `json:"decision_id"`
	ActionID     string          `json:"action_id"`
	GrantID      string          `json:"grant_id"`
	ClaimID      string          `json:"claim_id"`
	Fence        int64           `json:"fence"`
	EscalationID string          `json:"escalation_id"`
	Version      int             `json:"version"`
	Package      string          `json:"package"`
	Spec         string          `json:"spec"`
	Params       json.RawMessage `json:"params"`
	Binding      string          `json:"binding"`
}

type floorReaderManifest struct {
	Now      time.Time                 `json:"now"`
	Owner    string                    `json:"owner"`
	Machine  string                    `json:"machine"`
	Project  string                    `json:"project"`
	Jobs     []floorReaderJob          `json:"jobs"`
	Attempts map[string]RunAttempt     `json:"attempts"`
	Retries  map[string]RetryExecution `json:"retries"`
}

func floorReaderResult(err error) string {
	if err == nil {
		return "ok"
	}
	return fmt.Sprintf("ERR %s: %v", ErrorCode(err), err)
}

func floorReaderFields(t reflect.Type) []string {
	var names []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
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

// floorReaderPreserved reports whether the proposal the current code wrote
// still carries the same parameters and binding after the floor worked on
// the job, on the job or in its archive.
func floorReaderPreserved(f *fixture, j floorReaderJob) string {
	job, err := f.store.GetJob(f.ctx, j.JobID)
	if err != nil {
		return floorReaderResult(err)
	}
	p, where := job.Proposals[j.ProposalID], "job"
	if p == nil {
		archived, err := f.store.ListArchivedProposals(f.ctx, j.JobID, 0)
		if err != nil {
			return floorReaderResult(err)
		}
		for _, a := range archived {
			if a.ProposalID == j.ProposalID {
				p, where = a, "archive"
				break
			}
		}
	}
	if p == nil {
		return "LOST: proposal " + j.ProposalID + " is on neither the job nor the archive"
	}
	var got, want any
	if err := json.Unmarshal(p.Action.Params, &got); err != nil {
		return "LOST: unreadable params: " + err.Error()
	}
	if err := json.Unmarshal(j.Params, &want); err != nil {
		return "LOST: unreadable manifest params: " + err.Error()
	}
	switch {
	case !reflect.DeepEqual(got, want):
		return fmt.Sprintf("CHANGED: params %s, written %s (%s)", p.Action.Params, j.Params, where)
	case p.BindingDigest != j.Binding:
		return fmt.Sprintf("CHANGED: binding %s, written %s (%s)", p.BindingDigest, j.Binding, where)
	}
	return "ok (" + where + ", " + string(p.State) + ")"
}

func TestRollbackFloorReader(t *testing.T) {
	in, out := os.Getenv("DAGU_ROLLBACK_FLOOR_IN"), os.Getenv("DAGU_ROLLBACK_FLOOR_OUT")
	if in == "" || out == "" {
		t.Skip("run by the current code's TestRollbackFloorReadersReadCurrentRecords")
	}
	b, err := os.ReadFile(filepath.Join(in, "manifest.json"))
	require.NoError(t, err)
	var man floorReaderManifest
	require.NoError(t, json.Unmarshal(b, &man))

	f := &fixture{t: t, ctx: context.Background(), now: man.Now, owner: man.Owner, machine: man.Machine, project: man.Project}
	f.dagsDir = filepath.Join(in, "dags")
	f.dags = NewDAGStore(persis.NewDAGRepository(dag.NewStore(f.dagsDir), persis.DAGRepositoryOptions{}))
	s, err := NewFileStore(filepath.Join(in, "data"), WithClock(f.clock), WithDAGStore(f.dags))
	require.NoError(t, err, "the floor's store opens the current code's directory")
	f.store = s
	rc := withRuns(f)
	rc.attempts, rc.retries = man.Attempts, man.Retries
	if rc.attempts == nil {
		rc.attempts = map[string]RunAttempt{}
	}
	if rc.retries == nil {
		rc.retries = map[string]RetryExecution{}
	}

	results := map[string]map[string]string{}
	store := map[string]string{}
	results["store"] = store
	_, err = f.store.GetOwner(f.ctx, man.Owner)
	store["get_owner"] = floorReaderResult(err)
	_, err = f.store.GetProject(f.ctx, man.Project)
	store["get_project"] = floorReaderResult(err)
	_, err = f.store.GetMachine(f.ctx, man.Machine)
	store["get_machine"] = floorReaderResult(err)
	_, err = f.store.ListMachines(f.ctx, man.Owner)
	store["list_machines"] = floorReaderResult(err)
	jobs, err := f.store.ListJobs(f.ctx, JobFilter{OwnerID: man.Owner})
	store["list_jobs"] = floorReaderResult(err)
	if err == nil && len(jobs) != len(man.Jobs) {
		store["list_jobs"] = fmt.Sprintf("LOST: listed %d jobs, the store has %d", len(jobs), len(man.Jobs))
	}
	store["rebuild_resource_index"] = floorReaderResult(f.store.RebuildResourceIndex(f.ctx))

	for _, j := range man.Jobs {
		res := map[string]string{}
		results[j.Record] = res

		_, err := f.store.GetJob(f.ctx, j.JobID)
		res["1_get_job"] = floorReaderResult(err)
		_, err = f.store.GetVersion(f.ctx, j.JobID, j.Version)
		res["2_get_version"] = floorReaderResult(err)
		_, err = f.store.ListEvents(f.ctx, j.JobID, 0)
		res["2_list_events"] = floorReaderResult(err)
		_, err = f.store.ListDecisions(f.ctx, j.JobID, 0)
		res["2_list_decisions"] = floorReaderResult(err)
		_, err = f.store.ListReviews(f.ctx, j.JobID, 0)
		res["2_list_reviews"] = floorReaderResult(err)
		_, err = f.store.ListClosures(f.ctx, j.JobID, 0)
		res["2_list_closures"] = floorReaderResult(err)
		_, err = f.store.ListArchivedProposals(f.ctx, j.JobID, 0)
		res["2_list_archived_proposals"] = floorReaderResult(err)
		_, err = f.store.ListArchivedActions(f.ctx, j.JobID, 0)
		res["2_list_archived_actions"] = floorReaderResult(err)
		_, err = f.tx(j.JobID, agent, func(*JobTx) error { return nil })
		res["3_any_job_tx"] = floorReaderResult(err)
		_, err = f.store.EndMovedOnRetries(f.ctx, j.JobID)
		res["4_end_moved_on_retries"] = floorReaderResult(err)

		switch j.Scenario {
		case "decided":
			// The floor carries out the decision.
			_, err = f.tx(j.JobID, agent, func(tx *JobTx) error {
				ec, err := tx.AcquireClaim(ClaimExecution, Reviewer{MachineID: f.machine}, time.Hour)
				if err != nil {
					return err
				}
				actionID, err := ApprovedActionID(j.ProposalID, j.DecisionID)
				if err != nil {
					return err
				}
				_, err = tx.Authorize(EffectRequest{ActionID: actionID, JobVersion: j.Version, PackageDigest: j.Package,
					Approved: &ApprovedEffect{ProposalID: j.ProposalID, DecisionID: j.DecisionID, ClaimID: ec.ClaimID, Fence: ec.Fence}})
				return err
			})
			res["5_authorize_pending_decision"] = floorReaderResult(err)
		case "executing", "uncertain":
			// The floor settles the current code's action: its request
			// admitted a new execution (admittedRetry).
			job, gerr := f.store.GetJob(f.ctx, j.JobID)
			if gerr == nil && job.Actions[j.ActionID] != nil {
				a := job.Actions[j.ActionID]
				req, rerr := ir.NewRetryRequest(ir.NewDAGRunRef(j.JobID, j.RunID), "a1", "", a.ActionID, strconv.Itoa(a.Attempt), a.BindingDigest)
				require.NoError(t, rerr)
				rc.mu.Lock()
				rc.attempts[j.RunID] = RunAttempt{AttemptID: "a2", SpecSHA256: j.Spec, Status: "queued"}
				rc.retries[req.ID] = RetryExecution{Ref: ExecutionRef("a2", ""), Request: *req}
				rc.mu.Unlock()
			}
			_, err = f.tx(j.JobID, agent, func(tx *JobTx) error {
				_, err := tx.SettleAction(Settlement{ActionID: j.ActionID, GrantID: j.GrantID, ClaimID: j.ClaimID, Fence: j.Fence,
					State: ActionSucceeded, Receipt: ExecutionRef("a2", "")})
				return err
			})
			res["5_settle_"+j.Scenario+"_action"] = floorReaderResult(err)
		case "escalated":
			// A person answers the reviewer's question with retry.
			job, gerr := f.store.GetJob(f.ctx, j.JobID)
			switch {
			case gerr != nil:
				err = gerr
			case job.Proposals[j.EscalationID] == nil:
				err = fmt.Errorf("escalation %s is not on the job", j.EscalationID)
			default:
				_, err = decide(f, j.JobID, job.Proposals[j.EscalationID], VerdictRetry, ProposalDecided, "floor-"+j.Record)
			}
			res["5_answer_escalation_retry"] = floorReaderResult(err)
		}

		// A later person's retry on the SAME job, of another failed run.
		later := j.RunID + "-later"
		rc.mu.Lock()
		rc.attempts[later] = failedAttempt("b1", j.Spec)
		rc.mu.Unlock()
		_, err = f.tx(j.JobID, person, func(tx *JobTx) error {
			_, _, err := tx.ProposeRetry(RetryRunParams{RunID: later, AttemptID: "b1", RunSpecSHA256: j.Spec, PackageDigest: j.Package}, "later-"+j.Record)
			return err
		})
		res["6_later_person_retry_same_job"] = floorReaderResult(err)
		_, err = f.tx(j.JobID, agent, func(*JobTx) error { return nil })
		res["7_any_job_tx_after"] = floorReaderResult(err)
		res["8_params_and_binding_preserved"] = floorReaderPreserved(f, j)
	}

	rep := map[string]any{
		"fields": map[string][]string{
			ActionRetryRun:        floorReaderFields(reflect.TypeOf(RetryRunParams{})),
			ActionUncertainEffect: floorReaderFields(reflect.TypeOf(UncertainEffectParams{})),
		},
		"results": results,
	}
	b, err = json.MarshalIndent(rep, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(out, b, 0o600))
}
