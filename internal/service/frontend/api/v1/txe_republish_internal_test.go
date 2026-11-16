// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

func republishRefusalCode(t *testing.T, err error) string {
	t.Helper()
	var apiErr *Error
	require.True(t, errors.As(err, &apiErr), "%v", err)
	code, _ := apiErr.Details["code"].(string)
	return code
}

func republishExpectation() *persis.ExpectedExecution {
	return republishExpectationFor(nil)
}

// republishExpectationFor is the request made for action (its binding), or
// a fixed binding without one.
func republishExpectationFor(action *registry.Action) *persis.ExpectedExecution {
	binding := "bd1"
	if action != nil {
		binding = action.BindingDigest
	}
	return &persis.ExpectedExecution{AttemptID: "a1b2c3", QueuedAt: "",
		Request: &ir.RetryRequest{ActionID: "act_1", ActionAttempt: "1", BindingDigest: binding}}
}

// A request that asks to accept failed prerequisites is refused before
// anything is read unless it is a conditional retry, made for an action
// attempt, of the publish step alone.
func TestTxeRepublishShape(t *testing.T) {
	ok := republishExpectation()
	assert.NoError(t, txeRepublishShape("publish", "", false, false, ok))
	for name, err := range map[string]error{
		"another step":       txeRepublishShape("run", "", false, false, ok),
		"no step":            txeRepublishShape("", "", false, false, ok),
		"with downstream":    txeRepublishShape("publish", "", true, false, ok),
		"bypassing":          txeRepublishShape("publish", "", false, true, ok),
		"in a sub-DAG":       txeRepublishShape("publish", "sub-1", false, false, ok),
		"not conditional":    txeRepublishShape("publish", "", false, false, nil),
		"made for no action": txeRepublishShape("publish", "", false, false, &persis.ExpectedExecution{AttemptID: "a1b2c3"}),
	} {
		require.Error(t, err, name)
		assert.Equal(t, txeRepublishUnsupported, republishRefusalCode(t, err), name)
	}
}

var republishNow = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

// republishJob holds the decided proposal its actions carry out, as a job
// does while such an action is in flight.
var republishJob = &registry.Job{JobID: "job_1", Version: 3, PackageDigest: "sha256:pkg",
	Proposals: map[string]*registry.Proposal{"prp_1": {ProposalID: "prp_1", State: registry.ProposalDecided,
		Decision: &registry.Decision{DecisionID: "dec_1", ProposalID: "prp_1", Verdict: registry.VerdictRetry,
			Actor: registry.Actor{Kind: registry.ActorHuman, ID: "alice"}}}}}

func retryRunAction(params map[string]any) *registry.Action {
	raw, _ := json.Marshal(params)
	spec := registry.ActionSpec{Name: registry.ActionRetryRun, Params: raw}
	binding, _ := registry.BindingDigest(republishJob, spec)
	return &registry.Action{ActionID: "act_1", Attempt: 1, BindingDigest: binding, Kind: registry.ActionApproved,
		State: registry.ActionExecuting, JobVersion: 3, ProposalID: "prp_1", DecisionID: "dec_1",
		Grant: &registry.Grant{GrantID: "grt_1", ActionID: "act_1", Attempt: 1, ExpiresAt: republishNow.Add(time.Minute)},
		Spec:  spec}
}

// A registered job's conditional retry is held to the approved
// dagu.retry_run of this run's expected execution it is made for, and is
// carried out only in the form that decision approved (TXE-7517): a
// republish as the publish step alone, an explicit rerun from the job's
// step with includeDownstream, a retry naming neither as the whole run.
// Every refusal has the code every reviewer reads as "nothing started"; one
// in a form other than a republish also says retry_unbound.
func TestTxeRepublishBinding(t *testing.T) {
	const run = "run-1"
	job := republishJob
	bind := func(action *registry.Action, form registry.RetryForm) error {
		return txeRepublishBinding(job, action, run, republishExpectationFor(action), form, republishNow)
	}
	base := map[string]any{"run_id": run, "attempt_id": "a1b2c3", "queued_at": ""}
	with := func(params map[string]any, kv ...any) map[string]any {
		out := map[string]any{}
		maps.Copy(out, params)
		for i := 0; i < len(kv); i += 2 {
			out[kv[i].(string)] = kv[i+1]
		}
		return out
	}
	publish, rerun, unspecified := with(base, "step", "publish"), with(base, "step", "run"), base

	assert.NoError(t, bind(retryRunAction(publish), registry.RetryFormPublish), "an approved republish")
	assert.NoError(t, bind(retryRunAction(rerun), registry.RetryFormFromJobStep), "an approved rerun, from the job's step")
	assert.NoError(t, bind(retryRunAction(unspecified), registry.RetryFormWholeRun), "an approved retry naming no intent, of the whole run")

	// Each way an action can fail to bind, for each form: the action as the
	// form approves it, then changed.
	type variant struct {
		action *registry.Action
		job    *registry.Job
		expect *persis.ExpectedExecution
	}
	cases := func(params map[string]any) map[string]variant {
		mk := func(change func(*registry.Action)) variant {
			a := retryRunAction(params)
			change(a)
			return variant{action: a}
		}
		movedJob := *republishJob
		movedJob.PackageDigest = "sha256:other"
		agentDecided := *republishJob
		agentDecided.Proposals = map[string]*registry.Proposal{"prp_1": {ProposalID: "prp_1", State: registry.ProposalDecided,
			Decision: &registry.Decision{DecisionID: "dec_1", Verdict: registry.VerdictRetry, Actor: registry.Actor{Kind: registry.ActorAgent, ID: "bot"}}}}
		undecided := *republishJob
		undecided.Proposals = nil
		return map[string]variant{
			"no such action":                 {action: nil, expect: republishExpectation()},
			"not a retry_run":                mk(func(a *registry.Action) { a.Spec.Name = "custom.action" }),
			"another attempt of the action":  mk(func(a *registry.Action) { a.Attempt = 2 }),
			"another binding":                mk(func(a *registry.Action) { a.BindingDigest = "bd2" }),
			"a binding of the job as it was": {action: retryRunAction(params), job: &movedJob},
			"a request for another binding":  {action: retryRunAction(params), expect: republishExpectation()},
			"another run":                    {action: retryRunAction(with(params, "run_id", "run-2"))},
			"another execution":              {action: retryRunAction(with(params, "attempt_id", "ffffff"))},
			"another queue marker":           {action: retryRunAction(with(params, "queued_at", "2026-10-23T00:00:00Z"))},
			"not a person's decision":        mk(func(a *registry.Action) { a.Kind = registry.ActionRoutine }),
			"decided by an agent":            {action: retryRunAction(params), job: &agentDecided},
			"no decided proposal":            {action: retryRunAction(params), job: &undecided},
			"another decision":               mk(func(a *registry.Action) { a.DecisionID = "dec_2" }),
			"settled already (a replay)":     mk(func(a *registry.Action) { a.State = registry.ActionSucceeded }),
			"outcome uncertain":              mk(func(a *registry.Action) { a.State = registry.ActionUncertain }),
			"no grant":                       mk(func(a *registry.Action) { a.Grant = nil }),
			"grant expired":                  mk(func(a *registry.Action) { a.Grant.ExpiresAt = republishNow }),
			"grant for another attempt":      mk(func(a *registry.Action) { a.Grant.Attempt = 0 }),
			"approved for an older version":  mk(func(a *registry.Action) { a.JobVersion = 2 }),
		}
	}
	for form, params := range map[registry.RetryForm]map[string]any{
		registry.RetryFormPublish:     publish,
		registry.RetryFormFromJobStep: rerun,
		registry.RetryFormWholeRun:    unspecified,
	} {
		for name, v := range cases(params) {
			j, expect := job, v.expect
			if v.job != nil {
				j = v.job
			}
			if expect == nil {
				expect = republishExpectationFor(v.action)
			}
			err := txeRepublishBinding(j, v.action, run, expect, form, republishNow)
			require.Error(t, err, "%s: %s", form, name)
			assert.Equal(t, txeRepublishUnsupported, republishRefusalCode(t, err), "%s: %s", form, name)
			assert.Equal(t, form != registry.RetryFormPublish, refusalReason(err) == txeRetryUnbound, "%s: %s", form, name)
		}
	}

	// A decision is carried out only in its own form. In particular a rerun
	// sent with no step, as an older machine that ignores rerun sends it,
	// is refused: Dagu would keep a job step that succeeded and publish the
	// old seal instead of running the job again.
	for name, err := range map[string]error{
		"a rerun sent with no step":              bind(retryRunAction(rerun), registry.RetryFormWholeRun),
		"a rerun sent as a republish":            bind(retryRunAction(rerun), registry.RetryFormPublish),
		"no intent sent from the job step":       bind(retryRunAction(unspecified), registry.RetryFormFromJobStep),
		"no intent sent as a republish":          bind(retryRunAction(unspecified), registry.RetryFormPublish),
		"a republish sent with no step":          bind(retryRunAction(publish), registry.RetryFormWholeRun),
		"a republish sent from the job step":     bind(retryRunAction(publish), registry.RetryFormFromJobStep),
		"a legacy rerun key with a republish":    bind(retryRunAction(with(publish, "rerun", true)), registry.RetryFormPublish),
		"a legacy rerun key, from the job step":  bind(retryRunAction(with(base, "rerun", true)), registry.RetryFormFromJobStep),
		"a legacy rerun key, with no step":       bind(retryRunAction(with(base, "rerun", true)), registry.RetryFormWholeRun),
		"another step approved":                  bind(retryRunAction(with(base, "step", "check")), registry.RetryFormFromJobStep),
		"a request naming no action, no step":    txeRepublishBinding(job, nil, run, republishExpectation(), registry.RetryFormWholeRun, republishNow),
		"a request naming no action, as a rerun": txeRepublishBinding(job, nil, run, republishExpectation(), registry.RetryFormFromJobStep, republishNow),
	} {
		require.Error(t, err, name)
		assert.Equal(t, txeRepublishUnsupported, republishRefusalCode(t, err), name)
	}
}

// The form of a registered job's retry is read from what it asks of Dagu;
// a step retry that is no decision's form is refused before anything else.
func TestTxeRetryForm(t *testing.T) {
	for name, c := range map[string]struct {
		step, sub          string
		downstream, bypass bool
		accept             bool
		want               registry.RetryForm
	}{
		"no step":                          {want: registry.RetryFormWholeRun},
		"the job step with what follows":   {step: "run", downstream: true, want: registry.RetryFormFromJobStep},
		"the publish step, its failure ok": {step: "publish", accept: true, want: registry.RetryFormPublish},
	} {
		form, err := txeRetryForm(c.step, c.sub, c.downstream, c.bypass, c.accept)
		require.NoError(t, err, name)
		assert.Equal(t, c.want, form, name)
	}
	for name, c := range map[string]struct {
		step, sub          string
		downstream, bypass bool
	}{
		"the job step alone":             {step: "run"},
		"the publish step alone":         {step: "publish"},
		"the job step, bypassing":        {step: "run", downstream: true, bypass: true},
		"a step of a sub-DAG":            {step: "run", sub: "child-1", downstream: true},
		"another step with what follows": {step: "other", downstream: true},
	} {
		_, err := txeRetryForm(c.step, c.sub, c.downstream, c.bypass, false)
		require.Error(t, err, name)
		assert.Equal(t, txeRepublishUnsupported, republishRefusalCode(t, err), name)
		assert.Equal(t, txeRetryUnbound, refusalReason(err), name)
	}
}

func refusalReason(err error) string {
	if apiErr, ok := errors.AsType[*Error](err); ok {
		reason, _ := apiErr.Details["reason"].(string)
		return reason
	}
	return ""
}

// The job's DAG must be exactly what the TXE renderer writes, as written
// (txepkg.CheckGeneratedPublish, tested there in full) and as the loader
// reads it with the hub's base configuration, and its publish step must run
// the machine's own CLI. The job's variables and secrets are kept from a
// republish by the worker, not here.
func TestTxeGeneratedPublishStep(t *testing.T) {
	ctx := context.Background()
	// RenderDAG renders on the machine, so its paths are this OS's.
	root := "/h"
	if runtime.GOOS == "windows" {
		root = `C:\h`
	}
	cli := filepath.Join(root+" y", "bin", "dagu")
	render := func(mutate func(*txepkg.DAGSpec)) []byte {
		t.Helper()
		spec := txepkg.DAGSpec{
			Title: "t", JobID: "job_01K7A5ZQ8M3N4P5R6S7T8V9W01", OwnerID: "own_01K7A5ZQ8M3N4P5R6S7T8V9W0A",
			ProjectID: "prj_01K7A5ZQ8M3N4P5R6S7T8V9W0B", MachineID: "mch_01K7A5ZQ8M3N4P5R6S7T8V9W0C", Version: 1,
			PackageDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			WorkDir:       filepath.Join(root, "w"), OutputDir: filepath.Join(root, "o"), Entrypoint: []string{"./run.sh"},
			Schedule:       txepkg.Schedule{Cron: "0 2 * * *", Timezone: "UTC", TimeoutSec: 60},
			CLI:            txepkg.CLI{Dagu: cli, HomeRoot: root, StoreFlags: []string{"--dagu-home", filepath.Join(root, "client")}},
			Publish:        &txepkg.Publish{HubArtifacts: true},
			Env:            map[string]string{"TARGET": "vol-1"},
			CredentialRefs: []txepkg.CredentialRef{{Name: "LINEAR_API_KEY", Kind: txepkg.CredentialFile, Locator: filepath.Join(root, "k")}},
		}
		if mutate != nil {
			mutate(&spec)
		}
		data, err := txepkg.RenderDAG(spec)
		require.NoError(t, err)
		return data
	}
	checkWith := func(data []byte, base string, hub bool) error {
		id := txepkg.GeneratedIdentity{JobID: "job_01K7A5ZQ8M3N4P5R6S7T8V9W01", Version: 1, Home: root}
		return txeGeneratedPublishStep(ctx, &ir.DAG{Name: id.JobID, YamlData: data}, id, base, cli, hub)
	}
	check := func(data []byte) error { return checkWith(data, "", true) }

	assert.NoError(t, check(render(nil)))
	// What Dagu writes to base.yaml on first run, and base variables, which
	// a republish does not get.
	stock := "type: graph\noverlap_policy: skip\nlog_output: separate\nhist_retention_days: 30\nmax_clean_up_time_sec: 5\n" +
		"max_active_steps: 10\nmax_output_size: 1048576\ncatchup_window: \"6h\"\nenv:\n  - BASE_ONLY: x\n"
	assert.NoError(t, checkWith(render(nil), stock, true), "Dagu's default base configuration")
	assert.NoError(t, checkWith(render(func(s *txepkg.DAGSpec) { s.Publish = &txepkg.Publish{} }), "", false), "a job with machine deliverables alone")

	rendered := string(render(nil))
	quoted := strings.ReplaceAll("'"+cli+"'", `\`, `\\`) // as YAML's double quotes write it
	wrapped := strings.Replace(rendered, `command: "`+quoted+` txe artifacts publish`, `command: "sh -c 'touch /tmp/x' ; `+quoted+` txe artifacts publish`, 1)
	require.NotEqual(t, rendered, wrapped)
	for name, err := range map[string]error{
		"a shell wrapper":                 check([]byte(wrapped)),
		"a binary the job names":          check([]byte(strings.ReplaceAll(rendered, quoted, "./x"))),
		"another machine's CLI":           check(render(func(s *txepkg.DAGSpec) { s.CLI.Dagu = filepath.Join(root, "other", "bin", "dagu") })),
		"a base handler":                  checkWith(render(nil), "handler_on:\n  exit:\n    command: touch /tmp/x\n", true),
		"a base precondition":             checkWith(render(nil), "preconditions:\n  - condition: \"true\"\n", true),
		"a base shell":                    checkWith(render(nil), "shell: /tmp/sh\n", true),
		"a base container":                checkWith(render(nil), "container:\n  image: alpine\n", true),
		"base step defaults":              checkWith(render(nil), "defaults:\n  continue_on:\n    failure: true\n", true),
		"no artifact directory for hub":   checkWith(render(func(s *txepkg.DAGSpec) { s.Publish = &txepkg.Publish{} }), "", true),
		"an artifact directory unasked":   checkWith(render(nil), "", false),
		"a base artifact directory moved": checkWith(render(nil), "artifacts:\n  dir: /tmp/elsewhere\n", true),
		"base params":                     checkWith(render(nil), "params:\n  - BASH_ENV: /tmp/x\n", true),
		"a base TXE variable":             checkWith(render(nil), "env:\n  - TXE_DAGU_HOME: /tmp/elsewhere\n", true),
		"artifacts turned off in the DAG": check([]byte(strings.Replace(rendered, "  enabled: true", "  enabled: false", 1))),
	} {
		require.Error(t, err, name)
		assert.Equal(t, txeRepublishUnsupported, republishRefusalCode(t, err), name)
	}
}

// The publish step must run the CLI the machine installed in the TXE home it
// registered the job's package under, whatever the hub's operating system.
func TestTxeMachineCLI(t *testing.T) {
	for path, want := range map[string][2]string{
		"/Users/u/.local/share/txe-dagu/packages/job_1/sha256-0123": {"/Users/u/.local/share/txe-dagu/bin/dagu", "/Users/u/.local/share/txe-dagu"},
		"/packages/job_1/sha256-0123":                               {"/bin/dagu", "/"},
		`C:\Users\u\txe-dagu\packages\job_1\sha256-0123`:            {`C:\Users\u\txe-dagu\bin\dagu`, `C:\Users\u\txe-dagu`},
		`C:\packages\job_1\sha256-0123`:                             {`C:\bin\dagu`, `C:`},
		`\\srv\share\txe\packages\job_1\sha256-0123`:                {`\\srv\share\txe\bin\dagu`, `\\srv\share\txe`},
	} {
		cli, home, err := txeMachineCLI("job_1", path)
		require.NoError(t, err, path)
		assert.Equal(t, want, [2]string{cli, home}, path)
	}
	for _, path := range []string{
		"", "packages/job_1/sha256-0", "/x/packages/job_2/sha256-0", "/x/../y/packages/job_1/sha256-0",
		"/x//packages/job_1/s", "/x/./packages/job_1/s", "/x/packages/job_1/s/t", "/x/packages/job_1/",
		`C:/x/packages/job_1/s`, `C:\x/packages\job_1\s`, `C:\x\.\packages\job_1\s`, `C:\x\\packages\job_1\s`,
		`C:\x\..\packages\job_1\s`, `C:\x\packages\job_1\s\`, `x\packages\job_1\s`,
	} {
		_, _, err := txeMachineCLI("job_1", path)
		assert.Error(t, err, path)
	}
}

// A republish is refused before it is dispatched when the job's machine has
// live workers and none advertises the capability: an older worker would
// run the step retry without the option. A worker whose heartbeat is late
// counts as neither capable nor live.
func TestTxeRepublishWorkerCheck(t *testing.T) {
	selector := map[string]string{dispatch.MachineLabel: "mch_1"}
	capable := map[string]string{dispatch.MachineLabel: "mch_1", dispatch.AcceptFailedPrerequisitesLabel: dispatch.CapabilityLabelValue}
	other := map[string]string{dispatch.MachineLabel: "mch_2", dispatch.AcceptFailedPrerequisitesLabel: dispatch.CapabilityLabelValue}
	type worker struct {
		labels map[string]string
		health coordinatorv1.WorkerHealthStatus
	}
	live := func(labels map[string]string) worker {
		return worker{labels, coordinatorv1.WorkerHealthStatus_WORKER_HEALTH_STATUS_HEALTHY}
	}
	late := func(labels map[string]string) worker {
		return worker{labels, coordinatorv1.WorkerHealthStatus_WORKER_HEALTH_STATUS_WARNING}
	}
	check := func(workers ...worker) error {
		stub := &stubCoordinatorClient{}
		for i, w := range workers {
			stub.workers = append(stub.workers, &coordinatorv1.WorkerInfo{WorkerId: string(rune('a' + i)), Labels: w.labels, HealthStatus: w.health})
		}
		return (&API{coordinatorCli: stub}).txeRepublishWorkerCheck(context.Background(), selector)
	}
	refused := func(err error, name string) {
		t.Helper()
		require.Error(t, err, name)
		var apiErr *Error
		require.True(t, errors.As(err, &apiErr), name)
		assert.Equal(t, http.StatusConflict, apiErr.HTTPStatus, name)
		assert.Equal(t, txeRepublishWorkerMissing, apiErr.Details["code"], name)
	}

	assert.NoError(t, check(live(capable)))
	assert.NoError(t, check(live(selector), live(capable)), "one capable worker of the machine is enough")
	assert.NoError(t, check(late(selector), live(capable)), "a late older worker does not count")
	assert.NoError(t, check(), "no workers: the coordinator's own refusal decides")
	assert.NoError(t, check(live(other)), "only another machine's workers: the coordinator's own refusal decides")
	assert.NoError(t, check(late(selector), late(capable)), "no live worker of the machine: the coordinator's own refusal decides")

	refused(check(live(selector)), "an older worker alone")
	refused(check(late(capable), live(selector)), "a capable worker that is late, beside a live older one")
	refused(check(worker{capable, coordinatorv1.WorkerHealthStatus_WORKER_HEALTH_STATUS_UNHEALTHY}, live(selector)), "an unhealthy capable worker")
}
