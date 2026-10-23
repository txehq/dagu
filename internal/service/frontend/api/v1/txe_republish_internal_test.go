// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
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

var republishJob = &registry.Job{JobID: "job_1", Version: 3, PackageDigest: "sha256:pkg"}

func retryRunAction(params map[string]string) *registry.Action {
	raw, _ := json.Marshal(params)
	spec := registry.ActionSpec{Name: registry.ActionRetryRun, Params: raw}
	binding, _ := registry.BindingDigest(republishJob, spec)
	return &registry.Action{ActionID: "act_1", Attempt: 1, BindingDigest: binding, Kind: registry.ActionApproved,
		State: registry.ActionExecuting, JobVersion: 3,
		Grant: &registry.Grant{GrantID: "grt_1", ActionID: "act_1", Attempt: 1, ExpiresAt: republishNow.Add(time.Minute)},
		Spec:  spec}
}

// A republish is held to an approved dagu.retry_run of this run's expected
// execution with step "publish", and that approval is carried out only as a
// republish.
func TestTxeRepublishBinding(t *testing.T) {
	const run = "run-1"
	job := republishJob
	bind := func(action *registry.Action, accept bool) error {
		return txeRepublishBinding(job, action, run, republishExpectationFor(action), accept, republishNow)
	}
	publish := map[string]string{"run_id": run, "attempt_id": "a1b2c3", "queued_at": "", "step": "publish"}
	whole := map[string]string{"run_id": run, "attempt_id": "a1b2c3", "queued_at": ""}
	with := func(base map[string]string, k, v string) map[string]string {
		out := map[string]string{}
		maps.Copy(out, base)
		out[k] = v
		return out
	}

	assert.NoError(t, bind(retryRunAction(publish), true))
	assert.NoError(t, bind(retryRunAction(whole), false), "an ordinary retry stays as it was")
	assert.NoError(t, bind(nil, false), "another follow-up is the decision service's to bind")

	other := retryRunAction(publish)
	other.Spec.Name = "custom.action"
	stale := retryRunAction(publish)
	stale.Attempt = 2
	rebound := retryRunAction(publish)
	rebound.BindingDigest = "bd2"
	outdated := retryRunAction(publish)
	movedJob := *republishJob
	movedJob.PackageDigest = "sha256:other"
	routine := retryRunAction(publish)
	routine.Kind = registry.ActionRoutine
	settled := retryRunAction(publish)
	settled.State = registry.ActionSucceeded
	ungranted := retryRunAction(publish)
	ungranted.Grant = nil
	expired := retryRunAction(publish)
	expired.Grant.ExpiresAt = republishNow
	oldGrant := retryRunAction(publish)
	oldGrant.Grant.Attempt = 0
	oldVersion := retryRunAction(publish)
	oldVersion.JobVersion = 2
	for name, err := range map[string]error{
		"no such action":                 bind(nil, true),
		"not a retry_run":                bind(other, true),
		"whole-run approval republished": bind(retryRunAction(whole), true),
		"publish approval run whole":     bind(retryRunAction(publish), false),
		"another step approved":          bind(retryRunAction(with(whole, "step", "run")), false),
		"another attempt of the action":  bind(stale, true),
		"another binding":                bind(rebound, true),
		"a binding of the job as it was": txeRepublishBinding(&movedJob, outdated, run, republishExpectationFor(outdated), true, republishNow),
		"a request for another binding":  txeRepublishBinding(job, retryRunAction(publish), run, republishExpectation(), true, republishNow),
		"another run":                    bind(retryRunAction(with(publish, "run_id", "run-2")), true),
		"another execution":              bind(retryRunAction(with(publish, "attempt_id", "ffffff")), true),
		"not a person's decision":        bind(routine, true),
		"settled already":                bind(settled, true),
		"no grant":                       bind(ungranted, true),
		"grant expired":                  bind(expired, true),
		"grant for another attempt":      bind(oldGrant, true),
		"approved for an older version":  bind(oldVersion, true),
		"another queue marker":           bind(retryRunAction(with(publish, "queued_at", "2026-10-23T00:00:00Z")), true),
	} {
		require.Error(t, err, name)
		assert.Equal(t, txeRepublishUnsupported, republishRefusalCode(t, err), name)
	}
}

// The job's DAG must be exactly what the TXE renderer writes, as written
// (txepkg.CheckGeneratedPublish, tested there in full) and as the loader
// reads it, and its publish step must run the machine's own CLI. The job's
// variables and secrets are kept from a republish by the worker, not here.
func TestTxeGeneratedPublishStep(t *testing.T) {
	ctx := context.Background()
	render := func(mutate func(*txepkg.DAGSpec)) []byte {
		t.Helper()
		spec := txepkg.DAGSpec{
			Title: "t", JobID: "job_01K7A5ZQ8M3N4P5R6S7T8V9W01", OwnerID: "own_01K7A5ZQ8M3N4P5R6S7T8V9W0A",
			ProjectID: "prj_01K7A5ZQ8M3N4P5R6S7T8V9W0B", MachineID: "mch_01K7A5ZQ8M3N4P5R6S7T8V9W0C", Version: 1,
			PackageDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			WorkDir:       "/w", OutputDir: "/o", Entrypoint: []string{"./run.sh"},
			Schedule:       txepkg.Schedule{Cron: "0 2 * * *", Timezone: "UTC", TimeoutSec: 60},
			CLI:            txepkg.CLI{Dagu: "/h y/bin/dagu", HomeRoot: "/h", StoreFlags: []string{"--dagu-home", "/h/client"}},
			Publish:        &txepkg.Publish{HubArtifacts: true},
			Env:            map[string]string{"TARGET": "vol-1"},
			CredentialRefs: []txepkg.CredentialRef{{Name: "LINEAR_API_KEY", Kind: txepkg.CredentialFile, Locator: "/k"}},
		}
		if mutate != nil {
			mutate(&spec)
		}
		data, err := txepkg.RenderDAG(spec)
		require.NoError(t, err)
		return data
	}
	check := func(data []byte) error {
		return txeGeneratedPublishStep(ctx, &ir.DAG{Name: "job_01K7A5ZQ8M3N4P5R6S7T8V9W01", YamlData: data}, "/h y/bin/dagu")
	}

	assert.NoError(t, check(render(nil)))

	rendered := string(render(nil))
	wrapped := strings.Replace(rendered, `command: "'/h y/bin/dagu' txe artifacts publish`, `command: "sh -c 'touch /tmp/x' ; '/h y/bin/dagu' txe artifacts publish`, 1)
	require.NotEqual(t, rendered, wrapped)
	for name, data := range map[string][]byte{
		"a shell wrapper":        []byte(wrapped),
		"a binary the job names": []byte(strings.ReplaceAll(rendered, "'/h y/bin/dagu'", "./x")),
		"another machine's CLI":  render(func(s *txepkg.DAGSpec) { s.CLI.Dagu = "/other/bin/dagu" }),
	} {
		err := check(data)
		require.Error(t, err, name)
		assert.Equal(t, txeRepublishUnsupported, republishRefusalCode(t, err), name)
	}
}

// The publish step must run the CLI the machine installed in the TXE home it
// registered the job's package under.
func TestTxeMachineCLI(t *testing.T) {
	cli, err := txeMachineCLI("job_1", "/Users/u/.local/share/txe-dagu/packages/job_1/sha256-0123")
	require.NoError(t, err)
	assert.Equal(t, "/Users/u/.local/share/txe-dagu/bin/dagu", cli)
	for _, path := range []string{"", "packages/job_1/sha256-0", "/x/packages/job_2/sha256-0", "/x/../y/packages/job_1/sha256-0", "/packages/job_1/s"} {
		_, err := txeMachineCLI("job_1", path)
		assert.Error(t, err, path)
	}
}

// A republish is refused before it is dispatched when the job's machine has
// connected workers and none advertises the capability: an older worker
// would run the step retry without the option.
func TestTxeRepublishWorkerCheck(t *testing.T) {
	selector := map[string]string{dispatch.MachineLabel: "mch_1"}
	capable := map[string]string{dispatch.MachineLabel: "mch_1", dispatch.AcceptFailedPrerequisitesLabel: dispatch.CapabilityLabelValue}
	other := map[string]string{dispatch.MachineLabel: "mch_2", dispatch.AcceptFailedPrerequisitesLabel: dispatch.CapabilityLabelValue}
	check := func(workers ...map[string]string) error {
		stub := &stubCoordinatorClient{}
		for i, labels := range workers {
			stub.workers = append(stub.workers, &coordinatorv1.WorkerInfo{WorkerId: string(rune('a' + i)), Labels: labels})
		}
		return (&API{coordinatorCli: stub}).txeRepublishWorkerCheck(context.Background(), selector)
	}

	assert.NoError(t, check(capable))
	assert.NoError(t, check(selector, capable), "one capable worker of the machine is enough")
	assert.NoError(t, check(), "no workers: the coordinator's own refusal decides")
	assert.NoError(t, check(other), "only another machine's workers: the coordinator's own refusal decides")

	err := check(selector)
	require.Error(t, err)
	var apiErr *Error
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, http.StatusConflict, apiErr.HTTPStatus)
	assert.Equal(t, txeRepublishWorkerMissing, apiErr.Details["code"])
}
