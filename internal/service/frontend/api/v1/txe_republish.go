// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/runenv"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/spec"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

// A republish (TXE-5067) is a conditional step retry of a TXE job's publish
// step that may treat the job's failed step as satisfied: the job's sealed
// result is published by a new execution, and the job does not run again.
// It is the dagu.retry_run decision a person approved with step "publish".

const (
	// txeRepublishUnsupported refuses a request that cannot be a republish.
	txeRepublishUnsupported = "accept_failed_prerequisites_unsupported"
	// txeRepublishWorkerMissing refuses a republish no connected worker of
	// the job's machine can run: none advertises the capability.
	txeRepublishWorkerMissing = "worker_capability_missing"
)

func txeRepublishRefusal(format string, args ...any) error {
	return &Error{HTTPStatus: http.StatusBadRequest, Code: api.ErrorCodeBadRequest,
		Message: fmt.Sprintf(format, args...), Details: map[string]any{"code": txeRepublishUnsupported}}
}

// txeRepublishShape checks a request that asks to accept failed
// prerequisites before anything is read: it must be a conditional retry,
// made for an action attempt, of the publish step alone.
func txeRepublishShape(stepName, subDAGRunID string, includeDownstream, bypassPreconditions bool, expect *persis.ExpectedExecution) error {
	switch {
	case stepName != txepkg.PublishStepName:
		return txeRepublishRefusal("acceptFailedPrerequisites applies only to the %q step of a TXE job", txepkg.PublishStepName)
	case includeDownstream || bypassPreconditions || subDAGRunID != "":
		return txeRepublishRefusal("acceptFailedPrerequisites does not combine with includeDownstream, bypassPreconditions or subDAGRunId")
	case expect == nil || expect.Request == nil:
		return txeRepublishRefusal("acceptFailedPrerequisites needs expectedAttemptId, expectedQueuedAt and the retryRequest of the approved action")
	}
	return nil
}

// txeRetryRunAction is the part of a dagu.retry_run action's params a
// republish is bound to.
type txeRetryRunAction struct {
	RunID     string `json:"run_id"`
	AttemptID string `json:"attempt_id"`
	QueuedAt  string `json:"queued_at"`
	Step      string `json:"step"`
}

// txeCheckRepublish binds a conditional retry of a registered job's run to
// the action it was made for, both ways: a republish needs an approved
// dagu.retry_run of this run's expected execution with step "publish", and
// such an approval cannot be used for any other retry. It is called after
// the job's admission (txeAdmitDAG), so dag is the job's current version.
// baseConfig is the base configuration the retry is dispatched with.
func (a *API) txeCheckRepublish(ctx context.Context, dag *ir.DAG, baseConfig, runID string, expect *persis.ExpectedExecution, accept bool) error {
	jobID, err := txeJobIdentity(dag)
	if err != nil {
		return err
	}
	if jobID == "" {
		if accept {
			return txeRepublishRefusal("acceptFailedPrerequisites applies only to a registered TXE job's run")
		}
		return nil
	}
	if expect == nil || expect.Request == nil {
		return nil // not made for an action: nothing to bind
	}
	s, err := a.txeStore()
	if err != nil {
		return err
	}
	job, err := s.GetJob(ctx, jobID)
	if err != nil {
		return err
	}
	if accept {
		version, err := s.GetVersion(ctx, jobID, job.Version)
		if err != nil {
			return err
		}
		cli, home, err := txeMachineCLI(jobID, version.Package.Path)
		if err != nil {
			return err
		}
		hub := slices.ContainsFunc(version.ExpectedOutcome.Deliverables, func(d registry.Deliverable) bool { return d.Delivery == registry.DeliveryHub })
		id := txepkg.GeneratedIdentity{JobID: jobID, Version: job.Version, Home: home}
		if err := txeGeneratedPublishStep(ctx, dag, id, baseConfig, cli, hub); err != nil {
			return err
		}
	}
	return txeRepublishBinding(job, job.Actions[expect.Request.ActionID], runID, expect, accept, time.Now())
}

// txeRepublishBinding decides a registered job's conditional retry against
// the action it names (nil when the job has none by that id). A republish
// is carried out only for the approved action's attempt that is executing
// now, under its live grant, for the job's current version.
func txeRepublishBinding(job *registry.Job, action *registry.Action, runID string, expect *persis.ExpectedExecution, accept bool, now time.Time) error {
	jobID := job.JobID
	if action == nil || action.Spec.Name != registry.ActionRetryRun {
		if accept {
			return txeRepublishRefusal("retryRequest names no dagu.retry_run action of job %s", jobID)
		}
		return nil // another kind of follow-up; the decision service binds it
	}
	var params txeRetryRunAction
	if err := json.Unmarshal(action.Spec.Params, &params); err != nil {
		return txeRepublishRefusal("action %s has unreadable params", action.ActionID)
	}
	publishOnly := params.Step == txepkg.PublishStepName
	switch {
	case params.Step != "" && !publishOnly:
		return txeRepublishRefusal("action %s retries step %q; only %q is a step a decision retries", action.ActionID, params.Step, txepkg.PublishStepName)
	case publishOnly && !accept:
		return txeRepublishRefusal("action %s was approved as a republish of the sealed result; it is carried out only as one (stepName %q, acceptFailedPrerequisites)", action.ActionID, txepkg.PublishStepName)
	case !accept:
		return nil
	case !publishOnly:
		return txeRepublishRefusal("action %s was approved as a retry of the run, not a republish of its sealed result", action.ActionID)
	case strconv.Itoa(action.Attempt) != expect.Request.ActionAttempt || action.BindingDigest != expect.Request.BindingDigest:
		return txeRepublishRefusal("retryRequest does not name the current attempt and binding of action %s", action.ActionID)
	case params.RunID != runID || params.AttemptID != expect.AttemptID || params.QueuedAt != expect.QueuedAt:
		return txeRepublishRefusal("action %s was approved for another run or execution", action.ActionID)
	case action.Kind != registry.ActionApproved:
		return txeRepublishRefusal("action %s is not a person's approved decision", action.ActionID)
	case action.State != registry.ActionExecuting || action.Grant == nil || action.Grant.Attempt != action.Attempt || !now.Before(action.Grant.ExpiresAt):
		return txeRepublishRefusal("action %s is not executing attempt %d under a live grant", action.ActionID, action.Attempt)
	case action.JobVersion != job.Version:
		return txeRepublishRefusal("action %s was approved for version %d of job %s, which is now at version %d", action.ActionID, action.JobVersion, jobID, job.Version)
	}
	// The binding is recomputed from the job as it is now, as the registry
	// computes it, so an approval of another version, package or action
	// cannot pass as this one's.
	current, err := registry.BindingDigest(job, action.Spec)
	if err != nil || current != action.BindingDigest {
		return txeRepublishRefusal("action %s no longer binds job %s as it is now", action.ActionID, jobID)
	}
	return nil
}

// txeGeneratedPublishStep checks that the job's DAG, as stored (the bytes
// admission matched to the registered version), has exactly the publish
// step the TXE renderer writes and nothing else that would run with it. The
// bytes are checked as written (txepkg.CheckGeneratedPublish) and as Dagu's
// own loader reads them with the base configuration the task carries, the
// way the worker loads the task's definition, so that what is checked is
// what runs. id is the registered job, version and machine home it must
// have been rendered for; hub is whether the registered version has a hub deliverable,
// which the publish step needs the run's artifact directory for.
func txeGeneratedPublishStep(ctx context.Context, dag *ir.DAG, id txepkg.GeneratedIdentity, baseConfig, cli string, hub bool) error {
	if err := txepkg.CheckGeneratedPublish(dag.YamlData, id); err != nil {
		return txeRepublishRefusal("job %s's DAG is not the one the TXE renderer writes: %v", dag.Name, err)
	}
	if err := txeLoadedPublishStep(ctx, dag, baseConfig, cli, hub); err != nil {
		return txeRepublishRefusal("job %s's DAG is not the one the TXE renderer writes: %v", dag.Name, err)
	}
	return nil
}

// txeMachineCLI is the CLI the machine's worker installed, at bin/dagu of
// its TXE home, the home the machine asserted the job's package under
// (<home>/packages/<job>/<package>), and that home. The publish step must
// run that binary and no other: a binary named only by the DAG could be
// anything. The path is the machine's, written with its own separator, which
// need not be the hub's: "/" for a POSIX path, "\" for a Windows drive or
// UNC path (registry.MachineAbsPath), as the client joins both on the
// machine.
func txeMachineCLI(jobID, packagePath string) (cli, home string, err error) {
	refuse := txeRepublishRefusal("job %s's registered package path does not name the machine's TXE home", jobID)
	if !registry.MachineAbsPath(packagePath) {
		return "", "", refuse
	}
	sep := "/"
	if !strings.HasPrefix(packagePath, "/") {
		sep = `\`
	}
	if !txeCleanMachinePath(packagePath, sep) {
		return "", "", refuse
	}
	marker := sep + "packages" + sep + jobID + sep
	// A POSIX home may be "/" itself, which puts the marker first; a
	// Windows home is at least a drive or a UNC share.
	i := strings.LastIndex(packagePath, marker)
	if i < 0 || (i == 0 && sep != "/") || strings.Contains(packagePath[i+len(marker):], sep) {
		return "", "", refuse
	}
	home = packagePath[:i]
	cli = home + sep + "bin" + sep + "dagu"
	if home == "" {
		home = "/"
	}
	return cli, home, nil
}

// txeCleanMachinePath reports whether p, absolute on the machine, is written
// as the machine's filepath.Join writes it: no empty or "." segment, and for
// a Windows path no "/".
func txeCleanMachinePath(p, sep string) bool {
	if sep == "/" {
		return path.Clean(p) == p
	}
	if strings.Contains(p, "/") {
		return false
	}
	rest, unc := strings.CutPrefix(p, `\\`)
	if !unc {
		rest = p[len(`C:\`):]
	}
	for segment := range strings.SplitSeq(rest, sep) {
		if segment == "" || segment == "." {
			return false
		}
	}
	return true
}

// txeLoadedPublishStep checks the DAG as the loader reads it: no handler or
// precondition; the job's step then the publish step alone; the publish step
// one command, the machine's CLI's artifacts publish with the resource
// check's store flags, with nothing else that runs or changes how it runs;
// the run's artifact directory on exactly when the job has a hub
// deliverable. The base configuration may not change what runs either
// (txeBaseConfigChanges). The job's variables and secrets do not reach a
// republish at all: the worker runs it with the TXE variables alone and
// resolves no secret (agent republishScopedDAG), and only such a worker is
// given it.
func txeLoadedPublishStep(ctx context.Context, dag *ir.DAG, baseConfig, cli string, hub bool) error {
	load := func(opts ...spec.LoadOption) (*ir.DAG, error) {
		return spec.LoadYAML(ctx, dag.YamlData, append([]spec.LoadOption{spec.WithName(dag.Name), spec.WithoutEval()}, opts...)...)
	}
	loaded, err := load()
	if err != nil {
		return fmt.Errorf("it does not load: %w", err)
	}
	if baseConfig != "" {
		effective, err := load(spec.WithBaseConfigContent([]byte(baseConfig)))
		if err != nil {
			return fmt.Errorf("it does not load with the base configuration: %w", err)
		}
		if changed := txeBaseConfigChanges(loaded, effective); len(changed) > 0 {
			return fmt.Errorf("the base configuration sets %s, which would run with the publish step", strings.Join(changed, ", "))
		}
		loaded = effective
	}
	if loaded.HandlerOn != (ir.HandlerOn{}) || len(loaded.Preconditions) > 0 {
		return errors.New("it has a handler or a precondition")
	}
	if artifacts := loaded.Artifacts; (artifacts != nil && artifacts.Enabled) != hub || (artifacts != nil && artifacts.Dir != "") {
		return errors.New("its artifact directory does not match the job's hub deliverables")
	}
	if len(loaded.Steps) != 2 || loaded.Steps[0].Name != txepkg.RunStepName || loaded.Steps[1].Name != txepkg.PublishStepName {
		return errors.New("it does not have the job's step and the publish step alone")
	}
	run, publish := loaded.Steps[0], loaded.Steps[1]
	if len(run.Commands) == 0 {
		return errors.New("the job's step has no commands")
	}
	check := run.Commands[0]
	if check.Command != cli || len(check.Args) < 9 || !slices.Equal(check.Args[:3], []string{"txe", "resource", "check"}) {
		return errors.New("the job's step does not start with the machine's CLI's resource check")
	}
	want := append([]string{"txe", "artifacts", "publish"}, check.Args[9:]...)
	switch {
	case len(publish.Commands) != 1 || publish.Commands[0].Command != check.Command || !slices.Equal(publish.Commands[0].Args, want):
		return errors.New("the publish step does not run the CLI's artifacts publish alone")
	case publish.Shell != "" || publish.Script != "" || publish.ExecutorConfig.Type != "" || len(publish.ExecutorConfig.Config) > 0:
		return errors.New("the publish step sets a shell, a script or an executor")
	case len(publish.Preconditions) > 0 || publish.SubDAG != nil || publish.Parallel != nil || len(publish.Env) > 0:
		return errors.New("the publish step sets a precondition, a sub-DAG, parallel items or env")
	case !reflect.ValueOf(publish.ContinueOn).IsZero() || !reflect.ValueOf(publish.RepeatPolicy).IsZero():
		return errors.New("the publish step continues on failure or repeats")
	case !slices.Equal(publish.Depends, []string{txepkg.RunStepName}):
		return errors.New("the publish step does not follow the job's step alone")
	}
	return nil
}

// txeBaseIgnored are the DAG settings a base configuration may change for a
// republish. A republish does not use them (its dotenv files and secrets are
// dropped by the worker, and the rest describe the stored DAG), or they
// schedule, limit or describe the run and run nothing: Dagu's default base
// configuration sets several. Its variables are compared apart
// (txeStepEnv). Every other setting, params and one added later included,
// must be the DAG's own.
var txeBaseIgnored = map[string]bool{
	"Dotenv": true, "Secrets": true, "EnvEvaluated": true, "RootEnvSpan": true,
	"YamlData": true, "BaseConfigData": true, "BaseConfigWorkspace": true, "Location": true, "SourceFile": true,
	"BuildErrors": true, "BuildWarnings": true,
	"Type": true, "Schedule": true, "StopSchedule": true, "RestartSchedule": true, "SkipIfSuccessful": true,
	"CatchupWindow": true, "OverlapPolicy": true, "MaxActiveRuns": true, "MaxActiveSteps": true, "Queue": true,
	"HistRetentionDays": true, "HistRetentionRuns": true, "MaxCleanUpTime": true, "MaxOutputSize": true,
	"LogOutput": true, "Labels": true, "Description": true, "Group": true,
}

// txeBaseConfigChanges names the settings of effective, the DAG loaded with
// its base configuration, that differ from loaded, the DAG alone, other
// than txeBaseIgnored. Of the variables, only those a republish keeps
// (runenv.TXEStepEnvNames) must be the DAG's own: the worker drops the rest.
func txeBaseConfigChanges(loaded, effective *ir.DAG) []string {
	var changed []string
	own, based := reflect.ValueOf(loaded).Elem(), reflect.ValueOf(effective).Elem()
	for i := range own.NumField() {
		field := own.Type().Field(i)
		switch {
		case txeBaseIgnored[field.Name] || !field.IsExported():
		case field.Name == "Env":
			if !slices.Equal(txeStepEnv(loaded.Env), txeStepEnv(effective.Env)) {
				changed = append(changed, "Env ("+strings.Join(runenv.TXEStepEnvNames, ", ")+")")
			}
		case !reflect.DeepEqual(own.Field(i).Interface(), based.Field(i).Interface()):
			changed = append(changed, field.Name)
		}
	}
	return changed
}

// txeStepEnv are the entries of env a republish keeps.
func txeStepEnv(env []string) []string {
	var kept []string
	for _, entry := range env {
		if name, _, _ := strings.Cut(entry, "="); slices.Contains(runenv.TXEStepEnvNames, name) {
			kept = append(kept, entry)
		}
	}
	return kept
}

// txeRepublishWorkerCheck refuses a republish before it is dispatched when
// live workers of the job's machine are connected and none of them can run
// it; a worker whose heartbeat is late counts as neither.
// It runs before anything is queued or created, so its 409
// worker_capability_missing has had no effect and a client may settle on it.
// Without live workers, or when they cannot be listed, the coordinator's own
// refusal decides, as for any task. If the workers change after this check,
// the coordinator still gives the task only to a worker whose labels match
// its selector, which carries the capability label (executor.CreateTask);
// with none it refuses before creating an attempt, and the hub reports that
// as for any conditional retry (503 dispatch_uncertain): the client looks
// the execution up by its request rather than settling.
func (a *API) txeRepublishWorkerCheck(ctx context.Context, selector map[string]string) error {
	if a.coordinatorCli == nil {
		return nil
	}
	workers, err := a.coordinatorCli.GetWorkers(ctx)
	if err != nil || len(workers) == 0 {
		return nil
	}
	capable := map[string]string{dispatch.AcceptFailedPrerequisitesLabel: dispatch.CapabilityLabelValue}
	maps.Copy(capable, selector)
	machineWorkers := 0
	for _, w := range workers {
		// A worker whose heartbeat is late may be gone: only a live one can
		// take the task, so only a live one counts, capable or not.
		if w == nil || w.GetHealthStatus() != coordinatorv1.WorkerHealthStatus_WORKER_HEALTH_STATUS_HEALTHY ||
			!dispatch.SelectorAdmits(w.GetLabels(), selector, dispatch.MachinePinningOff) {
			continue
		}
		machineWorkers++
		if dispatch.SelectorAdmits(w.GetLabels(), capable, dispatch.MachinePinningOff) {
			return nil
		}
	}
	if machineWorkers == 0 {
		return nil
	}
	return &Error{HTTPStatus: http.StatusConflict, Code: api.ErrorCodeConflict,
		Message: "no connected worker of the job's machine can republish a sealed result: upgrade its worker",
		Details: map[string]any{"code": txeRepublishWorkerMissing}}
}
