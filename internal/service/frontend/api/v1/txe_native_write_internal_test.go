// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
)

const writeSpec = "steps:\n  - name: s\n    run: echo s\n"

// pinned is writeSpec pinned to a machine, as a machine's own DAG must be.
func pinned(machine string) string {
	return "worker_selector:\n  txe.machine: " + machine + "\n" + writeSpec
}

// writeWorld is two owners with a machine DAG of A's and an ownerless DAG
// on file, in one mode.
type writeWorld struct {
	*twoOwners
	reviewerA, reviewerB, plain string
}

func newWriteWorld(t *testing.T, mode string) writeWorld {
	t.Helper()
	w := newTwoOwners(t, mode)
	ww := writeWorld{twoOwners: w, reviewerA: "txe-reviewer-" + w.machineA[len("mch_"):],
		reviewerB: "txe-reviewer-" + w.machineB[len("mch_"):], plain: "nightly-backup"}
	ctx := context.Background()
	require.NoError(t, w.api.dagRepository.Create(ctx, ww.reviewerA, []byte(pinned(w.machineA))))
	require.NoError(t, w.api.dagRepository.Create(ctx, ww.plain, []byte(writeSpec)))
	w.api.authService = noWebhooks{}
	return ww
}

// noWebhooks is the fixture's auth service with no webhook store, which a
// deleted DAG's webhook is cleaned up from.
type noWebhooks struct{ AuthService }

func (noWebhooks) HasWebhookStore() bool { return false }

func (w writeWorld) update(ctx context.Context, name string) int {
	spec := writeSpec
	if name == w.reviewerA {
		spec = pinned(w.machineA)
	}
	return w.updateWith(ctx, name, spec)
}

func (w writeWorld) updateWith(ctx context.Context, name, spec string) int {
	_, err := w.api.UpdateDAGSpec(ctx, apigen.UpdateDAGSpecRequestObject{FileName: name, Body: &apigen.UpdateDAGSpecJSONRequestBody{Spec: spec}})
	return statusOf(err)
}

func (w writeWorld) create(ctx context.Context, name, spec string) int {
	_, err := w.api.CreateNewDAG(ctx, apigen.CreateNewDAGRequestObject{Body: &apigen.CreateNewDAGJSONRequestBody{Name: name, Spec: &spec}})
	return statusOf(err)
}

func (w writeWorld) rename(ctx context.Context, from, to string) int {
	_, err := w.api.RenameDAG(ctx, apigen.RenameDAGRequestObject{FileName: from, Body: &apigen.RenameDAGJSONRequestBody{NewFileName: to}})
	return statusOf(err)
}

func (w writeWorld) remove(ctx context.Context, name string) int {
	_, err := w.api.DeleteDAG(ctx, apigen.DeleteDAGRequestObject{FileName: name})
	return statusOf(err)
}

// statusOf of a nil error is 200 here: the write went through.
const wrote = http.StatusOK

// A caller held to its owner is decided by owner in every mode: it writes its
// own machine's DAG, never a job's (the registry's), nor another owner's or
// an ownerless DAG, which it is not told exist.
func TestTxeNativeWritesOwnerHeldCallers(t *testing.T) {
	for _, mode := range []string{"", "observe", "enforce"} {
		t.Run("mode="+mode, func(t *testing.T) {
			w := newWriteWorld(t, mode)
			personA, cliA, personB, nobody := neutral(w.personA), neutral(w.cliA), neutral(w.personB), neutral(w.nobody)

			for _, ctx := range []context.Context{personA, cliA} {
				require.Equal(t, wrote, w.update(ctx, w.reviewerA), "own machine's DAG")
			}
			require.Equal(t, http.StatusForbidden, w.update(personA, w.jobA), "own job: the registry's")
			for _, ctx := range []context.Context{personB, nobody} {
				require.Equal(t, http.StatusNotFound, w.update(ctx, w.reviewerA))
				require.Equal(t, http.StatusNotFound, w.update(ctx, w.jobA))
			}
			require.Equal(t, http.StatusNotFound, w.update(personA, w.plain), "the platform's")

			// Create and rename are decided at both ends.
			require.Equal(t, http.StatusNotFound, w.create(personA, w.reviewerB, pinned(w.machineB)), "another owner's machine name")
			require.Equal(t, http.StatusNotFound, w.create(personA, "anything", writeSpec), "an ownerless name")
			require.Equal(t, http.StatusNotFound, w.rename(personA, w.reviewerA, "elsewhere"), "to an ownerless name")
			require.Equal(t, http.StatusForbidden, w.rename(personA, w.reviewerA, w.jobA), "to a job's name")
			// A spec that declares another DAG's name is that DAG.
			require.NotEqual(t, wrote, w.create(personA, "x", "name: "+w.jobA+"\n"+writeSpec))

			require.Equal(t, wrote, w.remove(personA, w.reviewerA), "own machine's DAG")
			require.Equal(t, http.StatusForbidden, w.remove(personA, w.jobA))
			require.Equal(t, http.StatusNotFound, w.remove(personB, w.jobA))

			// The hub's own switch on DAG writes still holds.
			w.api.config.Server.Permissions[config.PermissionWriteDAGs] = false
			require.Equal(t, w.create(cliA, w.reviewerA, writeSpec), statusOf(errPermissionDenied))
		})
	}
}

// Legacy keys and the platform administrator: as before in off; in observe
// let through (and logged); in enforce a job's DAG is nobody's to write, a
// machine's only its owner's, and an ownerless DAG the administrator's.
func TestTxeNativeWritesLegacyAndAdministrator(t *testing.T) {
	type expect struct{ job, machine, plain, toJob int }
	for mode, want := range map[string]map[string]expect{
		"":        {"legacy": {wrote, wrote, wrote, wrote}, "admin": {wrote, wrote, wrote, wrote}},
		"observe": {"legacy": {wrote, wrote, wrote, wrote}, "admin": {wrote, wrote, wrote, wrote}},
		"enforce": {
			"legacy": {http.StatusNotFound, http.StatusNotFound, http.StatusNotFound, http.StatusNotFound},
			"admin":  {http.StatusForbidden, http.StatusForbidden, wrote, http.StatusForbidden},
		},
	} {
		t.Run("mode="+mode, func(t *testing.T) {
			for who, e := range want {
				w := newWriteWorld(t, mode)
				ctx := w.legacy
				if who == "admin" {
					ctx = w.admin
				}
				require.Equal(t, e.job, w.update(ctx, w.jobA), "%s job", who)
				require.Equal(t, e.machine, w.update(ctx, w.reviewerA), "%s machine", who)
				require.Equal(t, e.plain, w.update(ctx, w.plain), "%s ownerless", who)
				require.Equal(t, e.toJob, w.rename(ctx, w.plain, "job_01J0000000000000000000000Z"), "%s rename to a job's name", who)
			}
		})
	}
}

// An inline spec runs a definition that is not stored: it stays closed to a
// caller held to its owner, even under its own machine's DAG name, and in
// enforce a legacy key does not run one as an owner's DAG.
func TestTxeInlineSpecRunsAreDecidedAsWrites(t *testing.T) {
	for _, mode := range []string{"", "enforce"} {
		w := newWriteWorld(t, mode)
		run := func(ctx context.Context, name string) int {
			_, err := w.api.ExecuteDAGRunFromSpec(ctx, apigen.ExecuteDAGRunFromSpecRequestObject{
				Body: &apigen.ExecuteDAGRunFromSpecJSONRequestBody{Spec: writeSpec, Name: &name}})
			return statusOf(err)
		}
		require.Equal(t, http.StatusForbidden, run(neutral(w.personA), w.reviewerA), "mode %q", mode)
		if mode == "enforce" {
			require.Equal(t, http.StatusNotFound, run(w.legacy, w.reviewerA))
		}
	}
}

// A write is decided on what the store and the loader will use: the name as
// the store resolves it, every name the spec declares, and every machine it
// runs on. A machine's own DAG runs only on that machine.
func TestTxeNativeWritesDecideWhatTheStoreAndLoaderUse(t *testing.T) {
	for _, mode := range []string{"", "enforce"} {
		t.Run("mode="+mode, func(t *testing.T) {
			w := newWriteWorld(t, mode)
			personA := neutral(w.personA)

			// The store resolves these to the job's and B's machine's files.
			for _, name := range []string{w.jobA + ".yaml", w.jobA + ".yml", w.jobA + ".YAML", strings.ToLower(w.jobA), "JOB_" + w.jobA[len("job_"):]} {
				require.Contains(t, []int{http.StatusForbidden, http.StatusNotFound}, w.create(personA, name, writeSpec), name)
			}
			// Refused, whether by the name check or by the owner decision.
			require.NotEqual(t, wrote, w.create(personA, strings.ToUpper(w.reviewerB)+".yml", pinned(w.machineB)))
			require.NotEqual(t, wrote, w.create(personA, w.reviewerB+".yml", pinned(w.machineB)))

			// The first document's declared name is the stored DAG's name
			// at load time: on A's own machine DAG, an otherwise permitted
			// file, declaring B's job is refused.
			require.Equal(t, http.StatusNotFound, w.updateWith(personA, w.reviewerA, "name: "+w.jobB+"\n"+pinned(w.machineA)))
			require.Equal(t, http.StatusForbidden, w.updateWith(personA, w.reviewerA, "name: "+w.jobA+"\n"+pinned(w.machineA)))

			// A local DAG named another owner's job is that job.
			child := pinned(w.machineA) + "---\nname: " + w.jobB + "\n" + pinned(w.machineA)
			require.Equal(t, http.StatusNotFound, w.updateWith(personA, w.reviewerA, child))

			// Where it runs: unpinned, pinned elsewhere, or computed, a
			// machine's DAG is refused; pinned to its machine it is written.
			require.Equal(t, http.StatusForbidden, w.updateWith(personA, w.reviewerA, writeSpec), "unpinned")
			require.Equal(t, http.StatusNotFound, w.updateWith(personA, w.reviewerA, pinned(w.machineB)), "on B's machine")
			require.Equal(t, http.StatusBadRequest, w.updateWith(personA, w.reviewerA, "worker_selector:\n  txe.machine: ${M}\n"+writeSpec), "computed")
			// A local DAG of no owner is not A's to declare.
			require.Equal(t, http.StatusNotFound, w.updateWith(personA, w.reviewerA, pinned(w.machineA)+"---\nname: helper\n"+writeSpec), "a local DAG of no owner")
			require.Equal(t, wrote, w.updateWith(personA, w.reviewerA, pinned(w.machineA)))

			// Steps are placements too: a step may not send work, or call a
			// DAG, where A may not write.
			stepTo := func(machine string) string {
				return "worker_selector:\n  txe.machine: " + w.machineA + "\nsteps:\n  - name: s\n    call: " + w.reviewerA +
					"\n    worker_selector:\n      txe.machine: " + machine + "\n"
			}
			require.Equal(t, http.StatusNotFound, w.updateWith(personA, w.reviewerA, stepTo(w.machineB)), "a step on B's machine")
			require.Equal(t, http.StatusBadRequest, w.updateWith(personA, w.reviewerA, stepTo("${M}")), "a step's computed machine")
			handlerTo := pinned(w.machineA) + "handler_on:\n  failure:\n    call: " + w.reviewerA +
				"\n    worker_selector:\n      txe.machine: " + w.machineB + "\n"
			require.Equal(t, http.StatusNotFound, w.updateWith(personA, w.reviewerA, handlerTo), "a handler on B's machine")
			calls := func(dag string) string {
				return "worker_selector:\n  txe.machine: " + w.machineA + "\nsteps:\n  - name: s\n    call: " + dag + "\n"
			}
			require.Equal(t, http.StatusNotFound, w.updateWith(personA, w.reviewerA, calls(w.reviewerB)), "calling B's machine DAG")
			require.Equal(t, http.StatusNotFound, w.updateWith(personA, w.reviewerA, calls(w.jobB)), "calling B's job")
			require.Equal(t, http.StatusForbidden, w.updateWith(personA, w.reviewerA, calls(w.jobA)), "calling a job: the registry's")
			require.Equal(t, wrote, w.updateWith(personA, w.reviewerA, stepTo(w.machineA)), "a step on A's own machine")

			// A spec that does not load cannot be verified.
			require.Equal(t, http.StatusBadRequest, w.updateWith(personA, w.reviewerA, "steps: [unclosed\n"))

			// Renaming a file to a machine's name moves its definition there:
			// an unpinned one is refused.
			require.Equal(t, http.StatusNotFound, w.rename(personA, w.reviewerA, w.reviewerB))
		})
	}
	// An ownerless DAG sent to an owner's machine is that machine's to allow:
	// in enforce, the administrator does not write one.
	w := newWriteWorld(t, "enforce")
	require.Equal(t, http.StatusForbidden, w.updateWith(w.admin, w.plain, pinned(w.machineA)))
	// An ownerless file declaring a job's name is that job, which no one
	// writes natively; nor does a create or rename reach one through a
	// file name the store resolves to it.
	require.Equal(t, http.StatusForbidden, w.updateWith(w.admin, w.plain, "name: "+w.jobA+"\n"+writeSpec))
	require.Equal(t, http.StatusForbidden, w.create(w.admin, w.jobB+".yaml", writeSpec))
	require.Equal(t, http.StatusForbidden, w.rename(w.admin, w.plain, w.jobB+".yml"))
	require.Equal(t, wrote, w.updateWith(w.admin, w.plain, writeSpec))
	// In off a legacy key writes as before, wherever it sends it.
	off := newWriteWorld(t, "")
	require.Equal(t, wrote, off.updateWith(off.legacy, off.plain, pinned(off.machineA)))
}
