// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	apigen "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
)

const writeSpec = "steps:\n  - name: s\n    run: echo s\n"

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
	require.NoError(t, w.api.dagRepository.Create(ctx, ww.reviewerA, []byte(writeSpec)))
	require.NoError(t, w.api.dagRepository.Create(ctx, ww.plain, []byte(writeSpec)))
	w.api.authService = noWebhooks{}
	return ww
}

// noWebhooks is the fixture's auth service with no webhook store, which a
// deleted DAG's webhook is cleaned up from.
type noWebhooks struct{ AuthService }

func (noWebhooks) HasWebhookStore() bool { return false }

func (w writeWorld) update(ctx context.Context, name string) int {
	_, err := w.api.UpdateDAGSpec(ctx, apigen.UpdateDAGSpecRequestObject{FileName: name, Body: &apigen.UpdateDAGSpecJSONRequestBody{Spec: writeSpec}})
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
			require.Equal(t, http.StatusNotFound, w.create(personA, w.reviewerB, writeSpec), "another owner's machine name")
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
