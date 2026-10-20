// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A job runs only on its machine: every document its spec defines names that
// machine, a step that selects a machine names this one, and a step calls
// only the spec's own DAGs. A spec that sends work anywhere else, or does not
// say plainly where, is refused at registration and at a new version, and
// nothing is stored (TXE-4717).
func TestJobSpecRunsOnlyOnItsMachine(t *testing.T) {
	f := newFixture(t)
	other := f.mint(PrefixMachine)
	own := "worker_selector:\n  txe.machine: " + f.machine + "\n"

	helper := func(machine string) string {
		return "---\nname: helper\nworker_selector:\n  txe.machine: " + machine + "\nsteps:\n  - name: h\n    run: echo h\n"
	}
	refused := map[string]string{
		"a step selects another machine": own + fmt.Sprintf(
			"steps:\n  - name: run\n    call: helper\n    worker_selector:\n      txe.machine: %s\n", other) + helper(f.machine),
		"a handler selects another machine": own + fmt.Sprintf(
			"handler_on:\n  failure:\n    call: helper\n    worker_selector:\n      txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/run.sh\n", other) + helper(f.machine),
		"a local DAG selects another machine": own +
			"steps:\n  - name: run\n    call: helper\n" + helper(other),
		"a local DAG names no machine": own +
			"steps:\n  - name: run\n    call: helper\n---\nname: helper\nsteps:\n  - name: h\n    run: echo h\n",
		"a step calls a DAG the spec does not define": own +
			"steps:\n  - name: run\n    call: somebody-elses-dag\n",
		"a step calls a computed DAG": own +
			"params:\n  - TARGET: helper\nsteps:\n  - name: run\n    call: ${TARGET}\n" + helper(f.machine),
		"a step selects labels but no machine": own +
			"steps:\n  - name: run\n    call: helper\n    worker_selector:\n      os: linux\n" + helper(f.machine),
		"a selector is written with space": "worker_selector:\n  txe.machine: \" " + f.machine + "\"\n" +
			"steps:\n  - name: run\n    run: /pkg/run.sh\n",
	}
	for name, spec := range refused {
		t.Run(name, func(t *testing.T) {
			v := f.version(1)
			v.DAG.Spec = spec
			jobID := f.mint(PrefixJob)
			_, err := f.store.Register(f.ctx, RegisterInput{JobID: jobID, RequestID: "r-" + jobID, OwnerID: f.owner,
				ProjectID: f.project, MachineID: f.machine, JobKey: "k-" + jobID, Version: v}, cli)
			assert.Equal(t, CodeInvalid, code(t, err))
			assert.NotContains(t, err.Error(), "does not load", "refused for where it runs, not as unloadable")
			_, err = f.store.GetJob(f.ctx, jobID)
			assert.Equal(t, CodeNotFound, code(t, err), "nothing is stored")
		})
	}

	// A new version is held to the same rule, and the job keeps its version.
	job := f.register("placement")
	v := f.version(2)
	v.DAG.Spec = refused["a step selects another machine"]
	_, err := f.store.UpdateVersion(f.ctx, job.JobID, "upd-other", 1, v, cli)
	assert.Equal(t, CodeInvalid, code(t, err))
	got, err := f.store.GetJob(f.ctx, job.JobID)
	require.NoError(t, err)
	assert.Equal(t, 1, got.Version)

	// Pinned throughout, with its own local DAG and steps on its machine, a
	// spec registers.
	v = f.version(3)
	v.DAG.Spec = own + fmt.Sprintf(
		"steps:\n  - name: run\n    call: helper\n    worker_selector:\n      txe.machine: %s\n  - name: last\n    run: echo done\n    depends: run\n", f.machine) +
		helper(f.machine)
	_, err = f.store.UpdateVersion(f.ctx, job.JobID, "upd-own", 1, v, cli)
	require.NoError(t, err)
}
