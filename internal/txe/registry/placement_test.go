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
		"a foreach body selects another machine": own + fmt.Sprintf(
			"steps:\n  - name: loop\n    foreach:\n      items: [one]\n      steps:\n        - name: escape\n          call: helper\n          worker_selector:\n            txe.machine: %s\n", other) + helper(f.machine),
		"a nested foreach body calls a DAG the spec does not define": own +
			"steps:\n  - name: outer\n    foreach:\n      items: [one]\n      steps:\n        - name: inner\n          foreach:\n            items: [two]\n            steps:\n              - name: escape\n                call: somebody-elses-dag\n",
		"a chat step's tool is a DAG the spec does not define": own +
			"steps:\n  - name: ask\n    type: chat\n    llm:\n      provider: openai\n      model: gpt-4o\n      tools: [somebody-elses-dag]\n    messages:\n      - role: user\n        content: hi\n",
		"the DAG's own llm tool is a DAG the spec does not define": own +
			"llm:\n  provider: openai\n  model: gpt-4o\n  tools: [somebody-elses-dag]\nsteps:\n  - name: ask\n    type: chat\n    messages:\n      - role: user\n        content: hi\n",
		"a step runs an action package": own +
			"steps:\n  - name: act\n    action: someone/some-action@v1\n",
		// A local DAG runs with its own document alone: whatever it calls,
		// itself included, is looked up outside the spec.
		"a local DAG calls itself": own + "steps:\n  - name: run\n    call: helper\n" +
			"---\nname: helper\n" + own + "steps:\n  - name: again\n    call: helper\n",
		"a local DAG calls another local DAG": own + "steps:\n  - name: run\n    call: helper\n" +
			"---\nname: helper\n" + own + "steps:\n  - name: next\n    call: other\n" + helper(f.machine)[len("---\nname: helper"):len("---\nname: helper")] +
			"---\nname: other\n" + own + "steps:\n  - name: o\n    run: echo o\n",
		// The runtime looks a tool up exactly as written.
		"a tool named with surrounding space": own +
			"steps:\n  - name: ask\n    type: chat\n    llm:\n      provider: openai\n      model: gpt-4o\n      tools: [\" helper\"]\n    messages:\n      - role: user\n        content: hi\n" + helper(f.machine),
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

	// The job's own DAG calling itself runs what is stored under its name,
	// outside the spec.
	t.Run("the job's DAG calls itself", func(t *testing.T) {
		jobID := f.mint(PrefixJob)
		v := f.version(1)
		v.DAG.Spec = own + "steps:\n  - name: again\n    call: " + jobID + "\n"
		_, err := f.store.Register(f.ctx, RegisterInput{JobID: jobID, RequestID: "r-" + jobID, OwnerID: f.owner,
			ProjectID: f.project, MachineID: f.machine, JobKey: "k-" + jobID, Version: v}, cli)
		assert.Equal(t, CodeInvalid, code(t, err))
	})

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
