// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
	"github.com/dagucloud/dagu/v2/internal/txe/probe"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

// scriptedProber answers every target from outcomes, keyed by uid; the
// external lookup is the only part of the check that is not real here.
type scriptedProber struct {
	mu       sync.Mutex
	outcomes map[string]probe.Result
}

func (p *scriptedProber) Supports(string) bool { return true }

func (p *scriptedProber) Probe(_ context.Context, t probe.Target, _ probe.Credentials) probe.Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r, ok := p.outcomes[t.StableID["uid"]]; ok {
		return r
	}
	return probe.Result{Outcome: probe.Unknown, Detail: "not scripted"}
}

func (p *scriptedProber) set(uid string, r probe.Result) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.outcomes[uid] = r
}

type noCreds struct{}

func (noCreds) Lookup(string) (probe.Credential, bool) { return probe.Credential{}, false }

// The worker-side resource check speaks to the real /api/v1/txe server and
// registry: a pre-run check admits a ready job whose targets are present,
// leaves an unconfirmed target incomplete for the machine to retry, and an
// authoritative absence retires the job so the next pre-run stops.
func TestTxeResourceCheckAgainstTheHub(t *testing.T) {
	server := builtinServer(t)
	token := loginAndGetToken(t, server, "admin", "adminpass")
	ctx := context.Background()
	c := txeclient.New(fmt.Sprintf("http://127.0.0.1:%d/api/v1", server.Config.Server.Port), token, http.DefaultClient)

	cli := txeclient.Actor{Kind: txeclient.ActorKindCLI, ID: "cc4-test"}
	owner, machine, jobID := mint(t, registry.PrefixOwner), mint(t, registry.PrefixMachine), mint(t, registry.PrefixJob)
	require.NoError(t, c.Do(ctx, http.MethodPost, "/txe/owners", nil,
		map[string]any{"owner_id": owner, "display_name": "Connor Wang", "actor": cli}, nil))
	require.NoError(t, c.Do(ctx, http.MethodPost, "/txe/machines", nil,
		map[string]any{"machine_id": machine, "owner_id": owner, "display_name": "laptop", "actor": cli}, nil))
	project, err := c.EnsureProject(ctx, owner, "github.com/txehq/txe", "", cli)
	require.NoError(t, err)

	cm := func(uid, name, check string) txeclient.Target {
		return txeclient.Target{Kind: "kubernetes.configmap", Environment: "dev", DisplayName: "probe-ns/" + name,
			StableID: map[string]string{"cluster_uid": "c1", "uid": uid}, ExistenceCheck: check}
	}
	digest := fmt.Sprintf("sha256:%064x", 7)
	job, err := c.RegisterJob(ctx, txeclient.RegisterRequest{
		JobID: jobID, RequestID: "r1", OwnerID: owner, ProjectID: project.ProjectID, MachineID: machine, JobKey: "key:" + jobID,
		Version: txeclient.JobVersion{
			Title: "t", Purpose: "p",
			Package: txeclient.Package{Digest: digest, Path: "/pkg", Entrypoint: "run.sh",
				CredentialRefs: []txeclient.CredentialRef{{Name: "TXE_KUBECONFIG", Kind: "file", Locator: "/Users/me/.kube/config"}}},
			DAG:     txeclient.DAGRef{Spec: fmt.Sprintf("worker_selector:\n  txe.machine: %s\nsteps:\n  - name: run\n    run: /pkg/run.sh\n", machine)},
			Targets: []txeclient.Target{cm("u-pre", "pre", probe.CheckPreRun), cm("u-rec", "rec", probe.CheckReconcile)},
		},
		Actor: cli,
	})
	require.NoError(t, err)
	_, err = c.MarkReady(ctx, jobID, txeclient.ReadyRequest{ExpectedRevision: job.Revision,
		Package: txeclient.PackageEvidence{Digest: digest, Path: "/pkg", MachineID: machine}, Actor: cli})
	require.NoError(t, err)

	journal, err := probe.OpenJournal(filepath.Join(t.TempDir(), "journal.json"))
	require.NoError(t, err)
	prober := &scriptedProber{outcomes: map[string]probe.Result{}}
	var out bytes.Buffer
	check := &probe.Check{Registry: probe.ClientRegistry{Client: c}, Probes: probe.Probes{prober}, Journal: journal,
		MachineID: machine, Client: "test", Out: &out}

	// Until the scheduler has built the resource index the hub refuses every
	// report (409 not_ready): the run does not start and the report is held.
	prober.set("u-pre", probe.Result{Outcome: probe.Present})
	code, err := check.PreRun(ctx, jobID, 1, noCreds{})
	require.NoError(t, err, out.String())
	assert.Equal(t, probe.ExitUnobserved, code, out.String())
	assert.Contains(t, out.String(), "not_ready")

	// Build the index as the scheduler does, on the hub's own store. The
	// held report is delivered first and the run may start.
	store, err := registry.NewFileStore(server.Config.Paths.DataDir)
	require.NoError(t, err)
	require.NoError(t, store.RebuildResourceIndex(ctx))
	out.Reset()
	code, err = check.PreRun(ctx, jobID, 1, noCreds{})
	require.NoError(t, err, out.String())
	assert.Equal(t, probe.ExitOK, code, out.String())
	assert.Contains(t, out.String(), `"resent":true`)

	// A target the check could not observe is recorded, the run does not
	// start, and the hub shows the job's target as unconfirmed.
	prober.set("u-pre", probe.Result{Outcome: probe.Unknown, Detail: "no kubeconfig"})
	code, err = check.PreRun(ctx, jobID, 1, noCreds{})
	require.NoError(t, err, out.String())
	assert.Equal(t, probe.ExitUnobserved, code, out.String())
	unconfirmed, err := c.Job(ctx, jobID)
	require.NoError(t, err)
	assert.Equal(t, string(registry.AvailabilityTargetUnconfirmed), unconfirmed.Availability.State)

	// The periodic pass observes only the reconcile target; it leaves
	// nothing incomplete for the machine.
	prober.set("u-pre", probe.Result{Outcome: probe.Present})
	prober.set("u-rec", probe.Result{Outcome: probe.Present})
	res, code, err := check.Periodic(ctx, time.Now().Add(time.Minute), func(string, int) probe.Credentials { return noCreds{} })
	require.NoError(t, err, out.String())
	assert.Equal(t, probe.ExitOK, code, "%+v %s", res, out.String())
	assert.Equal(t, probe.PeriodicResult{Observed: 1}, res)
	incomplete, _, err := check.Registry.IncompleteEvents(ctx, machine, "", 200)
	require.NoError(t, err)
	assert.Empty(t, incomplete)

	// The unconfirmed target does not block admission: the next run's
	// pre-run check observes it present and the job is ready again.
	code, err = check.PreRun(ctx, jobID, 1, noCreds{})
	require.NoError(t, err, out.String())
	assert.Equal(t, probe.ExitOK, code, out.String())
	ready, err := c.Job(ctx, jobID)
	require.NoError(t, err)
	assert.Equal(t, string(registry.AvailabilityReady), ready.Availability.State)

	// An authoritative absence retires the job on the hub, so the next
	// pre-run check stops instead of starting the run.
	prober.set("u-pre", probe.Result{Outcome: probe.Absent, Authoritative: true, Evidence: []string{"GET configmaps/probe-ns/pre: 404"}})
	code, err = check.PreRun(ctx, jobID, 1, noCreds{})
	require.NoError(t, err, out.String())
	assert.Equal(t, probe.ExitStop, code, out.String())
	after, err := c.Job(ctx, jobID)
	require.NoError(t, err)
	assert.Equal(t, "retired", after.Lifecycle)
	code, err = check.PreRun(ctx, jobID, 1, noCreds{})
	require.Error(t, err)
	assert.Equal(t, probe.ExitStop, code)
}
