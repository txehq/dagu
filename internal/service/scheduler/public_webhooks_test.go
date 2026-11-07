// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package scheduler

import (
	"context"
	"errors"
	"fmt"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/profile"
	"github.com/dagucloud/dagu/v2/internal/publicwebhook"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type profileResolverFunc func() (string, error)

func (f profileResolverFunc) ResolveProfile(context.Context, string, string) (string, error) {
	return f()
}

// A DAG whose default profile cannot run fails its deliveries; a profile
// store that cannot be read only delays them.
func TestWebhookRunsProfileErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		labels  []string
		err     error
		invalid bool
	}{
		{name: "disabled profile", err: fmt.Errorf("runtime profile prod: %w", profile.ErrDisabled), invalid: true},
		{name: "missing profile", err: fmt.Errorf("runtime profile prod: %w", profile.ErrNotFound), invalid: true},
		{name: "invalid workspace label", labels: []string{"workspace=bad/name"}, invalid: true},
		{name: "unreadable profile store", err: errors.New("read profiles: input/output error")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runs := &webhookRuns{dagExecutor: NewDAGExecutor(nil, nil, "", "",
				WithDAGExecutorProfileResolver(profileResolverFunc(func() (string, error) { return "", tc.err })))}
			dag := &ir.DAG{Name: "ci", Labels: ir.NewLabels(tc.labels)}

			err := runs.Enqueue(context.Background(), "ci.yaml", dag, "delivery-1", "")
			require.Error(t, err)
			assert.Equal(t, tc.invalid, errors.Is(err, publicwebhook.ErrInvalidRun), err)
		})
	}
}

// The relay applies the hub's webhook owner rule (txeauth.DecideUnboundTrigger,
// TXE-5923): an owner's DAG, by any name it answers to, is refused as a run
// that cannot start, before anything is queued, under enforce and when the
// scheduler did not load the owner mode. Every alias the rule resolves is
// covered by the rule's own tests; these check that the relay uses it.
func TestPublicWebhookOwnerRule(t *testing.T) {
	t.Parallel()
	const job = "job_01M5YYYYYYYYYYYYYYYYYYYYYY"
	machineDAG := txeauth.MachineDAGs("mch_01M5ZZZZZZZZZZZZZZZZZZZZZZ")[0]
	for _, mode := range []string{"", config.TXEAuthzModeEnforce} {
		for name, dag := range map[string]*ir.DAG{
			"registered job":           {Name: job},
			"machine DAG":              {Name: machineDAG},
			"job file declaring alias": {Name: "alias", Location: "/dags/" + job + ".yaml"},
		} {
			t.Run(mode+"/"+name, func(t *testing.T) {
				runs := &webhookRuns{config: &config.Config{TXE: config.TXEConfig{Authz: config.TXEAuthzConfig{Mode: mode}}}}
				// No store or executor: the refusal comes before either is used.
				err := runs.Enqueue(context.Background(), dag.Name, dag, "run-1", "")
				require.ErrorIs(t, err, publicwebhook.ErrInvalidRun)
				require.ErrorIs(t, err, txeauth.ErrUnboundOwnerDAG)
			})
		}
	}
}
