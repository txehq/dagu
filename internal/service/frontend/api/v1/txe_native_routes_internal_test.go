// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// A webhook token is no owner's principal: where owners are enforced it
// starts no owner's DAG, answered as a webhook that does not exist. In off
// and observe an owner's machine DAG is triggered as before. A job's DAG is
// admitted as any start of it is, in every mode, so a job the registry does
// not admit is not run by its webhook either (TXE-4741).
func TestTxeWebhookTriggerOfAnOwnersDAG(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"", "observe", "enforce"} {
		t.Run("mode="+mode, func(t *testing.T) {
			w := newTwoOwners(t, mode)
			machineDAG := &ir.DAG{Name: txeauth.MachineDAGs(w.machineA)[0]}
			jobDAG := &ir.DAG{Name: w.jobA}
			ownerless := &ir.DAG{Name: "nightly"}
			// A machine's DAG file that declares an ordinary name is that
			// machine's DAG all the same.
			alias := &ir.DAG{Name: "nightly", Location: "/dags/" + txeauth.MachineDAGs(w.machineA)[0] + ".yaml"}

			require.NoError(t, w.api.txeWebhookTrigger(ctx, ownerless), "an ownerless DAG")
			if mode == "enforce" {
				assert.Equal(t, http.StatusNotFound, statusOf(w.api.txeWebhookTrigger(ctx, machineDAG)))
				assert.Equal(t, http.StatusNotFound, statusOf(w.api.txeWebhookTrigger(ctx, jobDAG)))
				assert.Equal(t, http.StatusNotFound, statusOf(w.api.txeWebhookTrigger(ctx, alias)), "an alias of A's machine DAG")
				return
			}
			assert.NoError(t, w.api.txeWebhookTrigger(ctx, machineDAG))
			assert.Error(t, w.api.txeWebhookTrigger(ctx, jobDAG), "a job not ready is not admitted")
		})
	}
}

// txeOwnedIdentity reads an owner's DAG from a DAG's file, then from the file
// it was loaded from (all a queued run keeps), then from its declared name;
// without a location, the declared name never comes before the source file.
func TestTxeOwnedIdentity(t *testing.T) {
	machineA := txeauth.MachineDAGs("mch_01M4AAAAAAAAAAAAAAAAAAAAAA")[0]
	machineB := txeauth.MachineDAGs("mch_01M4BBBBBBBBBBBBBBBBBBBBBB")[0]
	for name, tc := range map[string]struct {
		dag  ir.DAG
		want string
	}{
		"its file":                         {ir.DAG{Name: "nightly", Location: "/dags/" + machineA + ".yaml"}, machineA},
		"its source file, queued":          {ir.DAG{Name: "nightly", SourceFile: "/dags/" + machineA + ".yaml"}, machineA},
		"source file before declared name": {ir.DAG{Name: machineB, SourceFile: "/dags/" + machineA + ".yaml"}, machineA},
		"its declared name":                {ir.DAG{Name: machineB, Location: "/dags/nightly.yaml"}, machineB},
		"no owner's":                       {ir.DAG{Name: "nightly", Location: "/dags/backup.yaml"}, "backup"},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, txeOwnedIdentity(&tc.dag))
		})
	}
}
