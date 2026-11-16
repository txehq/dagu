// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TXE-7629: a person's rerun is stored as step "run". The other intents'
// stored params, proposal ids and binding digests are byte-identical to what
// the code before it wrote (the values below were computed on main at
// 97b3feabd), so decisions already recorded bind as they did.
func TestRetryIntentEncodingIsPinned(t *testing.T) {
	job := &Job{JobID: "job_pinned", Version: 3, PackageDigest: "sha256:pinned-package"}
	base := RetryRunParams{RunID: "run-1", AttemptID: "att-1", QueuedAt: "q-1", RunSpecSHA256: "sha256:pinned-spec", PackageDigest: job.PackageDigest}
	ref := ExecutionRef(base.AttemptID, base.QueuedAt)
	for name, want := range map[string]struct {
		step, intent, params, proposal, binding string
	}{
		"unspecified": {"", RetryIntentUnspecified,
			`{"run_id":"run-1","attempt_id":"att-1","queued_at":"q-1","run_spec_sha256":"sha256:pinned-spec","package_digest":"sha256:pinned-package"}`,
			"prp_501RB88A6QPS0DHBQ31ZVSZR5X", "sha256:53e3aabfa4fb350471cf81f931f7afd59ad6836fcf718834c9c1f0398451f54d"},
		"republish": {RetryStepPublish, RetryIntentRepublish,
			`{"run_id":"run-1","attempt_id":"att-1","queued_at":"q-1","run_spec_sha256":"sha256:pinned-spec","package_digest":"sha256:pinned-package","step":"publish"}`,
			"prp_5D17N6EYHKWDY6X87WVHRW7A4Z", "sha256:024d68c4470701b9cf747f6e87b40f67df8e4b3909d86f8200edbf5d01b468e5"},
		// The rerun's proposal id is derived from its intent, as before; its
		// params, and so its binding, now name the job's step.
		"rerun": {RetryStepRun, RetryIntentRerun,
			`{"run_id":"run-1","attempt_id":"att-1","queued_at":"q-1","run_spec_sha256":"sha256:pinned-spec","package_digest":"sha256:pinned-package","step":"run"}`,
			"prp_15MR1R89TWHF8GCT53DRZ0C8HS", "sha256:0c1bcd240cfd465809d5a755b58660cefc7adcd00e43e8da2fae6a836932eef9"},
	} {
		t.Run(name, func(t *testing.T) {
			p := base
			p.Step = want.step
			raw, err := json.Marshal(p)
			require.NoError(t, err)
			assert.Equal(t, want.params, string(raw))
			assert.Equal(t, want.intent, p.Intent())
			id, err := RetryIntentProposalID(p.RunID, ref, job.Version, p.Intent())
			require.NoError(t, err)
			binding, err := BindingDigest(job, ActionSpec{Name: ActionRetryRun, Params: raw})
			require.NoError(t, err)
			assert.Equal(t, want.proposal, id)
			assert.Equal(t, want.binding, binding)
		})
	}
}
