// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity/fixture"
)

func machineOnly(t *testing.T, l *fixture.Layout) []continuity.Issue {
	t.Helper()
	inv, err := continuity.Scan(context.Background(), continuity.Options{
		Roots:         []continuity.Root{{Area: continuity.AreaMachineHome, Path: l.MachineHome, Label: "laptop-home"}},
		ExpectedOwner: fixture.StableOwner, Label: "test", Now: func() time.Time { return scanTime }})
	require.NoError(t, err)
	return continuity.Validate(inv, continuity.Policy{})
}

// A machine home is inventoried on its machine, apart from the hub. What
// only the hub's registry can answer is reported as not checked; what the
// home itself shows still blocks.
func TestMachineHomeValidatesAlone(t *testing.T) {
	t.Parallel()
	l, f := build(t)
	issues := machineOnly(t, l)
	assert.Empty(t, continuity.Blocking(issues))
	assert.Equal(t, 3, codes(issues, continuity.SeverityWarn)["not_checked"], "the owner record, and machine.json's owner and machine")

	t.Run("an identity of another owner", func(t *testing.T) {
		l, _ := build(t)
		edit(t, homePath(l, "machine.json"), func(m map[string]any) { m["owner_id"] = impostor })
		assert.Positive(t, codes(machineOnly(t, l), continuity.SeverityBlock)["owner_mismatch"])
	})
	t.Run("a package that changed", func(t *testing.T) {
		l, _ := build(t)
		p := packageFile(l, f, "validation")
		require.NoError(t, os.Chmod(p, 0o700))
		require.NoError(t, os.WriteFile(p, []byte("#!/bin/sh\necho changed\n"), 0o700))
		assert.Positive(t, codes(machineOnly(t, l), continuity.SeverityBlock)["package_corrupt"])
	})
	t.Run("with the hub's data, a missing owner still blocks", func(t *testing.T) {
		l, _ := build(t)
		require.NoError(t, os.Remove(regPath(l, "owners/"+fixture.StableOwner)))
		got := blocking(t, l)
		assert.Positive(t, got["owner_missing"])
		assert.Zero(t, codes(continuity.Validate(scan(t, l), continuity.Policy{}), continuity.SeverityWarn)["not_checked"])
	})
}
