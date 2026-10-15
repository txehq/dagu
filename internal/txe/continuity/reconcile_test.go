// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package continuity_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/continuity"
	"github.com/dagucloud/dagu/v2/internal/txe/continuity/fixture"
)

func scanRoots(t *testing.T, label string, rs ...continuity.Root) *continuity.Inventory {
	t.Helper()
	inv, err := continuity.Scan(context.Background(), continuity.Options{Roots: rs, ExpectedOwner: fixture.StableOwner,
		Label: label, Now: func() time.Time { return scanTime }})
	require.NoError(t, err)
	return inv
}

// hubAndMachine scans the hub's roots and the machine home apart, as the
// freeze does: the hub in a Pod, the machine on the machine.
func hubAndMachine(t *testing.T, l *fixture.Layout) (hub, machine *continuity.Inventory) {
	t.Helper()
	rs := roots(l)
	return scanRoots(t, "freeze", rs[0], rs[1], rs[3]), scanRoots(t, "freeze", rs[2])
}

// Inventories taken apart and reconciled are the inventory of one scan:
// the same records and files, validated across the hub and the machine.
func TestReconcileIsOneScan(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	hub, machine := hubAndMachine(t, l)
	joint, err := continuity.Reconcile(hub, machine)
	require.NoError(t, err)
	issues := continuity.Validate(joint, continuity.Policy{})
	assert.Empty(t, continuity.Blocking(issues))
	assert.Zero(t, codes(issues, continuity.SeverityWarn)["not_checked"], "the registry is in the joint inventory")
	assert.ElementsMatch(t, []string{hub.Digest, machine.Digest}, joint.Parts)

	whole := scanRoots(t, "freeze", roots(l)...)
	assert.Equal(t, whole.Counts, joint.Counts)
	rep := continuity.Compare(whole, joint, continuity.CompareOptions{})
	assert.Empty(t, rep.Issues)
	assert.Empty(t, rep.Added)
	assert.Empty(t, rep.Changed)

	// The order of the parts does not matter.
	again, err := continuity.Reconcile(machine, hub)
	require.NoError(t, err)
	assert.Equal(t, joint.Digest, again.Digest)
}

// What only the two together can show blocks in the joint inventory,
// though each part alone validates.
func TestReconcileChecksAcrossInventories(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(t *testing.T, l *fixture.Layout, f *fixture.Facts)
		want   string
	}{
		{"the machine's identity names another owner", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) {
			edit(t, homePath(l, "machine.json"), func(m map[string]any) { m["owner_id"] = impostor })
		}, "owner_mismatch"},
		{"the hub no longer holds the machine", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			require.NoError(t, os.Remove(regPath(l, "machines/"+f.Machine)))
		}, "dangling_ref"},
		{"the hub no longer holds the owner", func(t *testing.T, l *fixture.Layout, _ *fixture.Facts) {
			require.NoError(t, os.Remove(regPath(l, "owners/"+fixture.StableOwner)))
		}, "owner_missing"},
		{"the machine lost a package the hub assigns to it", func(t *testing.T, l *fixture.Layout, f *fixture.Facts) {
			require.NoError(t, fixture.Unseal(homePath(l, "packages/"+f.Jobs["manual-retire"])))
			require.NoError(t, os.RemoveAll(homePath(l, "packages/"+f.Jobs["manual-retire"])))
		}, "package_missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, f := build(t)
			tc.break_(t, l, f)
			hub, machine := hubAndMachine(t, l)
			joint, err := continuity.Reconcile(hub, machine)
			require.NoError(t, err)
			got := codes(continuity.Validate(joint, continuity.Policy{}), continuity.SeverityBlock)
			assert.Positive(t, got[tc.want], "want %s, got %v", tc.want, got)
		})
	}
}

// Inventories that do not belong together are refused, never merged.
func TestReconcileRefusesWhatDoesNotBelongTogether(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	rs := roots(l)
	hub, machine := hubAndMachine(t, l)
	reseal := func(inv *continuity.Inventory, change func(*continuity.Inventory)) *continuity.Inventory {
		data, err := json.Marshal(inv)
		require.NoError(t, err)
		c, err := continuity.Decode(data)
		require.NoError(t, err)
		change(c)
		require.NoError(t, c.Seal())
		return c
	}
	joint, err := continuity.Reconcile(hub, machine)
	require.NoError(t, err)
	otherHub := rs[0]
	otherHub.Label = "hub-data-2"
	otherHome := rs[2]
	otherHome.Label = "laptop-home-2"
	otherDAGs := rs[1]
	otherDAGs.Label = "hub-dags-2"
	for name, parts := range map[string][]*continuity.Inventory{
		"one part":                 {hub},
		"the same part twice":      {hub, machine, machine},
		"no machine home":          {hub, scanRoots(t, "freeze", otherDAGs)},
		"no hub data directory":    {machine, scanRoots(t, "freeze", rs[1])},
		"two hub data directories": {hub, machine, scanRoots(t, "freeze", otherHub)},
		"two hub data directories, nothing else shared": {hub, machine, reseal(scanRoots(t, "freeze", otherHub), func(c *continuity.Inventory) {
			c.Records, c.Files = nil, nil
		})},
		"a root in two parts":        {hub, machine, scanRoots(t, "freeze", rs[2], otherHome)},
		"another label":              {hub, scanRoots(t, "after", rs[2])},
		"another expected owner":     {hub, reseal(machine, func(c *continuity.Inventory) { c.ExpectedOwner = impostor })},
		"another permission-bit set": {hub, reseal(machine, func(c *continuity.Inventory) { c.ModeBits = !c.ModeBits })},
		"a joint inventory as part":  {joint, machine},
		"a record in two parts": {hub, reseal(machine, func(c *continuity.Inventory) {
			c.Records = append(c.Records, hub.Records[0])
		})},
		"a file under the other part's root": {hub, reseal(machine, func(c *continuity.Inventory) {
			c.Files = append(c.Files, continuity.File{Root: "hub-data", Path: "dag-runs/planted", Policy: continuity.PolicyMutable})
		})},
		"a record under the other part's root": {machine, reseal(hub, func(c *continuity.Inventory) {
			c.Records = append(c.Records, continuity.Record{Store: "laptop-home", ID: "machine.json.planted", Class: continuity.ClassMachineIdentity})
		})},
		"a machine identity for the other part's root": {machine, reseal(hub, func(c *continuity.Inventory) {
			c.Machines = map[string]string{"laptop-home": "mch_01M4ZZZZZZZZZZZZZZZZZZZZZZ"}
		})},
		"a kept entry under the other part's root": {machine, reseal(hub, func(c *continuity.Inventory) {
			c.Kept = append(c.Kept, continuity.Kept{Root: "laptop-home", Path: "base.yaml", Digest: "sha256:" + strings.Repeat("a", 64), Provenance: "x"})
		})},
		"an exclusion under the other part's root": {machine, reseal(hub, func(c *continuity.Inventory) {
			c.Excluded = append(c.Excluded, continuity.Excluded{Root: "laptop-home", Path: "outputs", Reason: "x"})
		})},
		"a missing first part": {nil, hub, machine},
		"a missing later part": {hub, nil, machine},
		"a file under a root no part scanned": {hub, reseal(machine, func(c *continuity.Inventory) {
			c.Files = append(c.Files, continuity.File{Root: "nowhere", Path: "x", Policy: continuity.PolicyMutable})
		})},
		"a machine named twice": {hub, reseal(machine, func(c *continuity.Inventory) {
			c.Machines["laptop-home"] = "mch_01M4ZZZZZZZZZZZZZZZZZZZZZZ"
		}), reseal(scanRoots(t, "freeze", otherHome), func(c *continuity.Inventory) {
			c.Machines["laptop-home"] = c.Machines["laptop-home-2"]
		})},
	} {
		_, err := continuity.Reconcile(parts...)
		assert.ErrorIs(t, err, continuity.ErrIncompatible, name)
	}
}

// A malformed or altered inventory is refused when it is read.
func TestDecodeRefusesMalformedInventories(t *testing.T) {
	t.Parallel()
	l, _ := build(t)
	_, machine := hubAndMachine(t, l)
	data, err := json.Marshal(machine)
	require.NoError(t, err)
	_, err = continuity.Decode(data)
	require.NoError(t, err)
	for name, doc := range map[string]string{
		"an altered record":  strings.Replace(string(data), machine.Records[0].SHA256, "sha256:"+strings.Repeat("0", 64), 1),
		"an unknown field":   strings.Replace(string(data), `"format":`, `"merged_by":"x","format":`, 1),
		"trailing data":      string(data) + "{}",
		"a trailing bracket": string(data) + "]",
		"a trailing brace":   string(data) + "}garbage",
		"not JSON":           "{",
	} {
		_, err := continuity.Decode([]byte(doc))
		assert.Error(t, err, name)
	}
}

// The freeze gate: reconcile before, reconcile after, compare the joint
// inventories. A loss on either side blocks.
func TestJointCompareSeesBothSides(t *testing.T) {
	t.Parallel()
	l, f := build(t)
	before, err := continuity.Reconcile(hubAndMachine(t, l))
	require.NoError(t, err)
	require.NoError(t, os.Remove(filepath.Join(l.DataDir, filepath.FromSlash(f.HubArtifacts[0]))))
	require.NoError(t, os.Remove(homePath(l, f.MachineArtifacts[1])))
	after, err := continuity.Reconcile(hubAndMachine(t, l))
	require.NoError(t, err)
	missing := map[string]bool{}
	for _, i := range continuity.Compare(before, after, continuity.CompareOptions{}).Issues {
		if i.Code == "file_missing" {
			missing[strings.SplitN(i.ID, "/", 2)[0]] = true
		}
	}
	assert.True(t, missing["hub-data"], "%v", missing)
	assert.True(t, missing["laptop-home"], "%v", missing)
}
