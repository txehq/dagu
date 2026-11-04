// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// On a machine with a context store but no "txe" context yet (after the
// developer install, before sign-in), every command that needs the hub says
// how to get one, not "context not found" (TXE-4723). The hint is the one
// "dagu txe login" gives without --hub.
func TestTXEHubCommandsWithoutAContextSayToLogIn(t *testing.T) {
	f := newTXEStoreFixture(t)
	for _, args := range [][]string{
		{"whoami"},
		{"list"},
		{"inspect", "job_01ARZ3NDEKTSV4RRFFQ69G5FAV"},
		{"register", "-f", "job.yaml"},
		{"login"},
	} {
		out, err := f.run(args...)
		require.Error(t, err, args)
		assert.Contains(t, err.Error(), txeNoHubHint, "%v: %s", args, out)
		assert.NotContains(t, err.Error(), "context not found", args)
		if args[0] != "login" {
			// The store it was missing from is named, for a log of a step
			// that ran with the wrong store.
			assert.Contains(t, err.Error(), `no context "txe" in `+f.contexts+": ", args)
		}
	}
}

// A --context the caller named keeps the resolver's error, whether it names
// the hub's context or another.
func TestTXEANamedMissingContextIsStillAnError(t *testing.T) {
	f := newTXEStoreFixture(t)
	for _, name := range []string{txeContextName, "staging"} {
		_, err := f.run("whoami", "--context", name)
		require.Error(t, err, name)
		assert.Contains(t, err.Error(), "failed to resolve context \""+name+"\"", name)
		assert.Contains(t, err.Error(), "context not found", name)
		assert.NotContains(t, err.Error(), txeNoHubHint, name)
	}
}

// A local command runs without the hub's context: doctor reports the
// missing context as a failed check with the same hint, and exits as it did.
func TestTXEDoctorWithoutAContextReportsTheLoginHint(t *testing.T) {
	f := newTXEStoreFixture(t)
	out, err := f.run("doctor")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "context not found")
	assert.Contains(t, out, "hub context")
	assert.Contains(t, out, txeNoHubHint)
}

// The hook marks only a context it defaulted; a named one carries no hint.
func TestTXEDefaultsMarksADefaultedContext(t *testing.T) {
	keepDaguEnvironment(t)
	t.Setenv("TXE_DAGU_HOME", t.TempDir())
	command := func() *cobra.Command {
		c := &cobra.Command{Use: "whoami"}
		c.Flags().String("dagu-home", "", "")
		c.Flags().String("context", "", "")
		return c
	}

	c := command()
	require.NoError(t, txeDefaults(c, nil))
	assert.Equal(t, txeNoHubHint, c.Annotations[defaultContextHintAnnotation])

	c = command()
	require.NoError(t, c.Flags().Set("context", txeContextName))
	require.NoError(t, txeDefaults(c, nil))
	assert.Empty(t, c.Annotations[defaultContextHintAnnotation])

	local := command()
	local.Annotations = map[string]string{txeLocalAnnotation: "true"}
	require.NoError(t, txeDefaults(local, nil))
	assert.Empty(t, local.Annotations[defaultContextHintAnnotation])
}
