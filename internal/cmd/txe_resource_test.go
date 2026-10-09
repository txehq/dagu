// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"errors"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/txe/probe"
)

const (
	txeTestMachine = "mch_01JTXE0000000000000000F1X3"
	txeTestJob     = "job_01JTXE00000000000000000AAA"
)

func runTXEResource(t *testing.T, args ...string) error {
	t.Helper()
	keepDaguEnvironment(t)
	t.Setenv("TXE_DAGU_HOME", t.TempDir())
	root := &cobra.Command{Use: "dagu", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(TXE())
	root.SetArgs(append([]string{"txe", "resource", "check"}, args...))
	return root.Execute()
}

func exitCode(err error) int {
	if coded, ok := errors.AsType[interface {
		error
		ExitCode() int
	}](err); ok {
		return coded.ExitCode()
	}
	if err != nil {
		return 1
	}
	return 0
}

// Arguments that do not bind a check to one machine and one rendered job
// version are refused with exit 2 before anything is observed or reported.
func TestTXEResourceCheckRefusesUnboundArguments(t *testing.T) {
	for name, args := range map[string][]string{
		"no version":         {"--machine", txeTestMachine, "--job", txeTestJob},
		"version zero":       {"--machine", txeTestMachine, "--job", txeTestJob, "--job-version", "0"},
		"version not number": {"--machine", txeTestMachine, "--job", txeTestJob, "--job-version", "two"},
		"version alone":      {"--machine", txeTestMachine, "--job-version", "2"},
		"bad machine":        {"--machine", "laptop"},
		"path in job":        {"--machine", txeTestMachine, "--job", "job_../../x", "--job-version", "1"},
		"job id is machine":  {"--machine", txeTestMachine, "--job", txeTestMachine, "--job-version", "1"},
		"bad timeout":        {"--machine", txeTestMachine, "--timeout", "-5s"},
	} {
		t.Run(name, func(t *testing.T) {
			err := runTXEResource(t, args...)
			require.Error(t, err)
			assert.Equal(t, probe.ExitUsage, exitCode(err), err.Error())
		})
	}
}

// --machine is required: the check never guesses which machine it is on.
func TestTXEResourceCheckRequiresMachine(t *testing.T) {
	err := runTXEResource(t, "--job", txeTestJob, "--job-version", "1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "machine")
}

// Without the worker installer's machine identity there is nothing to bind
// to; the check fails instead of reporting as someone else.
func TestTXEResourceCheckNeedsTheMachineIdentity(t *testing.T) {
	err := runTXEResource(t, "--machine", txeTestMachine)
	require.Error(t, err)
	assert.Equal(t, probe.ExitInternal, exitCode(err), err.Error())
}
