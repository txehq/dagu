// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
)

// What a txe command prints never carries a control character from a stored
// record, whether it is formatted text, an error, or JSON.
func TestTXEOutputIsCleaned(t *testing.T) {
	hostile := "title\x1b[2J\nRegistration: ready\u202e"

	t.Run("FormattedText", func(t *testing.T) {
		var out bytes.Buffer
		p := &txePrinter{w: &out}
		p.f("Title: %s (%d) %v\n", hostile, 3, []string{hostile})
		require.NoError(t, p.err)
		assert.NotContains(t, out.String(), "\x1b")
		assert.NotContains(t, out.String(), "\u202e")
		assert.Equal(t, 1, bytes.Count(out.Bytes(), []byte("\n")), "a stored line break did not become a line of output")
		assert.Contains(t, out.String(), `title\x1b[2J\x0aRegistration: ready\u202e (3)`)
	})

	t.Run("Error", func(t *testing.T) {
		root := &cobra.Command{Use: "txe"}
		root.AddCommand(&cobra.Command{Use: "boom", RunE: func(*cobra.Command, []string) error {
			return &txeclient.ErrRejected{RequestID: "req_1", Refusal: &txeclient.Error{Status: 409, Code: "duplicate", Message: hostile}}
		}})
		txeCleanErrors(root)
		root.SetArgs([]string{"boom"})
		root.SilenceErrors, root.SilenceUsage = true, true

		err := root.Execute()
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "\x1b")
		assert.NotContains(t, err.Error(), "\n")
		// The original error is still reachable.
		var rejected *txeclient.ErrRejected
		require.ErrorAs(t, err, &rejected)
		assert.True(t, txeclient.IsCode(err, "duplicate"))
		assert.False(t, errors.Is(err, txeclient.ErrReviewerSession))
	})

	t.Run("JSON", func(t *testing.T) {
		var out bytes.Buffer
		require.NoError(t, txeWriteJSON(&out, map[string]any{"title": hostile, "raw": json.RawMessage(`{"reason":"a\u009bb"}`), "name": "caf\u00e9 \U0001f600"}))
		for _, r := range out.String() {
			if r != '\n' {
				assert.False(t, r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x202e, "output holds %U", r)
			}
		}
		// It is still the same JSON.
		var back map[string]any
		require.NoError(t, json.Unmarshal(out.Bytes(), &back))
		assert.Equal(t, hostile, back["title"])
		assert.Equal(t, "caf\u00e9 \U0001f600", back["name"])
		assert.Equal(t, map[string]any{"reason": "a\u009bb"}, back["raw"])
	})
}

// keepDaguEnvironment puts the process's DAGU_* variables back when the test
// ends. A txe command clears them, and sets two, for the whole process.
func keepDaguEnvironment(t *testing.T) {
	t.Helper()
	before := map[string]string{}
	for _, variable := range os.Environ() {
		if name, value, _ := strings.Cut(variable, "="); strings.HasPrefix(name, "DAGU_") {
			before[name] = value
		}
	}
	t.Cleanup(func() {
		for _, variable := range os.Environ() {
			if name, _, _ := strings.Cut(variable, "="); strings.HasPrefix(name, "DAGU_") {
				_ = os.Unsetenv(name)
			}
		}
		for name, value := range before {
			_ = os.Setenv(name, value)
		}
	})
}

// A configuration with relative paths puts the context store wherever the
// command happens to run. The store a session resolved is recorded as two
// absolute directories, and a command given those two reads the same store
// from any directory, as a job's publish step must.
func TestTXEHubContextPinsResolvedStore(t *testing.T) {
	keepDaguEnvironment(t)
	base, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	// The user's home is HOME on Unix and USERPROFILE on Windows.
	t.Setenv("HOME", base)
	t.Setenv("USERPROFILE", base)
	t.Setenv("TXE_DAGU_HOME", filepath.Join(base, "txe-home"))
	home, session, step := filepath.Join(base, "hub-home"), filepath.Join(base, "session"), filepath.Join(base, "step")
	for _, dir := range []string{home, session, step} {
		require.NoError(t, os.MkdirAll(dir, 0o700))
	}
	config := filepath.Join(base, "hub.yaml")
	require.NoError(t, os.WriteFile(config, []byte("paths:\n  contexts_dir: ./contexts\n  data_dir: ./data\n"), 0o600))

	probe := func(dir string, args ...string) txeclient.HubContext {
		t.Helper()
		t.Chdir(dir)
		var hub txeclient.HubContext
		root := &cobra.Command{Use: "dagu", SilenceErrors: true, SilenceUsage: true}
		family := TXE()
		family.AddCommand(NewCommand(&cobra.Command{
			Use: "probe", Annotations: map[string]string{txeLocalAnnotation: "true"},
		}, nil, func(ctx *Context, _ []string) error {
			hub = txeHubContext(ctx)
			return nil
		}))
		root.AddCommand(family)
		root.SetArgs(append([]string{"txe", "probe"}, args...))
		require.NoError(t, root.Execute())
		return hub
	}

	registered := probe(session, "--dagu-home", home, "--config", config)
	assert.Equal(t, filepath.Join(session, "contexts"), registered.ContextsDir)
	assert.Equal(t, filepath.Join(session, "data"), registered.DataDir)
	assert.Equal(t, config, registered.ConfigFile)

	// The same two flags, from a step's directory, name a different store.
	replayed := probe(step, "--dagu-home", home, "--config", config)
	assert.Equal(t, filepath.Join(step, "contexts"), replayed.ContextsDir)

	// With the two directories named outright, it is the registered store.
	pinned := probe(step, "--dagu-home", home, "--config", config,
		"--contexts-dir", registered.ContextsDir, "--data-dir", registered.DataDir)
	assert.Equal(t, registered.ContextsDir, pinned.ContextsDir)
	assert.Equal(t, registered.DataDir, pinned.DataDir)

	// A home written with ~ is recorded as the configuration loader reads it.
	userHome, err := os.UserHomeDir()
	require.NoError(t, err)
	tilde := probe(session, "--dagu-home", "~/custom-dagu")
	assert.Equal(t, filepath.Join(userHome, "custom-dagu"), tilde.DaguHome)
}

// A txe command takes its context store from its flags. DAGU_* variables,
// which a job's step inherits from the worker, are dropped before the
// configuration is read, and the default store is the TXE home's own.
func TestTXEDefaultsIgnoreInheritedEnvironment(t *testing.T) {
	keepDaguEnvironment(t)
	txeHome := filepath.Join(t.TempDir(), "txe-home")
	worker := filepath.Join(t.TempDir(), "worker-home")
	t.Setenv("TXE_DAGU_HOME", txeHome)
	inherited := []string{"DAGU_HOME", "DAGU_CONTEXTS_DIR", "DAGU_DATA_DIR", "DAGU_ENCRYPTION_KEY", "DAGU_CONFIG", "DAGU__DATA"}
	for _, name := range inherited {
		t.Setenv(name, filepath.Join(worker, name))
	}
	t.Setenv("DAG_RUN_ID", "run-1")

	command := func() *cobra.Command {
		c := &cobra.Command{Use: "publish"}
		c.Flags().String("dagu-home", "", "")
		c.Flags().String("context", "", "")
		return c
	}

	c := command()
	require.NoError(t, txeDefaults(c, nil))
	for _, name := range inherited {
		_, set := os.LookupEnv(name)
		assert.False(t, set, "%s survived", name)
	}
	assert.Equal(t, "run-1", os.Getenv("DAG_RUN_ID"), "a run's own variables are kept")
	assert.Equal(t, txeHome, os.Getenv("TXE_DAGU_HOME"))
	home, _ := c.Flags().GetString("dagu-home")
	assert.Equal(t, filepath.Join(txeHome, "client"), home)
	name, _ := c.Flags().GetString("context")
	assert.Equal(t, txeContextName, name)

	// A store named by flag is kept.
	c = command()
	require.NoError(t, c.Flags().Set("dagu-home", "/srv/other-store"))
	require.NoError(t, c.Flags().Set("context", "staging"))
	require.NoError(t, txeDefaults(c, nil))
	home, _ = c.Flags().GetString("dagu-home")
	assert.Equal(t, "/srv/other-store", home)
	name, _ = c.Flags().GetString("context")
	assert.Equal(t, "staging", name)
}

// The session a change is attributed to is derived for a Claude Code session
// and never invented.
func TestTXESession(t *testing.T) {
	command := &cobra.Command{Use: "x"}
	command.Flags().String("session", "", "")
	ctx := &Context{Context: t.Context(), Command: command}

	t.Setenv("TMUX", "")
	t.Setenv("TXE_SESSION", "")
	t.Setenv("CODEX_THREAD_ID", "")
	t.Setenv("CLAUDE_CONFIG_DIR", "/Users/x/.claude2")
	t.Setenv("CLAUDE_CODE_SESSION_ID", "855054c9-633c-4dcc")
	assert.Equal(t, "cc2-s855054", txeSession(ctx))

	t.Setenv("CLAUDE_CONFIG_DIR", "/Users/x/.claude")
	assert.Equal(t, "cc-s855054", txeSession(ctx))

	// A Codex thread started from that Claude session carries both ids. The
	// Claude ones are its parent's, so nothing is derived.
	t.Setenv("CLAUDE_CONFIG_DIR", "/Users/x/.claude2")
	t.Setenv("CODEX_THREAD_ID", "0199e3a4-7c1e-7b2a-9d4f-5e6a7b8c9d0e")
	assert.Empty(t, txeSession(ctx), "a Codex thread is not its parent Claude session")
	t.Setenv("CODEX_THREAD_ID", "")

	t.Setenv("CLAUDE_CONFIG_DIR", "/Users/x/.config/other")
	assert.Empty(t, txeSession(ctx), "not a Claude Code session: nothing is guessed")

	t.Setenv("TXE_SESSION", "codex-1a2b3c")
	assert.Equal(t, "codex-1a2b3c", txeSession(ctx))

	require.NoError(t, command.Flags().Set("session", "cc9-explicit"))
	assert.Equal(t, "cc9-explicit", txeSession(ctx))
}

// Every txe subcommand belongs to the txe family, which is what makes the
// whole family use the hub's context.
func TestTXECommandFamily(t *testing.T) {
	root := &cobra.Command{Use: "dagu"}
	txe := TXE()
	root.AddCommand(txe)
	for _, sub := range txe.Commands() {
		assert.Equal(t, "txe", commandFamilyName(sub), sub.Name())
		for _, leaf := range sub.Commands() {
			assert.Equal(t, "txe", commandFamilyName(leaf), leaf.Name())
		}
	}
	assert.Equal(t, commandScopeContextAware, scopeForCommand("txe"))
	// A command of another family that happens to be called txe deeper down
	// is not affected.
	other := &cobra.Command{Use: "txe"}
	parent := &cobra.Command{Use: "other"}
	parent.AddCommand(other)
	root.AddCommand(parent)
	assert.False(t, isTXECommand(other))
}
