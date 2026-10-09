// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
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
