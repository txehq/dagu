// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	txeclient "github.com/dagucloud/dagu/v2/internal/txe/client"
)

// A change made by the hub or by a worker's own check has no session. It is
// named by what the registry recorded instead of being left blank.
func TestTXEActorName(t *testing.T) {
	assert.Equal(t, "cc2-s855054", txeActorName(txeclient.Actor{Kind: "cli", ID: "admin", Session: "cc2-s855054"}))
	assert.Equal(t, "reconciler registry", txeActorName(txeclient.Actor{Kind: "reconciler", ID: "registry"}))
	assert.Equal(t, "cli", txeActorName(txeclient.Actor{Kind: "cli"}))
	assert.Equal(t, "admin", txeActorName(txeclient.Actor{ID: "admin"}))
	assert.Equal(t, "(not recorded)", txeActorName(txeclient.Actor{}))
}

// An error is printed on one line with everything unprintable escaped,
// because it may quote what another session stored. Two errors are laid out
// over several lines by this program or by the YAML reader, and keep their
// line breaks; anything else in them that is not printable is still escaped.
func TestTXEShownErrorKeepsTheLayoutOfASpecError(t *testing.T) {
	reader := errors.New("[3:1] unknown field \"titel\"\n   2 | job_key: abc\n>  3 | titel: \x1b[31mtypo\n       ^")
	shown := (&txeShownError{err: fmt.Errorf("register: %w", &txeclient.SpecSyntaxError{Path: "job.yaml", Err: reader})}).Error()
	assert.Equal(t, "register: parse job spec job.yaml: [3:1] unknown field \"titel\"\n   2 | job_key: abc\n>  3 | titel: \\x1b[31mtypo\n       ^", shown)

	fromHub := (&txeShownError{err: errors.New("the hub said: first\nsecond")}).Error()
	assert.Equal(t, `the hub said: first\x0asecond`, fromHub)
}
