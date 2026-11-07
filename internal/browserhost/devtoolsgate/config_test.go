// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	valid := Config{Token: NewToken(), Executable: "/usr/bin/chrome", Args: ChromeArgs(LaunchOptions{UserDataDir: "/tmp/p"})}
	require.NoError(t, valid.validate())

	cases := map[string]Config{
		"no token":                {Executable: "/usr/bin/chrome"},
		"token with path":         {Token: "a/b", Executable: "/usr/bin/chrome"},
		"no executable":           {Token: NewToken()},
		"negative cap":            {Token: NewToken(), Executable: "/usr/bin/chrome", MaxLifetime: -time.Second},
		"negative unattended cap": {Token: NewToken(), Executable: "/usr/bin/chrome", MaxUnattended: -time.Second},
		"port flag":               {Token: NewToken(), Executable: "/usr/bin/chrome", Args: []string{"--remote-debugging-port=9222"}},
		"pipe flag":               {Token: NewToken(), Executable: "/usr/bin/chrome", Args: []string{"--remote-debugging-pipe"}},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, cfg.validate())
		})
	}
	assert.True(t, errors.Is(cases["port flag"].validate(), ErrDebuggingFlagInArgs))
	assert.True(t, errors.Is(cases["no token"].validate(), ErrTokenRequired))
	// The lifetime policy is resolved in one place: zero MaxUnattended is
	// the default, zero MaxLifetime is no hard cap, explicit values stand.
	assert.Equal(t, lifetimePolicy{hardCap: 0, unattended: DefaultMaxUnattended}, Config{}.lifetime())
	assert.Equal(t, lifetimePolicy{hardCap: time.Hour, unattended: DefaultMaxUnattended}, Config{MaxLifetime: time.Hour}.lifetime())
	assert.Equal(t, lifetimePolicy{hardCap: 0, unattended: 90 * time.Minute}, Config{MaxUnattended: 90 * time.Minute}.lifetime())
	assert.Equal(t, lifetimePolicy{hardCap: time.Hour, unattended: time.Minute}, Config{MaxLifetime: time.Hour, MaxUnattended: time.Minute}.lifetime())
}

func TestTokenAndBaseURL(t *testing.T) {
	t.Parallel()
	token := NewToken()
	assert.Len(t, token, 26, "rand.Text gives 26 base32 characters")
	assert.NotEqual(t, token, NewToken())

	base := BaseURL(4321, token)
	assert.Equal(t, "http://127.0.0.1:4321/"+token, base)
	assert.Equal(t, token, TokenOf(base))
	assert.Equal(t, token, TokenOf(base+"/json/version"))
	assert.Equal(t, token, TokenOf("ws://127.0.0.1:4321/"+token+"/devtools/browser/x"))
	assert.Equal(t, "", TokenOf("http://127.0.0.1:9222"))
	assert.Equal(t, "", TokenOf("http://127.0.0.1:9222/"))
	assert.Equal(t, "", TokenOf("::not a url"))
	_, err := url.Parse(base)
	require.NoError(t, err)
}
