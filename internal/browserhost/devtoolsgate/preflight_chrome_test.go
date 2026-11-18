// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startRealMux starts real Chrome on args with the gate's own start, as the
// gate does up to its check, but without the profile preference launchBrowser
// sets: a test sets it, or leaves it out, itself. The browser sends every
// request to proxy.
func startRealMux(t *testing.T, args []string, proxy *credentialProxy) *mux {
	t.Helper()
	process, err := startBrowserProcess(Config{Executable: requireChrome(t), Args: args})
	require.NoError(t, err)
	t.Cleanup(func() { _ = process.end() })
	m := newMux(process.pipe)
	newProxyResponder(m, *proxy.auth()).install()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = m.run(ctx) }()
	startCtx, cancelStart := context.WithTimeout(ctx, 60*time.Second)
	defer cancelStart()
	_, err = readVersion(startCtx, m)
	require.NoError(t, err)
	require.NoError(t, m.start(startCtx))
	return m
}

func realChromeArgs(profile string, proxy *credentialProxy) []string {
	return ChromeArgs(LaunchOptions{
		UserDataDir: profile,
		Headless:    true,
		NoSandbox:   os.Getenv("CI") != "" || (runtime.GOOS == "linux" && os.Geteuid() == 0),
		Extra:       proxy.chromeArgs(),
	})
}

// browserTargets lists the browser's own report of its targets, past the
// gate's filters: the URL and context of each.
func browserTargets(t *testing.T, m *mux) []targetInfoWithURL {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := m.call(ctx, "", "Target.getTargets", map[string]any{})
	require.NoError(t, err)
	var listed struct {
		TargetInfos []targetInfoWithURL `json:"targetInfos"`
	}
	require.NoError(t, json.Unmarshal(result, &listed))
	return listed.TargetInfos
}

type targetInfoWithURL struct {
	TargetID         string `json:"targetId"`
	Type             string `json:"type"`
	URL              string `json:"url"`
	BrowserContextID string `json:"browserContextId"`
}

// assertProbeGone checks, in the browser's own report, that no target of an
// extension is left, and that the probe's files are gone from the profile.
func assertProbeGone(t *testing.T, m *mux, profile string) {
	t.Helper()
	for _, target := range browserTargets(t, m) {
		assert.False(t, strings.HasPrefix(target.URL, "chrome-extension://"), "a probe target is left: %+v", target)
	}
	assert.Empty(t, probeLeftovers(t, profile))
}

// Real Chrome on the gate's own profile WITHOUT its preference allows a
// window off the record, and the check rejects that outcome: the gate would
// serve nobody. The probe's window loads nothing (no request reaches the
// proxy or the site), it is closed, and the probe is removed. This shows the
// check rejects an allowed-incognito outcome; it is not a test of platform
// policy, which outranks the preference the same way.
func TestRealChromeCheckRejectsABrowserThatAllowsWindowsOffTheRecord(t *testing.T) {
	site := newTestSite(t)
	proxy := newCredentialProxy(t, site)
	profile := ownedProfile(t)
	args := realChromeArgs(profile, proxy)
	m := startRealMux(t, args, proxy)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	err := checkOffTheRecordRefused(ctx, m, args)
	require.ErrorIs(t, err, errOffTheRecordAllowed)
	t.Logf("the check: %v", err)
	eventually(t, 10*time.Second, func() bool {
		for _, target := range browserTargets(t, m) {
			if target.BrowserContextID != m.ownContext {
				return false
			}
		}
		return true
	}, "the window off the record is closed")
	assertProbeGone(t, m, profile)
	// A bounded margin for a request a window would have sent.
	time.Sleep(time.Second)
	assertNoProbeTraffic(t, proxy, site)
}

// Real Chrome on the gate's own profile with its preference passes the
// check, and the probe is removed before anyone could be served.
func TestRealChromeCheckPassesABrowserThatRefusesWindowsOffTheRecord(t *testing.T) {
	site := newTestSite(t)
	proxy := newCredentialProxy(t, site)
	profile := ownedProfile(t)
	args := realChromeArgs(profile, proxy)
	require.NoError(t, disableOffTheRecord(args))
	m := startRealMux(t, args, proxy)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	started := time.Now()
	require.NoError(t, checkOffTheRecordRefused(ctx, m, args))
	t.Logf("the check took %v", time.Since(started))
	assertProbeGone(t, m, profile)
	assertNoProbeTraffic(t, proxy, site)
}

// assertNoProbeTraffic checks that nothing the probe or its window could
// send reached the network: no request reached the site, and the proxy
// carried or challenged none and refused none for the site. Chrome's own
// background requests (its services, refused by the test proxy, as in a
// browser that never ran the probe) are logged, not counted.
func assertNoProbeTraffic(t *testing.T, proxy *credentialProxy, site *testSite) {
	t.Helper()
	proxy.mu.Lock()
	refused := append([]string(nil), proxy.refused...)
	challenged, authorized := len(proxy.challenged), len(proxy.authorized)
	proxy.mu.Unlock()
	t.Logf("Chrome's own requests the proxy refused: %v", refused)
	assert.Zero(t, challenged+authorized, "the proxy carried or challenged nothing")
	for _, request := range refused {
		assert.NotContains(t, request, site.host(), "nothing for the site reached the proxy")
		assert.NotContains(t, request, site.crossSiteHost())
	}
	assert.Zero(t, site.totalHits(), "nothing reached the site")
}

// headlessShellEnv names Chrome's headless shell, for
// TestRealHeadlessShellIsRefused.
const headlessShellEnv = "CHROME_HEADLESS_SHELL_PATH"

// Chrome's headless shell runs no extension, so the gate cannot ask it
// whether it refuses windows off the record, and does not start it: Start
// fails with that reason and serves nothing.
func TestRealHeadlessShellIsRefused(t *testing.T) {
	shell := os.Getenv(headlessShellEnv)
	if shell == "" {
		t.Skip(headlessShellEnv + " is not set")
	}
	self, err := os.Executable()
	require.NoError(t, err)
	profile, err := os.MkdirTemp("", "dagu-gate-headless-shell-")
	require.NoError(t, err)
	// Registered first, so it runs last: the shell's last processes may
	// still be writing as it ends.
	t.Cleanup(func() {
		eventually(t, 15*time.Second, func() bool { return os.RemoveAll(profile) == nil }, "the profile is removed")
	})
	require.NoError(t, ClaimProfile(profile))
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	handle, err := Start(ctx, self, Config{
		Token:      NewToken(),
		Executable: shell,
		Args: ChromeArgs(LaunchOptions{
			UserDataDir: profile,
			Headless:    true,
			NoSandbox:   os.Getenv("CI") != "" || (runtime.GOOS == "linux" && os.Geteuid() == 0),
		}),
	})
	require.Error(t, err)
	assert.Nil(t, handle, "nothing is served")
	assert.Contains(t, err.Error(), errNoExtensions.Error())
	assert.Empty(t, probeLeftovers(t, profile))
}
