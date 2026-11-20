// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// probeLeftovers lists what the probe left in the profile.
func probeLeftovers(t *testing.T, profile string) []string {
	t.Helper()
	entries, err := os.ReadDir(profile)
	require.NoError(t, err)
	var left []string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), probeDirName) {
			left = append(left, entry.Name())
		}
	}
	return left
}

func runProbe(t *testing.T, tg *testGate, profile string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return checkOffTheRecordRefused(ctx, tg.mux, []string{"--user-data-dir=" + profile})
}

func fakeProbeLifecycle(f *fakeBrowser) (loaded, uninstalled []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.extensionsLoaded...), append([]string(nil), f.uninstalled...)
}

// A browser that refuses a window off the record passes, and the probe the
// gate wrote into its own profile is uninstalled, gone from the browser's
// targets and list, and its files removed.
func TestOffTheRecordCheckPassesABrowserThatRefuses(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	profile := ownedProfile(t)
	require.NoError(t, runProbe(t, tg, profile))
	loaded, uninstalled := fakeProbeLifecycle(tg.fake)
	require.Len(t, loaded, 1)
	assert.Equal(t, profile, filepath.Dir(loaded[0]), "the probe is written in the gate's own profile")
	assert.True(t, strings.HasPrefix(filepath.Base(loaded[0]), probeDirName))
	assert.Equal(t, []string{fakeProbeID}, uninstalled)
	assert.False(t, tg.mux.hasTarget(probeURL(fakeProbeID)))
	assert.Empty(t, probeLeftovers(t, profile))
}

// The check rejects a browser that opens a window off the record, as a
// profile without the gate's preference does (or a platform policy can
// make it); the window is closed before it runs, and the probe removed.
func TestOffTheRecordCheckRejectsABrowserThatOpensOne(t *testing.T) {
	t.Parallel()
	tg := startTestGateWith(t, func(_ *mux, f *fakeBrowser) { f.offTheRecord = "opens" })
	profile := ownedProfile(t)
	err := runProbe(t, tg, profile)
	require.ErrorIs(t, err, errOffTheRecordAllowed)
	assert.ErrorContains(t, err, "IncognitoModeAvailability")
	tg.fake.mu.Lock()
	var opened []string
	for _, target := range tg.fake.targets {
		if target.context == fakeOffTheRecordContext {
			opened = append(opened, target.id)
		}
	}
	resumed := append([]string(nil), tg.fake.resumed...)
	tg.fake.mu.Unlock()
	assert.Empty(t, opened, "the window off the record is closed")
	for _, id := range opened {
		assert.NotContains(t, resumed, id)
	}
	_, uninstalled := fakeProbeLifecycle(tg.fake)
	assert.Equal(t, []string{fakeProbeID}, uninstalled)
	assert.Empty(t, probeLeftovers(t, profile))
}

// A browser that cannot be asked is refused: one without extensions, one
// whose probe never answers within probeTimeout, and one whose probe the
// gate cannot verify it removed.
func TestOffTheRecordCheckFailsClosed(t *testing.T) {
	t.Parallel()
	t.Run("no extensions", func(t *testing.T) {
		t.Parallel()
		tg := startTestGateWith(t, func(_ *mux, f *fakeBrowser) { f.offTheRecord = "none" })
		profile := ownedProfile(t)
		assert.ErrorIs(t, runProbe(t, tg, profile), errNoExtensions)
		assert.Empty(t, probeLeftovers(t, profile))
	})
	t.Run("no answer", func(t *testing.T) {
		t.Parallel()
		tg := startTestGateWith(t, func(_ *mux, f *fakeBrowser) { f.offTheRecord = "hangs" })
		profile := ownedProfile(t)
		started := time.Now()
		err := runProbe(t, tg, profile)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.Less(t, time.Since(started), probeTimeout+probeCleanupTimeout, "bounded by probeTimeout")
		_, uninstalled := fakeProbeLifecycle(tg.fake)
		assert.Equal(t, []string{fakeProbeID}, uninstalled, "removed all the same")
		assert.Empty(t, probeLeftovers(t, profile))
	})
	t.Run("probe not removed", func(t *testing.T) {
		t.Parallel()
		tg := startTestGateWith(t, func(_ *mux, f *fakeBrowser) { f.keepsProbe = true })
		profile := ownedProfile(t)
		assert.ErrorContains(t, runProbe(t, tg, profile), "remove the off-the-record probe: uninstall")
	})
}

// Start fails, and serves nobody, for a browser the check refuses.
func TestStartServesNoBrowserTheCheckRefuses(t *testing.T) {
	t.Parallel()
	self, err := os.Executable()
	require.NoError(t, err)
	for flag, want := range map[string]string{
		"--opens-off-the-record": "IncognitoModeAvailability",
		"--no-extensions":        "runs no extensions",
		"--probe-hangs":          "deadline exceeded",
	} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			handle, err := Start(ctx, self, Config{Token: NewToken(), Executable: self, Args: fakeBrowserArgs(flag)})
			require.Error(t, err)
			assert.Nil(t, handle, "nothing is served")
			assert.Contains(t, err.Error(), want)
		})
	}
}
