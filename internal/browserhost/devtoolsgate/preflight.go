// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The profile's preference (profile.go) is what the browser should read,
// but a platform policy takes precedence over a profile in Chrome. So before
// the gate serves anyone it asks the browser itself, the way something
// running in it would: a probe extension the gate writes into its own
// profile asks for a window off the record, and the gate starts only when
// the browser refuses. What this shows is the browser's state at start.
//
//   - The probe is the gate's own: the gate writes it into a new directory of
//     its own profile, loads it, and asks on its own session on the probe's
//     worker, before it listens for any client. No client can supply, see or
//     skip it.
//   - It asks for a window on about:blank: nothing it opens loads anything
//     from the network.
//   - It must finish within probeTimeout with the browser's refusal. Any
//     other answer, an error, an exception, a timeout or no answer fails
//     the start.
//   - Its clean-up is verified before the gate listens: the extension is
//     uninstalled and gone from the browser's targets (and from its list of
//     extensions, where the browser has one), and the directory is gone.
//     Clean-up that cannot be verified fails the start.
//   - A browser that runs no extension, such as Chrome's headless shell,
//     cannot be asked, and is refused: the gate starts only a browser it
//     can check.
//
// Limit: a platform policy changed while a browser runs. Chrome reads its
// platform policy again while it runs, and the DevTools protocol reports
// no change of policy, so a policy that allows windows off the record once
// the browser started is not seen by the gate. Changing a platform policy
// takes the host's administrator, or code that runs as the browser's user
// (where the platform lets a user set policy), and neither is in the gate's
// scope (doc.go). The gate then still closes, while it holds them, the
// targets it is told of outside the browser's own context (mux.go), but it
// does not hold such a window's first request.

// errOffTheRecordAllowed is the error of a browser that opened a window off
// the record.
var errOffTheRecordAllowed = errors.New("the browser opens windows off the record (a platform policy, IncognitoModeAvailability, can allow them over the profile's preference); the gate starts no such browser")

// errNoExtensions is the error of a browser that runs no extension, so the
// probe cannot ask it.
var errNoExtensions = errors.New("the browser runs no extensions (Chrome's headless shell?), so the gate cannot check that it refuses windows off the record; use Chrome or Chromium")

// offTheRecordRefusal is how the browser refuses a window off the record.
const offTheRecordRefusal = "Incognito mode is disabled."

const (
	probeManifest = `{"manifest_version": 3, "name": "Dagu DevTools gate probe", "version": "1.0", "background": {"service_worker": "worker.js"}}`
	probeWorker   = "// The DevTools gate asks the browser through this worker whether it opens windows off the record.\n"
	probeDirName  = ".dagu-devtools-gate-probe-"
	// probeAsk asks for a window off the record and says how the browser
	// answered.
	probeAsk = `chrome.windows.create({incognito: true, url: "about:blank"}).then(w => "opened", e => "refused " + e.message)`
	// probeReady says whether the extension API is up in the worker.
	probeReady = `typeof chrome === "object" && chrome.windows ? "up" : "down"`
	// probeTimeout bounds the probe, and probeCleanupTimeout its clean-up.
	probeTimeout        = 10 * time.Second
	probeCleanupTimeout = 10 * time.Second
	probePollPause      = 50 * time.Millisecond
)

// checkOffTheRecordRefused fails unless the browser refuses a window off
// the record and the probe that asked is gone again. args are the
// browser's, naming the gate's own profile, in which the probe is written.
func checkOffTheRecordRefused(ctx context.Context, m *mux, args []string) (err error) {
	userDataDir, _ := profileDirs(args)
	dir, err := os.MkdirTemp(userDataDir, probeDirName)
	if err != nil {
		return fmt.Errorf("write the off-the-record probe: %w", err)
	}
	probeID := ""
	defer func() {
		if cleanErr := m.removeProbe(dir, probeID); cleanErr != nil {
			err = errors.Join(err, fmt.Errorf("remove the off-the-record probe: %w", cleanErr))
		}
	}()
	for name, content := range map[string]string{"manifest.json": probeManifest, "worker.js": probeWorker} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			return fmt.Errorf("write the off-the-record probe: %w", err)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	result, err := m.call(ctx, "", "Extensions.loadUnpacked", map[string]any{"path": dir})
	if err != nil {
		if strings.Contains(err.Error(), "wasn't found") {
			return errNoExtensions
		}
		return fmt.Errorf("load the off-the-record probe: %w", err)
	}
	var loaded struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(result, &loaded); err != nil || loaded.ID == "" {
		return errors.New("load the off-the-record probe: the browser named no extension")
	}
	probeID = loaded.ID
	session, err := m.awaitProbeWorker(ctx, probeURL(probeID))
	if err != nil {
		return err
	}
	for {
		if answer, err := evaluateString(ctx, m, session, probeReady); err == nil && answer == "up" {
			break
		}
		if err := pollPause(ctx); err != nil {
			return fmt.Errorf("the off-the-record probe did not start: %w", err)
		}
	}
	answer, err := evaluateString(ctx, m, session, probeAsk)
	if err != nil {
		return fmt.Errorf("ask the off-the-record probe: %w", err)
	}
	if answer != "refused "+offTheRecordRefusal {
		return fmt.Errorf("%w (asked for one, the browser answered %q)", errOffTheRecordAllowed, answer)
	}
	return nil
}

func probeURL(id string) string { return "chrome-extension://" + id + "/" }

// removeProbe uninstalls the probe extension id, when one was loaded, and
// removes its directory, and verifies both: the extension is gone from the
// browser's targets and, where the browser lists extensions, from that
// list, and the directory is gone.
func (m *mux) removeProbe(dir, id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), probeCleanupTimeout)
	defer cancel()
	var errs []error
	if id != "" {
		if _, err := m.call(ctx, "", "Extensions.uninstall", map[string]any{"id": id}); err != nil {
			errs = append(errs, fmt.Errorf("uninstall: %w", err))
		} else {
			errs = append(errs, m.awaitProbeGone(ctx, id))
		}
	}
	for {
		_ = os.RemoveAll(dir)
		if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
			break
		}
		// A browser can keep the files open a moment after it let go.
		if err := pollPause(ctx); err != nil {
			errs = append(errs, fmt.Errorf("the probe's files are still there: %s", dir))
			break
		}
	}
	return errors.Join(errs...)
}

// awaitProbeGone waits until no target of the extension id is left and the
// browser does not list it.
func (m *mux) awaitProbeGone(ctx context.Context, id string) error {
	for m.hasTarget(probeURL(id)) {
		if err := pollPause(ctx); err != nil {
			return fmt.Errorf("the probe's worker is still running: %w", err)
		}
	}
	result, err := m.call(ctx, "", "Extensions.getExtensions", map[string]any{})
	if err != nil {
		if strings.Contains(err.Error(), "wasn't found") {
			// A browser that does not list its extensions.
			return nil
		}
		return fmt.Errorf("list the browser's extensions: %w", err)
	}
	var listed struct {
		Extensions []struct {
			ID string `json:"id"`
		} `json:"extensions"`
	}
	if err := json.Unmarshal(result, &listed); err != nil {
		return fmt.Errorf("list the browser's extensions: %w", err)
	}
	for _, extension := range listed.Extensions {
		if extension.ID == id {
			return errors.New("the browser still lists the probe")
		}
	}
	return nil
}

// hasTarget reports whether the gate holds a target whose URL starts with
// prefix.
func (m *mux) hasTarget(prefix string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.allTargetsLocked() {
		var info struct {
			URL string `json:"url"`
		}
		if json.Unmarshal(t.info, &info) == nil && strings.HasPrefix(info.URL, prefix) {
			return true
		}
	}
	return false
}

// awaitProbeWorker returns the gate's own session on the service worker
// whose URL starts with prefix, once the gate's auto-attach holds it.
func (m *mux) awaitProbeWorker(ctx context.Context, prefix string) (string, error) {
	for {
		m.mu.Lock()
		for _, t := range m.allTargetsLocked() {
			var info struct {
				URL string `json:"url"`
			}
			if t.typ != "service_worker" || t.gateSession == "" || json.Unmarshal(t.info, &info) != nil || !strings.HasPrefix(info.URL, prefix) {
				continue
			}
			session := t.gateSession
			m.mu.Unlock()
			return session, nil
		}
		m.mu.Unlock()
		if err := pollPause(ctx); err != nil {
			return "", fmt.Errorf("the off-the-record probe's worker did not start: %w", err)
		}
	}
}

// evaluateString evaluates expression on session, awaiting the promise it
// returns, and returns its string value. An exception or a value that is
// not a string is an error.
func evaluateString(ctx context.Context, m *mux, session, expression string) (string, error) {
	result, err := m.call(ctx, session, "Runtime.evaluate", map[string]any{
		"expression": expression, "awaitPromise": true, "returnByValue": true,
	})
	if err != nil {
		return "", err
	}
	var evaluated struct {
		Result struct {
			Value any `json:"value"`
		} `json:"result"`
		Exception json.RawMessage `json:"exceptionDetails"`
	}
	if err := json.Unmarshal(result, &evaluated); err != nil {
		return "", err
	}
	if len(evaluated.Exception) > 0 {
		return "", fmt.Errorf("the probe threw: %s", evaluated.Exception)
	}
	value, ok := evaluated.Result.Value.(string)
	if !ok {
		return "", fmt.Errorf("the probe answered no string: %s", result)
	}
	return value, nil
}

// pollPause waits probePollPause between two looks, within ctx's deadline.
// It arms no timer (TestGuardOneLifetimeClock).
func pollPause(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	time.Sleep(probePollPause)
	return ctx.Err()
}
