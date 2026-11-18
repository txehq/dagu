// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package playwrightpin

import (
	"bytes"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

const playwrightLockfile = "ui/pnpm-lock.yaml"

// The manifest may name the locked version exactly; pnpm refuses a frozen
// install when the two disagree.
const playwrightManifest = "ui/package.json"

// Dockerfile.dev runs the pinned Playwright on Ubuntu 24.04's Node.js 18, and
// Playwright 1.61 is the last release that supports it. Raise this only with
// a newer Node.js in that image.
const playwrightCeilingMinor = 61

var (
	lockedPlaywright = regexp.MustCompile(`(?m)^  playwright@([^:\s]+):\s*$`)

	// Each pattern captures the version a line pins. A variable reference
	// such as ${PLAYWRIGHT_VERSION} reads the pin and is not one.
	playwrightPinPatterns = []*regexp.Regexp{
		// npx playwright@1.2.3, '@playwright/test@1.2.3', playwright-core@1.2.3
		regexp.MustCompile(`(?:^|[^\w@/.-])(?:@playwright/test|playwright(?:-core)?)@([^\s'"` + "`" + `:,)\]}]+)`),
		// ARG PLAYWRIGHT_VERSION=1.2.3, PLAYWRIGHT_VERSION: "1.2.3"
		regexp.MustCompile(`PLAYWRIGHT_VERSION\s*[=:]\s*["']?([^\s"',;]+)`),
		// "@playwright/test": "1.2.3" in a package manifest
		regexp.MustCompile(`"(?:@playwright/test|playwright|playwright-core)"\s*:\s*"([^"]+)"`),
		// mcr.microsoft.com/playwright:v1.2.3-noble
		regexp.MustCompile(`mcr\.microsoft\.com/playwright(?:/[\w-]+)?:([\w.-]+)`),
		// playwright==1.2.3 (Python)
		regexp.MustCompile(`(?:^|[^\w-])playwright\s*[=~<>!]=\s*([\w.]+)`),
	}

	// A capture is a pin only when it looks like a version (1.2.3, v1.2.3-noble)
	// or a dist-tag (latest); anything else is code that mentions the package.
	playwrightPinShape = regexp.MustCompile(`^(?:v?\d+(?:\.\d+)*(?:[-+][\w.]+)?|[a-z][a-z-]*)$`)

	playwrightSkipDirs = []string{".git", "node_modules", "ui/dist", "ui/playwright-report", "ui/test-results"}
)

// This file holds the patterns and the negative fixtures, so it is the one
// file the scan leaves out.
const playwrightPinTestFile = "internal/tools/playwrightpin/playwrightpin_test.go"

const playwrightMaxFileBytes = 16 << 20

type playwrightPin struct {
	file    string
	line    int
	version string
}

func TestOnePlaywrightPin(t *testing.T) {
	t.Parallel()

	version, err := checkPlaywrightPins(os.DirFS(repoRoot(t)))
	require.NoError(t, err)
	t.Logf("Playwright %s, pinned by %s", version, playwrightLockfile)
}

// The negatives are pure data, checked in memory.
func TestOnePlaywrightPinRefusesASecondPin(t *testing.T) {
	t.Parallel()

	lock := func(versions ...string) string {
		var b strings.Builder
		b.WriteString("lockfileVersion: '9.0'\n\npackages:\n\n")
		for _, v := range versions {
			fmt.Fprintf(&b, "  '@playwright/test@%s':\n    resolution: {}\n\n  playwright@%s:\n    resolution: {}\n\n", v, v)
		}
		return b.String()
	}
	manifest := func(spec string) string {
		return `{"devDependencies": {"@playwright/test": "` + spec + `"}}` + "\n"
	}
	readsLock := "RUN --mount=type=bind,source=ui/pnpm-lock.yaml,target=/tmp/pnpm-lock.yaml \\\n" +
		"    PLAYWRIGHT_VERSION=\"$(sed -n 's/x/y/p' /tmp/pnpm-lock.yaml)\"; \\\n" +
		"    npx --yes \"playwright@${PLAYWRIGHT_VERSION}\" install --no-shell chromium\n"
	tree := func(files map[string]string) fstest.MapFS {
		base := map[string]string{
			playwrightLockfile: lock("1.61.1"),
			playwrightManifest: manifest("1.61.1"),
			"Dockerfile.dev":   readsLock,
		}
		maps.Copy(base, files)
		out := fstest.MapFS{}
		for name, content := range base {
			if content != "" {
				out[name] = &fstest.MapFile{Data: []byte(content)}
			}
		}
		return out
	}

	ok, err := checkPlaywrightPins(tree(nil))
	require.NoError(t, err)
	require.Equal(t, "1.61.1", ok)

	// A reference to the pin, or a node_modules copy, is not a second pin.
	_, err = checkPlaywrightPins(tree(map[string]string{
		"scripts/ci/install.sh":                       "npx --yes \"playwright@${versions}\" install chromium-headless-shell\n",
		"ui/node_modules/playwright/package.json":     `{"name": "playwright", "version": "1.0.0", "dependencies": {"playwright-core": "1.0.0"}}`,
		"docs/browser.md":                             "Playwright 1.61 is the last release that runs on Node.js 18.\n",
		".github/workflows/e2e.yaml":                  "run: pnpm exec playwright install --with-deps chromium\n",
		"internal/test/chrometest/workflows_test.go":  "\"npx playwright test\"\n",
		"internal/runtime/builtin/browser/README.txt": "playwright@ is the npm package\n",
	}))
	require.NoError(t, err)

	for name, files := range map[string]map[string]string{
		"a different version in Dockerfile.dev": {
			"Dockerfile.dev": "ARG PLAYWRIGHT_VERSION=1.60.0\nRUN npx --yes \"playwright@${PLAYWRIGHT_VERSION}\" install chromium\n",
		},
		"the same version written again outside the lockfile": {
			".github/workflows/ci.yaml": "run: npx --yes playwright@1.61.1 install chromium\n",
		},
		"a dist-tag": {
			"scripts/ci/install.sh": "npx --yes playwright@latest install chromium\n",
		},
		"a Playwright container image": {
			"deploy/e2e/Dockerfile": "FROM mcr.microsoft.com/playwright:v1.61.1-noble\n",
		},
		"a Python pin": {
			"tools/requirements.txt": "playwright==1.61.0\n",
		},
		"two versions in the lockfile": {
			playwrightLockfile: lock("1.61.1", "1.59.1"),
		},
		"no version in the lockfile": {
			playwrightLockfile: "lockfileVersion: '9.0'\n",
		},
		"a manifest range": {
			playwrightManifest: manifest("^1.55.1"),
		},
		"a manifest version the lockfile does not hold": {
			playwrightManifest: manifest("1.60.0"),
		},
		"a version past the dev image's Node.js": {
			playwrightLockfile: lock("1.62.0"),
			playwrightManifest: manifest("1.62.0"),
		},
		"a Dockerfile.dev that does not read the lockfile": {
			"Dockerfile.dev": "RUN npx --yes playwright install chromium\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := checkPlaywrightPins(tree(files))
			require.Error(t, err)
			t.Log(err)
		})
	}
}

// checkPlaywrightPins returns the version ui/pnpm-lock.yaml pins, or an error
// naming every other pin in the tree and every way the tree breaks the rule.
func checkPlaywrightPins(fsys fs.FS) (string, error) {
	lock, err := fs.ReadFile(fsys, playwrightLockfile)
	if err != nil {
		return "", err
	}
	var versions []string
	for _, m := range lockedPlaywright.FindAllSubmatch(lock, -1) {
		if v := string(m[1]); !slices.Contains(versions, v) {
			versions = append(versions, v)
		}
	}
	if len(versions) != 1 {
		return "", fmt.Errorf("%s must lock exactly one playwright version, found %q", playwrightLockfile, versions)
	}
	version := versions[0]

	var problems []string
	if minor, ok := playwrightMinor(version); !ok || minor > playwrightCeilingMinor {
		problems = append(problems, fmt.Sprintf(
			"%s locks playwright %s; Dockerfile.dev runs it on Node.js 18, which Playwright supports only up to 1.%d",
			playwrightLockfile, version, playwrightCeilingMinor))
	}

	dockerfile, err := fs.ReadFile(fsys, "Dockerfile.dev")
	if err != nil {
		return "", err
	}
	if !bytes.Contains(dockerfile, []byte("source="+playwrightLockfile)) {
		problems = append(problems, "Dockerfile.dev must read the Playwright version from "+playwrightLockfile)
	}

	pins, err := findPlaywrightPins(fsys)
	if err != nil {
		return "", err
	}
	for _, pin := range pins {
		switch pin.file {
		case playwrightLockfile:
			// The source of truth; its versions were checked above.
		case playwrightManifest:
			if pin.version != version {
				problems = append(problems, fmt.Sprintf(
					"%s:%d: %q must be exactly the locked playwright %s",
					pin.file, pin.line, pin.version, version))
			}
		default:
			problems = append(problems, fmt.Sprintf(
				"%s:%d: pins playwright %q; read the version from %s (locked: %s)",
				pin.file, pin.line, pin.version, playwrightLockfile, version))
		}
	}
	if len(problems) > 0 {
		return version, fmt.Errorf("Playwright has more than one pin (TXE-7866):\n%s", strings.Join(problems, "\n"))
	}
	return version, nil
}

func findPlaywrightPins(fsys fs.FS) ([]playwrightPin, error) {
	var pins []playwrightPin
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if slices.Contains(playwrightSkipDirs, name) || slices.Contains(playwrightSkipDirs, path.Base(name)) {
				return fs.SkipDir
			}
			return nil
		}
		if name == playwrightPinTestFile || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > playwrightMaxFileBytes {
			return nil
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return err
		}
		if bytes.IndexByte(data[:min(len(data), 8000)], 0) >= 0 {
			return nil // binary
		}
		if !bytes.Contains(bytes.ToLower(data), []byte("playwright")) {
			return nil
		}
		for i, line := range strings.Split(string(data), "\n") {
			for _, pattern := range playwrightPinPatterns {
				for _, m := range pattern.FindAllStringSubmatch(line, -1) {
					// Any manifest spec counts, so that a range is refused.
					if name != playwrightManifest && !playwrightPinShape.MatchString(m[1]) {
						continue
					}
					pins = append(pins, playwrightPin{file: name, line: i + 1, version: m[1]})
				}
			}
		}
		return nil
	})
	return pins, err
}

func playwrightMinor(version string) (int, bool) {
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 || parts[0] != "1" {
		return 0, false
	}
	minor, err := strconv.Atoi(parts[1])
	return minor, err == nil
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, ".github", "workflows")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "no repository root (go.mod beside .github/workflows) above the test's directory")
		dir = parent
	}
}
