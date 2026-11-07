// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// ErrBrowserNotFound reports that no browser was found to launch.
var ErrBrowserNotFound = errors.New("no Chrome installation found; set CHROME_PATH or browser.executable")

// FindBrowser returns the browser to launch: explicit when set, else the
// CHROME_PATH environment variable, else the installation the SDK's own
// launcher would have picked on this platform.
func FindBrowser(explicit string) (string, error) {
	return findBrowser(explicit, runtime.GOOS, os.Getenv, exec.LookPath, isFile)
}

func findBrowser(explicit, goos string, getenv func(string) string, lookPath func(string) (string, error), fileExists func(string) bool) (string, error) {
	if explicit != "" {
		if fileExists(explicit) {
			return explicit, nil
		}
		return "", fmt.Errorf("browser executable %q does not exist", explicit)
	}
	if configured := getenv("CHROME_PATH"); configured != "" && fileExists(configured) {
		return configured, nil
	}
	var candidates []string
	switch goos {
	case "darwin":
		candidates = []string{
			"/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Google Chrome Beta.app/Contents/MacOS/Google Chrome Beta",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
		}
	case "windows":
		roots := []string{getenv("LOCALAPPDATA"), getenv("PROGRAMFILES"), getenv("PROGRAMFILES(X86)")}
		suffixes := [][]string{
			{"Google", "Chrome SxS", "Application", "chrome.exe"},
			{"Google", "Chrome", "Application", "chrome.exe"},
		}
		for _, root := range roots {
			if root == "" {
				continue
			}
			for _, suffix := range suffixes {
				candidates = append(candidates, filepath.Join(append([]string{root}, suffix...)...))
			}
		}
	case "linux":
		for _, name := range []string{"google-chrome-stable", "google-chrome", "chromium-browser", "chromium"} {
			if path, err := lookPath(name); err == nil {
				candidates = append(candidates, path)
			}
		}
	default:
		return "", fmt.Errorf("launching a browser is not supported on %s", goos)
	}
	for _, candidate := range candidates {
		if fileExists(candidate) {
			return candidate, nil
		}
	}
	return "", ErrBrowserNotFound
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}
