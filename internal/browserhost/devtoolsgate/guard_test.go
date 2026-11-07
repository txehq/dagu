// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These guards hold the class fix together: a browser is launched in one
// place, on a pipe, and its address never reaches a line of text.

// moduleRoot finds the repository root from the test's directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "go.mod not found above %s", dir)
		dir = parent
	}
}

// goSources parses every non-test Go file under root/internal.
func goSources(t *testing.T, root string) map[string]*ast.File {
	t.Helper()
	files := make(map[string]*ast.File)
	fset := token.NewFileSet()
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = file
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, files)
	return files
}

// importName returns the name a file uses for an import path, or "".
func importName(file *ast.File, path string) string {
	for _, imp := range file.Imports {
		value, err := strconv.Unquote(imp.Path.Value)
		if err != nil || value != path {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		return filepath.Base(value)
	}
	return ""
}

// TestGuardOneBrowserLaunch: the SDK's port launcher is not called anywhere,
// nothing reserves a debugging port, and the only processes the browser
// packages start are the browser (in the gate) and the gate itself.
func TestGuardOneBrowserLaunch(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	files := goSources(t, root)

	allowedExec := map[string]bool{
		"internal/browserhost/devtoolsgate/launch.go": true,
		"internal/browserhost/devtoolsgate/start.go":  true,
	}
	// The gate names the pipe flags where it builds and validates them, and
	// nowhere else may a remote-debugging flag be spelled, whole or in part.
	allowedDebuggingLiteral := map[string]bool{
		"internal/browserhost/devtoolsgate/launch_unix.go":    true,
		"internal/browserhost/devtoolsgate/launch_windows.go": true,
		"internal/browserhost/devtoolsgate/config.go":         true,
	}
	var sdkLaunches, debuggingLiterals, execs, portFuncs []string
	for path, file := range files {
		sdk := importName(file, sdkModule)
		execName := importName(file, "os/exec")
		browserPackage := strings.HasPrefix(path, "internal/browserhost/") || strings.HasPrefix(path, "internal/runtime/builtin/browser/")
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncDecl:
				if node.Name.Name == "freeLoopbackPort" {
					portFuncs = append(portFuncs, path)
				}
			case *ast.BasicLit:
				if node.Kind == token.STRING && strings.Contains(strings.ToLower(node.Value), "remote-debugging") && !allowedDebuggingLiteral[path] {
					debuggingLiterals = append(debuggingLiterals, path)
				}
			case *ast.SelectorExpr:
				// Any mention, not only a call: a function value assigned
				// and called later is the same launch.
				pkg, ok := node.X.(*ast.Ident)
				if !ok {
					return true
				}
				if sdk != "" && pkg.Name == sdk && node.Sel.Name == "LaunchLocalBrowser" {
					sdkLaunches = append(sdkLaunches, path)
				}
				if browserPackage && execName != "" && pkg.Name == execName &&
					(node.Sel.Name == "Command" || node.Sel.Name == "CommandContext") && !allowedExec[path] {
					execs = append(execs, path)
				}
			}
			return true
		})
	}
	assert.Empty(t, sdkLaunches, "stagehand.LaunchLocalBrowser starts Chrome on a port; launch through devtoolsgate.Start")
	assert.Empty(t, debuggingLiterals, "a remote-debugging flag is spelled only where the gate builds the pipe flags")
	assert.Empty(t, portFuncs, "no browser debugging port is reserved anywhere")
	assert.Empty(t, execs, "the browser packages start processes only in the gate's launch.go and start.go")
}

// TestGuardOneLifetimeClock: the gate ends a healthy browser by time in one
// place, the keeper in attend.go, on ticks of the gate's clock. No file of
// the package arms a timer (time.NewTimer, time.After, time.AfterFunc), and a
// ticker is made only where the clock is defined; so a new concern cannot
// end the browser on a clock of its own, and the policy's defaults are
// resolved by Config.lifetime alone (TXE-6201).
func TestGuardOneLifetimeClock(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	files := goSources(t, root)
	forbidden := map[string]bool{"NewTimer": true, "After": true, "AfterFunc": true}
	var timers, tickers, lifetimeReads []string
	for path, file := range files {
		if !strings.HasPrefix(path, "internal/browserhost/devtoolsgate/") {
			continue
		}
		timeName := importName(file, "time")
		ast.Inspect(file, func(n ast.Node) bool {
			selector, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if timeName != "" && pkg.Name == timeName {
				if forbidden[selector.Sel.Name] {
					timers = append(timers, path+": time."+selector.Sel.Name)
				}
				if selector.Sel.Name == "NewTicker" && path != "internal/browserhost/devtoolsgate/attend.go" {
					tickers = append(tickers, path)
				}
			}
			// The policy's fields are read through Config.lifetime, nowhere else.
			if (selector.Sel.Name == "MaxLifetime" || selector.Sel.Name == "MaxUnattended") &&
				!strings.HasSuffix(path, "/attend.go") && !strings.HasSuffix(path, "/config.go") {
				lifetimeReads = append(lifetimeReads, path+": "+selector.Sel.Name)
			}
			return true
		})
	}
	assert.Empty(t, timers, "the gate arms no timer; the keeper's ticks end a browser by time")
	assert.Empty(t, tickers, "a ticker comes from the gate's clock in attend.go")
	assert.Empty(t, lifetimeReads, "the lifetime fields are resolved by Config.lifetime only")

	// A permanent helper outside the package opts in through
	// HelperHandshake, never by spelling the marker itself, so the marker
	// has one source and a consumer cannot copy it half right.
	var markerCopies []string
	for path, file := range files {
		if strings.HasPrefix(path, "internal/browserhost/devtoolsgate/") {
			continue
		}
		gateName := importName(file, "github.com/dagucloud/dagu/v2/internal/browserhost/devtoolsgate")
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				pkg, ok := node.X.(*ast.Ident)
				if ok && gateName != "" && pkg.Name == gateName && (node.Sel.Name == "HelperHeader" || node.Sel.Name == "HelperValue") {
					markerCopies = append(markerCopies, path+": devtoolsgate."+node.Sel.Name)
				}
			case *ast.BasicLit:
				if node.Kind == token.STRING && (strings.Contains(node.Value, HelperHeader) || strings.Contains(node.Value, HelperValue)) {
					markerCopies = append(markerCopies, path+": "+node.Value)
				}
			}
			return true
		})
	}
	assert.Empty(t, markerCopies, "a helper opts in with devtoolsgate.HelperHandshake(); the marker is spelled only in the gate")
}

// TestGuardAddressNeverFormatted: a browser address carries the gate's
// token, so no code in the browser packages hands one to a formatting,
// logging or error-building function. Redact it first. The check reads
// names, so an address copied into a variable with another name escapes it;
// reviews of the browser packages read for that.
func TestGuardAddressNeverFormatted(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	files := goSources(t, root)
	formatting := map[string]map[string]bool{
		"fmt":    {"Errorf": true, "Sprintf": true, "Sprint": true, "Sprintln": true, "Printf": true, "Println": true, "Print": true, "Fprintf": true, "Fprintln": true, "Fprint": true},
		"errors": {"New": true},
		"log":    {"Printf": true, "Println": true, "Print": true, "Fatalf": true},
		"slog":   {"Info": true, "Warn": true, "Error": true, "Debug": true, "String": true},
	}
	var leaks []string
	for path, file := range files {
		if !strings.HasPrefix(path, "internal/browserhost/") && !strings.HasPrefix(path, "internal/runtime/builtin/browser/") {
			continue
		}
		if strings.HasPrefix(path, "internal/browserhost/devtoolsgate/") {
			// The gate builds the address; it has its own redaction tests.
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || !formatting[pkg.Name][selector.Sel.Name] {
				return true
			}
			for _, arg := range call.Args {
				if namesAddress(arg) {
					leaks = append(leaks, path+": "+pkg.Name+"."+selector.Sel.Name)
				}
			}
			return true
		})
	}
	assert.Empty(t, leaks, "a browser address reached text; pass it through browserhost.RedactCDPURL or RedactError")
}

// namesAddress reports whether an expression names a browser address: an
// identifier or field called CDPURL (in any case) or a gate handle's URL.
func namesAddress(expr ast.Expr) bool {
	switch node := expr.(type) {
	case *ast.Ident:
		return strings.Contains(strings.ToLower(node.Name), "cdpurl")
	case *ast.SelectorExpr:
		if strings.Contains(strings.ToLower(node.Sel.Name), "cdpurl") {
			return true
		}
		if node.Sel.Name == "URL" {
			if x, ok := node.X.(*ast.Ident); ok && (x.Name == "gate" || x.Name == "handle" || x.Name == "h") {
				return true
			}
		}
		return namesAddress(node.X)
	case *ast.BinaryExpr:
		return namesAddress(node.X) || namesAddress(node.Y)
	case *ast.ParenExpr:
		return namesAddress(node.X)
	case *ast.CallExpr:
		// A call that redacts is the fix, not a leak; any other call on an
		// address (TrimRight, Sprintf…) still carries it.
		switch fun := node.Fun.(type) {
		case *ast.SelectorExpr:
			if strings.HasPrefix(fun.Sel.Name, "Redact") {
				return false
			}
		case *ast.Ident:
			if strings.HasPrefix(fun.Name, "Redact") {
				return false
			}
		}
		return slices.ContainsFunc(node.Args, namesAddress)
	}
	return false
}

// TestGuardTokenNotOnCommandLine: the gate's own process gets a constant
// command line, and the browser's arguments are built without the token.
func TestGuardTokenNotOnCommandLine(t *testing.T) {
	t.Parallel()
	token := NewToken()
	cfg := Config{Token: token, Executable: "/opt/chrome", Args: ChromeArgs(LaunchOptions{UserDataDir: "/tmp/p"})}
	for _, arg := range cfg.Args {
		assert.NotContains(t, arg, token)
	}
	for _, flag := range pipeFlagsForTest() {
		assert.NotContains(t, flag, token)
	}
}
