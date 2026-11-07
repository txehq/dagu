// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sdkModule = "github.com/browserbase/stagehand/packages/sdk-go/v4"

func TestChromeArgs(t *testing.T) {
	t.Parallel()
	args := ChromeArgs(LaunchOptions{
		UserDataDir: "/tmp/profile",
		Headless:    true,
		Viewport:    &Viewport{Width: 800, Height: 600},
		ProxyServer: "http://127.0.0.1:3128",
		NoSandbox:   true,
		Extra:       []string{"--user-agent=UA"},
	})
	assert.Equal(t, "about:blank", args[len(args)-1], "the initial page comes last")
	assert.Contains(t, args, "--window-size=800,600")
	assert.Contains(t, args, "--user-data-dir=/tmp/profile")
	assert.Contains(t, args, "--headless")
	assert.Contains(t, args, "--no-sandbox")
	assert.Contains(t, args, "--proxy-server=http://127.0.0.1:3128")
	assert.Contains(t, args, "--user-agent=UA")
	for _, arg := range args {
		assert.False(t, strings.HasPrefix(arg, "--remote-debugging-"), "the gate adds the pipe flags itself: %s", arg)
	}
	require.NoError(t, Config{Token: NewToken(), Executable: "x", Args: args}.validate())

	plain := ChromeArgs(LaunchOptions{UserDataDir: "/tmp/p"})
	assert.Contains(t, plain, "--window-size=1280,800", "the SDK's default window")
	assert.NotContains(t, plain, "--headless")
	assert.NotContains(t, plain, "--no-sandbox")
}

// TestChromeArgsMatchSDK reads the SDK module's launcher and fails when its
// default flags or window size change, so the browser the gate starts keeps
// behaving as the SDK's would.
func TestChromeArgsMatchSDK(t *testing.T) {
	t.Parallel()
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", sdkModule).Output()
	require.NoError(t, err, "the SDK module must be in the module cache")
	dir := strings.TrimSpace(string(out))
	require.NotEmpty(t, dir)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(dir, "chrome_launcher.go"), nil, 0)
	require.NoError(t, err)

	var flags []string
	constants := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			for i, name := range node.Names {
				if name.Name == "defaultChromeFlags" && i < len(node.Values) {
					if lit, ok := node.Values[i].(*ast.CompositeLit); ok {
						for _, element := range lit.Elts {
							flags = append(flags, stringExpr(t, element))
						}
					}
				}
				if (name.Name == "defaultChromeWidth" || name.Name == "defaultChromeHeight") && i < len(node.Values) {
					constants[name.Name] = stringExpr(t, node.Values[i])
				}
			}
		}
		return true
	})
	require.NotEmpty(t, flags, "defaultChromeFlags not found in the SDK's chrome_launcher.go")
	assert.Equal(t, flags, sdkDefaultChromeFlags, "the SDK's default flags changed; update sdkDefaultChromeFlags")
	assert.Equal(t, strconv.Itoa(sdkDefaultWidth), constants["defaultChromeWidth"])
	assert.Equal(t, strconv.Itoa(sdkDefaultHeight), constants["defaultChromeHeight"])
}

// stringExpr evaluates a string or integer literal, including concatenated
// string literals.
func stringExpr(t *testing.T, expr ast.Expr) string {
	t.Helper()
	switch node := expr.(type) {
	case *ast.BasicLit:
		if node.Kind == token.STRING {
			value, err := strconv.Unquote(node.Value)
			require.NoError(t, err)
			return value
		}
		return node.Value
	case *ast.BinaryExpr:
		require.Equal(t, token.ADD, node.Op)
		return stringExpr(t, node.X) + stringExpr(t, node.Y)
	case *ast.ParenExpr:
		return stringExpr(t, node.X)
	default:
		t.Fatalf("unexpected expression %T in the SDK's launcher", expr)
		return ""
	}
}
