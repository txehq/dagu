// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// commandChannelExecutors are the notification service calls through which a
// handler can make a command channel run its text on the hub's host: saving
// one, testing one, and testing a DAG's routes.
var commandChannelExecutors = map[string]bool{"SaveChannel": true, "SendChannelTest": true, "SendTest": true}

// Every handler that can make a command channel run on the hub's host makes
// the host-execution decision itself (requireCommandChannelAccess, which
// applies txeHostExecution, TXE-5923). A new handler that reaches one of
// these calls without it fails here.
func TestEveryCommandChannelPathDecidesHostExecution(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := gotoken.NewFileSet()
	var reached []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		require.NoError(t, err)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			executes, decides := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if recv, ok := sel.X.(*ast.SelectorExpr); ok && recv.Sel.Name == "notificationService" && commandChannelExecutors[sel.Sel.Name] {
					executes = true
				}
				if sel.Sel.Name == "requireCommandChannelAccess" {
					decides = true
				}
				return true
			})
			if executes {
				reached = append(reached, fn.Name.Name)
				assert.True(t, decides, "%s reaches a command channel without requireCommandChannelAccess", fn.Name.Name)
			}
		}
	}
	assert.NotEmpty(t, reached, "the guard found the handlers")
}
