// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package frontend

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Every route the terminal is served on carries the host-execution decision
// (TxeHostExecutionRefused, TXE-5923). A registration of the terminal
// handler without it fails here.
func TestEveryTerminalRouteDecidesHostExecution(t *testing.T) {
	t.Parallel()
	file, err := parser.ParseFile(gotoken.NewFileSet(), "server.go", nil, parser.SkipObjectResolution)
	require.NoError(t, err)
	var routes, decided int
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		handler, ok := call.Args[1].(*ast.SelectorExpr)
		if !ok || handler.Sel.Name != "ServeHTTP" {
			return true
		}
		if id, ok := handler.X.(*ast.Ident); !ok || id.Name != "termHandler" {
			return true
		}
		routes++
		found := false
		ast.Inspect(call.Fun, func(m ast.Node) bool {
			if sel, ok := m.(*ast.SelectorExpr); ok && sel.Sel.Name == "TxeHostExecutionRefused" {
				found = true
			}
			return true
		})
		if found {
			decided++
		}
		return true
	})
	require.Positive(t, routes, "the terminal routes were found")
	assert.Equal(t, routes, decided, "every terminal route carries TxeHostExecutionRefused")
}
