// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package mcp

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xuri/excelize/v2"
)

// A call from Dagu Cloud never reads a file on this server's host, whatever
// role it carries: the workbook target is refused before the file is opened
// (TXE-5923).
func TestCloudCallsNeverReadAHostWorkbook(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "secret.xlsx")
	f := excelize.NewFile()
	require.NoError(t, f.SetCellValue("Sheet1", "A1", "host-secret-cell"))
	require.NoError(t, f.SaveAs(path))
	require.NoError(t, f.Close())

	session := connectTestClient(t, t.Context(), newServer(nil, &remoteCalls{approvals: func(context.Context) bool { return false }}))
	res, err := session.CallTool(t.Context(), &mcpsdk.CallToolParams{
		Name:      toolRead,
		Arguments: map[string]any{"target": readTargetWorkbook, "path": path},
	})
	require.NoError(t, err)
	require.True(t, res.IsError)
	body, err := json.Marshal(res)
	require.NoError(t, err)
	assert.Contains(t, string(body), readErrorUnsupportedReadTarget)
	assert.Contains(t, string(body), "calls from Dagu Cloud may not", "refused as a Cloud call, not for want of an API")
	assert.NotContains(t, string(body), "host-secret-cell")
	assert.NotContains(t, string(body), "Sheet1")
}

// A local call without the API to decide it is refused too, not read.
func TestALocalHostFileReadNeedsADecision(t *testing.T) {
	t.Parallel()
	svc := &Service{}
	require.Error(t, svc.authorizeReadTarget(t.Context(), readTargetWorkbook))
	require.NoError(t, svc.authorizeReadTarget(t.Context(), readTargetReferences))
	var readErr *readToolError
	require.ErrorAs(t, svc.authorizeReadTarget(t.Context(), "not-a-target"), &readErr, "an unlisted target is refused")
	assert.Equal(t, readErrorUnsupportedReadTarget, readErr.Code)
}

// Every target readToolImpl serves is classified in readTargetSources, and
// the list names no target it does not serve. A new target added to the
// switch without a source fails here (and is refused at run time).
func TestEveryReadTargetHasASource(t *testing.T) {
	t.Parallel()
	consts, files := packageStringConsts(t)
	var served []string
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "readToolImpl" {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				clause, ok := n.(*ast.CaseClause)
				if !ok {
					return true
				}
				for _, expr := range clause.List {
					id, ok := expr.(*ast.Ident)
					require.True(t, ok, "a case of readToolImpl names a target constant")
					value, ok := consts[id.Name]
					require.True(t, ok, "constant %s", id.Name)
					served = append(served, value)
				}
				return true
			})
		}
	}
	require.NotEmpty(t, served, "readToolImpl was found")
	for _, target := range served {
		_, ok := readTargetSources[target]
		assert.True(t, ok, "read target %q has no source in readTargetSources", target)
	}
	for target := range readTargetSources {
		assert.Contains(t, served, target, "readTargetSources lists %q, which readToolImpl does not serve", target)
	}
	assert.Equal(t, readFromHostFile, readTargetSources[readTargetWorkbook])
}

// Every tool the local server offers has a Cloud decision, and the Cloud
// server offers exactly the ones allowed. Tools are offered only through
// addTool, which applies the decision.
func TestEveryToolHasACloudDecision(t *testing.T) {
	t.Parallel()
	list := func(server *mcpsdk.Server) []string {
		res, err := connectTestClient(t, t.Context(), server).ListTools(t.Context(), nil)
		require.NoError(t, err)
		var names []string
		for _, tool := range res.Tools {
			names = append(names, tool.Name)
		}
		return names
	}
	local := list(NewServer(nil))
	require.NotEmpty(t, local)
	var allowed []string
	for _, name := range local {
		decision, ok := cloudTools[name]
		assert.True(t, ok, "tool %q has no Cloud decision in cloudTools", name)
		if decision {
			allowed = append(allowed, name)
		}
	}
	assert.ElementsMatch(t, allowed, list(newServer(nil, &remoteCalls{approvals: func(context.Context) bool { return false }})))

	_, files := packageStringConsts(t)
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "AddTool" {
					assert.Equal(t, "addTool", fn.Name.Name, "a tool is offered outside addTool, which applies the Cloud decision")
				}
				return true
			})
		}
	}
}

// packageStringConsts parses the package's non-test files and returns their
// string constants by name.
func packageStringConsts(t *testing.T) (map[string]string, []*ast.File) {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()
	consts := map[string]string{}
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		files = append(files, file)
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, id := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
						if v, err := strconv.Unquote(lit.Value); err == nil {
							consts[id.Name] = v
						}
					}
				}
			}
		}
	}
	return consts, files
}
