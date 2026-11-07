// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/persis/testutil"
)

// The claim deadline (TXE-5923) is a property of how task records are made,
// not of each caller. A new pending task's payload has one maker,
// newPendingPayload, and a task record is encoded only by newDispatchRecord,
// which stamps a missing deadline. This test fails a writer added outside
// them: one that builds its own payload, or encodes one itself, could store a
// task with no deadline, which would wait for a worker forever. On the other
// side, a task becomes a claim only in claimNextPending, which never hands out
// a task past its deadline; a claim made anywhere else fails this test too.
func TestDispatchTaskPayloadsHaveOneMaker(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()
	var checked int
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		require.NoError(t, err)
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			payloadVars := taskPayloadVars(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.CompositeLit:
					if isIdent(n.Type, "dispatchTaskPayload") && len(n.Elts) > 0 {
						checked++
						assert.Equal(t, "newPendingPayload", fn.Name.Name,
							"%s: a dispatch task payload is built outside newPendingPayload, so it may lack a claim deadline", fset.Position(n.Pos()))
					}
				case *ast.CallExpr:
					sel, ok := n.Fun.(*ast.SelectorExpr)
					if ok && sel.Sel.Name == "newDispatchRecord" && len(n.Args) > 0 {
						if id, ok := n.Args[0].(*ast.CallExpr); ok && isIdent(id.Fun, "claimDispatchRecordID") {
							checked++
							assert.Equal(t, "claimNextPending", fn.Name.Name,
								"%s: a claim record is made outside claimNextPending, which never hands out a task past its claim deadline", fset.Position(n.Pos()))
						}
					}
					if !ok || !isIdent(sel.X, "persis") || sel.Sel.Name != "Encode" || len(n.Args) != 1 {
						return true
					}
					arg := n.Args[0]
					if u, ok := arg.(*ast.UnaryExpr); ok {
						arg = u.X
					}
					if id, ok := arg.(*ast.Ident); ok && payloadVars[id.Name] {
						checked++
						assert.Equal(t, "newDispatchRecord", fn.Name.Name,
							"%s: a dispatch task payload is encoded outside newDispatchRecord, which stamps its claim deadline", fset.Position(n.Pos()))
					}
				}
				return true
			})
		}
	}
	assert.GreaterOrEqual(t, checked, 3, "the guard found the maker, the encoder and the claim")
}

// taskPayloadVars names fn's parameters and variables of type
// dispatchTaskPayload or *dispatchTaskPayload, and those assigned one.
func taskPayloadVars(fn *ast.FuncDecl) map[string]bool {
	vars := map[string]bool{}
	isPayload := func(expr ast.Expr) bool {
		if star, ok := expr.(*ast.StarExpr); ok {
			expr = star.X
		}
		return isIdent(expr, "dispatchTaskPayload")
	}
	fields := []*ast.Field{}
	if fn.Recv != nil {
		fields = append(fields, fn.Recv.List...)
	}
	fields = append(fields, fn.Type.Params.List...)
	for _, field := range fields {
		if isPayload(field.Type) {
			for _, name := range field.Names {
				vars[name.Name] = true
			}
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.ValueSpec:
			if n.Type != nil && isPayload(n.Type) {
				for _, name := range n.Names {
					vars[name.Name] = true
				}
			}
		case *ast.AssignStmt:
			for i, rhs := range n.Rhs {
				if i >= len(n.Lhs) {
					break
				}
				id, ok := n.Lhs[i].(*ast.Ident)
				if !ok {
					continue
				}
				if lit, ok := rhs.(*ast.CompositeLit); ok && isPayload(lit.Type) {
					vars[id.Name] = true
				}
				if call, ok := rhs.(*ast.CallExpr); ok {
					if f, ok := call.Fun.(*ast.Ident); ok && f.Name == "dispatchTaskPayloadFromRecord" {
						vars[id.Name] = true
					}
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "newPendingPayload" {
						vars[id.Name] = true
					}
				}
			}
		}
		return true
	})
	return vars
}

func isIdent(expr ast.Expr, name string) bool {
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == name
}

// newDispatchRecord stores, for a payload with no deadline, the one its
// enqueue time gives it, so a writer that forgets the deadline still bounds
// the task.
func TestNewDispatchRecordStampsAMissingDeadline(t *testing.T) {
	t.Parallel()
	enqueuedAt := time.Date(2026, 11, 7, 3, 0, 0, 0, time.UTC)
	s := NewDispatchTaskStore(testutil.NewMemoryBackend().Collection("dispatch_tasks"), WithUnclaimedDispatchTimeout(time.Hour))
	payload := dispatchTaskPayload{
		Version: dispatchTaskStoreVersion, TaskFileName: "task_x.json", EnqueuedAt: enqueuedAt.UnixMilli(),
		Task: &dispatch.DispatchTask{DAGRunID: "run", AttemptKey: "key"},
	}
	rec, err := s.newDispatchRecord("pending/task_x", &payload, enqueuedAt, enqueuedAt)
	require.NoError(t, err)
	var stored dispatchTaskPayload
	require.NoError(t, persis.Decode(rec, &stored))
	assert.Equal(t, enqueuedAt.Add(time.Hour).UnixMilli(), stored.ClaimDeadline)
	assert.False(t, stored.ClaimUnbounded)
}
