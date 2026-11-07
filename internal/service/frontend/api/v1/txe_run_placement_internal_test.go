// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/dispatch"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// A per-run worker selector places the run as a spec's worker_selector
// does, and is decided the same way (TXE-5923): an owner cannot send a run,
// its own machine DAG's or any other, to another owner's machine, whose
// worker would run the caller's definition.
func TestTxeRunPlacementDecidesTheMachine(t *testing.T) {
	w := newTwoOwners(t, "enforce")
	own := txeauth.MachineDAGs(w.machineA)[0]
	pin := func(machine string) map[string]string { return map[string]string{dispatch.MachineLabel: machine} }
	machineDAG := &ir.DAG{Name: own, WorkerSelector: pin(w.machineA)}

	err := w.api.txeRunPlacement(w.cliA, machineDAG, pin(w.machineB))
	require.Error(t, err, "a machine's own DAG is sent only to that machine")
	assert.NotEqual(t, http.StatusOK, statusOf(err))
	require.NoError(t, w.api.txeRunPlacement(w.cliA, machineDAG, pin(w.machineA)), "its own machine, unchanged")

	plain := &ir.DAG{Name: "nightly"}
	require.Error(t, w.api.txeRunPlacement(w.cliA, plain, pin(w.machineB)), "another owner's machine")
	require.Error(t, w.api.txeRunPlacement(w.personA, plain, pin(w.machineB)), "for a person too")
	require.NoError(t, w.api.txeRunPlacement(w.cliA, plain, map[string]string{"os": "linux"}), "no machine named")

	override := api.WorkerSelectorOverride(pin(w.machineB))
	_, err = w.api.applyWorkerSelectorOverride(w.cliA, machineDAG, &override)
	require.Error(t, err, "the override path decides before it applies")
	assert.Equal(t, w.machineA, machineDAG.WorkerSelector[dispatch.MachineLabel], "nothing was applied")
}

// Every handler that reads a request's worker selector applies it through
// applyWorkerSelectorOverride, which decides the placement; and only
// reapplyWorkerSelector puts a selector on a DAG. A new run route that
// applies a request's selector another way fails here.
func TestEveryRunSelectorIsDecided(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := gotoken.NewFileSet()
	var readers []string
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
			readsRequest, decides := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.SelectorExpr:
					if n.Sel.Name == "WorkerSelector" {
						if body, ok := n.X.(*ast.SelectorExpr); ok && body.Sel.Name == "Body" {
							readsRequest = true
						}
					}
					if n.Sel.Name == "ApplyWorkerSelector" {
						assert.Equal(t, "reapplyWorkerSelector", fn.Name.Name, "%s puts a selector on a DAG", fn.Name.Name)
					}
				case *ast.CallExpr:
					if sel, ok := n.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "applyWorkerSelectorOverride" {
						decides = true
					}
				}
				return true
			})
			if readsRequest {
				readers = append(readers, fn.Name.Name)
				assert.True(t, decides, "%s reads a request's worker selector without applyWorkerSelectorOverride", fn.Name.Name)
			}
		}
	}
	assert.GreaterOrEqual(t, len(readers), 5, "the run routes were found: %v", readers)
}
