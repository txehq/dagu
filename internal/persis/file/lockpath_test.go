// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package file

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsLockMetadataPath(t *testing.T) {
	t.Parallel()
	lock := map[string]bool{
		// What the store writes: a record lock bucket and the directory
		// lock inside it, with its owner token.
		"data/distributed/active-runs/.dagu_record_locks":                                    true,
		"data/distributed/active-runs/.dagu_record_locks/6a":                                 true,
		"data/distributed/active-runs/.dagu_record_locks/6a/.dagu_lock":                      true,
		"data/distributed/active-runs/.dagu_record_locks/6a/.dagu_lock/owner":                true,
		"data/distributed/active-runs/.dagu_record_locks/6a/.dagu_lock.releasing.1699/owner": true,
		"data/monitor/state.json.lock/.dagu_lock":                                            true,
		".dagu_lock": true,
		// Data that only looks like a lock is asserted on, not passed over.
		"data/dag-runs/billing/status.jsonl":                  false,
		"data/dag-runs/billing/status.jsonl.lock":             false,
		"artifacts/run-1/report.lock":                         false,
		"artifacts/run-1/.dagu_lock.txt":                      false,
		"artifacts/run-1/dagu_record_locks/notes.txt":         false,
		"data/distributed/active-runs/.dagu_record_locks.bak": false,
		"data/materialization/locks/abc.lock":                 false,
		"":                                                    false,
	}
	if runtime.GOOS == "windows" {
		// The path CI reported, with the separator that OS uses.
		lock[`D:\a\_temp\dagu-test\data\distributed\active-runs\.dagu_record_locks\6a\.dagu_lock`] = true
	}
	for path, want := range lock {
		assert.Equal(t, want, IsLockMetadataPath(path), path)
	}
}

// The classification is written once. The store's own walks and anything
// else in this package that needs it ask IsLockMetadataName or
// IsLockMetadataPath rather than comparing the reserved names themselves.
func TestLockMetadataRuleHasOneHome(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := token.NewFileSet()
	var leaks []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "lockpath.go" {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				if pkg, ok := node.X.(*ast.Ident); ok && pkg.Name == "dirlock" && node.Sel.Name == "IsLockDirectoryName" {
					leaks = append(leaks, name+": dirlock.IsLockDirectoryName")
				}
			case *ast.BinaryExpr:
				for _, side := range []ast.Expr{node.X, node.Y} {
					if ident, ok := side.(*ast.Ident); ok && ident.Name == "recordLockDirectoryName" {
						leaks = append(leaks, name+": compares recordLockDirectoryName")
					}
				}
			}
			return true
		})
	}
	assert.Empty(t, leaks, "lock metadata is classified in lockpath.go only")
}
