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

// linkActs are the license manager calls that open, approve, read, refresh,
// rename or end the Dagu Console link; the rest only read the license for a
// feature check.
var linkActs = map[string]bool{
	"ActivateWithKey": true, "Connect": true, "ConnectStatus": true, "CancelConnect": true,
	"Refresh": true, "RenameServer": true, "Deactivate": true, "CloudCredentials": true,
}

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

// What leaves the hub for Dagu Cloud is written only by setReportLevel and
// chooseRemoteAccessLevel, or by UpdateLicenseRemoteAccess behind
// requireCloudAccess, and each of them makes the egress decision
// (txeCloudEgress, TXE-5923). A new writer of either level fails here.
func TestEveryCloudEgressWriterDecides(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := gotoken.NewFileSet()
	writers := map[string]bool{}
	linkUsers, linkDecided, egressDecided := map[string]bool{}, map[string]bool{}, map[string]bool{}
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
			writes, decides := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if recv, ok := sel.X.(*ast.SelectorExpr); ok &&
					((recv.Sel.Name == "cloudReport" && sel.Sel.Name == "SetLevel") ||
						(recv.Sel.Name == "cloudAccess" && sel.Sel.Name == "Set")) {
					writes = true
				}
				// Every use of the Dagu Console link: opening, approving,
				// reading, refreshing or ending it.
				if recv, ok := sel.X.(*ast.SelectorExpr); ok && recv.Sel.Name == "licenseManager" && linkActs[sel.Sel.Name] {
					linkUsers[fn.Name.Name] = true
				}
				if sel.Sel.Name == "txeCloudEgress" || sel.Sel.Name == "requireCloudAccess" {
					decides = true
				}
				if sel.Sel.Name == "requireLicenseManagement" {
					linkDecided[fn.Name.Name] = true
				}
				return true
			})
			if writes {
				writers[fn.Name.Name] = true
				assert.True(t, decides, "%s writes what leaves the hub without txeCloudEgress", fn.Name.Name)
			}
			if decides {
				egressDecided[fn.Name.Name] = true
			}
		}
	}
	assert.Equal(t, map[string]bool{"setReportLevel": true, "chooseRemoteAccessLevel": true, "UpdateLicenseRemoteAccess": true}, writers)
	// A handler that uses the Dagu Console link decides egress first, itself
	// or through requireLicenseManagement. Helpers that only describe a
	// status the handler read are listed here, by name, with that reason.
	describesOnly := map[string]bool{
		// Reports only whether a link exists, for the public webhook route,
		// and discards the credentials.
		"connectedToDaguCloud": true,
	}
	for name := range linkUsers {
		if describesOnly[name] {
			continue
		}
		assert.True(t, egressDecided[name] || linkDecided[name], "%s uses the Dagu Console link without txeCloudEgress", name)
	}
	assert.NotEmpty(t, linkUsers)
}
