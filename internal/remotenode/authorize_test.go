// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package remotenode

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The one reading of which node a request is for.
func TestSelected(t *testing.T) {
	t.Parallel()
	for query, want := range map[string]struct {
		name   string
		remote bool
		err    error
	}{
		"":                                  {},
		"?remoteNode=":                      {},
		"?remoteNode=local":                 {},
		"?remoteNode=edge":                  {name: "edge", remote: true},
		"?remoteNode=LOCAL":                 {name: "LOCAL", remote: true},
		"?remoteNode=edge&remoteNode=edge":  {err: ErrAmbiguousSelection},
		"?remoteNode=local&remoteNode=edge": {err: ErrAmbiguousSelection},
	} {
		name, remote, err := Selected(httptest.NewRequest(http.MethodGet, "/api/v1/dags"+query, nil))
		assert.ErrorIs(t, err, want.err, query)
		assert.Equal(t, want.name, name, query)
		assert.Equal(t, want.remote, remote, query)
	}
}

// A node's credential is sent only for a request the local decision allowed.
func TestApplyAuthNeedsTheLocalDecision(t *testing.T) {
	t.Parallel()
	node := &RemoteNode{AuthType: AuthTypeToken, AuthToken: "remote-secret"}
	req := httptest.NewRequest(http.MethodGet, "http://edge/api/v1/dags", nil)
	require.ErrorIs(t, node.ApplyAuth(req), ErrUseNotAuthorized)
	assert.Empty(t, req.Header.Get("Authorization"), "no credential without the decision")

	allowed := req.WithContext(WithUseAuthorized(context.Background()))
	require.NoError(t, node.ApplyAuth(allowed))
	assert.Equal(t, "Bearer remote-secret", allowed.Header.Get("Authorization"))
}

// Only the API's local decision marks a request as allowed to use a node's
// credential: a call to WithUseAuthorized anywhere else in the source, which
// would send it without the decision, fails here.
func TestOnlyTheLocalDecisionAllowsACredential(t *testing.T) {
	t.Parallel()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	require.NoError(t, err)
	var found []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "node_modules", ".git", "ui", ".local", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || !bytes.Contains(data, []byte("WithUseAuthorized")) {
			return err
		}
		file, err := parser.ParseFile(gotoken.NewFileSet(), path, data, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
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
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "WithUseAuthorized" {
					found = append(found, filepath.ToSlash(rel)+":"+fn.Name.Name)
				}
				return true
			})
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"internal/service/frontend/api/v1/txe_remote_nodes.go:authorizeRemoteNode"}, found)
}
