// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package onbehalf_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The packages whose requests to the identity provider are made on another
// request's behalf, and must be built on onbehalf.Context.
var guardedPackages = []string{"../transportauth", "../cliauth"}

// notOnBehalf lists the requests in those packages that are a caller's own,
// so the caller's trace is for them: "package.Function" to the reason. An
// entry that matches nothing fails the test, so the list stays current.
var notOnBehalf = map[string]string{
	"cliauth.DiscoverHub": "the CLI's own request to the hub, not made for another request",
}

const (
	helperPath = "github.com/dagucloud/dagu/v2/internal/txe/onbehalf"
	oidcPath   = "github.com/coreos/go-oidc"
)

// Every request the guarded packages build with a context, and every
// context handed to go-oidc, which builds requests of its own, takes a
// context that came through onbehalf.Context in the same function. A new
// renewal, or a new request in a renewal's path, cannot leave the caller's
// trace on by omission.
func TestEveryProviderRequestIsMadeOnBehalf(t *testing.T) {
	used := map[string]bool{}
	var violations []string
	for _, dir := range guardedPackages {
		fset := token.NewFileSet()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			// Every file of every build, the platform-specific ones included.
			file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			violations = append(violations, checkFile(fset, file.Name.Name, file, used)...)
		}
	}
	sort.Strings(violations)
	for _, v := range violations {
		t.Error(v)
	}
	for name := range notOnBehalf {
		if !used[name] {
			t.Errorf("notOnBehalf lists %s, which builds no request any more; remove the entry", name)
		}
	}
}

// requestCalls are the calls checked, by import path and function, with the
// index of their context argument.
var requestCalls = map[string]map[string]int{
	"net/http": {"NewRequestWithContext": 0},
	oidcPath:   {"NewProvider": 0, "ClientContext": 0},
}

type fileCheck struct {
	fset  *token.FileSet
	names map[string]string // local import name -> path
	pkg   string
}

func checkFile(fset *token.FileSet, pkgName string, file *ast.File, used map[string]bool) []string {
	c := &fileCheck{fset: fset, names: map[string]string{}, pkg: pkgName}
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		name := filepath.Base(path)
		if after, ok := strings.CutPrefix(name, "go-"); ok {
			name = after // go-oidc is package oidc
		}
		if imp.Name != nil {
			name = imp.Name.Name
		}
		c.names[name] = path
	}
	var out []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		qualified := c.pkg + "." + fn.Name.Name
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			path, sel, ok := c.selector(call.Fun)
			if !ok {
				return true
			}
			idx, checked := requestCalls[path][sel]
			if !checked || len(call.Args) <= idx {
				return true
			}
			if reason, listed := notOnBehalf[qualified]; listed {
				used[qualified] = true
				_ = reason
				return true
			}
			if !c.onBehalf(fn.Body, call.Args[idx], call.Pos()) {
				out = append(out, fmt.Sprintf("%s: %s in %s takes a context that did not come through onbehalf.Context; a request made for another request drops its trace there, or the function is listed in notOnBehalf with its reason",
					c.fset.Position(call.Pos()), c.display(path, sel), qualified))
			}
			return true
		})
	}
	return out
}

// display names a call as the file does, by its import's local name.
func (c *fileCheck) display(path, sel string) string {
	for name, p := range c.names {
		if p == path {
			return name + "." + sel
		}
	}
	return path + "." + sel
}

// selector resolves pkg.Name in a call to its import path and name.
func (c *fileCheck) selector(fun ast.Expr) (path, name string, ok bool) {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", "", false
	}
	path, ok = c.names[ident.Name]
	return path, sel.Sel.Name, ok
}

// onBehalf reports whether expr, a context used at pos, came through
// onbehalf.Context: the call itself, a context derived from such a call by
// the context package or by oidc.ClientContext, or a variable last assigned
// one of those before pos in body.
func (c *fileCheck) onBehalf(body *ast.BlockStmt, expr ast.Expr, pos token.Pos) bool {
	switch e := expr.(type) {
	case *ast.CallExpr:
		path, name, ok := c.selector(e.Fun)
		if !ok || len(e.Args) == 0 {
			return false
		}
		if path == helperPath && name == "Context" {
			return true
		}
		if path == "context" || (path == oidcPath && name == "ClientContext") {
			return c.onBehalf(body, e.Args[0], pos)
		}
		return false
	case *ast.Ident:
		var last ast.Expr
		ast.Inspect(body, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || assign.Pos() >= pos {
				return true
			}
			for i, lhs := range assign.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || id.Name != e.Name {
					continue
				}
				if len(assign.Rhs) == len(assign.Lhs) {
					last = assign.Rhs[i]
				} else {
					last = assign.Rhs[0]
				}
			}
			return true
		})
		return last != nil && c.onBehalf(body, last, pos)
	default:
		return false
	}
}
