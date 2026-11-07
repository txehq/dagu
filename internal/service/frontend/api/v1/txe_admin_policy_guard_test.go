// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"fmt"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// txeAdminGuardFindings holds the package's source to txeAdminOperations
// (TXE-6139). Every function that calls requireAdmin or requireManagerOrAbove
// must be classified; its class must fit the call it makes and the owner
// rule its class names; and no entry may name a function that calls neither.
// It returns one line per violation, so a negative control can read them.
func txeAdminGuardFindings(files []*ast.File, inventory map[string]txeAdminOperation) []string {
	type calls struct {
		admin, manager, hubHidden, dagDecided bool
	}
	seen := map[string]calls{}
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			var c calls
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				switch sel.Sel.Name {
				case "requireAdmin":
					c.admin = true
				case "requireManagerOrAbove":
					c.manager = true
				case "txeHubHidden":
					c.hubHidden = true
				case "txeNativeWriteClosed", "txeDAGFileRoute", "txeDAGRoute":
					c.dagDecided = true
				}
				return true
			})
			if c.admin || c.manager {
				seen[fn.Name.Name] = c
			}
		}
	}

	var findings []string
	for name, c := range seen {
		op, ok := inventory[name]
		if !ok {
			findings = append(findings, fmt.Sprintf("%s asks for the administrator or manager role and is not classified in txeAdminOperations", name))
			continue
		}
		if strings.TrimSpace(op.owners) == "" {
			findings = append(findings, fmt.Sprintf("%s says nothing of what it means to owners", name))
		}
		switch op.class {
		case txeAdminPlatform:
			if !c.admin {
				findings = append(findings, fmt.Sprintf("%s is classified %s and never calls requireAdmin, which carries the platform rule", name, op.class))
			}
		case txeAdminHubRecords:
			if !c.hubHidden {
				findings = append(findings, fmt.Sprintf("%s is classified %s and does not apply txeHubHidden", name, op.class))
			}
		case txeAdminOwnerScoped:
			if !c.dagDecided {
				findings = append(findings, fmt.Sprintf("%s is classified %s and is not decided on a DAG's owner (txeNativeWriteClosed, txeDAGFileRoute or txeDAGRoute)", name, op.class))
			}
		case txeAdminUnowned:
			if !c.manager {
				findings = append(findings, fmt.Sprintf("%s is classified %s and never calls requireManagerOrAbove", name, op.class))
			}
		default:
			findings = append(findings, fmt.Sprintf("%s has an unknown class %q", name, op.class))
		}
	}
	for name := range inventory {
		if _, ok := seen[name]; !ok {
			findings = append(findings, fmt.Sprintf("txeAdminOperations names %s, which asks for no role: a stale entry", name))
		}
	}
	sort.Strings(findings)
	return findings
}

func parsePackageSourcesByName(t *testing.T) map[string]*ast.File {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := gotoken.NewFileSet()
	files := map[string]*ast.File{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		require.NoError(t, err)
		files[name] = file
	}
	return files
}

func parsePackageSources(t *testing.T) []*ast.File {
	t.Helper()
	return slices.Collect(maps.Values(parsePackageSourcesByName(t)))
}

// Every function that asks for the hub's administrator or manager role is
// classified, with what it means to owners, and each class is applied the
// way the policy says (TXE-6139).
func TestEveryAdminRoleCallerIsClassified(t *testing.T) {
	t.Parallel()
	findings := txeAdminGuardFindings(parsePackageSources(t), txeAdminOperations)
	assert.Empty(t, findings, strings.Join(findings, "\n"))
	// The router sweep (txe_admin_routes_router_test.go) reads the same
	// inventory and callers from the source and reaches each by route.
}

// txePlatformRuleCopies are the functions outside txe_admin_policy.go that
// compare the mode with enforce and the scope with the platform
// administrator in one body: each is a different rule, not a copy of the
// platform rule, with its reason. A new function doing both without an
// entry here fails the guard (TXE-6139, proposed by CC3 for #230).
var txePlatformRuleCopies = map[string]string{
	"txeAuthorizeJobFor":   "a write only the job's machine makes: the administrator is held to the machine under enforce, which is a machine need, not the platform rule",
	"txeWholeHubListScope": "list filtering, not a refusal: a caller held to its owner gets an owner-filtered list, and only a non-platform caller under enforce an empty one",
	"txeNativeWriteName":   "a native write of a DAG of no owner: observe lets a legacy caller through, and the administrator is decided per DAG",
	"txeNativeCheck":       "a native read of a DAG of no owner: observe lets a legacy caller through, and the administrator is decided per DAG",
}

// txePlatformRuleCopyFindings holds the source to txePlatformRuleCopies.
func txePlatformRuleCopyFindings(files map[string]*ast.File, allowed map[string]string) []string {
	seen := map[string]bool{}
	for name, file := range files {
		if name == "txe_admin_policy.go" {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			enforce, platformAdmin := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					switch sel.Sel.Name {
					case "ModeEnforce":
						enforce = true
					case "ScopePlatformAdmin":
						platformAdmin = true
					}
				}
				return true
			})
			if enforce && platformAdmin {
				seen[fn.Name.Name] = true
			}
		}
	}
	var findings []string
	for name := range seen {
		if reason, ok := allowed[name]; !ok || strings.TrimSpace(reason) == "" {
			findings = append(findings, fmt.Sprintf("%s compares the mode with enforce and the scope with the platform administrator outside txe_admin_policy.go: a copy of the platform rule, or a different rule missing its reason in txePlatformRuleCopies", name))
		}
	}
	for name := range allowed {
		if !seen[name] {
			findings = append(findings, fmt.Sprintf("txePlatformRuleCopies names %s, which no longer does: a stale entry", name))
		}
	}
	sort.Strings(findings)
	return findings
}

// No function outside txe_admin_policy.go restates the platform rule: the
// ones that compare mode and scope the same way are different rules, each
// named with its reason. It reads the two selectors, not the expression's
// text, so a restatement in another shape is caught too; a rule written
// without either name is not, and the classification guard above is what
// holds every role-guarded route to the policy.
func TestNoCopyOfThePlatformRuleOutsideThePolicy(t *testing.T) {
	t.Parallel()
	findings := txePlatformRuleCopyFindings(parsePackageSourcesByName(t), txePlatformRuleCopies)
	assert.Empty(t, findings, strings.Join(findings, "\n"))
}

func TestPlatformRuleCopyGuardCatchesEachDrift(t *testing.T) {
	t.Parallel()
	copyOf := `func (a *API) other(c txeCall) bool { return c.mode == authz.ModeEnforce && c.scope.Kind() != authz.ScopePlatformAdmin }`
	cases := []struct {
		name, file, source string
		allowed            map[string]string
		want               string
	}{
		{"a copy in another file", "other.go", copyOf, map[string]string{}, "other compares the mode with enforce"},
		{"a copy with no reason", "other.go", copyOf, map[string]string{"other": " "}, "other compares the mode with enforce"},
		{"a stale entry", "other.go", `func (a *API) other() bool { return true }`, map[string]string{"gone": "was a rule"}, "names gone, which no longer does"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			file, err := parser.ParseFile(gotoken.NewFileSet(), tc.file, "package api\n"+tc.source, parser.SkipObjectResolution)
			require.NoError(t, err)
			findings := txePlatformRuleCopyFindings(map[string]*ast.File{tc.file: file}, tc.allowed)
			require.Len(t, findings, 1, strings.Join(findings, "\n"))
			assert.Contains(t, findings[0], tc.want)
		})
	}
	// The policy file itself, and a reasoned different rule, are clean.
	policy, err := parser.ParseFile(gotoken.NewFileSet(), "txe_admin_policy.go", "package api\n"+copyOf, parser.SkipObjectResolution)
	require.NoError(t, err)
	reasoned, err := parser.ParseFile(gotoken.NewFileSet(), "other.go", "package api\n"+copyOf, parser.SkipObjectResolution)
	require.NoError(t, err)
	assert.Empty(t, txePlatformRuleCopyFindings(map[string]*ast.File{"txe_admin_policy.go": policy, "other.go": reasoned}, map[string]string{"other": "a different rule"}))
}

func parseSnippet(t *testing.T, body string) []*ast.File {
	t.Helper()
	file, err := parser.ParseFile(gotoken.NewFileSet(), "snippet.go", "package api\n"+body, parser.SkipObjectResolution)
	require.NoError(t, err)
	return []*ast.File{file}
}

// Negative controls: the guard catches each way the inventory and the source
// can disagree, on synthetic sources it is handed.
func TestAdminRoleGuardCatchesEachDrift(t *testing.T) {
	t.Parallel()
	ok := txeAdminOperation{txeAdminPlatform, "does a platform thing"}
	cases := []struct {
		name      string
		source    string
		inventory map[string]txeAdminOperation
		want      string
	}{
		{"a new caller without a class",
			`func (a *API) NewRoute(ctx context.Context) error { return a.requireAdmin(ctx) }`,
			map[string]txeAdminOperation{}, "NewRoute asks for the administrator or manager role and is not classified"},
		{"a manager caller without a class",
			`func (a *API) NewRoute(ctx context.Context) error { return a.requireManagerOrAbove(ctx) }`,
			map[string]txeAdminOperation{}, "NewRoute asks for the administrator or manager role and is not classified"},
		{"a platform class on a manager-only call",
			`func (a *API) NewRoute(ctx context.Context) error { return a.requireManagerOrAbove(ctx) }`,
			map[string]txeAdminOperation{"NewRoute": ok}, "never calls requireAdmin, which carries the platform rule"},
		{"hub records without txeHubHidden",
			`func (a *API) NewRoute(ctx context.Context) error { return a.requireManagerOrAbove(ctx) }`,
			map[string]txeAdminOperation{"NewRoute": {txeAdminHubRecords, "reads records"}}, "does not apply txeHubHidden"},
		{"owner scoped without a DAG decision",
			`func (a *API) NewRoute(ctx context.Context) error { return a.requireAdmin(ctx) }`,
			map[string]txeAdminOperation{"NewRoute": {txeAdminOwnerScoped, "changes a DAG"}}, "is not decided on a DAG's owner"},
		{"unowned on an admin-only call",
			`func (a *API) NewRoute(ctx context.Context) error { return a.requireAdmin(ctx) }`,
			map[string]txeAdminOperation{"NewRoute": {txeAdminUnowned, "changes a profile"}}, "never calls requireManagerOrAbove"},
		{"an entry with no meaning to owners",
			`func (a *API) NewRoute(ctx context.Context) error { return a.requireAdmin(ctx) }`,
			map[string]txeAdminOperation{"NewRoute": {txeAdminPlatform, " "}}, "says nothing of what it means to owners"},
		{"a stale entry",
			`func (a *API) Other(ctx context.Context) error { return nil }`,
			map[string]txeAdminOperation{"Gone": ok}, "names Gone, which asks for no role: a stale entry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings := txeAdminGuardFindings(parseSnippet(t, tc.source), tc.inventory)
			require.Len(t, findings, 1, strings.Join(findings, "\n"))
			assert.Contains(t, findings[0], tc.want)
		})
	}

	// And a classified source is clean: one of each class, applied as the
	// policy says.
	clean := `
func (a *API) P(ctx context.Context) error { return a.requireAdmin(ctx) }
func (a *API) H(ctx context.Context) error { if err := a.requireManagerOrAbove(ctx); err != nil { return err }; if a.txeHubHidden(ctx) { return errTxeHubRecords }; return nil }
func (a *API) O(ctx context.Context, name string) error { return a.txeNativeWriteClosed(ctx, func() error { return a.requireManagerOrAbove(ctx) }, nil, name) }
func (a *API) U(ctx context.Context) error { return a.requireManagerOrAbove(ctx) }
`
	findings := txeAdminGuardFindings(parseSnippet(t, clean), map[string]txeAdminOperation{
		"P": ok, "H": {txeAdminHubRecords, "reads"}, "O": {txeAdminOwnerScoped, "writes a DAG"}, "U": {txeAdminUnowned, "changes a profile"},
	})
	assert.Empty(t, findings, strings.Join(findings, "\n"))
	assert.True(t, slices.Contains([]txeAdminClass{txeAdminPlatform, txeAdminHubRecords, txeAdminOwnerScoped, txeAdminUnowned}, ok.class))
}
