// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// The Go half parses each directory's files (all build tags, no type
// checking) and follows values from the environment through a package:
//
//   - a source is a call to os.Getenv, os.LookupEnv, os.Environ, os.ExpandEnv,
//     os.UserHomeDir, os.UserCacheDir, os.UserConfigDir, os.TempDir,
//     runtime.GOROOT, a use of build.Default, or a command whose argv runs
//     `go env`;
//   - a variable or field assigned from a tainted expression is tainted, in
//     its function, or package-wide for a package-level name;
//   - a package function that returns a tainted value taints its calls, and
//     a parameter is tainted when any call in the package passes it a
//     tainted argument.
//
// It reports `go clean -modcache|-cache|-fuzzcache` in any argv or string,
// and os.RemoveAll, or an argv running rm -r, given a tainted path.

var envSources = map[string]map[string]bool{
	"os": {
		"Getenv": true, "LookupEnv": true, "Environ": true, "ExpandEnv": true,
		"UserHomeDir": true, "UserCacheDir": true, "UserConfigDir": true, "TempDir": true,
	},
	"runtime": {"GOROOT": true},
}

type goFile struct {
	src     source
	file    *ast.File
	imports map[string]string // local name -> import path
}

type goPkg struct {
	fset  *token.FileSet
	files []*goFile
	funcs map[string]*ast.FuncDecl // package-level functions, by name

	globals    map[string]bool          // tainted package-level names
	retTainted map[string]bool          // functions returning a tainted value
	params     map[string]map[int]bool  // tainted parameters by function and index
	locals     map[*ast.FuncDecl]taints // tainted names per function
}

type taints map[string]bool

func lintGoDir(srcs []source) ([]Finding, map[string][]directiveAt) {
	fset := token.NewFileSet()
	dirs := map[string][]directiveAt{}
	var out []Finding
	byPkg := map[string]*goPkg{}
	var order []string
	for _, s := range srcs {
		f, err := parser.ParseFile(fset, s.rel, s.data, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			if isTestdata(s.rel) {
				continue // a fixture that is not meant to compile
			}
			out = append(out, Finding{Path: s.rel, Line: 1, Rule: ruleParse, Msg: "cannot parse: " + err.Error()})
			continue
		}
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if reason, ok := parseDirective(c.Text); ok {
					dirs[s.rel] = append(dirs[s.rel], directiveAt{line: fset.Position(c.Pos()).Line, reason: reason})
				}
			}
		}
		pkgKey := f.Name.Name
		p := byPkg[pkgKey]
		if p == nil {
			p = &goPkg{fset: fset, funcs: map[string]*ast.FuncDecl{}, globals: map[string]bool{},
				retTainted: map[string]bool{}, params: map[string]map[int]bool{}, locals: map[*ast.FuncDecl]taints{}}
			byPkg[pkgKey] = p
			order = append(order, pkgKey)
		}
		gf := &goFile{src: s, file: f, imports: importNames(f)}
		p.files = append(p.files, gf)
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Body != nil {
				p.funcs[fd.Name.Name] = fd
			}
		}
	}
	sort.Strings(order)
	for _, k := range order {
		p := byPkg[k]
		p.solve()
		out = append(out, p.report()...)
	}
	return out, dirs
}

func isTestdata(rel string) bool {
	return strings.Contains("/"+path.Dir(rel)+"/", "/testdata/")
}

func importNames(f *ast.File) map[string]string {
	m := map[string]string{}
	for _, im := range f.Imports {
		p, err := strconv.Unquote(im.Path.Value)
		if err != nil {
			continue
		}
		name := path.Base(p)
		if im.Name != nil {
			name = im.Name.Name
		}
		m[name] = p
	}
	return m
}

// solve computes taint to a fixed point across the package.
func (p *goPkg) solve() {
	for changed := true; changed; {
		changed = false
		for _, gf := range p.files {
			for _, d := range gf.file.Decls {
				switch d := d.(type) {
				case *ast.GenDecl:
					for _, sp := range d.Specs {
						vs, ok := sp.(*ast.ValueSpec)
						if !ok {
							continue
						}
						for i, n := range vs.Names {
							if p.globals[n.Name] {
								continue
							}
							if rhsTainted(p, gf, nil, vs.Values, i) {
								p.globals[n.Name] = true
								changed = true
							}
						}
					}
				case *ast.FuncDecl:
					if d.Body == nil {
						continue
					}
					if p.solveFunc(gf, d) {
						changed = true
					}
				}
			}
		}
	}
}

// solveFunc updates one function's tainted names, its return taint, and the
// parameters it taints in the functions it calls. It reports any change.
func (p *goPkg) solveFunc(gf *goFile, fd *ast.FuncDecl) bool {
	local := p.locals[fd]
	if local == nil {
		local = taints{}
		p.locals[fd] = local
	}
	changed := false
	mark := func(key string) {
		if key == "" || local[key] {
			return
		}
		local[key] = true
		changed = true
		if !strings.Contains(key, ".") && p.isGlobalName(key) && !p.globals[key] {
			p.globals[key] = true
		}
	}
	if fd.Recv == nil && fd.Type.Params != nil {
		idx := 0
		for _, field := range fd.Type.Params.List {
			names := field.Names
			if len(names) == 0 {
				idx++
				continue
			}
			for _, n := range names {
				if p.params[fd.Name.Name][idx] {
					mark(n.Name)
				}
				idx++
			}
		}
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range n.Lhs {
				if rhsTainted(p, gf, local, n.Rhs, i) {
					mark(exprKey(lhs))
				}
			}
		case *ast.ValueSpec:
			for i, name := range n.Names {
				if rhsTainted(p, gf, local, n.Values, i) {
					mark(name.Name)
				}
			}
		case *ast.RangeStmt:
			if p.tainted(gf, local, n.X) {
				if n.Key != nil {
					mark(exprKey(n.Key))
				}
				if n.Value != nil {
					mark(exprKey(n.Value))
				}
			}
		case *ast.ReturnStmt:
			if fd.Recv == nil && !p.retTainted[fd.Name.Name] {
				results := n.Results
				if len(results) == 0 && fd.Type.Results != nil {
					// A bare return returns the named results.
					for _, field := range fd.Type.Results.List {
						for _, name := range field.Names {
							results = append(results, name)
						}
					}
				}
				for _, r := range results {
					if p.tainted(gf, local, r) {
						p.retTainted[fd.Name.Name] = true
						changed = true
						break
					}
				}
			}
		case *ast.CallExpr:
			if id, ok := n.Fun.(*ast.Ident); ok {
				if callee := p.funcs[id.Name]; callee != nil {
					for i, a := range n.Args {
						if p.params[id.Name][i] || !p.tainted(gf, local, a) {
							continue
						}
						if p.params[id.Name] == nil {
							p.params[id.Name] = map[int]bool{}
						}
						p.params[id.Name][i] = true
						changed = true
					}
				}
			}
		}
		return true
	})
	return changed
}

func (p *goPkg) isGlobalName(name string) bool {
	for _, gf := range p.files {
		if gf.file.Scope != nil && gf.file.Scope.Lookup(name) != nil {
			return true
		}
		for _, d := range gf.file.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, sp := range gd.Specs {
				if vs, ok := sp.(*ast.ValueSpec); ok {
					for _, n := range vs.Names {
						if n.Name == name {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// rhsTainted reports whether the value assigned to the i-th left-hand name is
// tainted. With one call on the right (v, ok := f()), every name takes it.
func rhsTainted(p *goPkg, gf *goFile, local taints, rhs []ast.Expr, i int) bool {
	switch {
	case len(rhs) == 0:
		return false
	case len(rhs) == 1:
		return p.tainted(gf, local, rhs[0])
	case i < len(rhs):
		return p.tainted(gf, local, rhs[i])
	}
	return false
}

// exprKey names an assignable expression: x, or a field chain such as d.cache.
func exprKey(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		if e.Name == "_" {
			return ""
		}
		return e.Name
	case *ast.SelectorExpr:
		if k := exprKey(e.X); k != "" {
			return k + "." + e.Sel.Name
		}
	case *ast.StarExpr:
		return exprKey(e.X)
	case *ast.ParenExpr:
		return exprKey(e.X)
	}
	return ""
}

// tainted reports whether an expression can carry a path the environment chose.
func (p *goPkg) tainted(gf *goFile, local taints, e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if found {
			return false
		}
		switch n := n.(type) {
		case *ast.FuncLit:
			return false // a closure's body is not its value
		case *ast.CallExpr:
			if createsTempCall(gf, n) {
				return false // a directory made under a unique name: its identity is known
			}
			if p.isSource(gf, n) {
				found = true
				return false
			}
			if id, ok := n.Fun.(*ast.Ident); ok && p.retTainted[id.Name] {
				found = true
				return false
			}
		case *ast.SelectorExpr:
			if pkg, ok := n.X.(*ast.Ident); ok && gf.imports[pkg.Name] == "go/build" && n.Sel.Name == "Default" {
				found = true
				return false
			}
			if k := exprKey(n); k != "" && (local[k] || p.globals[k]) {
				found = true
				return false
			}
		case *ast.Ident:
			if local[n.Name] || p.globals[n.Name] {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// isSource reports whether a call reads the environment.
func (p *goPkg) isSource(gf *goFile, call *ast.CallExpr) bool {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if pkg, ok := sel.X.(*ast.Ident); ok {
			if names := envSources[gf.imports[pkg.Name]]; names[sel.Sel.Name] {
				return true
			}
		}
	}
	lits := argvLiterals(call, nil)
	for i := 0; i+1 < len(lits); i++ {
		if lits[i] == "go" && lits[i+1] == "env" {
			return true
		}
	}
	// A go binary held in a variable: exec.Command(goBin, "env", "GOMODCACHE").
	if len(lits) >= 2 && lits[0] == "env" && strings.HasPrefix(lits[1], "GO") {
		return true
	}
	for _, s := range stringLits(call) {
		if goEnvRe.MatchString(normArgv(s)) {
			return true
		}
	}
	return false
}

// litEnv holds, per variable name, the string literals assigned to it as a
// value or an argv slice, so an argv built across variables is read whole:
// args := []string{"clean"}; args = append(args, "-modcache").
type litEnv map[string][]string

// argvLiterals lists the string literals among a call's arguments in order,
// looking into composite literals, append/slices calls that build an argv,
// and, with env, variables that hold literals.
func argvLiterals(call *ast.CallExpr, env litEnv) []string {
	var out []string
	for _, a := range call.Args {
		out = append(out, exprLits(a, env)...)
	}
	return out
}

func exprLits(e ast.Expr, env litEnv) []string {
	var out []string
	var walk func(e ast.Expr)
	walk = func(e ast.Expr) {
		switch e := e.(type) {
		case *ast.Ident:
			out = append(out, env[e.Name]...)
		case *ast.BasicLit:
			if e.Kind == token.STRING {
				if s, err := strconv.Unquote(e.Value); err == nil {
					out = append(out, s)
				}
			}
		case *ast.CompositeLit:
			for _, el := range e.Elts {
				walk(el)
			}
		case *ast.CallExpr:
			if argvBuilder(e) {
				for _, a := range e.Args {
					walk(a)
				}
			}
		case *ast.ParenExpr:
			walk(e.X)
		}
	}
	walk(e)
	return out
}

// collectLits records the literals each name is assigned within n, in
// source order, on top of env.
func collectLits(n ast.Node, env litEnv) {
	add := func(name string, rhs ast.Expr) {
		if name == "" || name == "_" {
			return
		}
		for _, s := range exprLits(rhs, env) {
			if !slices.Contains(env[name], s) {
				env[name] = append(env[name], s)
			}
		}
	}
	ast.Inspect(n, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) == len(n.Rhs) {
				for i, lhs := range n.Lhs {
					if id, ok := lhs.(*ast.Ident); ok {
						add(id.Name, n.Rhs[i])
					}
				}
			}
		case *ast.ValueSpec:
			if len(n.Names) == len(n.Values) {
				for i, id := range n.Names {
					add(id.Name, n.Values[i])
				}
			}
		}
		return true
	})
}

// cleanArgv reports literals that make a go clean of a whole cache.
func cleanArgv(lits []string) bool {
	return slices.Contains(lits, "clean") && slices.ContainsFunc(lits, func(s string) bool { return goCacheFlags[s] })
}

// argvBuilder reports a call that only assembles a slice: append, or
// slices.Concat/Clone.
func argvBuilder(call *ast.CallExpr) bool {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name == "append"
	case *ast.SelectorExpr:
		if pkg, ok := f.X.(*ast.Ident); ok && pkg.Name == "slices" {
			return f.Sel.Name == "Concat" || f.Sel.Name == "Clone"
		}
	}
	return false
}

func stringLits(n ast.Node) []string {
	var out []string
	ast.Inspect(n, func(n ast.Node) bool {
		if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			if s, err := strconv.Unquote(bl.Value); err == nil {
				out = append(out, s)
			}
		}
		return true
	})
	return out
}

// createsTempCall reports a call that creates a fresh directory or file:
// os.MkdirTemp, os.CreateTemp, ioutil.TempDir/TempFile, or a testing
// TempDir() method such as t.TempDir().
func createsTempCall(gf *goFile, call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if pkg, ok := sel.X.(*ast.Ident); ok {
		switch gf.imports[pkg.Name] {
		case "os":
			return sel.Sel.Name == "MkdirTemp" || sel.Sel.Name == "CreateTemp"
		case "io/ioutil":
			return sel.Sel.Name == "TempDir" || sel.Sel.Name == "TempFile"
		}
	}
	return sel.Sel.Name == "TempDir" && len(call.Args) == 0
}

// execCall reports a call that runs a command: os/exec's Command or
// CommandContext, or any call whose argv passes -c to a shell.
func execCall(gf *goFile, call *ast.CallExpr, lits []string) bool {
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if pkg, ok := sel.X.(*ast.Ident); ok && gf.imports[pkg.Name] == "os/exec" {
			return sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext"
		}
	}
	return slices.Contains(lits, "-c")
}

var goCacheFlags = map[string]bool{
	"-modcache": true, "--modcache": true, "-cache": true, "--cache": true,
	"-fuzzcache": true, "--fuzzcache": true,
}

var rmRecursiveFlag = func(s string) bool { return rmRecRe.MatchString(s) }

// report walks the package once more and reports what the solved taint makes
// a finding.
func (p *goPkg) report() []Finding {
	var out []Finding
	pkgLits := litEnv{}
	for _, gf := range p.files {
		for _, d := range gf.file.Decls {
			if gd, ok := d.(*ast.GenDecl); ok && gd.Tok != token.IMPORT {
				collectLits(gd, pkgLits)
			}
		}
	}
	for _, gf := range p.files {
		seenLit := map[*ast.BasicLit]bool{}
		harness := isHarness(gf.src.rel)
		var fd *ast.FuncDecl
		var env litEnv
		visit := func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CompositeLit:
				// An argv held in a variable: []string{"clean", "-modcache"}.
				lits := stringLitNodes(n)
				if len(lits) > 0 && !seenLit[lits[0]] && cleanArgv(exprLits(n, nil)) {
					out = append(out, p.at(gf, n, ruleGoClean, goCleanMsg))
					for _, s := range lits {
						seenLit[s] = true
					}
				}
			case *ast.CallExpr:
				if f, ok := p.callFinding(gf, p.locals[fd], env, n, harness); ok {
					out = append(out, f)
					for _, s := range stringLitNodes(n) {
						seenLit[s] = true
					}
				}
			case *ast.BinaryExpr:
				if n.Op == token.ADD && harness {
					if f, ok := p.concatFinding(gf, p.locals[fd], n); ok {
						out = append(out, f)
						for _, s := range stringLitNodes(n) {
							seenLit[s] = true
						}
						return false
					}
				}
			case *ast.BasicLit:
				if n.Kind != token.STRING || seenLit[n] {
					return true
				}
				s, err := strconv.Unquote(n.Value)
				if err != nil {
					return true
				}
				if goCleanIn(s) {
					out = append(out, p.at(gf, n, ruleGoClean, goCleanMsg))
				}
			}
			return true
		}
		for _, d := range gf.file.Decls {
			fd, _ = d.(*ast.FuncDecl)
			env = maps.Clone(pkgLits)
			if fd != nil {
				collectLits(fd, env)
			}
			ast.Inspect(d, visit)
		}
	}
	return out
}

func stringLitNodes(n ast.Node) []*ast.BasicLit {
	var out []*ast.BasicLit
	ast.Inspect(n, func(n ast.Node) bool {
		if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			out = append(out, bl)
		}
		return true
	})
	return out
}

func (p *goPkg) at(gf *goFile, n ast.Node, rule, msg string) Finding {
	return Finding{Path: gf.src.rel, Line: p.fset.Position(n.Pos()).Line, Rule: rule, Msg: msg}
}

// callFinding judges one call: a go clean argv, os.RemoveAll of a tainted
// path, or an argv running rm -r on a tainted path.
func (p *goPkg) callFinding(gf *goFile, local taints, env litEnv, call *ast.CallExpr, harness bool) (Finding, bool) {
	if argvBuilder(call) {
		// An append that only builds the argv is judged on its own
		// literals; the call that runs the argv reads it through env.
		env = nil
	}
	lits := argvLiterals(call, env)
	if cleanArgv(lits) {
		return p.at(gf, call, ruleGoClean, goCleanMsg), true
	}
	if slices.ContainsFunc(lits, goCleanIn) {
		return p.at(gf, call, ruleGoClean, goCleanMsg), true
	}
	if !harness {
		return Finding{}, false
	}
	if execCall(gf, call, lits) {
		// Shell text run by this call: sh -c "rm -rf $HOME/x".
		for _, s := range lits {
			if f, ok := p.shellLiteralFinding(gf, call, s); ok {
				return f, true
			}
		}
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		if pkg, ok := sel.X.(*ast.Ident); ok && gf.imports[pkg.Name] == "os" && sel.Sel.Name == "RemoveAll" && len(call.Args) == 1 {
			if p.tainted(gf, local, call.Args[0]) {
				return p.at(gf, call, ruleEnvDelete, "os.RemoveAll of a path read from the environment ("+exprText(call.Args[0])+"); remove only a directory this code created, such as t.TempDir() or os.MkdirTemp"), true
			}
			return Finding{}, false
		}
	}
	rm, recursive := false, false
	for _, s := range lits {
		if s == "rm" {
			rm = true
		} else if rm && rmRecursiveFlag(s) {
			recursive = true
		}
	}
	if rm && recursive {
		for _, a := range call.Args {
			if _, lit := a.(*ast.BasicLit); lit {
				continue
			}
			if p.tainted(gf, local, a) {
				return p.at(gf, call, ruleEnvDelete, "rm -r of a path read from the environment; remove only a directory this code created"), true
			}
		}
	}
	return Finding{}, false
}

// concatFinding judges shell text built by concatenation, such as
// "rm -rf " + dir with dir from the environment.
func (p *goPkg) concatFinding(gf *goFile, local taints, b *ast.BinaryExpr) (Finding, bool) {
	var parts []ast.Expr
	var flatten func(e ast.Expr)
	flatten = func(e ast.Expr) {
		if be, ok := e.(*ast.BinaryExpr); ok && be.Op == token.ADD {
			flatten(be.X)
			flatten(be.Y)
			return
		}
		parts = append(parts, e)
	}
	flatten(b)
	var text strings.Builder
	taintedPart := false
	for _, e := range parts {
		if bl, ok := e.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			s, _ := strconv.Unquote(bl.Value)
			text.WriteString(s)
			continue
		}
		if p.tainted(gf, local, e) {
			taintedPart = true
			text.WriteString("$HOME") // stands for the tainted value
		} else {
			text.WriteString("x")
		}
	}
	s := text.String()
	if goCleanIn(s) {
		return p.at(gf, b, ruleGoClean, goCleanMsg), true
	}
	if taintedPart {
		if f, ok := p.shellLiteralFinding(gf, b, s); ok {
			return f, true
		}
	}
	return Finding{}, false
}

// shellLiteralFinding judges shell text held in a Go string.
func (p *goPkg) shellLiteralFinding(gf *goFile, n ast.Node, s string) (Finding, bool) {
	if goCleanIn(s) {
		return p.at(gf, n, ruleGoClean, goCleanMsg), true
	}
	if !strings.Contains(s, "rm") && !strings.Contains(s, "find") {
		return Finding{}, false
	}
	sc := &scriptScan{l: langShell, tainted: map[string]bool{}, defined: map[string]bool{}}
	sc.logical = joinLines(langShell, lines([]byte(s)))
	sc.collectAssignments()
	sc.propagate()
	for _, lg := range sc.logical {
		if target, ok := sc.envDelete(stripComment(lg.text)); ok {
			return p.at(gf, n, ruleEnvDelete, "shell text deletes a path the environment chooses ("+strings.TrimSpace(target)+"); delete only a directory this code created"), true
		}
	}
	return Finding{}, false
}

func exprText(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprText(e.X) + "." + e.Sel.Name
	case *ast.CallExpr:
		return exprText(e.Fun) + "(...)"
	case *ast.BasicLit:
		return e.Value
	}
	return "expression"
}
