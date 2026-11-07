// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeauth

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
)

const unboundTestJob = "job_01M5YYYYYYYYYYYYYYYYYYYYYY"

func unboundTestMachineDAG() string { return MachineDAGs("mch_01M5ZZZZZZZZZZZZZZZZZZZZZZ")[0] }

// An owner's DAG, by every name it answers to, is decided as the owner's: its
// declared name, its file, the file a queued run was loaded from.
func TestDecideUnboundTriggerResolvesEveryAlias(t *testing.T) {
	t.Parallel()
	for name, dag := range map[string]*ir.DAG{
		"job":                    {Name: unboundTestJob},
		"machine DAG":            {Name: unboundTestMachineDAG()},
		"declared alias":         {Name: "alias", Location: "/dags/alias.yaml", SourceFile: "", YamlData: nil},
		"file declares alias":    {Name: "alias", Location: "/dags/" + unboundTestJob + ".yaml"},
		"queued run's source":    {Name: "alias", SourceFile: "/dags/" + unboundTestJob + ".yaml"},
		"machine file, any name": {Name: "nightly", Location: "/dags/" + unboundTestMachineDAG() + ".yml"},
		"declared as the job":    {Name: unboundTestJob, Location: "/dags/alias.yaml"},
	} {
		t.Run(name, func(t *testing.T) {
			owned := name != "declared alias"
			_, err := DecideUnboundTrigger(authz.ModeEnforce, true, dag, nil)
			if owned {
				require.ErrorIs(t, err, ErrUnboundOwnerDAG)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// The rule by mode, and with and without an owner store's answer.
func TestDecideUnboundTriggerByMode(t *testing.T) {
	t.Parallel()
	owner := &ir.DAG{Name: unboundTestJob}
	noOwner := &ir.DAG{Name: "nightly-report", Location: "/dags/nightly-report.yaml"}
	held := func(string) (bool, error) { return true, nil }
	unheld := func(string) (bool, error) { return false, nil }
	broken := func(string) (bool, error) { return false, errors.New("store down") }

	for _, tc := range []struct {
		name      string
		mode      authz.Mode
		known     bool
		dag       *ir.DAG
		owned     func(string) (bool, error)
		err       error
		wouldDeny bool
	}{
		{name: "enforce refuses an owner's DAG", mode: authz.ModeEnforce, known: true, dag: owner, owned: held, err: ErrUnboundOwnerDAG},
		{name: "unknown mode decides as enforce", mode: "", known: false, dag: owner, owned: nil, err: ErrUnboundOwnerDAG},
		{name: "unknown mode, even with off read", mode: authz.ModeOff, known: false, dag: owner, owned: nil, err: ErrUnboundOwnerDAG},
		{name: "enforce, store cannot tell", mode: authz.ModeEnforce, known: true, dag: owner, owned: broken, err: ErrUnboundOwnerUnknown},
		{name: "enforce, name of an unregistered owner", mode: authz.ModeEnforce, known: true, dag: owner, owned: unheld},
		{name: "observe allows and reports", mode: authz.ModeObserve, known: true, dag: owner, owned: held, wouldDeny: true},
		{name: "observe, store cannot tell", mode: authz.ModeObserve, known: true, dag: owner, owned: broken},
		{name: "off allows", mode: authz.ModeOff, known: true, dag: owner, owned: held},
		{name: "a DAG of no owner, enforce", mode: authz.ModeEnforce, known: true, dag: noOwner, owned: broken},
		{name: "a DAG of no owner, unknown mode", mode: "", known: false, dag: noOwner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			decision, err := DecideUnboundTrigger(tc.mode, tc.known, tc.dag, tc.owned)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				assert.Zero(t, decision.Trigger, "a refusal carries no allowance")
				return
			}
			require.NoError(t, err)
			assert.NotZero(t, decision.Trigger)
			assert.Equal(t, tc.wouldDeny, decision.WouldDeny)
		})
	}
}

// Only the owner rule makes the allowance a run no hub principal asks for
// needs: a call to intake.NewUnboundTrigger anywhere else in the source,
// which would queue such a run without the rule, fails here.
func TestOnlyTheOwnerRuleAllowsAnUnboundRun(t *testing.T) {
	t.Parallel()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
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
		if err != nil || !bytes.Contains(data, []byte("NewUnboundTrigger")) {
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
				name := ""
				switch f := call.Fun.(type) {
				case *ast.SelectorExpr:
					name = f.Sel.Name
				case *ast.Ident:
					name = f.Name
				}
				if name == "NewUnboundTrigger" {
					found = append(found, filepath.ToSlash(rel)+":"+fn.Name.Name)
				}
				return true
			})
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"internal/txe/txeauth/unbound.go:DecideUnboundTrigger"}, found)
}
