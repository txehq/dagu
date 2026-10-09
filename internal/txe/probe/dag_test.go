// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"strings"
	"testing"

	_ "github.com/dagucloud/dagu/v2/internal/runtime/builtin" // the loader needs the command executor registered
	"github.com/dagucloud/dagu/v2/internal/spec"
)

const testMachine = "mch_01JTXE0000000000000000F1X3"

func reconcileConfig() ReconcileDAGConfig {
	return ReconcileDAGConfig{
		MachineID:  testMachine,
		DaguBin:    "/Users/me/.txe/bin/dagu",
		StoreFlags: []string{"--dagu-home", "/Users/me/.txe", "--context", "txe"},
		Env:        map[string]string{"TXE_DAGU_HOME": "/Users/me/.txe", "DAGU_HOME": "/Users/me/.txe"},
	}
}

// The rendered DAG is one Dagu loads, named by the shared helper, bound to
// the machine's worker and running only the check.
func TestRenderReconcileDAG(t *testing.T) {
	name, out, err := RenderReconcileDAG(reconcileConfig())
	if err != nil {
		t.Fatal(err)
	}
	if name != ReconcileDAGName(testMachine) || len(name) > 40 {
		t.Fatalf("name = %q", name)
	}
	dag, err := spec.LoadYAML(t.Context(), out, spec.WithName(name), spec.WithoutEval())
	if err != nil {
		t.Fatalf("Dagu cannot load the rendered DAG: %v\n%s", err, out)
	}
	if dag.WorkerSelector["txe.machine"] != testMachine {
		t.Fatalf("worker selector = %v", dag.WorkerSelector)
	}
	if len(dag.Steps) != 1 {
		t.Fatalf("steps = %d, want 1", len(dag.Steps))
	}
	text := string(out)
	for _, want := range []string{
		"txe-probe-dag-version: 1",
		`schedule: "*/15 * * * *"`,
		"overlap_policy: skip",
		"max_active_runs: 1",
		"timeout_sec: 600",
		`command: "/Users/me/.txe/bin/dagu txe resource check --machine ` + testMachine + ` --dagu-home /Users/me/.txe --context txe"`,
		`  - DAGU_HOME: "/Users/me/.txe"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered DAG lacks %q:\n%s", want, text)
		}
	}
	// Deterministic: env order does not change the bytes.
	_, again, _ := RenderReconcileDAG(reconcileConfig())
	if string(again) != text {
		t.Fatal("rendering is not deterministic")
	}
	if strings.Index(text, "DAGU_HOME:") > strings.Index(text, "TXE_DAGU_HOME:") {
		t.Fatal("env is not sorted")
	}
}

func TestRenderReconcileDAGRefusesUnsafeInput(t *testing.T) {
	for name, mutate := range map[string]func(*ReconcileDAGConfig){
		"machine id":   func(c *ReconcileDAGConfig) { c.MachineID = "mch_short" },
		"binary shell": func(c *ReconcileDAGConfig) { c.DaguBin = "/bin/dagu; rm -rf /" },
		"flag space":   func(c *ReconcileDAGConfig) { c.StoreFlags = []string{"--context", "a b"} },
		"flag subst":   func(c *ReconcileDAGConfig) { c.StoreFlags = []string{"$(id)"} },
		"env name":     func(c *ReconcileDAGConfig) { c.Env = map[string]string{"bad-name": "x"} },
		"schedule":     func(c *ReconcileDAGConfig) { c.Schedule = "@every 5m" },
		"timeout":      func(c *ReconcileDAGConfig) { c.TimeoutSec = -1 },
		// The DAG is stored on the hub in plain text: credentials never.
		"env api key":    func(c *ReconcileDAGConfig) { c.Env = map[string]string{"TXE_DAGU_HOME": "dagu_0123456789abcdef"} },
		"env token name": func(c *ReconcileDAGConfig) { c.Env = map[string]string{"LINEAR_API_KEY": "/x"} },
		"env secret var": func(c *ReconcileDAGConfig) { c.Env = map[string]string{"GITHUB_TOKEN": "/x"} },
		"env long value": func(c *ReconcileDAGConfig) { c.Env = map[string]string{"X": "AKIAABCDEFGHIJKLMNOPQRSTUVWXYZ012345"} },
		"env linear key": func(c *ReconcileDAGConfig) { c.Env = map[string]string{"X": "lin_api_abc"} },
		"flag token":     func(c *ReconcileDAGConfig) { c.StoreFlags = []string{"--token=abc"} },
		"flag api key":   func(c *ReconcileDAGConfig) { c.StoreFlags = []string{"--context", "dagu_0123456789abcdef"} },
		// A JWT has dots, dashes and underscores but is no path.
		"env jwt": func(c *ReconcileDAGConfig) {
			c.Env = map[string]string{"X": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}
		},
		"flag jwt": func(c *ReconcileDAGConfig) {
			c.StoreFlags = []string{"--context", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-def_ghi"}
		},
		"env dots": func(c *ReconcileDAGConfig) { c.Env = map[string]string{"X": "/a/../../etc"} },
		"relative": func(c *ReconcileDAGConfig) { c.DaguBin = "dagu" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := reconcileConfig()
			mutate(&cfg)
			if _, _, err := RenderReconcileDAG(cfg); err == nil {
				t.Fatal("rendered unsafe input")
			}
		})
	}
}
