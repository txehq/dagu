// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package placement reads where a DAG spec sends its work: the machine each
// of its documents and steps selects, and the DAG each step calls, read as
// the loader and the runtime read them. Native DAG writes (TXE-4412) and job
// registration (TXE-4717) decide on what it reports, so the two cannot
// disagree about where a spec runs.
package placement

import (
	"errors"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/parser"

	"github.com/dagucloud/dagu/v2/internal/cmn/yamlutil"
	"github.com/dagucloud/dagu/v2/internal/ir"
)

// MachineLabel is the worker label that names a TXE machine.
const MachineLabel = "txe.machine"

// ErrUnverified means a spec's placement cannot be read: a worker selector
// or a called DAG is computed, a selector names labels but no machine, or a
// selector is written with space the loader would trim.
var ErrUnverified = errors.New("placement: a worker selector or a called DAG cannot be verified")

// Placement is one DAG a spec defines, or one step of it: the name it
// declares or calls, and the machine it is sent to, if any.
type Placement struct {
	// Name is a DAG the spec defines (its declared name) or a step calls.
	Name string
	// Machine is the txe.machine a document or a step selects, if any.
	Machine string
	// Step marks a step's placement or reference, not a document's.
	Step bool
	// Document is, for a step, the name of the DAG the spec defines that the
	// step belongs to.
	Document string
}

// Of reports every DAG dag defines (itself and each local DAG), by its name
// and the machine it is sent to, and every step of each, by the DAG it calls
// and the machine it sends that to. Steps are read wherever they run:
// handlers, and the body of a foreach, nested ones included. A DAG a chat
// step may call as a tool, named by the step or by the DAG's own llm
// settings, is a called DAG too. A step running an action package cannot be
// verified: the package's DAG is fetched when it runs and goes where it says.
// dag is the spec as the loader built it; Written checks what the loader
// cannot show.
func Of(dag *ir.DAG) ([]Placement, error) {
	if dag == nil {
		return nil, ErrUnverified
	}
	dags := []*ir.DAG{dag}
	for _, local := range dag.LocalDAGs {
		dags = append(dags, local)
	}
	var out []Placement
	for _, d := range dags {
		if d == nil {
			return nil, ErrUnverified
		}
		machine, err := SelectedMachine(d.WorkerSelector)
		if err != nil {
			return nil, err
		}
		// A base configuration's "worker_selector: local" survives a
		// document's own selector: the DAG would run on the hub, not on the
		// machine it names.
		if d.ForceLocal && machine != "" {
			return nil, ErrUnverified
		}
		out = append(out, Placement{Name: d.Name, Machine: machine})
		if d.LLM != nil {
			if out, err = toolPlacements(out, d.Name, d.LLM.Tools); err != nil {
				return nil, err
			}
		}
		steps := make([]*ir.Step, 0, len(d.Steps)+6)
		for i := range d.Steps {
			steps = append(steps, &d.Steps[i])
		}
		h := d.HandlerOn
		for _, handler := range []*ir.Step{h.Init, h.Failure, h.Success, h.Abort, h.Exit, h.Wait} {
			if handler != nil {
				steps = append(steps, handler)
			}
		}
		if out, err = stepPlacements(out, d.Name, steps); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// stepPlacements adds where each step of document, and each step of a
// foreach body, sends its work.
func stepPlacements(out []Placement, document string, steps []*ir.Step) ([]Placement, error) {
	for _, step := range steps {
		if step == nil {
			continue
		}
		if step.ExecutorConfig.Type == ir.ExecutorTypeAction {
			return nil, ErrUnverified
		}
		machine, err := SelectedMachine(step.WorkerSelector)
		if err != nil {
			return nil, err
		}
		called := ""
		if step.SubDAG != nil {
			called = step.SubDAG.Name
			if !literalName(called) {
				return nil, ErrUnverified
			}
		}
		if machine != "" || called != "" {
			out = append(out, Placement{Name: called, Machine: machine, Step: true, Document: document})
		}
		if step.LLM != nil {
			if out, err = toolPlacements(out, document, step.LLM.Tools); err != nil {
				return nil, err
			}
		}
		if step.Foreach != nil {
			body := make([]*ir.Step, 0, len(step.Foreach.Steps))
			for i := range step.Foreach.Steps {
				body = append(body, &step.Foreach.Steps[i])
			}
			if out, err = stepPlacements(out, document, body); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// toolPlacements adds each DAG a chat step of document may call as a tool.
func toolPlacements(out []Placement, document string, tools []string) ([]Placement, error) {
	for _, tool := range tools {
		if !literalName(tool) {
			return nil, ErrUnverified
		}
		out = append(out, Placement{Name: tool, Step: true, Document: document})
	}
	return out, nil
}

// literalName reports whether a called DAG's name is read the same by this
// check and by the runtime, which looks it up exactly as written: not
// empty, not computed, and with no surrounding space.
func literalName(name string) bool {
	return name != "" && name == strings.TrimSpace(name) && !strings.ContainsAny(name, "$`")
}

// SelectedMachine is the machine a worker selector sends work to, or "" for
// none, read as the runtime reads it: keys and values trimmed, and an empty
// or repeated key an error. The coordinator matches every label a selector
// names, and every worker carries labels that are not its machine (os, arch,
// txe.owner), so a selector that names labels but no machine can reach any
// machine that has them: where it runs cannot be decided, and it is not
// verified. Neither is a computed selector.
func SelectedMachine(selector map[string]string) (string, error) {
	seen := make(map[string]bool, len(selector))
	machine := ""
	for k, v := range selector {
		if strings.ContainsAny(k+v, "$`") {
			return "", ErrUnverified
		}
		key := strings.TrimSpace(k)
		if key == "" || seen[key] {
			return "", ErrUnverified
		}
		seen[key] = true
		if key == MachineLabel {
			machine = strings.TrimSpace(v)
		}
	}
	if len(selector) > 0 && machine == "" {
		return "", ErrUnverified
	}
	return machine, nil
}

// Written refuses a spec whose worker selectors, wherever they are written,
// have a key or value with surrounding space. The loader trims a DAG's
// selector as it builds it, so two keys that differ only in space collapse
// into one, by map order; the runtime trims a step's. Written already
// trimmed, a selector reads the same to this check, the loader and the
// runtime.
func Written(spec []byte) error {
	file, err := parser.ParseBytes(yamlutil.ClearEmptyDocumentSeparators(spec), 0)
	if err != nil || file == nil {
		return ErrUnverified
	}
	for _, doc := range file.Docs {
		if doc == nil || doc.Body == nil {
			continue
		}
		raw, err := doc.MarshalYAML()
		if err != nil {
			return ErrUnverified
		}
		var tree any
		if err := yaml.Unmarshal(raw, &tree); err != nil {
			return ErrUnverified
		}
		if !selectorsTrimmed(tree) {
			return ErrUnverified
		}
	}
	return nil
}

func selectorsTrimmed(node any) bool {
	switch n := node.(type) {
	case map[string]any:
		for k, v := range n {
			if strings.EqualFold(strings.TrimSpace(k), "worker_selector") {
				if selector, ok := v.(map[string]any); ok {
					for key, value := range selector {
						text, isText := value.(string)
						if key != strings.TrimSpace(key) || (isText && text != strings.TrimSpace(text)) {
							return false
						}
					}
				}
			}
			if !selectorsTrimmed(v) {
				return false
			}
		}
	case []any:
		for _, v := range n {
			if !selectorsTrimmed(v) {
				return false
			}
		}
	}
	return true
}
