// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

// Package workflowtriggers checks that no GitHub Actions workflow starts a
// second run of itself on a pull request's unchanged head (TXE-7841).
//
// A pull_request event type other than opened, synchronize and reopened
// (ready_for_review, edited, labeled, ...) fires without a new commit. Every
// workflow here shares one concurrency group per pull request and cancels the
// run in progress, so the second run cancels the first, on the same head SHA.
// The merge wrapper (.github/codex-review/merge.sh) refuses a head with a
// cancelled run, so the PR then needs a rerun of everything that was
// cancelled: a full duplicate CI run. PR #279 paid it for four workflows.
//
// ready_for_review is allowed only in a workflow whose every job is skipped on
// a draft (its job if reads github.event.pull_request.draft): there the draft's
// run did no work and the event starts the work for the first time. The other
// types are refused outright, except in the review gate (codex-review.yml),
// whose re-checks on edited, labeled and unlabeled are its documented design
// and which the merge wrapper reads by its own rule.
package workflowtriggers

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// headChangingTypes fire only when the head may be new, or when the pull
// request is opened or reopened; they are GitHub's default types.
var headChangingTypes = []string{"opened", "synchronize", "reopened"}

// gateWorkflow is the review gate, which re-checks on events that keep the head.
const gateWorkflow = "codex-review.yml"

// draftGate is the expression a job's if must read to be skipped on a draft.
const draftGate = "github.event.pull_request.draft"

type workflow struct {
	On   yaml.Node      `yaml:"on"`
	Jobs map[string]job `yaml:"jobs"`
}

type job struct {
	If string `yaml:"if"`
}

// Check returns one finding per pull_request or pull_request_target type in
// the workflow file base (its file name) that would run the workflow again on
// an unchanged head.
func Check(base string, data []byte) ([]string, error) {
	var wf workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("%s: %w", base, err)
	}
	var findings []string
	for _, event := range []string{"pull_request", "pull_request_target"} {
		types, err := eventTypes(&wf.On, event)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", base, err)
		}
		for _, typ := range types {
			if slices.Contains(headChangingTypes, typ) || base == gateWorkflow {
				continue
			}
			if typ == "ready_for_review" {
				if ungated := ungatedJobs(wf.Jobs); len(ungated) > 0 {
					findings = append(findings, fmt.Sprintf(
						"%s: %s type ready_for_review re-runs jobs a draft already ran on the same head (%s); "+
							"drop it, or skip every job on a draft with an if that reads %s",
						base, event, strings.Join(ungated, ", "), draftGate))
				}
				continue
			}
			findings = append(findings, fmt.Sprintf(
				"%s: %s type %s runs the workflow again on an unchanged head, and its run cancels the "+
					"head's earlier run; only %s may use it (TXE-7841)",
				base, event, typ, gateWorkflow))
		}
	}
	return findings, nil
}

// eventTypes returns the types event is listed with under on:, nil when the
// event is absent, and the default types when it is listed without types.
func eventTypes(on *yaml.Node, event string) ([]string, error) {
	if on.Kind == 0 { // no on: key
		return nil, nil
	}
	switch on.Kind {
	case yaml.ScalarNode:
		if on.Value == event {
			return headChangingTypes, nil
		}
		return nil, nil
	case yaml.SequenceNode:
		for _, n := range on.Content {
			if n.Value == event {
				return headChangingTypes, nil
			}
		}
		return nil, nil
	case yaml.MappingNode:
		for i := 0; i+1 < len(on.Content); i += 2 {
			if on.Content[i].Value != event {
				continue
			}
			var cfg struct {
				Types yaml.Node `yaml:"types"`
			}
			if err := on.Content[i+1].Decode(&cfg); err != nil {
				return nil, fmt.Errorf("on.%s: %w", event, err)
			}
			if cfg.Types.Kind == 0 { // no types: GitHub's defaults
				return headChangingTypes, nil
			}
			switch cfg.Types.Kind {
			case yaml.ScalarNode:
				return []string{cfg.Types.Value}, nil
			case yaml.SequenceNode:
				var types []string
				if err := cfg.Types.Decode(&types); err != nil {
					return nil, fmt.Errorf("on.%s.types: %w", event, err)
				}
				return types, nil
			case yaml.DocumentNode, yaml.MappingNode, yaml.AliasNode:
			}
			return nil, fmt.Errorf("on.%s.types is neither a list nor a string", event)
		}
		return nil, nil
	case yaml.DocumentNode, yaml.AliasNode:
		return nil, fmt.Errorf("on: is neither a string, a list nor a map")
	}
	return nil, fmt.Errorf("on: is neither a string, a list nor a map")
}

// ungatedJobs names the jobs whose if does not read the draft flag, sorted.
func ungatedJobs(jobs map[string]job) []string {
	var names []string
	for name, j := range jobs {
		if !strings.Contains(j.If, draftGate) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}
