// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package llmsgen_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestCIRunsLLMSCheckOnSkillChanges fails when CI could let llms.txt drift
// from skills/dagu again (TXE-7868): the Cleanup lint job must run
// `make llms-check`, and both CI triggers' path filters must include the
// generator's inputs and output. Without the paths, a PR that changes only
// skills/ or llms.txt starts no CI run at all.
func TestCIRunsLLMSCheckOnSkillChanges(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "..", ".github", "workflows", "ci.yaml"))
	if err != nil {
		t.Fatalf("read ci.yaml: %v", err)
	}
	var wf struct {
		On map[string]struct {
			Paths []string `yaml:"paths"`
		} `yaml:"on"`
		Jobs map[string]struct {
			If    string `yaml:"if"`
			Needs any    `yaml:"needs"`
			Steps []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse ci.yaml: %v", err)
	}

	for _, event := range []string{"push", "pull_request"} {
		trigger, ok := wf.On[event]
		if !ok {
			t.Fatalf("ci.yaml has no %s trigger", event)
		}
		for _, want := range []string{"skills/dagu/**", "llms.txt"} {
			if !slices.Contains(trigger.Paths, want) {
				t.Errorf("ci.yaml on.%s.paths lacks %q: a change to it alone would start no CI run", event, want)
			}
		}
	}

	job, ok := wf.Jobs["cleanuplint"]
	if !ok {
		t.Fatal("ci.yaml has no cleanuplint job")
	}
	if job.If != "" || job.Needs != nil {
		t.Errorf("cleanuplint must run on every change, with no if or needs: if=%q needs=%v", job.If, job.Needs)
	}
	found := false
	for _, step := range job.Steps {
		if strings.TrimSpace(step.Run) == "make llms-check" {
			found = true
		}
	}
	if !found {
		t.Error("cleanuplint has no step that runs `make llms-check`")
	}
}
