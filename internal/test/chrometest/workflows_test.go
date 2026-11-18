// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package chrometest

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TXE-7834: on a fresh Windows runner Chrome's files on the C: drive have
// never been read. When go test's first packages and Chrome read them at the
// same moment, Chrome took up to 47 s to answer and could miss the DevTools
// gate's 60 s start-up window. The shared Go setup action starts Chrome once,
// alone, before any test step. The tests below keep every Windows job on
// that action, so a new one cannot leave it out.

// setupAction is the composite action that warms Chrome on Windows.
const setupAction = "./.github/actions/setup-go-cache"

// warmStep is the action's step that starts Chrome once.
const warmStep = "Start Chrome once"

// noChromeJobs are the Windows jobs that do not set up Go, and why. A job
// here must not start a browser: its steps and the repository scripts they
// run are scanned for anything that could start one.
var noChromeJobs = map[string]string{
	"release.yaml/windows-installer":   "wraps the published dagu.exe in an Inno Setup installer; runs no tests",
	"npm-publish.yaml/verify-packages": "installs the published npm package and runs dagu version and dagu help",
}

// startsChrome matches step text that runs tests or drives a browser.
var startsChrome = regexp.MustCompile(`(?i)\bgo\s+test\b|\bmake\b|chrome|chromium|browser|stagehand|playwright|puppeteer|conformance|\bdagu(\.exe)?\s+(start|exec|server|scheduler|worker|computer)\b`)

// scriptRef finds repository files that a step's run text names.
var scriptRef = regexp.MustCompile(`[\w./\\-]+\.(?:sh|ps1|cmd|bat|py)\b`)

type workflowFile struct {
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	RunsOn   yaml.Node      `yaml:"runs-on"`
	Strategy yaml.Node      `yaml:"strategy"`
	Steps    []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	Name string `yaml:"name"`
	Uses string `yaml:"uses"`
	Run  string `yaml:"run"`
	If   string `yaml:"if"`
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "no go.mod above the test's directory")
		dir = parent
	}
}

// scalars returns every scalar value under n.
func scalars(n *yaml.Node) []string {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.ScalarNode {
		return []string{n.Value}
	}
	var out []string
	for _, c := range n.Content {
		out = append(out, scalars(c)...)
	}
	return out
}

// runsOnWindows reports whether a job can run on a Windows runner: a
// runs-on label names Windows, or runs-on takes a matrix value and some
// value of the job's matrix names Windows.
func runsOnWindows(job workflowJob) bool {
	labels := scalars(&job.RunsOn)
	for _, label := range labels {
		if strings.Contains(strings.ToLower(label), "windows") {
			return true
		}
	}
	for _, label := range labels {
		if strings.Contains(label, "matrix.") {
			for _, value := range scalars(&job.Strategy) {
				if strings.Contains(strings.ToLower(value), "windows") {
					return true
				}
			}
		}
	}
	return false
}

func readWorkflows(t *testing.T, root string) map[string]workflowFile {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.y*ml"))
	require.NoError(t, err)
	require.NotEmpty(t, paths)
	out := map[string]workflowFile{}
	for _, path := range paths {
		data, err := os.ReadFile(path) //nolint:gosec // the repository's own workflows
		require.NoError(t, err)
		var wf workflowFile
		require.NoError(t, yaml.Unmarshal(data, &wf), path)
		out[filepath.Base(path)] = wf
	}
	return out
}

func TestEveryWindowsJobReadsChromeBeforeItsTests(t *testing.T) {
	assert.Empty(t, windowsJobProblems(t, repoRoot(t), noChromeJobs))
}

// windowsJobProblems checks every Windows job of root's workflows against
// the rule: it sets up Go with setupAction, or it is in exempt and starts no
// browser, in its steps or in the repository scripts they run.
func windowsJobProblems(t *testing.T, root string, exempt map[string]string) []string {
	t.Helper()
	var problems []string
	seen := map[string]bool{}
	windowsJobs := 0
	for file, wf := range readWorkflows(t, root) {
		for name, job := range wf.Jobs {
			if !runsOnWindows(job) {
				continue
			}
			windowsJobs++
			id := file + "/" + name
			setsUpGo := slices.ContainsFunc(job.Steps, func(s workflowStep) bool { return s.Uses == setupAction })
			reason, listed := exempt[id]
			seen[id] = listed
			switch {
			case setsUpGo && listed:
				problems = append(problems, fmt.Sprintf("%s sets up Go; remove it from noChromeJobs", id))
			case setsUpGo:
			case !listed:
				problems = append(problems, fmt.Sprintf("%s runs on Windows without %s, which starts Chrome once before any test does (TXE-7834); use the action, or list the job in noChromeJobs with why it starts no browser", id, setupAction))
			default:
				for _, step := range job.Steps {
					for _, text := range append([]string{step.Uses, step.Run}, referencedScripts(root, step.Run)...) {
						if m := startsChrome.FindString(text); m != "" {
							problems = append(problems, fmt.Sprintf("%s (in noChromeJobs: %s): step %q may start a browser (%q); set up Go with %s instead", id, reason, step.Name, m, setupAction))
						}
					}
				}
			}
		}
	}
	if windowsJobs == 0 {
		problems = append(problems, "no Windows job found: the workflow reader is broken")
	}
	for id := range exempt {
		if !seen[id] {
			problems = append(problems, fmt.Sprintf("noChromeJobs lists %s, which is not a Windows job any more", id))
		}
	}
	slices.Sort(problems)
	return problems
}

func TestWindowsJobProblemsFindsEachBreach(t *testing.T) {
	write := func(t *testing.T, root, rel, content string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	}
	root := t.TempDir()
	write(t, root, ".github/workflows/a.yaml", `jobs:
  good:
    runs-on: windows-latest
    steps:
      - uses: ./.github/actions/setup-go-cache
      - run: go test ./...
  linux:
    runs-on: ubuntu-latest
    steps:
      - run: go test ./...
  bare:
    runs-on: windows-2025
    steps:
      - run: echo hi
  matrixed:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        include:
          - os: ubuntu-latest
          - os: windows-latest
    steps:
      - run: echo hi
  scripted:
    runs-on: [self-hosted, Windows]
    steps:
      - run: bash scripts/e2e.sh
  quiet:
    runs-on: windows-latest
    steps:
      - run: dagu version
  listedButSetsUp:
    runs-on: windows-latest
    steps:
      - uses: ./.github/actions/setup-go-cache
`)
	write(t, root, "scripts/e2e.sh", "#!/bin/sh\n\"$CHROME_PATH\" --headless about:blank\n")
	problems := windowsJobProblems(t, root, map[string]string{
		"a.yaml/scripted":        "claims no browser",
		"a.yaml/quiet":           "prints the version",
		"a.yaml/listedButSetsUp": "stale",
		"a.yaml/gone":            "removed job",
	})
	joined := strings.Join(problems, "\n")
	assert.Len(t, problems, 5, joined)
	for _, want := range []string{
		"a.yaml/bare runs on Windows without",
		"a.yaml/matrixed runs on Windows without",
		`a.yaml/scripted (in noChromeJobs: claims no browser): step "" may start a browser`,
		"a.yaml/listedButSetsUp sets up Go",
		"noChromeJobs lists a.yaml/gone",
	} {
		assert.Contains(t, joined, want)
	}
	assert.NotContains(t, joined, "a.yaml/good")
	assert.NotContains(t, joined, "a.yaml/linux")
	assert.NotContains(t, joined, "a.yaml/quiet")
}

// referencedScripts returns the contents of the repository files that run
// names, so a step that starts Chrome through a script is seen.
func referencedScripts(root, run string) []string {
	var out []string
	for _, ref := range scriptRef.FindAllString(run, -1) {
		path := filepath.Join(root, filepath.FromSlash(strings.ReplaceAll(ref, `\`, "/")))
		data, err := os.ReadFile(path) //nolint:gosec // a repository script a workflow runs
		if err == nil {
			out = append(out, string(data))
		}
	}
	return out
}

func TestTheSetupActionReadsChromeWhereTheTestsFindIt(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, ".github", "actions", "setup-go-cache", "action.yml"))
	require.NoError(t, err)
	var action struct {
		Runs struct {
			Steps []workflowStep `yaml:"steps"`
		} `yaml:"runs"`
	}
	require.NoError(t, yaml.Unmarshal(data, &action))
	idx := slices.IndexFunc(action.Runs.Steps, func(s workflowStep) bool { return s.Name == warmStep })
	require.GreaterOrEqual(t, idx, 0, "the setup action has no %q step", warmStep)
	step := action.Runs.Steps[idx]
	assert.Equal(t, "runner.os == 'Windows'", step.If)
	// Path looks in these places on Windows; the step must read the same.
	for _, want := range []string{"CHROME_PATH", "ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA", `Google\Chrome\Application`} {
		assert.Contains(t, step.Run, want)
	}
	// The read happens before Go is installed or any cache restored, while
	// the C: drive is idle.
	for i, s := range action.Runs.Steps {
		if s.Uses != "" {
			assert.Greater(t, i, idx, "step %q runs before Chrome is read", s.Name)
		}
	}
}

func TestStartsChromeSeesTestsAndBrowsers(t *testing.T) {
	for _, text := range []string{"go test ./...", "make conformance", `& "$env:ProgramFiles\Google\Chrome\Application\chrome.exe"`, "./dagu.exe start x.yaml", "npx playwright test"} {
		assert.Regexp(t, startsChrome, text)
	}
	for _, text := range []string{"dagu version", "dagu help", "npm install -g @dagucloud/dagu", "gh release download"} {
		assert.NotRegexp(t, startsChrome, text)
	}
}
