// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package installerapi

import (
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	tokenVar       = "DAGU_INSTALLER_GITHUB_TOKEN"
	installerPS1   = "scripts/installer.ps1"
	installerCMD   = "scripts/installer.cmd"
	workflowsDir   = ".github/workflows"
	githubAPIHost  = "api.github.com"
	releaseAPIName = "$Script:ReleaseApi"
)

var (
	// A step that runs the Windows installer, directly or through the CMD
	// wrapper. A path followed by | or ) is a shell case pattern (the changed
	// paths filter), not a run.
	runsWindowsInstaller = regexp.MustCompile(`\binstaller\.(?:ps1|cmd)(?:[^\w|)]|$)`)
	runsShellInstaller   = regexp.MustCompile(`\binstaller\.sh(?:[^\w|)]|$)`)
	// The workflow token, the only value the check accepts.
	workflowToken = regexp.MustCompile(`^\$\{\{\s*(?:github\.token|secrets\.GITHUB_TOKEN)\s*\}\}$`)
	webRequest    = regexp.MustCompile(`(?i)\bInvoke-(?:RestMethod|WebRequest)\b|\birm\b|\biwr\b`)
)

type workflowFile struct {
	Env  yaml.Node              `yaml:"env"`
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Env   yaml.Node      `yaml:"env"`
	Steps []workflowStep `yaml:"steps"`
}

type workflowStep struct {
	Name string    `yaml:"name"`
	Run  string    `yaml:"run"`
	Env  yaml.Node `yaml:"env"`
}

func TestInstallerAPICallsAreAuthenticated(t *testing.T) {
	t.Parallel()

	findings, err := check(os.DirFS(repoRoot(t)))
	require.NoError(t, err)
	require.Empty(t, findings, "fix each finding (TXE-7871):\n%s", strings.Join(findings, "\n"))
}

// The negatives are pure data, checked in memory.
func TestInstallerAPICallsAreAuthenticatedRefuses(t *testing.T) {
	t.Parallel()

	const goodPS1 = "$Script:ReleaseApi = \"https://api.github.com/repos/dagucloud/dagu/releases/latest\"\n" +
		"$apiToken = $env:DAGU_INSTALLER_GITHUB_TOKEN\n" +
		"$release = Invoke-RestMethod -Uri $Script:ReleaseApi -Headers $headers\n" +
		"Invoke-WebRequest -Uri $Url -OutFile $OutFile\n"
	const goodCMD = "powershell -NoProfile -ExecutionPolicy Bypass -File \"%TEMP_PS1%\" %*\n"
	step := func(env, run string) string {
		return "jobs:\n  t:\n    steps:\n      - name: install\n" + env + "        run: |\n          " + run + "\n"
	}
	const stepEnv = "        env:\n          DAGU_INSTALLER_GITHUB_TOKEN: ${{ github.token }}\n"
	tree := func(files map[string]string) fstest.MapFS {
		base := map[string]string{
			installerPS1:                      goodPS1,
			installerCMD:                      goodCMD,
			".github/workflows/ci.yaml":       step(stepEnv, `scripts\installer.cmd -NoPrompt`),
			".github/workflows/lint.yaml":     "jobs:\n  l:\n    steps:\n      - run: go test ./...\n",
			".github/workflows/README.md":     "installer.sh is not a workflow\n",
			".github/workflows/vars/env.yaml": "not: [a, workflow]\n",
		}
		maps.Copy(base, files)
		out := fstest.MapFS{}
		for name, content := range base {
			if content != "" {
				out[name] = &fstest.MapFile{Data: []byte(content)}
			}
		}
		return out
	}

	findings, err := check(tree(nil))
	require.NoError(t, err)
	require.Empty(t, findings)

	// The token may come from the job or the workflow, and secrets.GITHUB_TOKEN is the same token.
	for name, wf := range map[string]string{
		"job env": "jobs:\n  t:\n    env:\n      DAGU_INSTALLER_GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n" +
			"    steps:\n      - run: scripts\\installer.cmd\n",
		"workflow env": "env:\n  DAGU_INSTALLER_GITHUB_TOKEN: ${{github.token}}\n" +
			"jobs:\n  t:\n    steps:\n      - run: powershell -File scripts/installer.ps1 -NoPrompt\n",
		"a step that never runs the installer": step("", "go build ./cmd"),
		"a changed-paths case pattern":         step("", "case \"${file}\" in scripts/installer.cmd|scripts/installer.sh|scripts/installer.ps1) changed=true ;; esac"),
	} {
		findings, err := check(tree(map[string]string{".github/workflows/ci.yaml": wf}))
		require.NoError(t, err, name)
		require.Empty(t, findings, name)
	}

	for name, tc := range map[string]struct {
		files map[string]string
		want  string
	}{
		"a step without the token": {
			files: map[string]string{".github/workflows/ci.yaml": step("", `scripts\installer.cmd -NoPrompt`)},
			want:  `ci.yaml: job t, step "install" runs the Windows installer without DAGU_INSTALLER_GITHUB_TOKEN`,
		},
		"an expression-based install without the token": {
			files: map[string]string{".github/workflows/ci.yaml": step("", `$installerPath = (Resolve-Path "scripts/installer.ps1").Path`)},
			want:  `ci.yaml: job t, step "install" runs the Windows installer without DAGU_INSTALLER_GITHUB_TOKEN`,
		},
		"a step that clears the job's token": {
			files: map[string]string{".github/workflows/ci.yaml": "jobs:\n  t:\n    env:\n      DAGU_INSTALLER_GITHUB_TOKEN: ${{ github.token }}\n" +
				"    steps:\n      - env:\n          DAGU_INSTALLER_GITHUB_TOKEN: \"\"\n        run: scripts\\installer.cmd\n"},
			want: `ci.yaml: job t, step 1 runs the Windows installer without DAGU_INSTALLER_GITHUB_TOKEN`,
		},
		"a token that is not the workflow's": {
			files: map[string]string{".github/workflows/ci.yaml": step(strings.ReplaceAll(stepEnv, "${{ github.token }}", "${{ secrets.PERSONAL_PAT }}"), `scripts\installer.cmd`)},
			want:  `ci.yaml: job t, step "install" runs the Windows installer without DAGU_INSTALLER_GITHUB_TOKEN`,
		},
		"a step env that is an expression": {
			files: map[string]string{".github/workflows/ci.yaml": "jobs:\n  t:\n    steps:\n      - env: ${{ fromJSON(inputs.env) }}\n        run: scripts\\installer.cmd\n"},
			want:  `ci.yaml: job t, step 1 runs the Windows installer without DAGU_INSTALLER_GITHUB_TOKEN`,
		},
		"the shell installer": {
			files: map[string]string{".github/workflows/smoke.yml": step(stepEnv, "bash scripts/installer.sh --no-prompt")},
			want:  `smoke.yml: job t, step "install" runs installer.sh, which has no token path`,
		},
		"installer.ps1 no longer reads the token": {
			files: map[string]string{installerPS1: strings.ReplaceAll(goodPS1, "$env:DAGU_INSTALLER_GITHUB_TOKEN", "$null")},
			want:  "scripts/installer.ps1 does not read $env:DAGU_INSTALLER_GITHUB_TOKEN",
		},
		"a release API request without the headers": {
			files: map[string]string{installerPS1: goodPS1 + "$latest = Invoke-RestMethod -Uri $Script:ReleaseApi\n"},
			want:  "scripts/installer.ps1:5 requests the release API without -Headers $headers",
		},
		"a second api.github.com URL": {
			files: map[string]string{installerPS1: goodPS1 + "$assets = irm https://api.github.com/repos/dagucloud/dagu/releases\n"},
			want:  "scripts/installer.ps1:5 names api.github.com outside $Script:ReleaseApi",
		},
		"a GitHub API call in the CMD wrapper": {
			files: map[string]string{installerCMD: goodCMD + "powershell -Command \"irm https://api.github.com/repos/dagucloud/dagu/releases/latest\"\n"},
			want:  "scripts/installer.cmd:2 names api.github.com outside $Script:ReleaseApi",
		},
	} {
		findings, err := check(tree(tc.files))
		require.NoError(t, err, name)
		require.True(t, slices.ContainsFunc(findings, func(f string) bool { return strings.HasPrefix(f, tc.want) }),
			"%s: want a finding starting %q, got %q", name, tc.want, findings)
	}
}

// check returns one finding per installer run or installer request that can
// reach api.github.com without the workflow token.
func check(fsys fs.FS) ([]string, error) {
	var findings []string

	workflows, err := fs.ReadDir(fsys, workflowsDir)
	if err != nil {
		return nil, err
	}
	for _, entry := range workflows {
		name := entry.Name()
		if entry.IsDir() || (path.Ext(name) != ".yaml" && path.Ext(name) != ".yml") {
			continue
		}
		data, err := fs.ReadFile(fsys, path.Join(workflowsDir, name))
		if err != nil {
			return nil, err
		}
		found, err := checkWorkflow(name, data)
		if err != nil {
			return nil, err
		}
		findings = append(findings, found...)
	}

	found, err := checkInstallerSource(fsys)
	if err != nil {
		return nil, err
	}
	return append(findings, found...), nil
}

func checkWorkflow(name string, data []byte) ([]string, error) {
	var wf workflowFile
	if err := yaml.Unmarshal(data, &wf); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	var findings []string
	for _, jobID := range slices.Sorted(maps.Keys(wf.Jobs)) {
		job := wf.Jobs[jobID]
		for i, step := range job.Steps {
			label := fmt.Sprintf("step %d", i+1)
			if step.Name != "" {
				label = fmt.Sprintf("step %q", step.Name)
			}
			where := fmt.Sprintf("%s: job %s, %s", name, jobID, label)
			if runsShellInstaller.MatchString(step.Run) {
				findings = append(findings, where+" runs installer.sh, which has no token path; add one before testing it in CI")
			}
			if runsWindowsInstaller.MatchString(step.Run) && !hasWorkflowToken(&wf.Env, &job.Env, &step.Env) {
				findings = append(findings, where+" runs the Windows installer without "+tokenVar+": ${{ github.token }} in its env")
			}
		}
	}
	return findings, nil
}

// hasWorkflowToken reports whether the innermost env that sets tokenVar sets
// it to the workflow token. An env that is not a mapping (an expression) is
// unknown, which counts as missing.
func hasWorkflowToken(envs ...*yaml.Node) bool {
	value, set := "", false
	for _, env := range envs {
		if env.Kind == 0 {
			continue
		}
		if env.Kind != yaml.MappingNode {
			return false
		}
		for i := 0; i+1 < len(env.Content); i += 2 {
			if env.Content[i].Value == tokenVar {
				value, set = strings.TrimSpace(env.Content[i+1].Value), true
			}
		}
	}
	return set && workflowToken.MatchString(value)
}

func checkInstallerSource(fsys fs.FS) ([]string, error) {
	var findings []string
	for _, file := range []string{installerPS1, installerCMD} {
		data, err := fs.ReadFile(fsys, file)
		if err != nil {
			return nil, err
		}
		for i, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(strings.ToUpper(trimmed), "REM ") {
				continue
			}
			where := fmt.Sprintf("%s:%d", file, i+1)
			isDefinition := strings.HasPrefix(trimmed, releaseAPIName+" =")
			if strings.Contains(line, githubAPIHost) && !isDefinition {
				findings = append(findings, where+" names "+githubAPIHost+" outside "+releaseAPIName)
			}
			if strings.Contains(line, releaseAPIName) && !isDefinition && webRequest.MatchString(line) && !strings.Contains(line, "-Headers $headers") {
				findings = append(findings, where+" requests the release API without -Headers $headers")
			}
		}
		if file == installerPS1 && !strings.Contains(string(data), "$env:"+tokenVar) {
			findings = append(findings, file+" does not read $env:"+tokenVar)
		}
	}
	return findings, nil
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, ".github", "workflows")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "no repository root (go.mod beside .github/workflows) above the test's directory")
		dir = parent
	}
}
