// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package i5harness_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// renderer is a stand-in for `dagu txe review render`: it writes a reviewer DAG
// whose agent step carries prompt, encoded as RenderDAGs encodes it (a JSON
// string), into the --out-dir it is given.
func renderer(t *testing.T, dir, name, prompt string) string {
	t.Helper()
	enc, _ := json.Marshal(prompt)
	path := filepath.Join(dir, name)
	write(t, path, `#!/bin/sh
out=""
while [ $# -gt 0 ]; do [ "$1" = --out-dir ] && out=$2; shift; done
cat > "$out/txe-reviewer-01M00000000000000000000000.yaml" <<'EOF'
steps:
  - id: agent
    with:
      provider: "claude"
      prompt: `+string(enc)+`
EOF
echo "$out"
`)
	require.NoError(t, os.Chmod(path, 0o755))
	return path
}

func promptRecord(t *testing.T, args ...string) (map[string]any, string, int) {
	t.Helper()
	dir := t.TempDir()
	rec := filepath.Join(dir, "prompt.json")
	out, code := tool(t, "pin.py", append([]string{"prompt", "--workdir", filepath.Join(dir, "w"), "--record", rec}, args...)...)
	m := map[string]any{}
	if raw, err := os.ReadFile(rec); err == nil {
		require.NoError(t, json.Unmarshal(raw, &m))
	}
	return m, out, code
}

// R must render the pinned prompt (TrimSpace of prompt.md with CRLF as LF) and
// C must not: otherwise which binary installs the reviewer would not matter.
func TestPinPromptBindsTheReviewerBinary(t *testing.T) {
	dir := t.TempDir()
	pinned := "Read the packet.\r\n- `seal` means the job's result was sealed.\r\n"
	promptFile := write(t, filepath.Join(dir, "prompt.md"), "\n"+pinned+"\n")
	want := sha256Hex(strings.TrimSpace(strings.ReplaceAll(pinned, "\r\n", "\n")))
	r := renderer(t, dir, "dagu-r", strings.TrimSpace(strings.ReplaceAll(pinned, "\r\n", "\n")))
	c := renderer(t, dir, "dagu-c", "Read the packet.")

	m, out, code := promptRecord(t, "--reviewer-bin", r, "--base-bin", c, "--prompt-file", promptFile)
	require.Equal(t, 0, code, out)
	assert.Equal(t, true, m["ok"])
	assert.Equal(t, want, m["expected_rendered_sha256"])
	assert.Equal(t, want, m["reviewer"].(map[string]any)["rendered_prompt_sha256"])
	assert.Equal(t, sha(t, r), m["reviewer"].(map[string]any)["binary_sha256"])

	m, out, code = promptRecord(t, "--reviewer-bin", r, "--base-bin", r, "--prompt-file", promptFile)
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "C renders the same prompt as R")
	assert.Equal(t, false, m["ok"])

	m, out, code = promptRecord(t, "--reviewer-bin", c, "--base-bin", c, "--prompt-file", promptFile)
	assert.Equal(t, 2, code, out)
	assert.Contains(t, out, "R does not render the pinned prompt")
	assert.Equal(t, false, m["ok"])
}

// The real renderer of this tree renders its own txe/reviewer/prompt.md: the
// extraction and the expected hash agree with RenderDAGs itself.
func TestPinPromptMatchesTheRealRenderer(t *testing.T) {
	dagu := realDagu(t)
	dir := t.TempDir()
	other := renderer(t, dir, "dagu-c", "an older prompt")
	m, out, code := promptRecord(t, "--reviewer-bin", dagu, "--base-bin", other, "--prompt-file", filepath.Join("..", "reviewer", "prompt.md"))
	require.Equal(t, 0, code, out)
	assert.Equal(t, true, m["ok"])
	assert.Equal(t, m["expected_rendered_sha256"], m["reviewer"].(map[string]any)["rendered_prompt_sha256"])
}

func TestPreflightPrompt(t *testing.T) {
	dir := t.TempDir()
	r := write(t, filepath.Join(dir, "dagu-r"), "reviewer binary")
	manifest := func(prompt any, pinnedR string) string {
		m := map[string]any{"binaries": map[string]any{"R": map[string]string{"path": r, "sha256": pinnedR}}}
		if prompt != nil {
			m["prompt"] = prompt
		}
		b, _ := json.Marshal(m)
		return write(t, filepath.Join(t.TempDir(), "manifest.json"), string(b))
	}
	good := passingPrompt(sha(t, r))
	out, code := tool(t, "preflight.py", "prompt", "--manifest", manifest(good, sha(t, r)), "--reviewer-bin", r)
	require.Equal(t, 0, code, out)

	failed := passingPrompt(sha(t, r))
	failed["ok"] = false
	sameAsBase := passingPrompt(sha(t, r))
	sameAsBase["base"] = map[string]any{"rendered_prompt_sha256": "p-A"}
	for name, tc := range map[string]struct {
		prompt any
		pinned string
		want   string
	}{
		"no record":          {nil, sha(t, r), "has no prompt record"},
		"failed record":      {failed, sha(t, r), "not a pass"},
		"other reviewer":     {passingPrompt("0000"), sha(t, r), "was made for reviewer sha256 0000"},
		"other pinned R":     {good, "1111", "pins R at 1111"},
		"C renders the same": {sameAsBase, sha(t, r), "C renders the same prompt as R"},
	} {
		out, code := tool(t, "preflight.py", "prompt", "--manifest", manifest(tc.prompt, tc.pinned), "--reviewer-bin", r)
		assert.Equal(t, 2, code, "%s: %s", name, out)
		assert.Contains(t, out, tc.want, name)
	}
}

// init refuses a manifest without a passing prompt record for its R.
func TestRigInitRequiresThePromptRecord(t *testing.T) {
	f := newFakeRig(t)
	raw, err := os.ReadFile(f.manifest)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	delete(m, "prompt")
	b, _ := json.Marshal(m)
	f.manifest = write(t, filepath.Join(t.TempDir(), "manifest.json"), string(b))
	out, code := f.init(t)
	assert.NotEqual(t, 0, code)
	assert.Contains(t, out, "has no prompt record")
	assert.NoDirExists(t, f.root)
}
