// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txepkg

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCheckDurable(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home")
	worktree := filepath.Join(home, "code", "repo")
	scratch := filepath.Join(base, "scratch")
	for _, dir := range []string{
		filepath.Join(worktree, "scripts"),
		filepath.Join(home, ".local", "share", "txe-dagu", "packages"),
		scratch,
	} {
		require.NoError(t, os.MkdirAll(dir, 0o755))
	}
	// A linked worktree has a .git file; a main checkout has a directory.
	require.NoError(t, os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: elsewhere\n"), 0o644))
	policy := PathPolicy{TempRoots: []string{scratch}, HomeDir: home}

	require.NoError(t, policy.CheckDurable(filepath.Join(home, ".local", "share", "txe-dagu", "packages", "job_x")))
	require.ErrorIs(t, policy.CheckDurable(filepath.Join(worktree, "scripts", "run.sh")), ErrNotDurable)
	require.ErrorIs(t, policy.CheckDurable(worktree), ErrNotDurable)
	require.ErrorIs(t, policy.CheckDurable(filepath.Join(scratch, "pkg")), ErrNotDurable)
	require.ErrorIs(t, policy.CheckDurable("relative/path"), ErrNotDurable)

	// A repository at the home directory itself does not make everything
	// beneath it disposable.
	require.NoError(t, os.Mkdir(filepath.Join(home, ".git"), 0o755))
	require.NoError(t, policy.CheckDurable(filepath.Join(home, ".local", "share", "txe-dagu", "packages", "job_x")))
	require.ErrorIs(t, policy.CheckDurable(filepath.Join(worktree, "scripts", "run.sh")), ErrNotDurable)
}

// The default policy treats the system temporary directory as disposable
// through either of its names.
func TestDefaultPolicyRefusesTemp(t *testing.T) {
	policy := DefaultPathPolicy()
	require.ErrorIs(t, policy.CheckDurable(filepath.Join(t.TempDir(), "pkg")), ErrNotDurable)
	require.ErrorIs(t, policy.CheckDurable("/tmp/pkg"), ErrNotDurable)
}

func TestCredentialRefValidate(t *testing.T) {
	base := t.TempDir()
	scratch := filepath.Join(base, "scratch")
	require.NoError(t, os.Mkdir(scratch, 0o755))
	policy := PathPolicy{TempRoots: []string{scratch}}

	tests := []struct {
		name    string
		ref     CredentialRef
		wantErr string
	}{
		{name: "File", ref: CredentialRef{Name: "LINEAR_API_KEY", Kind: CredentialFile, Locator: filepath.Join(base, "linear-token")}},
		{name: "Env", ref: CredentialRef{Name: "KUBECONFIG", Kind: CredentialEnv, Locator: "KUBECONFIG"}},
		{name: "BadName", ref: CredentialRef{Name: "linear-key", Kind: CredentialEnv, Locator: "X"}, wantErr: "not a valid variable name"},
		{name: "RelativeFile", ref: CredentialRef{Name: "K", Kind: CredentialFile, Locator: "token"}, wantErr: "absolute path"},
		{name: "DisposableFile", ref: CredentialRef{Name: "K", Kind: CredentialFile, Locator: filepath.Join(scratch, "token")}, wantErr: "temporary directory"},
		{name: "ValueAsLocator", ref: CredentialRef{Name: "K", Kind: CredentialEnv, Locator: "lin_api_abc123!"}, wantErr: "not a valid variable name"},
		{name: "UnknownKind", ref: CredentialRef{Name: "K", Kind: "literal", Locator: "x"}, wantErr: "kind must be"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.ref.Validate(policy)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
