// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package agent

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/mailer/oauthconfig"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/runtime"
	"github.com/dagucloud/dagu/v2/internal/runtime/builtin/ssh"
	"github.com/dagucloud/dagu/v2/internal/secret/providers"
	"github.com/dagucloud/dagu/v2/internal/spec"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMailerConfigFromSMTP(t *testing.T) {
	t.Parallel()

	config, err := mailerConfigFromSMTP(&ir.SMTPConfig{
		Username: "sender@example.com",
		OAuth: &oauthconfig.Config{
			Provider: oauthconfig.ProviderMicrosoft, TenantID: "tenant",
			ClientID: "client", ClientSecret: "secret",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "smtp.office365.com", config.Host)
	assert.Equal(t, "587", config.Port)
	assert.Equal(t, "sender@example.com", config.Username)
	assert.NotNil(t, config.Token)
}

func TestErrorString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "NilError",
			err:      nil,
			expected: "",
		},
		{
			name:     "SimpleError",
			err:      errors.New("test error"),
			expected: "test error",
		},
		{
			name:     "WrappedError",
			err:      errors.New("outer: inner error"),
			expected: "outer: inner error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := errorString(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPanicToError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		panicObj    any
		expectedMsg string
	}{
		{
			name:        "WithError",
			panicObj:    errors.New("panic error"),
			expectedMsg: "panic error",
		},
		{
			name:        "WithString",
			panicObj:    "string panic",
			expectedMsg: "panic: string panic",
		},
		{
			name:        "WithInt",
			panicObj:    42,
			expectedMsg: "panic: 42",
		},
		{
			name:        "WithNil",
			panicObj:    nil,
			expectedMsg: "panic: <nil>",
		},
		{
			name:        "WithStruct",
			panicObj:    struct{ msg string }{msg: "test"},
			expectedMsg: "panic: {test}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := panicToError(tt.panicObj)
			assert.Equal(t, tt.expectedMsg, result.Error())
		})
	}
}

// DAG-level ssh fields resolve Dagu-owned references with the steps[].with
// rules, alongside unqualified environment syntax such as ${fqdn}. An
// unresolved reference stays literal.
func TestEvalSSHConfig(t *testing.T) {
	t.Parallel()

	dag, err := spec.LoadYAML(context.Background(), []byte(`
name: ssh-config
consts:
  - user: deploy
params:
  - name: fqdn
    type: string
steps:
  - name: ok
    run: "true"
`), spec.WithParams("fqdn=node.internal"))
	require.NoError(t, err)
	ctx := runtime.NewContext(context.Background(), dag, "test-run",
		filepath.Join(t.TempDir(), "run.log"),
		runtime.WithParams([]string{"fqdn=node.internal"}),
	)
	vars := runtime.GetEnv(ctx).UserEnvsMap()

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "Param", raw: "${params.fqdn}", want: "node.internal"},
		{name: "EnvShorthand", raw: "/keys/${fqdn}/id_rsa", want: "/keys/node.internal/id_rsa"},
		{name: "Const", raw: "${consts.user}", want: "deploy"},
		{name: "BuiltinContext", raw: "${context.dag.name}", want: "ssh-config"},
		{name: "UnknownParam", raw: "${params.missing}", want: "${params.missing}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := evalSSHConfig(ctx, ssh.Config{
				Host:    tt.raw,
				Bastion: &ssh.BastionConfig{Host: tt.raw},
			}, vars)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.Host)
			require.NotNil(t, got.Bastion)
			assert.Equal(t, tt.want, got.Bastion.Host)
		})
	}
}

// Only a secret whose source gave no value is classified, and only its name
// and provider are kept.
func TestRecordSecretFailure(t *testing.T) {
	t.Parallel()

	t.Run("Unresolved", func(t *testing.T) {
		a := &Agent{}
		cause := errors.New("secret file not found: /private/locator")
		a.recordSecretFailure(fmt.Errorf("failed to resolve secrets: %w", &providers.ResolveError{Name: "API_TOKEN", Provider: "file", Err: cause}))
		require.Equal(t, &ir.StartupFailure{Code: ir.StartupFailureSecretUnavailable, Secret: "API_TOKEN", Provider: "file"}, a.startupFailure)

		status := ir.DAGRunStatus{Error: "earlier"}
		a.applyStartupFailure(&status)
		require.Equal(t, `earlier; secret "API_TOKEN" could not be resolved from provider "file"`, status.Error)
		require.NotSame(t, a.startupFailure, status.StartupFailure)
		require.Equal(t, a.startupFailure, status.StartupFailure)
	})

	t.Run("AbortedStartup", func(t *testing.T) {
		a := &Agent{}
		a.recordSecretFailure(&providers.ResolveError{Name: "API_TOKEN", Provider: "file", Err: errors.New("not found")})
		// The run was stopped while it was starting.
		a.startupFinishedAt = time.Now()

		status := ir.DAGRunStatus{Status: ir.Aborted}
		a.applyStartupFailure(&status)
		require.Nil(t, status.StartupFailure)
		require.Empty(t, status.Error)
	})

	t.Run("RegistryReference", func(t *testing.T) {
		a := &Agent{}
		a.recordSecretFailure(&providers.ResolveError{Name: "DB_PASSWORD", Ref: "prod/db-password", Err: errors.New("not found")})
		require.Equal(t, &ir.StartupFailure{Code: ir.StartupFailureSecretUnavailable, Secret: "DB_PASSWORD"}, a.startupFailure)
		require.Equal(t, `secret "DB_PASSWORD" could not be resolved`, a.startupFailure.Message())
	})

	t.Run("OtherErrors", func(t *testing.T) {
		for _, err := range []error{
			errors.New(`failed to resolve secrets: invalid secret reference for "API_TOKEN": key is required`),
			errors.New("failed to resolve secrets: unknown secret provider: nope"),
			context.Canceled,
		} {
			a := &Agent{}
			a.recordSecretFailure(err)
			require.Nil(t, a.startupFailure, "%v", err)

			status := ir.DAGRunStatus{}
			a.applyStartupFailure(&status)
			require.Nil(t, status.StartupFailure)
			require.Empty(t, status.Error)
		}
	})
}
