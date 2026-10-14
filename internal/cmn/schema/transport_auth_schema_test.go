// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package schema

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigSchemaTransportAuth(t *testing.T) {
	t.Parallel()

	resolved := mustResolveConfigSchema(t)
	for _, tt := range []struct {
		name    string
		spec    string
		wantErr bool
	}{
		{name: "CoordinatorEnforce", spec: "coordinator:\n  auth:\n    mode: enforce\n    hub_key_file: /var/lib/dagu/coordinator/hub.key\n"},
		{name: "CoordinatorObserve", spec: "coordinator:\n  auth:\n    mode: observe\n"},
		{name: "WorkerCredential", spec: "worker:\n  auth:\n    credential_file: /etc/dagu/machine.json\n"},
		{name: "UnknownMode", spec: "coordinator:\n  auth:\n    mode: permissive\n", wantErr: true},
		{name: "UnknownCoordinatorKey", spec: "coordinator:\n  auth:\n    grace: 30m\n", wantErr: true},
		{name: "UnknownWorkerKey", spec: "worker:\n  auth:\n    token: x\n", wantErr: true},
		{name: "EmptyCredentialFile", spec: "worker:\n  auth:\n    credential_file: \"\"\n", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := resolved.Validate(mustParseYAMLDocument(t, tt.spec))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}
