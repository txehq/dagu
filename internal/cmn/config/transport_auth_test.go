// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad_TransportAuthDefaultIsOff(t *testing.T) {
	cfg := loadFromYAML(t, "")
	assert.Equal(t, CoordinatorAuth{}, cfg.Coordinator.Auth)
	assert.False(t, cfg.Coordinator.Auth.Enabled())
	assert.Equal(t, WorkerAuth{}, cfg.Worker.Auth)

	cfg = loadFromYAML(t, "coordinator:\n  auth:\n    mode: off\n")
	assert.Equal(t, TXEAuthzModeOff, cfg.Coordinator.Auth.Mode)
	assert.False(t, cfg.Coordinator.Auth.Enabled())
}

func TestLoad_TransportAuthFromYAML(t *testing.T) {
	dir := t.TempDir()
	cfg := loadFromYAML(t, `
coordinator:
  port: 50055
  auth:
    mode: enforce
    hub_key_file: `+filepath.Join(dir, "hub.key")+`
worker:
  auth:
    credential_file: `+filepath.Join(dir, "machine.json")+`
`)
	assert.Equal(t, CoordinatorAuth{Mode: TXEAuthzModeEnforce, HubKeyFile: filepath.Join(dir, "hub.key")}, cfg.Coordinator.Auth)
	assert.True(t, cfg.Coordinator.Auth.Enabled())
	assert.Equal(t, filepath.Join(dir, "hub.key"), cfg.CoordinatorHubKeyFile())
	assert.Equal(t, WorkerAuth{CredentialFile: filepath.Join(dir, "machine.json")}, cfg.Worker.Auth)
	assert.Equal(t, 50055, cfg.Coordinator.Port, "the other coordinator keys still load")
}

func TestLoad_TransportAuthFromEnv(t *testing.T) {
	dir := t.TempDir()
	cfg := loadWithEnv(t, "", map[string]string{
		"DAGU_COORDINATOR_AUTH_MODE":         "observe",
		"DAGU_COORDINATOR_AUTH_HUB_KEY_FILE": filepath.Join(dir, "k"),
		"DAGU_WORKER_AUTH_CREDENTIAL_FILE":   filepath.Join(dir, "c.json"),
	})
	assert.Equal(t, CoordinatorAuth{Mode: TXEAuthzModeObserve, HubKeyFile: filepath.Join(dir, "k")}, cfg.Coordinator.Auth)
	assert.Equal(t, filepath.Join(dir, "c.json"), cfg.Worker.Auth.CredentialFile)
}

func TestLoad_HubKeyFileDefaultsUnderTheDataDirectory(t *testing.T) {
	dir := t.TempDir()
	cfg := loadFromYAML(t, "paths:\n  data_dir: "+dir+"\ncoordinator:\n  auth:\n    mode: observe\n")
	assert.Equal(t, filepath.Join(dir, "coordinator", "hub.key"), cfg.CoordinatorHubKeyFile())
}

func TestLoad_TransportAuthRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		yaml string
		want string
	}{
		"UnknownMode":           {"coordinator:\n  auth:\n    mode: enforcing\n", "unknown mode"},
		"ModeNotAString":        {"coordinator:\n  auth:\n    mode: 1\n", "must be a string"},
		"EmptyMode":             {"coordinator:\n  auth:\n    mode: \"\"\n", "is empty"},
		"NullMode":              {"coordinator:\n  auth:\n    mode:\n", "is empty"},
		"ScalarAuth":            {"coordinator:\n  auth: enforce\n", "must be a mapping"},
		"NullAuth":              {"coordinator:\n  auth:\n", "is empty"},
		"UnknownCoordinatorKey": {"coordinator:\n  auth:\n    grace: 30m\n", "unknown key"},
		"RelativeHubKey":        {"coordinator:\n  auth:\n    mode: observe\n    hub_key_file: hub.key\n", "absolute path"},
		"UnknownWorkerKey":      {"worker:\n  auth:\n    token: x\n", "unknown key"},
		"EmptyCredentialFile":   {"worker:\n  auth:\n    credential_file: \"\"\n", "is empty"},
		"RelativeCredential":    {"worker:\n  auth:\n    credential_file: machine.json\n", "absolute path"},
	} {
		t.Run(name, func(t *testing.T) {
			err := loadWithErrorFromYAML(t, tc.yaml)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestLoad_TransportAuthEmptyEnvIsRefused(t *testing.T) {
	for _, env := range []string{"DAGU_COORDINATOR_AUTH_MODE", "DAGU_COORDINATOR_AUTH_HUB_KEY_FILE", "DAGU_WORKER_AUTH_CREDENTIAL_FILE"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, "")
			err := loadWithErrorFromYAML(t, "")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "set but empty")
		})
	}
}

func TestLoad_TransportAuthIsReadForTheServicesThatUseIt(t *testing.T) {
	credential := filepath.Join(t.TempDir(), "machine.json")
	yaml := "coordinator:\n  auth:\n    mode: enforce\nworker:\n  auth:\n    credential_file: " + credential + "\n"

	// The hub's processes read the coordinator's mode, to know whether to
	// present the hub key; so does a run the hub starts, for the child
	// workflows it dispatches.
	for _, service := range []Service{ServiceCoordinator, ServiceServer, ServiceScheduler, ServiceAgent} {
		cfg := loadFromYAMLForService(t, service, yaml)
		assert.Equal(t, TXEAuthzModeEnforce, cfg.Coordinator.Auth.Mode, service)
		assert.Empty(t, cfg.Worker.Auth.CredentialFile, service)
	}
	cfg := loadFromYAMLForService(t, ServiceWorker, yaml)
	assert.Equal(t, credential, cfg.Worker.Auth.CredentialFile)
}

// A coordinator started on its own does not read the owner settings, so it
// would neither pin tasks to machines nor be held to authenticate workers.
// Owner authorization in observe or enforce, written in the file or the
// environment, refuses to load for it; a config with owners off, or none,
// loads as before, and the server and start-all read the settings
// (TXE-4720).
func TestLoad_ACoordinatorOnItsOwnRefusesOwners(t *testing.T) {
	for _, mode := range []string{TXEAuthzModeObserve, TXEAuthzModeEnforce} {
		file := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(file, []byte("txe:\n  authz:\n    mode: "+mode+"\n"), 0600))
		err := testLoadWithError(t, WithConfigFile(file), WithService(ServiceCoordinator))
		require.ErrorContains(t, err, "a coordinator started on its own", "file, %s", mode)

		t.Run("env "+mode, func(t *testing.T) {
			t.Setenv("DAGU_TXE_AUTHZ_MODE", mode)
			err := testLoadWithError(t, WithService(ServiceCoordinator))
			require.ErrorContains(t, err, "a coordinator started on its own")
		})
	}
	for _, yaml := range []string{"", "txe:\n  authz:\n    mode: off\n"} {
		cfg := loadFromYAMLForService(t, ServiceCoordinator, yaml+"coordinator:\n  auth:\n    mode: off\n")
		assert.Empty(t, cfg.TXE.Authz.Mode, "a coordinator on its own still reads no owner settings")
	}
	file := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(file, []byte("auth:\n  mode: builtin\ntxe:\n  authz:\n    mode: enforce\n"), 0600))
	cfg := testLoad(t, WithConfigFile(file))
	assert.Equal(t, TXEAuthzModeEnforce, cfg.TXE.Authz.Mode, "start-all reads them")

	// A worker and a scheduler start no coordinator: a shared config, or the
	// environment, with owners on loads for them as before.
	for _, service := range []Service{ServiceWorker, ServiceScheduler} {
		require.NoError(t, testLoadWithError(t, WithConfigFile(file), WithService(service)), "file, service %v", service)
		t.Run(fmt.Sprintf("env service %v", service), func(t *testing.T) {
			t.Setenv("DAGU_TXE_AUTHZ_MODE", TXEAuthzModeEnforce)
			require.NoError(t, testLoadWithError(t, WithService(service)))
		})
	}
}
