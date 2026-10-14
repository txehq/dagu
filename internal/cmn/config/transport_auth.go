// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CoordinatorAuth says whether the coordinator authenticates its callers.
type CoordinatorAuth struct {
	// Mode is off (today's behaviour, the default), observe or enforce.
	Mode string
	// HubKeyFile is the file holding the key the hub's own processes present.
	// Empty means the default under the data directory.
	HubKeyFile string
}

// Enabled reports whether the coordinator authenticates, in either mode.
func (a CoordinatorAuth) Enabled() bool {
	return a.Mode == TXEAuthzModeObserve || a.Mode == TXEAuthzModeEnforce
}

// WorkerAuth says how a worker proves which machine it is.
type WorkerAuth struct {
	// CredentialFile is the machine credential the enrolment wrote. Empty
	// means the worker presents no credential, as today.
	CredentialFile string
}

const (
	coordinatorAuthKey           = "coordinator.auth"
	coordinatorAuthModeKey       = "coordinator.auth.mode"
	coordinatorAuthHubKeyFileKey = "coordinator.auth.hub_key_file"
	workerAuthKey                = "worker.auth"
	workerAuthCredentialFileKey  = "worker.auth.credential_file"

	coordinatorAuthModeEnv       = "COORDINATOR_AUTH_MODE"
	coordinatorAuthHubKeyFileEnv = "COORDINATOR_AUTH_HUB_KEY_FILE"
	workerAuthCredentialFileEnv  = "WORKER_AUTH_CREDENTIAL_FILE"

	// defaultHubKeyFile is where the hub key lives when no file is named,
	// relative to the data directory.
	defaultHubKeyFile = "coordinator/hub.key"
)

// loadTransportAuthConfig reads coordinator.auth and worker.auth strictly, as
// the txe section is read: these values decide who may call the coordinator,
// so an empty value or an unknown key is an error rather than "off".
func (l *ConfigLoader) loadTransportAuthConfig(cfg *Config) error {
	type section struct {
		requires ConfigSection
		key      string
		allowed  []string
		envs     []string
	}
	for _, s := range []section{
		{SectionCoordinator, coordinatorAuthKey, []string{"mode", "hub_key_file"}, []string{coordinatorAuthModeEnv, coordinatorAuthHubKeyFileEnv}},
		{SectionWorker, workerAuthKey, []string{"credential_file"}, []string{workerAuthCredentialFileEnv}},
	} {
		if !l.requires(s.requires) {
			continue
		}
		for _, env := range s.envs {
			name := strings.ToUpper(AppSlug) + "_" + env
			if value, set := os.LookupEnv(name); set && value == "" {
				return fmt.Errorf("%s is set but empty: unset it, or give it a value", name)
			}
		}
		m, err := l.txeSection(s.key)
		if err != nil {
			return err
		}
		if err := onlyKeys(m, s.key, s.allowed...); err != nil {
			return err
		}
	}

	var err error
	if l.requires(SectionCoordinator) {
		if cfg.Coordinator.Auth.Mode, err = l.txeString(coordinatorAuthModeKey); err != nil {
			return err
		}
		if cfg.Coordinator.Auth.HubKeyFile, err = l.txeString(coordinatorAuthHubKeyFileKey); err != nil {
			return err
		}
	}
	if l.requires(SectionWorker) {
		if cfg.Worker.Auth.CredentialFile, err = l.txeString(workerAuthCredentialFileKey); err != nil {
			return err
		}
	}
	return nil
}

// validateTransportAuth checks coordinator.auth and worker.auth.
func (c *Config) validateTransportAuth() error {
	switch c.Coordinator.Auth.Mode {
	case "", TXEAuthzModeOff, TXEAuthzModeObserve, TXEAuthzModeEnforce:
	default:
		return fmt.Errorf("%s: unknown mode %q (off, observe or enforce)", coordinatorAuthModeKey, c.Coordinator.Auth.Mode)
	}
	if f := c.Coordinator.Auth.HubKeyFile; f != "" && !filepath.IsAbs(f) {
		return fmt.Errorf("%s must be an absolute path", coordinatorAuthHubKeyFileKey)
	}
	if f := c.Worker.Auth.CredentialFile; f != "" && !filepath.IsAbs(f) {
		return fmt.Errorf("%s must be an absolute path", workerAuthCredentialFileKey)
	}
	return nil
}

// CoordinatorHubKeyFile returns the hub key file: the one named, or the
// default under the data directory.
func (c *Config) CoordinatorHubKeyFile() string {
	if c.Coordinator.Auth.HubKeyFile != "" {
		return c.Coordinator.Auth.HubKeyFile
	}
	return filepath.Join(c.Paths.DataDir, filepath.FromSlash(defaultHubKeyFile))
}
