// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package txepkg builds, stores and verifies the durable job packages that a
// local worker executes, and keeps the registration journal and receipts.
//
// Everything it writes lives under the TXE home directory, outside every git
// worktree, so removing a coding session's worktree never removes a package.
package txepkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// EnvHome overrides the TXE home directory.
const EnvHome = "TXE_DAGU_HOME"

// Home is the machine-local durable directory shared by the worker and the CLI.
type Home struct {
	Root string
}

// DefaultHome returns the home named by TXE_DAGU_HOME, or
// ~/.local/share/txe-dagu.
func DefaultHome() (Home, error) {
	if root := os.Getenv(EnvHome); root != "" {
		if !filepath.IsAbs(root) {
			return Home{}, fmt.Errorf("%s must be an absolute path, got %q", EnvHome, root)
		}
		return Home{Root: filepath.Clean(root)}, nil
	}
	user, err := os.UserHomeDir()
	if err != nil {
		return Home{}, fmt.Errorf("locate home directory: %w", err)
	}
	return Home{Root: filepath.Join(user, ".local", "share", "txe-dagu")}, nil
}

// PackagesDir holds immutable packages as <job id>/<digest directory>.
func (h Home) PackagesDir() string { return filepath.Join(h.Root, "packages") }

// ReceiptsDir holds registration receipts and the registration journal.
func (h Home) ReceiptsDir() string { return filepath.Join(h.Root, "receipts") }

// OutputDir is where a job's scripts write durable results.
func (h Home) OutputDir(jobID string) string { return filepath.Join(h.Root, "outputs", jobID) }

// ClientDir is the Dagu home the CLI uses for its remote context.
func (h Home) ClientDir() string { return filepath.Join(h.Root, "client") }

// SkillDir holds unpacked skill revisions.
func (h Home) SkillDir() string { return filepath.Join(h.Root, "skill") }

// Machine is this machine's identity, minted once by the worker installer.
type Machine struct {
	Schema      int    `json:"schema"`
	MachineID   string `json:"machine_id"`
	OwnerID     string `json:"owner_id"`
	DisplayName string `json:"display_name,omitempty"`
}

// ErrNoMachine reports that the worker installer has not run on this machine.
var ErrNoMachine = errors.New("this machine has no machine.json; install the local worker first")

// Machine reads the machine identity. The file is never written here.
func (h Home) Machine() (*Machine, error) {
	path := filepath.Join(h.Root, "machine.json")
	data, err := os.ReadFile(path) //nolint:gosec // fixed file name under the TXE home
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w (looked for %s)", ErrNoMachine, path)
	}
	if err != nil {
		return nil, fmt.Errorf("read machine identity: %w", err)
	}
	var m Machine
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if m.MachineID == "" || m.OwnerID == "" {
		return nil, fmt.Errorf("%s has no machine_id or owner_id", path)
	}
	return &m, nil
}
