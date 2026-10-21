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
	"time"
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

// Machine is this machine's identity, minted once by "dagu txe machine create"
// or the worker installer, whichever runs first, and only read after that.
type Machine struct {
	Schema      int    `json:"schema"`
	MachineID   string `json:"machine_id"`
	OwnerID     string `json:"owner_id"`
	DisplayName string `json:"display_name,omitempty"`
}

// ErrNoMachine reports that this machine has no identity yet.
var ErrNoMachine = errors.New(`this machine has no machine.json; run "dagu txe machine create" first`)

// machineFile is the identity file's name under the TXE home.
const machineFile = "machine.json"

// Machine reads the machine identity. Only PublishMachine writes it.
func (h Home) Machine() (*Machine, error) {
	path := filepath.Join(h.Root, machineFile)
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

// PublishMachine writes m as this machine's identity, in the form the worker
// installer writes, but only if the machine has none: an existing identity is
// never replaced. It returns an error wrapping os.ErrExist when one exists, so
// that two processes publishing at once agree on the first.
//
// The record goes to a uniquely named temporary file that is then linked into
// place, as the installer does: an interrupted write leaves nothing that blocks
// the next one, and the link fails rather than overwrite.
func (h Home) PublishMachine(m Machine, now time.Time) error {
	if m.MachineID == "" || m.OwnerID == "" {
		return errors.New("a machine identity needs a machine id and an owner id")
	}
	if err := os.MkdirAll(h.Root, 0o700); err != nil {
		return fmt.Errorf("create the TXE home: %w", err)
	}
	record := struct {
		Schema      int    `json:"schema"`
		MachineID   string `json:"machine_id"`
		OwnerID     string `json:"owner_id"`
		DisplayName string `json:"display_name,omitempty"`
		CreatedAt   string `json:"created_at"`
	}{Schema: 1, MachineID: m.MachineID, OwnerID: m.OwnerID, DisplayName: m.DisplayName, CreatedAt: now.UTC().Format(time.RFC3339Nano)}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(h.Root, ".machine.*.tmp")
	if err != nil {
		return fmt.Errorf("write the machine identity: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write the machine identity: %w", err)
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write the machine identity: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write the machine identity: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write the machine identity: %w", err)
	}
	path := filepath.Join(h.Root, machineFile)
	if err := os.Link(tmp.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists: %w", path, os.ErrExist)
		}
		return fmt.Errorf("publish the machine identity: %w", err)
	}
	return nil
}
