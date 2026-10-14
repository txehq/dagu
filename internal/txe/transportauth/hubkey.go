// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package transportauth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// hubKeyBytes is the randomness in a key this package creates. It is written
// as hex, so the key presented is twice as long.
const hubKeyBytes = 32

// LoadOrCreateHubKey returns the hub key at path, creating it first when no
// file is there. The hub's own processes share the file on the hub's
// storage, so whichever starts first creates it and the others read it.
//
// The key is created with a link that never replaces a file, so two
// processes starting together end with the same key. The file must be a
// regular file only its owner can read, holding exactly one key in the
// shape this function writes; anything else is refused, never repaired or
// replaced.
func LoadOrCreateHubKey(path string) ([]byte, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("transportauth: the hub key's owner-only permissions cannot be checked on Windows")
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("transportauth: the hub key path must be absolute")
	}
	key, err := readHubKey(path)
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		return key, err
	}
	if err := createHubKey(path); err != nil {
		return nil, err
	}
	return readHubKey(path)
}

func readHubKey(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("transportauth: read the hub key: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("transportauth: the hub key is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("transportauth: the hub key file has mode %#o; it must be readable by its owner only (0600)", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the operator's configured hub key file
	if err != nil {
		return nil, fmt.Errorf("transportauth: read the hub key: %w", err)
	}
	text := strings.TrimSuffix(string(raw), "\n")
	if len(text) != 2*hubKeyBytes || strings.ToLower(text) != text {
		return nil, errors.New("transportauth: the hub key file does not hold a key of the expected shape")
	}
	if _, err := hex.DecodeString(text); err != nil {
		return nil, errors.New("transportauth: the hub key file does not hold a key of the expected shape")
	}
	return []byte(text), nil
}

func createHubKey(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("transportauth: create the hub key directory: %w", err)
	}
	random := make([]byte, hubKeyBytes)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("transportauth: generate the hub key: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("transportauth: create the hub key: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("transportauth: create the hub key: %w", err)
	}
	if _, err := tmp.WriteString(hex.EncodeToString(random) + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("transportauth: create the hub key: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("transportauth: create the hub key: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("transportauth: create the hub key: %w", err)
	}
	// A link fails when the name exists, so a key another process created
	// meanwhile is kept and read instead of replaced.
	if err := os.Link(tmpName, path); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("transportauth: create the hub key: %w", err)
	}
	if d, err := os.Open(dir); err == nil { //nolint:gosec // the hub key's own directory
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
