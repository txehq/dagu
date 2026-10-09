// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

// maxCredentialBytes bounds a credential file the probe reads.
const maxCredentialBytes = 1 << 20

// LocalCredentials resolves a job version's file credential references for
// the periodic check from this machine's own registration record, never
// from the registry: a version registered from this machine has a receipt
// and the exact request it sent, and only the references in that request
// are read. A hub record cannot steer the probe at another file.
type LocalCredentials struct {
	Home txepkg.Home
}

// For returns the credentials of version of jobID.
func (l LocalCredentials) For(jobID string, version int) Credentials {
	refs, err := l.Refs(jobID, version)
	if err != nil {
		reason := fmt.Sprintf("version %d of job %s has no registration record on this machine (%v); credential references are read only from it", version, jobID, err)
		return explained{FileCredentials{}, everyName(reason)}
	}
	out := FileCredentials{}
	missing := map[string]string{}
	for _, ref := range refs {
		switch ref.Kind {
		case "file":
			value, err := ReadCredentialFile(ref.Locator)
			if err != nil {
				missing[ref.Name] = "credential reference " + ref.Name + ": " + err.Error()
				continue
			}
			out[ref.Name] = value
		default:
			missing[ref.Name] = "credential reference " + ref.Name + " is an environment variable, which the periodic check does not receive"
		}
	}
	return explained{out, reasons(missing)}
}

// Refs returns the credential references this machine itself registered for
// version of jobID: those of the exact request `dagu txe register` filed
// beside the version's receipt. Anything that acts on a job's credentials
// on this machine reads them here, never from the registry's copy, which a
// hub record could change. An error means the version has no local
// registration record, and no reference may be used.
func (l LocalCredentials) Refs(jobID string, version int) ([]CredentialRef, error) {
	receipt, err := txepkg.NewJournal(l.Home).Receipt(jobID, version)
	if err != nil {
		return nil, err
	}
	if receipt.RequestID == "" || strings.ContainsAny(receipt.RequestID, `/\.`) {
		return nil, fmt.Errorf("receipt names request %q", receipt.RequestID)
	}
	path := filepath.Join(l.Home.ReceiptsDir(), jobID, "requests", receipt.RequestID+".json")
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("read registration request: %w", err)
	}
	var entry txepkg.Entry
	if err := json.Unmarshal(b, &entry); err != nil {
		return nil, fmt.Errorf("parse registration record: %w", err)
	}
	if entry.JobID != jobID || entry.Version != version {
		return nil, fmt.Errorf("registration record is for %s v%d", entry.JobID, entry.Version)
	}
	var req struct {
		Version struct {
			Package struct {
				CredentialRefs []CredentialRef `json:"credential_refs"`
			} `json:"package"`
		} `json:"version"`
	}
	if err := json.Unmarshal(entry.Request, &req); err != nil {
		return nil, fmt.Errorf("parse registration request: %w", err)
	}
	return req.Version.Package.CredentialRefs, nil
}

// everyName explains a missing reference whatever its name.
type everyName string

func (e everyName) reason(string) string { return string(e) }

// FileCredentials holds credential file contents read for the periodic
// check, by reference name.
type FileCredentials map[string]string

// Lookup returns the file's content.
func (f FileCredentials) Lookup(name string) (Credential, bool) {
	v, ok := f[name]
	return Credential{Value: v}, ok && v != ""
}

// explained adds why a reference is missing to a Credentials.
type explained struct {
	Credentials
	missing interface{ reason(string) string }
}

func (e explained) MissingReason(name string) string { return e.missing.reason(name) }

type reasons map[string]string

func (r reasons) reason(name string) string { return r[name] }

// ReadCredentialFile reads a credential file, at most 1 MiB, only at an
// absolute, clean path with no "..", and only if it is a regular file.
//
// On Unix the file is opened without following a symbolic link and checked
// on the open descriptor: it must be this user's and not writable by group
// or others, so it cannot be swapped between the check and the read.
//
// On Windows, permissions are ACLs this function does not inspect: it
// refuses a symbolic link with Lstat before opening (so a swap between the
// two is possible) and checks the opened file is regular, but enforces no
// ownership or writer restriction. Success there is not proof that another
// user cannot change the file.
func ReadCredentialFile(locator string) (string, error) {
	if locator == "" || !filepath.IsAbs(locator) || filepath.Clean(locator) != locator || strings.Contains(locator, "..") {
		return "", fmt.Errorf("locator %q is not an absolute, clean path", locator)
	}
	f, err := openNoFollow(locator)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("file %s does not exist on this machine", locator)
	}
	if err != nil {
		return "", fmt.Errorf("open %s (a symbolic link is refused): %w", locator, err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("file %s: %w", locator, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", locator)
	}
	if err := checkOwnership(locator, info); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxCredentialBytes+1))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", locator, err)
	}
	if len(b) > maxCredentialBytes {
		return "", fmt.Errorf("%s is larger than a credential file", locator)
	}
	return string(b), nil
}
