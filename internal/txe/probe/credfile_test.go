// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
)

const credJob = "job_01JTXE00000000000000000AAA"

// localHome holds the receipt and the filed registration request of version
// 2 of credJob, declaring refs, as `dagu txe register` leaves them.
func localHome(t *testing.T, refs []CredentialRef) txepkg.Home {
	t.Helper()
	home := txepkg.Home{Root: t.TempDir()}
	dir := filepath.Join(home.ReceiptsDir(), credJob)
	if err := os.MkdirAll(filepath.Join(dir, "requests"), 0o700); err != nil {
		t.Fatal(err)
	}
	receipt, _ := json.Marshal(txepkg.Receipt{Schema: 1, JobID: credJob, Version: 2, RequestID: "req_1"})
	if err := os.WriteFile(filepath.Join(dir, "v2.json"), receipt, 0o600); err != nil {
		t.Fatal(err)
	}
	request, _ := json.Marshal(map[string]any{"version": map[string]any{"package": map[string]any{"credential_refs": refs}}})
	entry, _ := json.Marshal(txepkg.Entry{Schema: 1, RequestID: "req_1", JobID: credJob, Version: 2, Request: request})
	if err := os.WriteFile(filepath.Join(dir, "requests", "req_1.json"), entry, 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

func writeCred(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("apiVersion: v1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// The periodic check takes credential references from this machine's own
// registration record and reads the file's content.
func TestLocalCredentialsFromTheRegistrationRecord(t *testing.T) {
	kubeconfig := filepath.Join(t.TempDir(), "config")
	writeCred(t, kubeconfig, 0o600)
	home := localHome(t, []CredentialRef{
		{Name: KubernetesCredential, Kind: "file", Locator: kubeconfig},
		{Name: LinearCredential, Kind: "env", Locator: "LINEAR_KEY"},
	})
	creds := LocalCredentials{Home: home}.For(credJob, 2)
	if c, ok := creds.Lookup(KubernetesCredential); !ok || c.Value != "apiVersion: v1\n" || c.Path != "" {
		t.Fatalf("kubernetes = %+v %v, want the file's content", c, ok)
	}
	r := (Linear{}).Probe(context.Background(), linearTarget("uuid-1"), creds)
	if r.Outcome != AuthDenied || !strings.Contains(r.Detail, "periodic check does not receive") {
		t.Fatalf("env ref: %+v", r)
	}
}

// A version not registered from this machine has no credentials for the
// periodic check, whatever the registry says; the reason is reported.
func TestLocalCredentialsRequireALocalRecord(t *testing.T) {
	home := localHome(t, nil)
	creds := LocalCredentials{Home: home}.For(credJob, 3)
	r := (Kubernetes{}).Probe(context.Background(), configMapTarget(), creds)
	if r.Outcome != AuthDenied || !strings.Contains(r.Detail, "no registration record on this machine") {
		t.Fatalf("result = %+v", r)
	}
}

// A file is read only at an absolute, clean path to a regular file this
// user owns that others cannot write; a symbolic link is refused.
func TestCredentialFileChecks(t *testing.T) {
	dir := t.TempDir()
	good, shared, target := filepath.Join(dir, "config"), filepath.Join(dir, "shared"), filepath.Join(dir, "target")
	writeCred(t, good, 0o600)
	writeCred(t, target, 0o600)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	cases := map[string]bool{
		good:                         true,
		"config":                     false, // relative
		dir + "/./config":            false, // not clean
		filepath.Join(dir, "absent"): false,
		dir:                          false, // a directory
		link:                         false, // a symbolic link
	}
	if runtime.GOOS != "windows" {
		writeCred(t, shared, 0o666)
		cases[shared] = false // writable by others
	}
	for locator, ok := range cases {
		_, err := ReadCredentialFile(locator)
		if (err == nil) != ok {
			t.Errorf("locator %q: err = %v, want accepted = %v", locator, err, ok)
		}
	}
}

// Refs returns exactly the references this machine registered, and nothing
// for a version it did not register.
func TestLocalRefsAreTheRegisteredOnes(t *testing.T) {
	want := []CredentialRef{{Name: KubernetesCredential, Kind: "file", Locator: "/Users/me/.kube/config"}}
	home := localHome(t, want)
	got, err := LocalCredentials{Home: home}.Refs(credJob, 2)
	if err != nil || len(got) != 1 || got[0] != want[0] {
		t.Fatalf("refs = %+v, %v", got, err)
	}
	if _, err := (LocalCredentials{Home: home}).Refs(credJob, 3); err == nil {
		t.Fatal("a version this machine did not register returned references")
	}
}

// Version returns the registered version object exactly as sent, and Refs
// is read from it.
func TestLocalVersionIsTheRegisteredRequest(t *testing.T) {
	refs := []CredentialRef{{Name: LinearCredential, Kind: "env", Locator: "LINEAR_API_KEY"}}
	home := localHome(t, refs)
	raw, err := LocalCredentials{Home: home}.Version(credJob, 2)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Package struct {
			CredentialRefs []CredentialRef `json:"credential_refs"`
		} `json:"package"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Package.CredentialRefs) != 1 || v.Package.CredentialRefs[0] != refs[0] {
		t.Fatalf("version = %s, %v", raw, err)
	}
	if _, err := (LocalCredentials{Home: home}).Version(credJob, 3); err == nil {
		t.Fatal("a version this machine did not register was returned")
	}
}

// The filed entry must be the request the receipt names: an entry with
// another request id under that file name is an inconsistent record and
// nothing of it is used.
func TestLocalVersionRefusesAMismatchedRequest(t *testing.T) {
	home := localHome(t, nil)
	path := filepath.Join(home.ReceiptsDir(), credJob, "requests", "req_1.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var entry txepkg.Entry
	if err := json.Unmarshal(b, &entry); err != nil {
		t.Fatal(err)
	}
	entry.RequestID = "req_other"
	b, _ = json.Marshal(entry)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (LocalCredentials{Home: home}).Version(credJob, 2); err == nil {
		t.Fatal("an entry for another request was accepted")
	}
}
