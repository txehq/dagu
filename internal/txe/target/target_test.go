// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package target

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Case is one entry of the shared registration fixture.
type Case struct {
	Target         Target
	ExistenceCheck string
	CredentialRefs []CredentialRef
	Reason         string
}

// UnmarshalJSON reads a case whose target carries its existence check.
func (c *Case) UnmarshalJSON(b []byte) error {
	var raw struct {
		Target struct {
			Target
			ExistenceCheck string `json:"existence_check"`
		} `json:"target"`
		CredentialRefs []CredentialRef `json:"credential_refs"`
		Reason         string          `json:"reason"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*c = Case{Target: raw.Target.Target, ExistenceCheck: raw.Target.ExistenceCheck,
		CredentialRefs: raw.CredentialRefs, Reason: raw.Reason}
	return nil
}

func loadFixture(t *testing.T) (accepted, refused []Case) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "txe", "contract", "fixtures", "registration", "probe-targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Accepted []Case `json:"accepted"`
		Refused  []Case `json:"refused"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Accepted) < 5 || len(doc.Refused) < 10 {
		t.Fatalf("fixture has %d accepted and %d refused cases", len(doc.Accepted), len(doc.Refused))
	}
	return doc.Accepted, doc.Refused
}

// The registration rules live here once; registration's validation and the
// probes both apply them, and both run this fixture.
func TestValidateSharedFixture(t *testing.T) {
	accepted, refused := loadFixture(t)
	for _, c := range accepted {
		if err := Validate(c.Target, c.ExistenceCheck, c.CredentialRefs); err != nil {
			t.Errorf("accepted %+v refused: %v", c.Target, err)
		}
	}
	for _, c := range refused {
		if c.Reason == "" {
			t.Errorf("refused case without a reason: %+v", c.Target)
		}
		if err := Validate(c.Target, c.ExistenceCheck, c.CredentialRefs); err == nil {
			t.Errorf("refused (%s) accepted: %+v", c.Reason, c.Target)
		}
	}
}

func TestParseKubeLocator(t *testing.T) {
	for display, want := range map[string]bool{
		"ns/name": true, "name": false, "a/b/c": false, "/name": false, "ns/": false, " ns/name": false, "ns/ name": false,
	} {
		if _, _, ok := ParseKubeLocator(display, true); ok != want {
			t.Errorf("namespaced %q: ok = %v, want %v", display, ok, want)
		}
	}
	if ns, name, ok := ParseKubeLocator("probe-ns", false); !ok || ns != "" || name != "probe-ns" {
		t.Fatalf("cluster-scoped = %q %q %v", ns, name, ok)
	}
	if _, _, ok := ParseKubeLocator("x/probe-ns", false); ok {
		t.Fatal("cluster-scoped kind took a namespace")
	}
}

// The shape rules hold whatever the existence check: a padded or extra
// identity field is refused before any probe looks it up.
func TestValidateShape(t *testing.T) {
	good := Target{Kind: "kubernetes.configmap", Environment: "dev", DisplayName: "ns/cm", StableID: map[string]string{KeyClusterUID: "c1", KeyUID: "u1"}}
	if err := ValidateShape(good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Target){
		"padded uid":    func(t *Target) { t.StableID = map[string]string{KeyClusterUID: "c1", KeyUID: "u1 "} },
		"extra key":     func(t *Target) { t.StableID = map[string]string{KeyClusterUID: "c1", KeyUID: "u1", "name": "cm"} },
		"no env":        func(t *Target) { t.Environment = "" },
		"bare name":     func(t *Target) { t.DisplayName = "cm" },
		"unknown kind":  func(t *Target) { t.Kind = "kubernetes.widget" },
		"other product": func(t *Target) { t.Kind = "aws.bucket" },
	} {
		bad := good
		bad.StableID = map[string]string{KeyClusterUID: "c1", KeyUID: "u1"}
		mutate(&bad)
		if err := ValidateShape(bad); err == nil {
			t.Errorf("%s accepted: %+v", name, bad)
		}
	}
}
