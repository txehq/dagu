// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type fixtureTarget struct {
	Target         Target
	ExistenceCheck string
	CredentialRefs []CredentialRef
	Reason         string
}

func (f *fixtureTarget) UnmarshalJSON(b []byte) error {
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
	*f = fixtureTarget{Target: raw.Target.Target, ExistenceCheck: raw.Target.ExistenceCheck,
		CredentialRefs: raw.CredentialRefs, Reason: raw.Reason}
	return nil
}

// The registration rules are shared with registration through one fixture,
// so what registration accepts is exactly what the probes can observe.
func TestValidateTargetSharedFixture(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "txe", "contract", "fixtures", "registration", "probe-targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Accepted []fixtureTarget `json:"accepted"`
		Refused  []fixtureTarget `json:"refused"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Accepted) < 5 || len(doc.Refused) < 10 {
		t.Fatalf("fixture has %d accepted and %d refused cases", len(doc.Accepted), len(doc.Refused))
	}
	for _, c := range doc.Accepted {
		if err := ValidateTarget(c.Target, c.ExistenceCheck, c.CredentialRefs); err != nil {
			t.Errorf("accepted %+v refused: %v", c.Target, err)
		}
	}
	for _, c := range doc.Refused {
		if c.Reason == "" {
			t.Errorf("refused case without a reason: %+v", c.Target)
		}
		if err := ValidateTarget(c.Target, c.ExistenceCheck, c.CredentialRefs); err == nil {
			t.Errorf("refused (%s) accepted: %+v", c.Reason, c.Target)
		}
	}
	// What registration accepts, the Kubernetes probe can locate: an
	// accepted locator never comes back unknown for its shape.
	k, _ := fakeKube(t, kubeSystem("c1"))
	for _, c := range doc.Accepted {
		if !(Kubernetes{}).Supports(c.Target.Kind) || c.ExistenceCheck == "event_only" {
			continue
		}
		if r := k.Probe(context.Background(), c.Target, kubeCreds); r.Outcome == Unknown {
			t.Errorf("accepted %+v is unknown to the probe: %s", c.Target, r.Detail)
		}
	}
}
