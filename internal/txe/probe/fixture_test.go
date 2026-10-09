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

// What registration accepts, the Kubernetes probe can locate: an accepted
// target is never unknown for its shape.
func TestAcceptedTargetsAreLocatable(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "txe", "contract", "fixtures", "registration", "probe-targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Accepted []struct {
			Target struct {
				Target
				ExistenceCheck string `json:"existence_check"`
			} `json:"target"`
		} `json:"accepted"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	k, _ := fakeKube(t, kubeSystem("c1"))
	probes := Probes{k}
	checked := 0
	for _, c := range doc.Accepted {
		if !k.Supports(c.Target.Kind) || c.Target.ExistenceCheck == "event_only" {
			continue
		}
		checked++
		if r := probes.Probe(context.Background(), c.Target.Target, kubeCreds); r.Outcome == Unknown {
			t.Errorf("accepted %+v is unknown to the probe: %s", c.Target.Target, r.Detail)
		}
	}
	if checked == 0 {
		t.Fatal("no accepted Kubernetes target in the fixture")
	}
}
