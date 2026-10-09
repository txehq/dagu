// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// CredentialRef is a credential reference a job version declares.
type CredentialRef struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Locator string `json:"locator"`
}

// ValidateTarget says whether a target the probes are asked to observe
// (existence_check pre_run or reconcile) can be observed, given the
// version's credential references. Registration calls it so a target no
// probe could ever check is refused when it is declared, not reported
// unknown weeks later. event_only targets need no probe and are not checked.
func ValidateTarget(t Target, existenceCheck string, refs []CredentialRef) error {
	if existenceCheck != CheckPreRun && existenceCheck != CheckReconcile {
		return nil
	}
	cred := func(name string, kinds ...string) error {
		for _, r := range refs {
			if r.Name != name {
				continue
			}
			if slices.Contains(kinds, r.Kind) {
				return nil
			}
			return fmt.Errorf("credential reference %q must be of kind %s", name, strings.Join(kinds, " or "))
		}
		return fmt.Errorf("a %s target needs a credential reference named %q", t.Kind, name)
	}
	switch {
	case t.Kind == KindLinearIssue:
		if err := exactKeys(t.StableID, KeyLinearIssueID); err != nil {
			return err
		}
		return cred(LinearCredential, "env", "file")
	case strings.HasPrefix(t.Kind, KubernetesKindPrefix):
		res, ok := kubeResources[strings.TrimPrefix(t.Kind, KubernetesKindPrefix)]
		if !ok {
			return fmt.Errorf("kind %s is not a Kubernetes kind the probe knows", t.Kind)
		}
		if t.Environment == "" {
			return fmt.Errorf("a %s target needs its cluster as environment", t.Kind)
		}
		if err := exactKeys(t.StableID, KeyClusterUID, KeyUID); err != nil {
			return err
		}
		if _, _, ok := kubeObjectName(t.DisplayName, res.namespaced); !ok {
			return fmt.Errorf("display name %q must be exactly %s for %s", t.DisplayName, kubeLocatorShape(res.namespaced), t.Kind)
		}
		if err := cred(KubernetesCredential, "file"); err != nil {
			return err
		}
		for _, r := range refs {
			if r.Name == KubernetesContextCredential && r.Kind != "env" {
				return fmt.Errorf("credential reference %q must be of kind env", KubernetesContextCredential)
			}
		}
		return nil
	}
	return fmt.Errorf("no probe observes kind %s; declare it event_only", t.Kind)
}

// exactKeys requires the stable id to hold exactly keys, each non-empty.
func exactKeys(id map[string]string, keys ...string) error {
	want := append([]string(nil), keys...)
	sort.Strings(want)
	got := make([]string, 0, len(id))
	for k, v := range id {
		if strings.TrimSpace(v) == "" || v != strings.TrimSpace(v) {
			return fmt.Errorf("stable id %s is empty or padded", k)
		}
		got = append(got, k)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		return fmt.Errorf("stable id must have exactly the keys %s, not %s", strings.Join(want, ", "), strings.Join(got, ", "))
	}
	return nil
}
