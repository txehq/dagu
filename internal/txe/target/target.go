// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package target holds the rules for a job's external targets that both
// registration and the existence probes apply: which kinds can be observed,
// what their stable identity and locator look like, and which credential
// references they need. It imports no other TXE package, so the registry
// client and the probes share one implementation.
package target

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Target is an external resource as a job version declares it: a kind and a
// stable identity. The display name never identifies it.
type Target struct {
	Kind        string            `json:"kind"`
	Environment string            `json:"environment,omitempty"`
	StableID    map[string]string `json:"stable_id"`
	DisplayName string            `json:"display_name,omitempty"`
}

// CredentialRef is a credential reference a job version declares.
type CredentialRef struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Locator string `json:"locator"`
}

// Existence checks a target declares.
const (
	CheckPreRun    = "pre_run"
	CheckReconcile = "reconcile"
	CheckEventOnly = "event_only"
)

// Kubernetes targets. The stable id holds only the identity; where the
// object lives is its display name, "namespace/name" for a namespaced kind
// and "name" for a cluster-scoped one.
const (
	KubernetesKindPrefix = "kubernetes."
	KeyClusterUID        = "cluster_uid"
	KeyUID               = "uid"
)

// Linear targets.
const (
	KindLinearIssue  = "linear.issue"
	KeyLinearIssueID = "id"
)

// Credential reference names. They are also the variables the job's own
// script receives, so the kubeconfig avoids KUBECONFIG, which kubectl reads
// as a path.
const (
	// KubernetesCredential is a file reference to the kubeconfig.
	KubernetesCredential = "TXE_KUBECONFIG" //nolint:gosec // A credential reference name, not a credential.
	// KubernetesContextCredential optionally names the context.
	KubernetesContextCredential = "TXE_KUBE_CONTEXT" //nolint:gosec // A credential reference name, not a credential.
	// LinearCredential holds the Linear API key, the name job authors
	// already declare for their own scripts.
	LinearCredential = "LINEAR_API_KEY" //nolint:gosec // A credential reference name, not a credential.
)

// KubeKind is a Kubernetes resource a target may name.
type KubeKind struct {
	Group, Version, Resource string
	Namespaced               bool
}

var kubeKinds = map[string]KubeKind{
	"configmap":             {"", "v1", "configmaps", true},
	"secret":                {"", "v1", "secrets", true},
	"service":               {"", "v1", "services", true},
	"persistentvolumeclaim": {"", "v1", "persistentvolumeclaims", true},
	"namespace":             {"", "v1", "namespaces", false},
	"deployment":            {"apps", "v1", "deployments", true},
	"statefulset":           {"apps", "v1", "statefulsets", true},
	"job":                   {"batch", "v1", "jobs", true},
	"cronjob":               {"batch", "v1", "cronjobs", true},
}

// LookupKube returns the Kubernetes resource a target kind names.
func LookupKube(kind string) (KubeKind, bool) {
	if !strings.HasPrefix(kind, KubernetesKindPrefix) {
		return KubeKind{}, false
	}
	k, ok := kubeKinds[strings.TrimPrefix(kind, KubernetesKindPrefix)]
	return k, ok
}

// ParseKubeLocator parses a display name that must be exactly
// "namespace/name" (namespaced) or "name" (cluster-scoped). Anything else is
// refused rather than guessed.
func ParseKubeLocator(displayName string, namespaced bool) (namespace, name string, ok bool) {
	parts := strings.Split(displayName, "/")
	for _, p := range parts {
		if p == "" || p != strings.TrimSpace(p) {
			return "", "", false
		}
	}
	switch {
	case namespaced && len(parts) == 2:
		return parts[0], parts[1], true
	case !namespaced && len(parts) == 1:
		return "", parts[0], true
	}
	return "", "", false
}

// KubeLocatorShape describes the locator a kind needs, for messages.
func KubeLocatorShape(namespaced bool) string {
	if namespaced {
		return `"namespace/name"`
	}
	return `"name"`
}

// ValidateShape says whether a target's kind, stable identity and locator
// meet the contract, whatever its existence check. A probe refuses to look
// up a target that does not, so a padded or extra identity field never
// reaches an authoritative report.
func ValidateShape(t Target) error {
	switch {
	case t.Kind == KindLinearIssue:
		return exactKeys(t.StableID, KeyLinearIssueID)
	case strings.HasPrefix(t.Kind, KubernetesKindPrefix):
		k, ok := LookupKube(t.Kind)
		if !ok {
			return fmt.Errorf("kind %s is not a Kubernetes kind the probe knows", t.Kind)
		}
		if t.Environment == "" {
			return fmt.Errorf("a %s target needs its cluster as environment", t.Kind)
		}
		if err := exactKeys(t.StableID, KeyClusterUID, KeyUID); err != nil {
			return err
		}
		if _, _, ok := ParseKubeLocator(t.DisplayName, k.Namespaced); !ok {
			return fmt.Errorf("display name %q must be exactly %s for %s", t.DisplayName, KubeLocatorShape(k.Namespaced), t.Kind)
		}
		return nil
	}
	return fmt.Errorf("no probe observes kind %s; declare it event_only", t.Kind)
}

// Validate says whether a target the probes are asked to observe
// (existence_check pre_run or reconcile) can be observed, given the
// version's credential references. Registration calls it so a target no
// probe could ever check is refused when it is declared, not reported
// unknown weeks later. event_only targets need no probe and are not checked.
func Validate(t Target, existenceCheck string, refs []CredentialRef) error {
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
	if err := ValidateShape(t); err != nil {
		return err
	}
	if t.Kind == KindLinearIssue {
		return cred(LinearCredential, "env", "file")
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
