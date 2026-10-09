// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"maps"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

// KubernetesKindPrefix starts every Kubernetes target kind, as in
// "kubernetes.configmap".
const KubernetesKindPrefix = "kubernetes."

// Stable identity keys of a Kubernetes target.
const (
	KeyClusterUID = "cluster_uid"
	KeyUID        = "uid"
	KeyNamespace  = "namespace"
	KeyName       = "name"
)

// KubernetesCredential names the credential reference holding the
// kubeconfig file; KubernetesContextCredential optionally names the context.
const (
	KubernetesCredential        = "kubernetes"
	KubernetesContextCredential = "kubernetes_context" //nolint:gosec // A credential reference name, not a credential.
)

type kubeResource struct {
	gvr        schema.GroupVersionResource
	namespaced bool
}

// kubeResources are the Kubernetes kinds a target may name.
var kubeResources = map[string]kubeResource{
	"configmap":             {schema.GroupVersionResource{Version: "v1", Resource: "configmaps"}, true},
	"secret":                {schema.GroupVersionResource{Version: "v1", Resource: "secrets"}, true},
	"service":               {schema.GroupVersionResource{Version: "v1", Resource: "services"}, true},
	"persistentvolumeclaim": {schema.GroupVersionResource{Version: "v1", Resource: "persistentvolumeclaims"}, true},
	"namespace":             {schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}, false},
	"deployment":            {schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, true},
	"statefulset":           {schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}, true},
	"job":                   {schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "jobs"}, true},
	"cronjob":               {schema.GroupVersionResource{Group: "batch", Version: "v1", Resource: "cronjobs"}, true},
}

var namespacesGVR = schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}

// KubeClientFactory builds a client from the kubeconfig at path and an
// optional context name.
type KubeClientFactory func(kubeconfigPath, contextName string) (dynamic.Interface, error)

// Kubernetes probes Kubernetes objects.
type Kubernetes struct {
	// NewClient defaults to a client built from the kubeconfig file.
	NewClient KubeClientFactory
}

func (Kubernetes) Supports(kind string) bool {
	_, ok := kubeResources[strings.TrimPrefix(kind, KubernetesKindPrefix)]
	return strings.HasPrefix(kind, KubernetesKindPrefix) && ok
}

// Probe first proves the client reaches the cluster the target names (the
// kube-system namespace's UID is the cluster's identity); only then is a
// NotFound evidence that the object is gone. The object found by name must
// carry the target's UID; another UID is the same name on a new object.
func (k Kubernetes) Probe(ctx context.Context, t Target, creds Credentials) Result {
	res := kubeResources[strings.TrimPrefix(t.Kind, KubernetesKindPrefix)]
	clusterUID, uid := trimmed(t.StableID[KeyClusterUID]), trimmed(t.StableID[KeyUID])
	namespace, name := kubeObjectName(t, res.namespaced)
	if clusterUID == "" || uid == "" || name == "" || (res.namespaced && namespace == "") {
		return Result{Outcome: Unreachable, Detail: "target lacks cluster_uid, uid, namespace or name; nothing to look up"}
	}
	cred, ok := creds.Lookup(KubernetesCredential)
	if !ok || cred.Path == "" {
		return noCredential(KubernetesCredential)
	}
	contextName := ""
	if c, ok := creds.Lookup(KubernetesContextCredential); ok {
		contextName = trimmed(c.Value)
	}
	newClient := k.NewClient
	if newClient == nil {
		newClient = kubeconfigClient
	}
	client, err := newClient(cred.Path, contextName)
	if err != nil {
		return Result{Outcome: Unreachable, Detail: "build Kubernetes client: " + err.Error()}
	}

	ns, err := client.Resource(namespacesGVR).Get(ctx, "kube-system", metav1.GetOptions{})
	if err != nil {
		return kubeError(ctx, err, "read kube-system to identify the cluster")
	}
	if got := string(ns.GetUID()); got != clusterUID {
		return Result{Outcome: Unreachable,
			Detail:   fmt.Sprintf("the credential reaches cluster %s, not the target's cluster %s", got, clusterUID),
			Evidence: []string{"kube-system uid=" + got}}
	}
	evidence := []string{"kube-system uid=" + clusterUID}

	ri := client.Resource(res.gvr)
	var getter dynamic.ResourceInterface = ri
	if res.namespaced {
		getter = ri.Namespace(namespace)
	}
	found, err := getter.Get(ctx, name, metav1.GetOptions{})
	ref := kubeRef(res, namespace, name)
	switch {
	case apierrors.IsNotFound(err):
		return Result{Outcome: Absent, Authoritative: true, Detail: ref + " not found in cluster " + clusterUID,
			Evidence: append(evidence, "GET "+ref+": 404")}
	case err != nil:
		return kubeError(ctx, err, "GET "+ref)
	}
	got := string(found.GetUID())
	evidence = append(evidence, "GET "+ref+": uid="+got)
	if got == uid {
		return Result{Outcome: Present, Detail: ref + " exists", Evidence: evidence}
	}
	observed := Target{Kind: t.Kind, Environment: t.Environment, DisplayName: t.DisplayName, StableID: map[string]string{}}
	maps.Copy(observed.StableID, t.StableID)
	observed.StableID[KeyUID] = got
	return Result{Outcome: Present, Observed: &observed,
		Detail:   fmt.Sprintf("%s now has uid %s, not the target's %s: a new object under the same name", ref, got, uid),
		Evidence: evidence}
}

// kubeObjectName reads namespace and name from the stable identity, falling
// back to a display name of the form "namespace/name" (or "name").
func kubeObjectName(t Target, namespaced bool) (string, string) {
	namespace, name := trimmed(t.StableID[KeyNamespace]), trimmed(t.StableID[KeyName])
	if name == "" && t.DisplayName != "" {
		if ns, n, ok := strings.Cut(t.DisplayName, "/"); ok && namespaced {
			namespace, name = trimmed(ns), trimmed(n)
		} else if !ok {
			name = trimmed(t.DisplayName)
		}
	}
	return namespace, name
}

func kubeRef(res kubeResource, namespace, name string) string {
	if res.namespaced {
		return res.gvr.Resource + "/" + namespace + "/" + name
	}
	return res.gvr.Resource + "/" + name
}

// kubeError maps an API error to what it allows. A refusal is auth_denied;
// everything else that is not an answer is unreachable or timeout.
func kubeError(ctx context.Context, err error, what string) Result {
	switch {
	case apierrors.IsUnauthorized(err) || apierrors.IsForbidden(err):
		return Result{Outcome: AuthDenied, Detail: what + ": " + err.Error()}
	case apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err):
		return Result{Outcome: Timeout, Detail: what + ": " + err.Error()}
	}
	return Result{Outcome: classify(ctx, err), Detail: what + ": " + err.Error()}
}

func kubeconfigClient(path, contextName string) (dynamic.Interface, error) {
	rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: path}
	overrides := &clientcmd.ConfigOverrides{CurrentContext: contextName}
	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, err
	}
	return dynamic.NewForConfig(cfg)
}
