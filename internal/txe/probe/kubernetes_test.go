// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	k8stesting "k8s.io/client-go/testing"
)

const (
	clusterUID = "cluster-0001"
	cmUID      = "cm-uid-0001"
)

type credMap map[string]Credential

func (c credMap) Lookup(name string) (Credential, bool) {
	v, ok := c[name]
	return v, ok
}

var kubeCreds = credMap{KubernetesCredential: {Path: "/home/me/.kube/config"}}

func object(apiVersion, kind, namespace, name, uid string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion(apiVersion)
	u.SetKind(kind)
	u.SetNamespace(namespace)
	u.SetName(name)
	u.SetUID(types.UID(uid))
	return u
}

func kubeSystem(uid string) *unstructured.Unstructured {
	return object("v1", "Namespace", "", "kube-system", uid)
}

func configMapTarget() Target {
	return Target{Kind: "kubernetes.configmap", DisplayName: "probe-ns/settings",
		StableID: map[string]string{KeyClusterUID: clusterUID, KeyUID: cmUID, KeyNamespace: "probe-ns", KeyName: "settings"}}
}

// fakeKube returns a probe whose client is a fake cluster holding objs, and
// the fake so a test can add reactors.
func fakeKube(t *testing.T, objs ...runtime.Object) (Kubernetes, *dynamicfake.FakeDynamicClient) {
	t.Helper()
	scheme := runtime.NewScheme()
	lists := map[schema.GroupVersionResource]string{
		{Version: "v1", Resource: "namespaces"}: "NamespaceList",
		{Version: "v1", Resource: "configmaps"}: "ConfigMapList",
	}
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, lists, objs...)
	var gotPath string
	k := Kubernetes{NewClient: func(path, _ string) (dynamic.Interface, error) {
		gotPath = path
		return client, nil
	}}
	t.Cleanup(func() {
		if gotPath != "" && gotPath != kubeCreds[KubernetesCredential].Path {
			t.Errorf("client built from %q, want the credential's kubeconfig", gotPath)
		}
	})
	return k, client
}

func TestKubernetesPresent(t *testing.T) {
	k, _ := fakeKube(t, kubeSystem(clusterUID), object("v1", "ConfigMap", "probe-ns", "settings", cmUID))
	r := k.Probe(context.Background(), configMapTarget(), kubeCreds)
	if r.Outcome != Present || r.Observed != nil || r.Authoritative {
		t.Fatalf("result = %+v, want present with the same identity", r)
	}
}

// NotFound is authoritative only after the client proved it reached the
// target's cluster.
func TestKubernetesAbsentIsAuthoritativeOnTheRightCluster(t *testing.T) {
	k, _ := fakeKube(t, kubeSystem(clusterUID))
	r := k.Probe(context.Background(), configMapTarget(), kubeCreds)
	if r.Outcome != Absent || !r.Authoritative {
		t.Fatalf("result = %+v, want authoritative absent", r)
	}
	if len(r.Evidence) != 2 || r.Evidence[0] != "kube-system uid="+clusterUID {
		t.Fatalf("evidence = %v, want the cluster identity and the 404", r.Evidence)
	}
}

// The same NotFound from another cluster says nothing about the target.
func TestKubernetesWrongClusterNotFoundIsUnreachable(t *testing.T) {
	k, _ := fakeKube(t, kubeSystem("cluster-other"))
	r := k.Probe(context.Background(), configMapTarget(), kubeCreds)
	if r.Outcome != Unreachable || r.Authoritative {
		t.Fatalf("result = %+v, want unreachable", r)
	}
}

// A same-name object with another UID is a new object: reported present
// under the observed identity, never as the target.
func TestKubernetesSameNameNewUIDIsReplacement(t *testing.T) {
	k, _ := fakeKube(t, kubeSystem(clusterUID), object("v1", "ConfigMap", "probe-ns", "settings", "cm-uid-0002"))
	r := k.Probe(context.Background(), configMapTarget(), kubeCreds)
	if r.Outcome != Present || r.Observed == nil {
		t.Fatalf("result = %+v, want present with a new identity", r)
	}
	if r.Observed.StableID[KeyUID] != "cm-uid-0002" || r.Observed.StableID[KeyClusterUID] != clusterUID ||
		r.Observed.Kind != "kubernetes.configmap" || r.Observed.DisplayName != "probe-ns/settings" {
		t.Fatalf("observed = %+v", r.Observed)
	}
	if configMapTarget().StableID[KeyUID] != cmUID {
		t.Fatal("the target's identity was changed")
	}
}

func TestKubernetesErrorsNeverReadAsDeletion(t *testing.T) {
	cm := schema.GroupResource{Resource: "configmaps"}
	for name, tc := range map[string]struct {
		resource string
		err      error
		want     Outcome
	}{
		"rbac on the object":  {"configmaps", apierrors.NewForbidden(cm, "settings", errors.New("rbac")), AuthDenied},
		"rbac on kube-system": {"namespaces", apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, "kube-system", errors.New("rbac")), AuthDenied},
		"expired token":       {"namespaces", apierrors.NewUnauthorized("token expired"), AuthDenied},
		"server timeout":      {"configmaps", apierrors.NewServerTimeout(cm, "get", 1), Timeout},
		"deadline":            {"namespaces", context.DeadlineExceeded, Timeout},
		"tunnel down":         {"namespaces", errors.New("dial tcp 127.0.0.1:6443: connect: connection refused"), Unreachable},
		"server error":        {"configmaps", apierrors.NewInternalError(errors.New("etcd")), Unreachable},
	} {
		t.Run(name, func(t *testing.T) {
			k, client := fakeKube(t, kubeSystem(clusterUID))
			client.PrependReactor("get", tc.resource, func(k8stesting.Action) (bool, runtime.Object, error) {
				return true, nil, tc.err
			})
			r := k.Probe(context.Background(), configMapTarget(), kubeCreds)
			if r.Outcome != tc.want || r.Authoritative {
				t.Fatalf("result = %+v, want %s", r, tc.want)
			}
		})
	}
}

func TestKubernetesWithoutCredentialOrIdentity(t *testing.T) {
	k, _ := fakeKube(t, kubeSystem(clusterUID))
	if r := k.Probe(context.Background(), configMapTarget(), credMap{}); r.Outcome != AuthDenied {
		t.Fatalf("no credential: %+v, want auth_denied", r)
	}
	noCluster := configMapTarget()
	delete(noCluster.StableID, KeyClusterUID)
	if r := k.Probe(context.Background(), noCluster, kubeCreds); r.Outcome != Unreachable || r.Authoritative {
		t.Fatalf("no cluster uid: %+v, want unreachable", r)
	}
}

// The display name "namespace/name" locates an object whose stable id
// carries only the UIDs.
func TestKubernetesNameFromDisplayName(t *testing.T) {
	k, _ := fakeKube(t, kubeSystem(clusterUID), object("v1", "ConfigMap", "probe-ns", "settings", cmUID))
	target := configMapTarget()
	delete(target.StableID, KeyNamespace)
	delete(target.StableID, KeyName)
	if r := k.Probe(context.Background(), target, kubeCreds); r.Outcome != Present {
		t.Fatalf("result = %+v, want present", r)
	}
}

func TestProbesDispatchByKind(t *testing.T) {
	ps := Probes{Kubernetes{}, Linear{}}
	if !(Kubernetes{}).Supports("kubernetes.configmap") || (Kubernetes{}).Supports("kubernetes.widget") || (Kubernetes{}).Supports("configmap") {
		t.Fatal("kubernetes kind support is wrong")
	}
	if r := ps.Probe(context.Background(), Target{Kind: "aws.bucket", StableID: map[string]string{"arn": "x"}}, credMap{}); r.Outcome != Unreachable {
		t.Fatalf("unknown kind: %+v, want unreachable", r)
	}
}

func TestReconcileDAGName(t *testing.T) {
	name := ReconcileDAGName("mch_01JTXE0000000000000000F1X3")
	if name != "txe-probe-01JTXE0000000000000000F1X3" || len(name) > 40 {
		t.Fatalf("name = %q (%d characters)", name, len(name))
	}
}
