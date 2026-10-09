// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
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
		StableID: map[string]string{KeyClusterUID: clusterUID, KeyUID: cmUID}}
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
	k := Kubernetes{NewClient: func(_ context.Context, cred Credential, _ string) (dynamic.Interface, error) {
		gotPath = cred.Path
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
	if r := k.Probe(context.Background(), noCluster, kubeCreds); r.Outcome != Unknown || r.Authoritative {
		t.Fatalf("no cluster uid: %+v, want unknown", r)
	}
}

// The display name is the locator and must be exactly "namespace/name" for
// a namespaced kind or "name" for a cluster-scoped one; any other shape is
// unknown, never guessed into a lookup that could come back NotFound.
func TestKubernetesLocatorIsStrict(t *testing.T) {
	k, _ := fakeKube(t, kubeSystem(clusterUID))
	for _, display := range []string{"", "settings", "probe-ns/settings/extra", "/settings", "probe-ns/", " probe-ns/settings"} {
		target := configMapTarget()
		target.DisplayName = display
		if r := k.Probe(context.Background(), target, kubeCreds); r.Outcome != Unknown || r.Authoritative {
			t.Errorf("display name %q: %+v, want unknown", display, r)
		}
	}
	ns := Target{Kind: "kubernetes.namespace", DisplayName: "probe-ns", StableID: map[string]string{KeyClusterUID: clusterUID, KeyUID: "ns-uid"}}
	if r := k.Probe(context.Background(), ns, kubeCreds); r.Outcome != Absent || !r.Authoritative {
		t.Fatalf("cluster-scoped %q: %+v, want authoritative absent", ns.DisplayName, r)
	}
	ns.DisplayName = "x/probe-ns"
	if r := k.Probe(context.Background(), ns, kubeCreds); r.Outcome != Unknown {
		t.Fatalf("cluster-scoped with a namespace: %+v, want unknown", r)
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

// A kubeconfig arriving as a resolved secret's content builds a client for
// that cluster without touching the filesystem.
func TestKubeconfigClientFromContent(t *testing.T) {
	const kubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: dev
  cluster: {server: "https://127.0.0.1:6443"}
users:
- name: probe
  user: {token: "not-a-real-token"}
contexts:
- name: dev
  context: {cluster: dev, user: probe}
current-context: dev
`
	if _, err := kubeconfigClient(context.Background(), Credential{Value: kubeconfig}, ""); err != nil {
		t.Fatalf("content: %v", err)
	}
	if _, err := kubeconfigClient(context.Background(), Credential{Value: kubeconfig}, "dev"); err != nil {
		t.Fatalf("named context: %v", err)
	}
	if _, err := kubeconfigClient(context.Background(), Credential{Value: "not yaml: ["}, ""); err == nil {
		t.Fatal("garbage kubeconfig built a client")
	}
}

// execKubeconfig is a kubeconfig whose user runs plugin for its credential.
func execKubeconfig(plugin string) string {
	return `apiVersion: v1
kind: Config
clusters:
- name: dev
  cluster: {server: "https://127.0.0.1:6443"}
users:
- name: probe
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1
      command: ` + plugin + `
      interactiveMode: Never
contexts:
- name: dev
  context: {cluster: dev, user: probe}
current-context: dev
`
}

func writePlugin(t *testing.T, body string) string {
	t.Helper()
	if goruntime.GOOS == "windows" {
		t.Skip("shell plugin")
	}
	path := filepath.Join(t.TempDir(), "plugin.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

// An exec credential plugin that never answers, such as one waiting for a
// login, is bounded by the check's deadline instead of hanging the run.
func TestExecPluginIsBounded(t *testing.T) {
	plugin := writePlugin(t, "sleep 30")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := kubeconfigClient(ctx, Credential{Value: execKubeconfig(plugin)}, "")
	if err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("err = %v after %s", err, time.Since(start))
	}
	if r := clientError(ctx, err); r.Outcome != Timeout {
		t.Fatalf("result = %+v, want timeout", r)
	}
}

// The plugin's token is handed to the client; a failing plugin is a
// credential that cannot be used, reported without its output.
func TestExecPluginCredential(t *testing.T) {
	ok := writePlugin(t, `echo '{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"tok"}}'`)
	if _, err := kubeconfigClient(context.Background(), Credential{Value: execKubeconfig(ok)}, ""); err != nil {
		t.Fatalf("token plugin: %v", err)
	}
	failing := writePlugin(t, "echo 'secret-in-stderr' >&2; exit 4")
	_, err := kubeconfigClient(context.Background(), Credential{Value: execKubeconfig(failing)}, "")
	r := clientError(context.Background(), err)
	if r.Outcome != AuthDenied || strings.Contains(r.Detail, "secret-in-stderr") || !strings.Contains(r.Detail, "status 4") {
		t.Fatalf("failing plugin: %+v", r)
	}
	empty := writePlugin(t, "echo '{}'")
	if _, err := kubeconfigClient(context.Background(), Credential{Value: execKubeconfig(empty)}, ""); clientError(context.Background(), err).Outcome != AuthDenied {
		t.Fatalf("plugin without a credential: %v", err)
	}
}

// A client-building error can quote the kubeconfig, credentials included;
// the reported detail never does.
func TestClientErrorsDoNotQuoteTheKubeconfig(t *testing.T) {
	kubeconfig := `apiVersion: v1
kind: Config
clusters:
- name: dev
  cluster: {server: "https://127.0.0.1:6443", proxy-url: "http://user:hunter2@[::1"}
users:
- name: probe
  user: {token: "tok-hunter2"}
contexts:
- name: dev
  context: {cluster: dev, user: probe}
current-context: dev
`
	_, err := kubeconfigClient(context.Background(), Credential{Value: kubeconfig}, "")
	r := clientError(context.Background(), err)
	if err == nil || strings.Contains(r.Detail, "hunter2") {
		t.Fatalf("err %v, detail %q", err, r.Detail)
	}
	r = kubeError(context.Background(), errors.New(`Get "http://user:hunter2@host": dial tcp: connection refused`), "GET x")
	if strings.Contains(r.Detail, "hunter2") {
		t.Fatalf("transport detail %q", r.Detail)
	}
}

// A plugin that asks for cluster information gets the cluster it
// authenticates to, and a plugin returning a token and a client certificate
// has both used.
func TestExecPluginClusterInfoAndBothCredentials(t *testing.T) {
	seen := filepath.Join(t.TempDir(), "exec-info.json")
	plugin := writePlugin(t, `printf '%s' "$KUBERNETES_EXEC_INFO" > `+seen+`
echo '{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"tok","clientCertificateData":"CERT","clientKeyData":"KEY"}}'`)
	cfg := &rest.Config{Host: "https://10.0.0.1:6443", TLSClientConfig: rest.TLSClientConfig{CAData: []byte("CA"), ServerName: "api.dev"},
		ExecProvider: &clientcmdapi.ExecConfig{Command: plugin, APIVersion: "client.authentication.k8s.io/v1", ProvideClusterInfo: true}}
	if err := applyExecCredential(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.BearerToken != "tok" || string(cfg.CertData) != "CERT" || string(cfg.KeyData) != "KEY" || cfg.ExecProvider != nil {
		t.Fatalf("config = token %q cert %q key %q exec %v", cfg.BearerToken, cfg.CertData, cfg.KeyData, cfg.ExecProvider)
	}
	b, err := os.ReadFile(seen)
	if err != nil {
		t.Fatal(err)
	}
	var info struct {
		Spec struct {
			Interactive bool `json:"interactive"`
			Cluster     *struct {
				Server string `json:"server"`
				Name   string `json:"tls-server-name"`
				CAData []byte `json:"certificate-authority-data"`
			} `json:"cluster"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(b, &info); err != nil {
		t.Fatalf("exec info %s: %v", b, err)
	}
	if info.Spec.Interactive || info.Spec.Cluster == nil || info.Spec.Cluster.Server != "https://10.0.0.1:6443" ||
		info.Spec.Cluster.Name != "api.dev" || string(info.Spec.Cluster.CAData) != "CA" {
		t.Fatalf("exec info = %s", b)
	}
	// Without provideClusterInfo no cluster is sent.
	cfg.ExecProvider = &clientcmdapi.ExecConfig{Command: plugin, APIVersion: "client.authentication.k8s.io/v1"}
	if err := applyExecCredential(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(seen); strings.Contains(string(b), "cluster") {
		t.Fatalf("cluster sent without being asked: %s", b)
	}
}
