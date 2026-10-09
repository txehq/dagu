// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"os/exec"
	"syscall"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/dagucloud/dagu/v2/internal/txe/target"
)

// Kubernetes target constants, as package target defines them.
const (
	KubernetesKindPrefix        = target.KubernetesKindPrefix
	KeyClusterUID               = target.KeyClusterUID
	KeyUID                      = target.KeyUID
	KubernetesCredential        = target.KubernetesCredential
	KubernetesContextCredential = target.KubernetesContextCredential
)

var namespacesGVR = schema.GroupVersionResource{Version: "v1", Resource: "namespaces"}

// KubeClientFactory builds a client from a kubeconfig credential (a file
// path, or the kubeconfig's content as a resolved secret) and an optional
// context name, within ctx.
type KubeClientFactory func(ctx context.Context, kubeconfig Credential, contextName string) (dynamic.Interface, error)

// Kubernetes probes Kubernetes objects.
type Kubernetes struct {
	// NewClient defaults to a client built from the kubeconfig.
	NewClient KubeClientFactory
}

func (Kubernetes) Supports(kind string) bool {
	_, ok := target.LookupKube(kind)
	return ok
}

// Probe first proves the client reaches the cluster the target names (the
// kube-system namespace's UID is the cluster's identity); only then is a
// NotFound evidence that the object is gone. The object found by name must
// carry the target's UID exactly; another UID is the same name on a new
// object. Errors are reported by category, never verbatim, since a client
// error can quote a kubeconfig's credentials.
func (k Kubernetes) Probe(ctx context.Context, t Target, creds Credentials) Result {
	kind, _ := target.LookupKube(t.Kind)
	clusterUID, uid := t.StableID[KeyClusterUID], t.StableID[KeyUID]
	namespace, name, ok := target.ParseKubeLocator(t.DisplayName, kind.Namespaced)
	if clusterUID == "" || uid == "" || !ok {
		return Result{Outcome: Unknown, Detail: "target does not name a Kubernetes object exactly; not guessed"}
	}
	cred, ok := creds.Lookup(KubernetesCredential)
	if !ok || (cred.Path == "" && cred.Value == "") {
		return noCredential(creds, KubernetesCredential)
	}
	contextName := ""
	if c, ok := creds.Lookup(KubernetesContextCredential); ok {
		contextName = trimmed(c.Value)
	}
	newClient := k.NewClient
	if newClient == nil {
		newClient = kubeconfigClient
	}
	client, err := newClient(ctx, cred, contextName)
	if err != nil {
		return clientError(ctx, err)
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

	gvr := schema.GroupVersionResource{Group: kind.Group, Version: kind.Version, Resource: kind.Resource}
	ri := client.Resource(gvr)
	var getter dynamic.ResourceInterface = ri
	ref := kind.Resource + "/" + name
	if kind.Namespaced {
		getter = ri.Namespace(namespace)
		ref = kind.Resource + "/" + namespace + "/" + name
	}
	found, err := getter.Get(ctx, name, metav1.GetOptions{})
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

// errNoCredential marks a kubeconfig that holds no usable credential.
var errNoCredential = errors.New("no usable credential")

// clientError reports a failure to build a client without quoting it.
func clientError(ctx context.Context, err error) Result {
	switch {
	case errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil:
		return Result{Outcome: Timeout, Detail: "acquiring the Kubernetes credential took too long"}
	case errors.Is(err, errNoCredential):
		return Result{Outcome: AuthDenied, Detail: "the kubeconfig's credential cannot be used: " + err.Error()}
	}
	return Result{Outcome: Unreachable, Detail: "the kubeconfig could not be used to build a client"}
}

// kubeError maps an API or transport error to what it allows, by category.
func kubeError(ctx context.Context, err error, what string) Result {
	if status, ok := errors.AsType[*apierrors.StatusError](err); ok {
		s := status.ErrStatus
		detail := fmt.Sprintf("%s: HTTP %d %s", what, s.Code, s.Reason)
		switch {
		case apierrors.IsUnauthorized(err) || apierrors.IsForbidden(err):
			return Result{Outcome: AuthDenied, Detail: detail}
		case apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err):
			return Result{Outcome: Timeout, Detail: detail}
		}
		return Result{Outcome: Unreachable, Detail: detail}
	}
	outcome := classify(ctx, err)
	return Result{Outcome: outcome, Detail: what + ": " + transportCategory(outcome, err)}
}

// transportCategory names what kind of transport failure err is, without
// its text.
func transportCategory(outcome Outcome, err error) string {
	var dns *net.DNSError
	var unknownCA x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var record tls.RecordHeaderError
	switch {
	case outcome == Timeout:
		return "timed out"
	case errors.As(err, &dns):
		return "the server's name did not resolve"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.As(err, &unknownCA), errors.As(err, &hostname), errors.As(err, &invalid), errors.As(err, &record):
		return "TLS verification failed"
	}
	return "the request failed"
}

// kubeconfigClient builds a client from the kubeconfig. A background check
// must never wait for someone to log in, so an exec credential plugin is run
// here, non-interactively and within ctx, and its credential handed to the
// client; client-go would run it without a deadline. Legacy auth providers
// are refused.
func kubeconfigClient(ctx context.Context, kubeconfig Credential, contextName string) (dynamic.Interface, error) {
	overrides := &clientcmd.ConfigOverrides{CurrentContext: contextName}
	var loader clientcmd.ClientConfig
	if kubeconfig.Path != "" {
		rules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig.Path}
		loader = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	} else {
		raw, err := clientcmd.Load([]byte(kubeconfig.Value))
		if err != nil {
			return nil, errors.New("parse kubeconfig")
		}
		loader = clientcmd.NewNonInteractiveClientConfig(*raw, contextName, overrides, nil)
	}
	cfg, err := loader.ClientConfig()
	if err != nil {
		return nil, errors.New("resolve kubeconfig")
	}
	if cfg.AuthProvider != nil {
		return nil, fmt.Errorf("%w: auth provider %q is not supported; use an exec plugin or a token", errNoCredential, cfg.AuthProvider.Name)
	}
	if cfg.ExecProvider != nil {
		if err := applyExecCredential(ctx, cfg); err != nil {
			return nil, err
		}
	}
	cfg.Timeout = requestTimeout
	return dynamic.NewForConfig(cfg)
}

// execCredential is the output of a client-go exec credential plugin.
type execCredential struct {
	Status *struct {
		Token                 string `json:"token"`
		ClientCertificateData string `json:"clientCertificateData"`
		ClientKeyData         string `json:"clientKeyData"`
	} `json:"status"`
}

// applyExecCredential runs cfg's exec plugin under ctx and puts the
// credential it prints into cfg in place of the plugin.
func applyExecCredential(ctx context.Context, cfg *rest.Config) error {
	ec := cfg.ExecProvider
	spec := map[string]any{"interactive": false}
	if ec.ProvideClusterInfo {
		// The plugin asked for the cluster it authenticates to: send it as
		// client-go would, including the cluster's exec extension.
		cluster, err := execCluster(cfg)
		if err != nil {
			return fmt.Errorf("%w: the cluster information for the credential plugin could not be read", errNoCredential)
		}
		spec["cluster"] = cluster
	}
	info, _ := json.Marshal(map[string]any{"apiVersion": ec.APIVersion, "kind": "ExecCredential", "spec": spec})
	cmd := exec.CommandContext(ctx, ec.Command, ec.Args...) //nolint:gosec // the plugin the machine's own kubeconfig names
	cmd.Env = append(os.Environ(), "KUBERNETES_EXEC_INFO="+string(info))
	for _, e := range ec.Env {
		cmd.Env = append(cmd.Env, e.Name+"="+e.Value)
	}
	cmd.Stdin = nil
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	var out bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &out, n: maxCredentialBytes}
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return context.DeadlineExceeded
		}
		if exit, ok := errors.AsType[*exec.ExitError](err); ok {
			return fmt.Errorf("%w: the credential plugin exited with status %d (it may need an interactive login)", errNoCredential, exit.ExitCode())
		}
		return fmt.Errorf("%w: the credential plugin could not run", errNoCredential)
	}
	var cred execCredential
	if err := json.Unmarshal(out.Bytes(), &cred); err != nil || cred.Status == nil {
		return fmt.Errorf("%w: the credential plugin printed no credential", errNoCredential)
	}
	// A plugin may return a token, a client certificate, or both, as
	// client-go allows; both are used when both are given.
	hasCert := cred.Status.ClientCertificateData != "" && cred.Status.ClientKeyData != ""
	if cred.Status.Token == "" && !hasCert {
		return fmt.Errorf("%w: the credential plugin printed no token or certificate", errNoCredential)
	}
	if cred.Status.Token != "" {
		cfg.BearerToken = cred.Status.Token
	}
	if hasCert {
		cfg.CertData, cfg.KeyData = []byte(cred.Status.ClientCertificateData), []byte(cred.Status.ClientKeyData)
	}
	cfg.ExecProvider = nil
	return nil
}

// execCluster is the spec.cluster client-go sends an exec plugin that asks
// for cluster information, in the plugin API's JSON field names.
func execCluster(cfg *rest.Config) (map[string]any, error) {
	c, err := rest.ConfigToExecCluster(cfg)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"server": c.Server}
	if c.TLSServerName != "" {
		out["tls-server-name"] = c.TLSServerName
	}
	if c.InsecureSkipTLSVerify {
		out["insecure-skip-tls-verify"] = true
	}
	if len(c.CertificateAuthorityData) > 0 {
		out["certificate-authority-data"] = c.CertificateAuthorityData
	}
	if c.ProxyURL != "" {
		out["proxy-url"] = c.ProxyURL
	}
	if c.DisableCompression {
		out["disable-compression"] = true
	}
	if c.Config != nil {
		raw, err := extensionJSON(c.Config)
		if err != nil {
			return nil, err
		}
		out["config"] = raw
	}
	return out, nil
}

// extensionJSON is a kubeconfig extension object as raw JSON.
func extensionJSON(obj runtime.Object) (json.RawMessage, error) {
	if u, ok := obj.(*runtime.Unknown); ok {
		return json.RawMessage(u.Raw), nil
	}
	b, err := json.Marshal(obj)
	return json.RawMessage(b), err
}

// limitedWriter keeps at most n bytes and drops the rest.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	keep := p
	if len(keep) > l.n {
		keep = keep[:l.n]
	}
	l.n -= len(keep)
	if _, err := l.w.Write(keep); err != nil {
		return 0, err
	}
	return len(p), nil
}
