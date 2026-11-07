// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package providers

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	secretref "github.com/dagucloud/dagu/v2/internal/secret/ref"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const vaultSecretBody = `{"data":{"data":{"password":"s3cret"}}}`

func vaultRef(options map[string]string) secretref.Ref {
	return secretref.Ref{Name: "DB_PASSWORD", Key: "kv/data/app/password", Options: options}
}

// recordingVault is a Vault server that keeps every token it was sent.
type recordingVault struct {
	*httptest.Server
	mu     sync.Mutex
	tokens []string
}

func (v *recordingVault) seen() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.tokens...)
}

func newRecordingVault(t *testing.T, answer http.HandlerFunc) *recordingVault {
	t.Helper()
	v := &recordingVault{}
	v.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v.mu.Lock()
		v.tokens = append(v.tokens, r.Header.Get("X-Vault-Token"))
		v.mu.Unlock()
		if answer != nil {
			answer(w, r)
			return
		}
		_, _ = w.Write([]byte(vaultSecretBody))
	}))
	t.Cleanup(v.Close)
	return v
}

// The Vault client follows a redirect itself, with the same token. A redirect
// to another server is refused, so the host's token never reaches it; a
// redirect within the same server is followed. The refusal names no address.
func TestVaultRedirectKeepsTheTokenWithItsServer(t *testing.T) {
	other := newRecordingVault(t, nil)
	host := newRecordingVault(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/kv/data/app":
			http.Redirect(w, r, other.URL+"/v1/kv/data/app?token=ambient-token", http.StatusTemporaryRedirect)
		case "/v1/kv/data/moved":
			http.Redirect(w, r, "/v1/kv/data/app2", http.StatusTemporaryRedirect)
		default:
			_, _ = w.Write([]byte(vaultSecretBody))
		}
	})
	t.Setenv("VAULT_ADDR", host.URL)
	t.Setenv("VAULT_TOKEN", "ambient-token")
	t.Setenv("VAULT_AGENT_ADDR", "")

	_, err := (&vaultResolver{}).Resolve(context.Background(), vaultRef(nil))
	require.Error(t, err, "a redirect to another server is refused")
	assert.NotContains(t, err.Error(), "ambient-token")
	assert.NotContains(t, err.Error(), other.URL)
	assert.Empty(t, other.seen(), "the token never reaches the server the redirect named")

	value, err := (&vaultResolver{}).Resolve(context.Background(), secretref.Ref{Name: "X", Key: "kv/data/moved/password"})
	require.NoError(t, err, "a redirect within the same server is followed")
	assert.Equal(t, "s3cret", value)
}

// Whether a DAG's address is the host's own is decided on the canonical
// address, and anything unusual is another server, keeping the host's
// credentials back.
func TestSameVaultAddressIsCanonicalAndFailsClosed(t *testing.T) {
	t.Parallel()
	host := "https://vault.example.com"
	for _, same := range []string{
		"https://vault.example.com",
		"https://vault.example.com/",
		"HTTPS://Vault.Example.com",
		"https://vault.example.com:443",
		" https://vault.example.com/ ",
	} {
		assert.True(t, sameVaultAddress(same, host), same)
	}
	for _, other := range []string{
		"http://vault.example.com",
		"https://vault.example.com:8200",
		"https://vault.example.com.evil.test",
		"https://vault.example.com@evil.test",
		"https://user@vault.example.com",
		"https://vault.example.com/other",
		"https://vault.example.com/?x=1",
		"https://vault.example.com/#f",
		"ftp://vault.example.com",
		"vault.example.com",
		"https://",
		"::",
		"",
	} {
		assert.False(t, sameVaultAddress(other, host), other)
	}
	assert.True(t, sameVaultAddress("http://127.0.0.1:8200/", "http://127.0.0.1:8200"))
	assert.False(t, sameVaultAddress("http://127.0.0.1:8200", "http://localhost:8200"), "another spelling of a host is another server")
}

// Host and DAG clients resolve side by side without sharing credentials: the
// clearing is the client's own, never the process environment's.
func TestVaultHostAndDAGClientsDoNotShareCredentials(t *testing.T) {
	host := newRecordingVault(t, nil)
	other := newRecordingVault(t, nil)
	t.Setenv("VAULT_ADDR", host.URL)
	t.Setenv("VAULT_TOKEN", "ambient-token")
	t.Setenv("VAULT_AGENT_ADDR", "")

	resolver := &vaultResolver{}
	var wg sync.WaitGroup
	var failures atomic.Int64
	for i := range 40 {
		wg.Go(func() {
			ref := vaultRef(nil)
			if i%2 == 1 {
				ref = vaultRef(map[string]string{"vault_address": other.URL})
			}
			if _, err := resolver.Resolve(context.Background(), ref); err != nil {
				failures.Add(1)
			}
		})
	}
	wg.Wait()
	assert.Zero(t, failures.Load())
	assert.Equal(t, "ambient-token", os.Getenv("VAULT_TOKEN"), "the process environment is untouched")
	for _, token := range host.seen() {
		assert.Equal(t, "ambient-token", token)
	}
	for _, token := range other.seen() {
		assert.Empty(t, token, "the DAG's server never sees the host's token")
	}
	assert.NotEmpty(t, host.seen())
	assert.NotEmpty(t, other.seen())
}

// The process environment's client certificate (VAULT_CLIENT_CERT and
// VAULT_CLIENT_KEY) is the host's credential: it is presented to the host's
// Vault and not to one a DAG names. The environment's CA trust is kept for
// both.
func TestVaultEnvironmentClientCertificateStaysWithTheHostsVault(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeClientCertificate(t, dir)

	tlsVault := func() (*httptest.Server, *atomic.Int64) {
		var presented atomic.Int64
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				presented.Add(1)
			}
			_, _ = w.Write([]byte(vaultSecretBody))
		}))
		server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
		server.StartTLS()
		t.Cleanup(server.Close)
		return server, &presented
	}
	host, hostPresented := tlsVault()
	other, otherPresented := tlsVault()
	caFile := filepath.Join(dir, "ca.pem")
	require.NoError(t, os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: host.Certificate().Raw}), 0o600))

	t.Setenv("VAULT_ADDR", host.URL)
	t.Setenv("VAULT_TOKEN", "ambient-token")
	t.Setenv("VAULT_AGENT_ADDR", "")
	t.Setenv("VAULT_CACERT", caFile)
	t.Setenv("VAULT_CLIENT_CERT", certFile)
	t.Setenv("VAULT_CLIENT_KEY", keyFile)

	_, err := (&vaultResolver{}).Resolve(context.Background(), vaultRef(nil))
	require.NoError(t, err)
	assert.Positive(t, hostPresented.Load(), "the host's Vault gets the host's client certificate")

	_, err = (&vaultResolver{}).Resolve(context.Background(), vaultRef(map[string]string{"vault_address": other.URL}))
	require.NoError(t, err, "the environment's CA trust still holds for the DAG's Vault")
	assert.Zero(t, otherPresented.Load(), "the DAG's Vault never gets the host's client certificate")
}

func writeClientCertificate(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dagu-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	certFile := filepath.Join(dir, "client.pem")
	keyFile := filepath.Join(dir, "client-key.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return certFile, keyFile
}
