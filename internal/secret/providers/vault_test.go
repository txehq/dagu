// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package providers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	secretref "github.com/dagucloud/dagu/v2/internal/secret/ref"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockVaultClient is a mock for vaultClient interface.
type MockVaultClient struct {
	ReadFunc       func(ctx context.Context, path string) (map[string]any, error)
	LookupSelfFunc func(ctx context.Context) (map[string]any, error)
}

func (m *MockVaultClient) Read(ctx context.Context, path string) (map[string]any, error) {
	if m.ReadFunc == nil {
		return nil, nil
	}
	return m.ReadFunc(ctx, path)
}

func (m *MockVaultClient) LookupSelf(ctx context.Context) (map[string]any, error) {
	if m.LookupSelfFunc == nil {
		return map[string]any{"display_name": "mock", "policies": []string{"default"}}, nil
	}
	return m.LookupSelfFunc(ctx)
}

func TestVaultResolver_Name(t *testing.T) {
	resolver := &vaultResolver{}
	assert.Equal(t, "vault", resolver.Name())
}

func TestVaultResolver_Validate(t *testing.T) {
	resolver := &vaultResolver{}

	t.Run("ValidReference", func(t *testing.T) {
		ref := secretref.Ref{
			Name:     "API_KEY",
			Provider: "vault",
			Key:      "secret/data/my-secret",
		}
		err := resolver.Validate(ref)
		require.NoError(t, err)
	})

	t.Run("EmptyKey", func(t *testing.T) {
		ref := secretref.Ref{
			Name:     "SECRET",
			Provider: "vault",
			Key:      "",
		}
		err := resolver.Validate(ref)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "key")
	})
}

func TestVaultResolver_Resolve(t *testing.T) {
	ctx := context.Background()

	t.Run("SuccessfulResolutionWithConvention", func(t *testing.T) {
		mockClient := &MockVaultClient{
			ReadFunc: func(_ context.Context, path string) (map[string]any, error) {
				if path == "kv/data/dummy" {
					return map[string]any{
						"data": map[string]any{
							"my-secret": "super-secret-value",
						},
					}, nil
				}
				return nil, fmt.Errorf("not found")
			},
		}

		resolver := &vaultResolver{client: mockClient}
		ref := secretref.Ref{
			Name:     "MY_API_KEY",
			Provider: "vault",
			Key:      "kv/data/dummy/my-secret",
		}

		value, err := resolver.Resolve(ctx, ref)
		require.NoError(t, err)
		assert.Equal(t, "super-secret-value", value)
	})

	t.Run("TrailingSlashHandling", func(t *testing.T) {
		mockClient := &MockVaultClient{
			ReadFunc: func(_ context.Context, path string) (map[string]any, error) {
				if path == "kv/data/dummy" {
					return map[string]any{
						"my-secret": "value-with-slash",
					}, nil
				}
				return nil, nil
			},
		}

		resolver := &vaultResolver{client: mockClient}
		ref := secretref.Ref{
			Name:     "MY_API_KEY",
			Provider: "vault",
			Key:      "kv/data/dummy/my-secret/",
		}

		value, err := resolver.Resolve(ctx, ref)
		require.NoError(t, err)
		assert.Equal(t, "value-with-slash", value)
	})

	t.Run("ExplicitFieldOption", func(t *testing.T) {
		mockClient := &MockVaultClient{
			ReadFunc: func(_ context.Context, path string) (map[string]any, error) {
				if path == "kv/data/dummy" {
					return map[string]any{
						"api_key": "v2-secret",
					}, nil
				}
				return nil, nil
			},
		}

		resolver := &vaultResolver{client: mockClient}
		ref := secretref.Ref{
			Name:     "MY_API_KEY",
			Provider: "vault",
			Key:      "kv/data/dummy",
			Options:  map[string]string{"field": "api_key"},
		}

		value, err := resolver.Resolve(ctx, ref)
		require.NoError(t, err)
		assert.Equal(t, "v2-secret", value)
	})

	t.Run("NotFound", func(t *testing.T) {
		mockClient := &MockVaultClient{
			ReadFunc: func(_ context.Context, _ string) (map[string]any, error) {
				return nil, nil
			},
		}

		resolver := &vaultResolver{client: mockClient}
		ref := secretref.Ref{
			Name:     "MY_SECRET",
			Provider: "vault",
			Key:      "kv/data/dummy/missing",
		}

		_, err := resolver.Resolve(ctx, ref)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("KV_V1_DataFieldAmbiguity", func(t *testing.T) {
		// Verify that if a KV v1 secret has a field named "data" that is NOT a map,
		// we don't try to unwrap it and instead treat it as a regular field.
		mockClient := &MockVaultClient{
			ReadFunc: func(_ context.Context, _ string) (map[string]any, error) {
				return map[string]any{
					"data": "actual-value",
				}, nil
			},
		}

		resolver := &vaultResolver{client: mockClient}
		ref := secretref.Ref{
			Name:     "TEST",
			Provider: "vault",
			Key:      "path/data", // Convention: path="path", field="data"
		}

		value, err := resolver.Resolve(ctx, ref)
		require.NoError(t, err)
		assert.Equal(t, "actual-value", value)
	})

	t.Run("DeepPathConvention", func(t *testing.T) {
		mockClient := &MockVaultClient{
			ReadFunc: func(_ context.Context, path string) (map[string]any, error) {
				if path == "projects/team-a/production/db" {
					return map[string]any{"password": "deep-secret"}, nil
				}
				return nil, nil
			},
		}

		resolver := &vaultResolver{client: mockClient}
		ref := secretref.Ref{
			Name:     "DB_PASS",
			Provider: "vault",
			Key:      "projects/team-a/production/db/password",
		}

		value, err := resolver.Resolve(ctx, ref)
		require.NoError(t, err)
		assert.Equal(t, "deep-secret", value)
	})
}

func TestVaultResolver_Concurrency(t *testing.T) {
	ctx := context.Background()
	mockClient := &MockVaultClient{
		ReadFunc: func(_ context.Context, _ string) (map[string]any, error) {
			return map[string]any{"value": "ok"}, nil
		},
	}

	resolver := &vaultResolver{client: mockClient}
	ref := secretref.Ref{
		Name:     "CONCURRENT",
		Provider: "vault",
		Key:      "path/value",
	}

	const numRoutines = 50
	done := make(chan bool, numRoutines)

	for range numRoutines {
		go func() {
			_, err := resolver.Resolve(ctx, ref)
			assert.NoError(t, err)
			done <- true
		}()
	}

	for range numRoutines {
		<-done
	}
}

func TestVaultResolver_CheckAccessibility(t *testing.T) {
	ctx := context.Background()

	t.Run("Accessible", func(t *testing.T) {
		mockClient := &MockVaultClient{
			LookupSelfFunc: func(_ context.Context) (map[string]any, error) {
				return map[string]any{"id": "token"}, nil
			},
			ReadFunc: func(_ context.Context, _ string) (map[string]any, error) {
				return map[string]any{"field": "exists"}, nil
			},
		}

		resolver := &vaultResolver{client: mockClient}
		ref := secretref.Ref{
			Name:     "TEST",
			Provider: "vault",
			Key:      "path/field",
		}

		err := resolver.CheckAccessibility(ctx, ref)
		require.NoError(t, err)
	})

	t.Run("TokenInvalid", func(t *testing.T) {
		mockClient := &MockVaultClient{
			LookupSelfFunc: func(_ context.Context) (map[string]any, error) {
				return nil, fmt.Errorf("permission denied")
			},
		}

		resolver := &vaultResolver{client: mockClient}
		ref := secretref.Ref{
			Name:     "TEST",
			Provider: "vault",
			Key:      "path/field",
		}

		err := resolver.CheckAccessibility(ctx, ref)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token lookup failed")
	})
}

func TestVaultResolver_resolveClientSettings(t *testing.T) {
	t.Run("DefaultsWithoutConfig", func(t *testing.T) {
		resolver := &vaultResolver{}

		settings := resolver.resolveClientSettings(context.Background(), secretref.Ref{})

		assert.Empty(t, settings.address)
		assert.Empty(t, settings.token)
	})

	t.Run("ConfigOnly", func(t *testing.T) {
		resolver := &vaultResolver{}
		ctx := config.WithConfig(context.Background(), &config.Config{
			Secrets: config.SecretsConfig{
				Vault: config.VaultSecretsConfig{
					Address: "https://vault.example.com",
					Token:   "config-token",
				},
			},
		})

		settings := resolver.resolveClientSettings(ctx, secretref.Ref{})

		assert.Equal(t, "https://vault.example.com", settings.address)
		assert.Equal(t, "config-token", settings.token)
	})

	t.Run("OptionsOverridePerField", func(t *testing.T) {
		resolver := &vaultResolver{}
		ctx := config.WithConfig(context.Background(), &config.Config{
			Secrets: config.SecretsConfig{
				Vault: config.VaultSecretsConfig{
					Address: "https://vault.example.com",
					Token:   "config-token",
				},
			},
		})
		ref := secretref.Ref{
			Options: map[string]string{
				"vault_address": "https://override.example.com",
			},
		}

		settings := resolver.resolveClientSettings(ctx, ref)

		// The host's token is for the host's Vault: a DAG that names
		// another address gets none of the host's credentials.
		assert.Equal(t, "https://override.example.com", settings.address)
		assert.Empty(t, settings.token)
		assert.True(t, settings.foreign)

		ref.Options["vault_token"] = "dag-token"
		settings = resolver.resolveClientSettings(ctx, ref)
		assert.Equal(t, "dag-token", settings.token, "a DAG may bring its own token to its own Vault")

		// The host's own address, written by the DAG, is not another Vault.
		ref.Options = map[string]string{"vault_address": "https://vault.example.com/"}
		settings = resolver.resolveClientSettings(ctx, ref)
		assert.Equal(t, "config-token", settings.token)
		assert.False(t, settings.foreign)
	})

	t.Run("HostClientCertificateStaysWithTheHostsVault", func(t *testing.T) {
		resolver := &vaultResolver{}
		ctx := config.WithConfig(context.Background(), &config.Config{
			Secrets: config.SecretsConfig{
				Vault: config.VaultSecretsConfig{
					Address:    "https://vault.example.com",
					ClientCert: "/path/to/client.pem",
					ClientKey:  "/path/to/client-key.pem",
					CACert:     "/path/to/ca.pem",
				},
			},
		})
		ref := secretref.Ref{Options: map[string]string{"vault_address": "https://override.example.com"}}

		settings := resolver.resolveClientSettings(ctx, ref)

		assert.Empty(t, settings.clientCert, "the host's client certificate is its credential")
		assert.Empty(t, settings.clientKey)
		assert.Equal(t, "/path/to/ca.pem", settings.caCert, "trust is not a credential")
	})

	t.Run("TLSFromConfig", func(t *testing.T) {
		resolver := &vaultResolver{}
		ctx := config.WithConfig(context.Background(), &config.Config{
			Secrets: config.SecretsConfig{
				Vault: config.VaultSecretsConfig{
					Address:    "https://vault.example.com",
					Token:      "config-token",
					CACert:     "/path/to/ca.pem",
					ClientCert: "/path/to/client.pem",
					ClientKey:  "/path/to/client-key.pem",
				},
			},
		})

		settings := resolver.resolveClientSettings(ctx, secretref.Ref{})

		assert.Equal(t, "/path/to/ca.pem", settings.caCert)
		assert.Equal(t, "/path/to/client.pem", settings.clientCert)
		assert.Equal(t, "/path/to/client-key.pem", settings.clientKey)
	})

	t.Run("TLSOptionsOverride", func(t *testing.T) {
		resolver := &vaultResolver{}
		ctx := config.WithConfig(context.Background(), &config.Config{
			Secrets: config.SecretsConfig{
				Vault: config.VaultSecretsConfig{
					Address: "https://vault.example.com",
					CACert:  "/path/to/ca.pem",
				},
			},
		})
		ref := secretref.Ref{
			Options: map[string]string{
				"vault_ca_cert":     "/other/ca.pem",
				"vault_client_cert": "/other/client.pem",
				"vault_client_key":  "/other/client-key.pem",
			},
		}

		settings := resolver.resolveClientSettings(ctx, ref)

		assert.Equal(t, "/other/ca.pem", settings.caCert)
		assert.Equal(t, "/other/client.pem", settings.clientCert)
		assert.Equal(t, "/other/client-key.pem", settings.clientKey)
	})
}

// Without Dagu settings, the resolver reaches the server and token named by
// the standard VAULT_ADDR and VAULT_TOKEN variables. Dagu settings win, and a
// Dagu address also wins over a Vault agent named by VAULT_AGENT_ADDR.
func TestVaultResolver_Resolve_StandardEnvironment(t *testing.T) {
	var gotToken atomic.Value
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken.Store(r.Header.Get("X-Vault-Token"))
		if r.URL.Path != "/v1/kv/data/app" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"data":{"password":"s3cret"}}}`))
	}))
	defer server.Close()
	t.Setenv("VAULT_ADDR", server.URL)
	t.Setenv("VAULT_TOKEN", "env-token")
	t.Setenv("VAULT_AGENT_ADDR", "")
	ref := secretref.Ref{Name: "DB_PASSWORD", Key: "kv/data/app/password"}

	value, err := (&vaultResolver{}).Resolve(context.Background(), ref)
	require.NoError(t, err)
	assert.Equal(t, "s3cret", value)
	assert.Equal(t, "env-token", gotToken.Load())

	ctx := config.WithConfig(context.Background(), &config.Config{
		Secrets: config.SecretsConfig{
			Vault: config.VaultSecretsConfig{Token: "config-token"},
		},
	})
	value, err = (&vaultResolver{}).Resolve(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, "s3cret", value)
	assert.Equal(t, "config-token", gotToken.Load())

	var agentCalled atomic.Bool
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		agentCalled.Store(true)
		http.Error(w, "unexpected agent request", http.StatusBadGateway)
	}))
	defer agent.Close()
	t.Setenv("VAULT_AGENT_ADDR", agent.URL)
	ctx = config.WithConfig(context.Background(), &config.Config{
		Secrets: config.SecretsConfig{
			Vault: config.VaultSecretsConfig{Address: server.URL},
		},
	})
	value, err = (&vaultResolver{}).Resolve(ctx, ref)
	require.NoError(t, err)
	assert.Equal(t, "s3cret", value)
	assert.False(t, agentCalled.Load())
}

// A DAG can name its own Vault address (secrets[].options.vault_address). The
// host's credentials, its configured token and client certificate and the
// ambient VAULT_TOKEN of the process, are for the host's own Vault, and are
// never sent to an address the DAG chose: there the client carries only what
// the DAG itself gave.
func TestVaultResolver_HostCredentialsStayWithTheHostsVault(t *testing.T) {
	serve := func(t *testing.T) (*httptest.Server, *atomic.Value) {
		t.Helper()
		var token atomic.Value
		token.Store("")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token.Store(r.Header.Get("X-Vault-Token"))
			_, _ = w.Write([]byte(`{"data":{"data":{"password":"s3cret"}}}`))
		}))
		t.Cleanup(server.Close)
		return server, &token
	}
	host, hostToken := serve(t)
	other, otherToken := serve(t)
	t.Setenv("VAULT_ADDR", host.URL)
	t.Setenv("VAULT_TOKEN", "ambient-token")
	t.Setenv("VAULT_AGENT_ADDR", "")
	ref := func(options map[string]string) secretref.Ref {
		return secretref.Ref{Name: "DB_PASSWORD", Key: "kv/data/app/password", Options: options}
	}

	// The host's own Vault gets the ambient token.
	_, err := (&vaultResolver{}).Resolve(context.Background(), ref(nil))
	require.NoError(t, err)
	assert.Equal(t, "ambient-token", hostToken.Load())

	// Another Vault the DAG names gets no token of the host's.
	_, _ = (&vaultResolver{}).Resolve(context.Background(), ref(map[string]string{"vault_address": other.URL}))
	assert.Empty(t, otherToken.Load(), "the ambient token never reaches an address the DAG chose")

	ctx := config.WithConfig(context.Background(), &config.Config{
		Secrets: config.SecretsConfig{Vault: config.VaultSecretsConfig{Address: host.URL, Token: "config-token"}},
	})
	otherToken.Store("")
	_, _ = (&vaultResolver{}).Resolve(ctx, ref(map[string]string{"vault_address": other.URL}))
	assert.Empty(t, otherToken.Load(), "the configured token never reaches an address the DAG chose")

	// The DAG's own token goes to the DAG's own Vault.
	_, err = (&vaultResolver{}).Resolve(ctx, ref(map[string]string{"vault_address": other.URL, "vault_token": "dag-token"}))
	require.NoError(t, err)
	assert.Equal(t, "dag-token", otherToken.Load())

	// Naming the host's own address is not another Vault.
	hostToken.Store("")
	_, err = (&vaultResolver{}).Resolve(ctx, ref(map[string]string{"vault_address": host.URL + "/"}))
	require.NoError(t, err)
	assert.Equal(t, "config-token", hostToken.Load())
}

func TestVaultResolver_getClient_CachesByResolvedSettings(t *testing.T) {
	var created []vaultClientSettings

	resolver := &vaultResolver{
		clientFactory: func(settings vaultClientSettings) (vaultClient, error) {
			created = append(created, settings)
			return &MockVaultClient{}, nil
		},
	}
	ctx := config.WithConfig(context.Background(), &config.Config{
		Secrets: config.SecretsConfig{
			Vault: config.VaultSecretsConfig{
				Address: "https://vault.example.com",
				Token:   "config-token",
			},
		},
	})
	ref := secretref.Ref{Name: "TEST", Provider: "vault", Key: "path/value"}

	client1, err := resolver.getClient(ctx, ref)
	require.NoError(t, err)
	client2, err := resolver.getClient(ctx, ref)
	require.NoError(t, err)
	assert.Same(t, client1, client2)
	require.Len(t, created, 1)
	assert.Equal(t, vaultClientSettings{
		address: "https://vault.example.com",
		token:   "config-token",
	}, created[0])

	overrideRef := secretref.Ref{
		Name:     "TEST",
		Provider: "vault",
		Key:      "path/value",
		Options: map[string]string{
			"vault_token": "override-token",
		},
	}

	client3, err := resolver.getClient(ctx, overrideRef)
	require.NoError(t, err)
	assert.NotSame(t, client1, client3)
	require.Len(t, created, 2)
	assert.Equal(t, vaultClientSettings{
		address: "https://vault.example.com",
		token:   "override-token",
	}, created[1])
}

func TestVaultResolver_CheckAccessibility_UsesMergedSettingsPath(t *testing.T) {
	var created []vaultClientSettings

	mockClient := &MockVaultClient{
		LookupSelfFunc: func(_ context.Context) (map[string]any, error) {
			return map[string]any{"id": "token"}, nil
		},
		ReadFunc: func(_ context.Context, _ string) (map[string]any, error) {
			return map[string]any{"value": "exists"}, nil
		},
	}
	resolver := &vaultResolver{
		clientFactory: func(settings vaultClientSettings) (vaultClient, error) {
			created = append(created, settings)
			return mockClient, nil
		},
	}
	ctx := config.WithConfig(context.Background(), &config.Config{
		Secrets: config.SecretsConfig{
			Vault: config.VaultSecretsConfig{
				Address: "https://vault.example.com",
				Token:   "config-token",
			},
		},
	})
	ref := secretref.Ref{
		Name:     "TEST",
		Provider: "vault",
		Key:      "path/value",
		Options: map[string]string{
			"vault_token": "override-token",
		},
	}

	err := resolver.CheckAccessibility(ctx, ref)
	require.NoError(t, err)
	require.Len(t, created, 1)
	assert.Equal(t, vaultClientSettings{
		address: "https://vault.example.com",
		token:   "override-token",
	}, created[0])
}
