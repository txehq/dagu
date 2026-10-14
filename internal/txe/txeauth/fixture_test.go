// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package txeauth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/internal/persis"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
)

const (
	testIssuer   = "https://issuer.example/realms/test"
	testAudience = "dagu-hub"
	testCLI      = "dagu-cli"
	testWorker   = "dagu-worker-a1"
	testKeyID    = "k1"
)

var testRSAKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

// memDAGs is the registry's DAG store, in memory.
type memDAGs struct {
	mu    sync.Mutex
	specs map[string][]byte
}

func (m *memDAGs) CheckSpec(_ context.Context, _ string, spec []byte) (registry.DAGFacts, error) {
	for line := range strings.SplitSeq(string(spec), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "txe.machine:"); ok {
			return registry.DAGFacts{WorkerSelector: map[string]string{"txe.machine": strings.TrimSpace(v)}}, nil
		}
	}
	return registry.DAGFacts{}, nil
}

func (m *memDAGs) SpecSHA256(_ context.Context, name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	spec, ok := m.specs[name]
	if !ok {
		return "", fmt.Errorf("dag %s: %w", name, persis.ErrNotFound)
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(spec)), nil
}

func (m *memDAGs) WriteSpec(_ context.Context, name string, spec []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.specs[name] = append([]byte(nil), spec...)
	return nil
}

// world is a registry with two owners. Owner A has a project, a machine and
// a job on it; owner B has only itself.
type world struct {
	ctx     context.Context
	dataDir string
	now     time.Time
	reg     *registry.Store
	ownerA  string
	ownerB  string
	project string
	machine string
	job     string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{ctx: context.Background(), dataDir: t.TempDir(), now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return w.now }
	reg, err := registry.NewFileStore(w.dataDir, registry.WithClock(clock), registry.WithDAGStore(&memDAGs{specs: map[string][]byte{}}))
	require.NoError(t, err)
	w.reg = reg
	id := func(p registry.Prefix) string {
		v, err := registry.NewID(p, w.now)
		require.NoError(t, err)
		return v
	}
	w.ownerA, w.ownerB = id(registry.PrefixOwner), id(registry.PrefixOwner)
	w.project, w.machine, w.job = id(registry.PrefixProject), id(registry.PrefixMachine), id(registry.PrefixJob)
	system := registry.Actor{Kind: registry.ActorSystem, ID: "test"}

	_, err = reg.CreateOwner(w.ctx, registry.Owner{OwnerID: w.ownerA, DisplayName: "Owner A"}, system)
	require.NoError(t, err)
	_, err = reg.CreateOwner(w.ctx, registry.Owner{OwnerID: w.ownerB, DisplayName: "Owner B"}, system)
	require.NoError(t, err)
	_, err = reg.CreateProject(w.ctx, registry.Project{ProjectID: w.project, OwnerID: w.ownerA, Key: "fixture"}, system)
	require.NoError(t, err)
	_, err = reg.CreateMachine(w.ctx, registry.Machine{MachineID: w.machine, OwnerID: w.ownerA, DisplayName: "laptop"}, system)
	require.NoError(t, err)
	_, err = reg.Register(w.ctx, registry.RegisterInput{
		JobID: w.job, RequestID: "req-1", OwnerID: w.ownerA, ProjectID: w.project, MachineID: w.machine, JobKey: "fixture",
		Version: registry.JobVersion{
			Title:   "Fixture",
			Purpose: "Test the owner lookups",
			Package: registry.Package{Digest: "sha256:" + strings.Repeat("a", 64), Path: "/var/txe/packages/fixture", Entrypoint: "run.sh"},
			DAG:     registry.DAGRef{Spec: "steps:\n  - run: ./run.sh\nworker_selector:\n  txe.machine: " + w.machine + "\n"},
			Targets: []registry.Target{{Kind: "k8s.pv", StableID: map[string]string{"uid": "pv-1"}}},
		},
	}, system)
	require.NoError(t, err)
	return w
}

// token signs an access token with the test key. Claims in over replace the
// defaults; a nil value removes one.
func token(t *testing.T, now time.Time, over map[string]any) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": testIssuer,
		"aud": testAudience,
		"azp": testCLI,
		"sub": "subject-a",
		"typ": "Bearer",
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
	for k, v := range over {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = testKeyID
	signed, err := tok.SignedString(testRSAKey())
	require.NoError(t, err)
	return signed
}
