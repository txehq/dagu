// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package distr_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/service/worker"
	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// This file runs a real scheduler, coordinator and worker with the
// coordinator authenticating every call (enforce). The identity provider is a
// synthetic one in this process: tokens are signed here and verified with
// its public key. No real provider, credential or network service is used.

const (
	refusalIssuer   = "https://issuer.invalid/realms/synthetic"
	refusalAudience = "dagu-hub"
	refusalSubject  = "synthetic-owner"
)

type tokenSourceFunc func(context.Context) (string, error)

func (f tokenSourceFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

type refusalAuth struct {
	config  *transportAuthConfig
	machine string
	revoke  func()
}

// newRefusalAuth makes an owner and a machine, binds the owner's identity,
// enrols the machine's worker client, and returns the coordinator options
// and the hub's and the worker's credentials.
func newRefusalAuth(t *testing.T) *refusalAuth {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	keys := authn.StaticKeys{"k1": {Public: &key.PublicKey, Algorithm: "RS256"}}

	reg, err := registry.NewFileStore(dir)
	require.NoError(t, err)
	owner, err := registry.NewID(registry.PrefixOwner, time.Now())
	require.NoError(t, err)
	machine, err := registry.NewID(registry.PrefixMachine, time.Now())
	require.NoError(t, err)
	by := registry.Actor{Kind: registry.ActorSystem, ID: "test"}
	_, err = reg.CreateOwner(ctx, registry.Owner{OwnerID: owner, DisplayName: "Owner"}, by)
	require.NoError(t, err)
	_, err = reg.CreateMachine(ctx, registry.Machine{MachineID: machine, OwnerID: owner, DisplayName: "Worker"}, by)
	require.NoError(t, err)

	client := "dagu-worker-" + machine
	svc, err := txeauth.NewService(config.TXEConfig{Authn: config.TXEAuthnConfig{
		Issuer: refusalIssuer, Audience: refusalAudience, JWKSURL: "https://issuer.invalid/unused",
		Clients: []config.TXEAuthnClient{{ID: client, Class: "worker"}},
	}}, dir, reg, txeauth.WithKeySource(keys))
	require.NoError(t, err)

	sign := func() (string, error) {
		now := time.Now().Truncate(time.Second)
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss": refusalIssuer, "sub": refusalSubject, "aud": refusalAudience, "azp": client,
			"typ": "Bearer", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		})
		tok.Header["kid"] = "k1"
		return tok.SignedString(key)
	}

	person := authn.Principal{Identity: authn.Identity{Issuer: refusalIssuer, Subject: refusalSubject}, Class: authn.ClassPerson}
	_, err = svc.Store().RequestBinding(ctx, person, authz.Shown{Username: "owner"})
	require.NoError(t, err)
	_, err = svc.Store().ApproveBinding(ctx, authz.PlatformAdmin("admin"), person.Identity, owner)
	require.NoError(t, err)
	scope, err := svc.Store().Resolve(ctx, person)
	require.NoError(t, err)
	token, err := sign()
	require.NoError(t, err)
	credential, err := svc.Verify(ctx, token)
	require.NoError(t, err)
	_, err = svc.Store().Enrol(ctx, scope, authz.EnrolmentRequest{MachineID: machine, Credential: credential})
	require.NoError(t, err)

	random := make([]byte, 32)
	_, err = rand.Read(random)
	require.NoError(t, err)
	hubKey := []byte(hex.EncodeToString(random))
	server, err := transportauth.NewServer(transportauth.ServerConfig{
		Mode: authz.ModeEnforce, Verifier: svc, Machines: svc.Store(), HubKey: hubKey,
	})
	require.NoError(t, err)

	return &refusalAuth{
		config: &transportAuthConfig{
			serverOptions: []grpc.ServerOption{
				grpc.ChainUnaryInterceptor(server.UnaryInterceptor()),
				grpc.ChainStreamInterceptor(server.StreamInterceptor()),
			},
			hub:      transportauth.NewHubCredentials(hubKey),
			worker:   transportauth.NewWorkerCredentials(tokenSourceFunc(func(context.Context) (string, error) { return sign() })),
			workerID: machine,
		},
		machine: machine,
		revoke: func() {
			_, err := svc.Store().RevokeEnrolment(ctx, scope, machine, authn.ClassWorker, "test: machine removed")
			require.NoError(t, err)
		},
	}
}

// A worker whose enrolment is revoked while it runs a step stops that step
// within RefusedCallsStopAfter of the coordinator's first refusal, and not
// before the documented threshold. Measured with the real constant: the step
// writes the time every second, and the test reads when it stopped.
func TestRefusedWorkerStopsItsRunningStepWithinTheBound(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses a POSIX shell loop")
	}
	if testing.Short() {
		t.Skip("waits for the real 60 s bound")
	}
	auth := newRefusalAuth(t)
	alive := filepath.Join(t.TempDir(), "alive")
	f := newTestFixture(t, fmt.Sprintf(`
name: refused-worker-stop
worker_selector:
  test: "true"
steps:
  - name: long
    run: |
      while :; do date +%%s > %s; sleep 1; done
`, test.ShellQuote(alive)),
		withTransportAuth(auth.config),
		withLabels(map[string]string{"test": "true", "txe.machine": auth.machine}),
	)
	defer f.cleanup()

	readAlive := func() (time.Time, bool) {
		raw, err := os.ReadFile(alive)
		if err != nil {
			return time.Time{}, false
		}
		var secs int64
		if _, err := fmt.Sscan(string(raw), &secs); err != nil {
			return time.Time{}, false
		}
		return time.Unix(secs, 0), true
	}

	require.NoError(t, f.enqueue())
	f.waitForQueued()
	f.startScheduler(30 * time.Second)
	require.Eventually(t, func() bool {
		_, ok := readAlive()
		return ok
	}, distrTestTimeout(30*time.Second), 50*time.Millisecond, "the step should start on the enrolled worker")

	revokedAt := time.Now()
	auth.revoke()

	// The step has stopped once its last tick is three seconds old.
	var lastTick time.Time
	require.Eventually(t, func() bool {
		tick, ok := readAlive()
		if !ok {
			return false
		}
		lastTick = tick
		return time.Since(tick) >= 3*time.Second
	}, distrTestTimeout(worker.RefusedCallsStopAfter+15*time.Second), 200*time.Millisecond, "the step should stop after the worker is refused")

	// The step stopped between its last tick and one second later.
	stoppedAfter := lastTick.Add(time.Second).Sub(revokedAt)
	t.Logf("source fake provider: step stopped about %s after the enrolment was revoked (bound %s after the first refusal)",
		stoppedAfter.Round(time.Second), worker.RefusedCallsStopAfter)
	// The first refusal comes within a second of the revocation, and the
	// step is cancelled no later than the bound after it.
	assert.LessOrEqual(t, stoppedAfter, worker.RefusedCallsStopAfter+3*time.Second)
	// Not early: the worker waits for the documented threshold, well short
	// of the 90 s stale-lease rule.
	assert.GreaterOrEqual(t, stoppedAfter, worker.RefusedCallsStopAfter-3*time.Second)
}
