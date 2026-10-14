// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package transportauth_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
	coordinatorv1 "github.com/dagucloud/dagu/v2/proto/coordinator/v1"
)

func machineLabels(machine string) map[string]string {
	return map[string]string{"txe.machine": machine, "os": "linux"}
}

func poll(workerID, machineLabel string) *coordinatorv1.PollRequest {
	labels := map[string]string{"os": "linux"}
	if machineLabel != "" {
		labels["txe.machine"] = machineLabel
	}
	return &coordinatorv1.PollRequest{WorkerId: workerID, PollerId: "p1", Labels: labels}
}

func codeOf(t *testing.T, err error) codes.Code {
	t.Helper()
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "not a gRPC status: %v", err)
	return st.Code()
}

func TestEnrolledWorkerIsTheMachineOfItsEnrolment(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.bindAndEnrol(subjectA, ownerA, clientA1Worker, machineA1)

	client := f.worker(f.token(subjectA, clientA1Worker))
	_, err := client.Poll(context.Background(), poll(machineA1+"@host@123", machineA1))
	require.NoError(t, err)

	caller := f.service.lastCaller()
	assert.Equal(t, transportauth.CallerMachine, caller.Kind)
	assert.Equal(t, authz.Machine{MachineID: machineA1, OwnerID: ownerA, Class: authn.ClassWorker}, caller.Machine)
	assert.Equal(t, clientA1Worker, caller.Principal.ClientID)

	d := f.lastDecision()
	assert.True(t, d.Allowed)
	assert.False(t, d.WouldDeny)
	assert.Equal(t, machineA1, d.MachineID)
	assert.Equal(t, ownerA, d.OwnerID)
}

func TestWorkerIDAndLabelsAreComparedNeverChosen(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.bindAndEnrol(subjectA, ownerA, clientA1Worker, machineA1)
	f.bindAndEnrol(subjectB, ownerB, clientB1Worker, machineB1)
	client := f.worker(f.token(subjectA, clientA1Worker))
	ctx := context.Background()

	cases := []struct {
		name   string
		req    *coordinatorv1.PollRequest
		reason transportauth.Reason
	}{
		{"another owner's machine as worker id", poll(machineB1+"@host@1", machineA1), transportauth.ReasonWorkerID},
		{"own owner's other machine as worker id", poll(machineA2, machineA1), transportauth.ReasonWorkerID},
		{"worker id sharing a prefix", poll(machineA1+"0@host", machineA1), transportauth.ReasonWorkerID},
		{"empty worker id", poll("", machineA1), transportauth.ReasonWorkerID},
		{"bare machine id and separator", poll(machineA1+"@", machineA1), transportauth.ReasonWorkerID},
		{"another machine's label", poll(machineA1+"@h", machineB1), transportauth.ReasonMachineLabel},
		{"no machine label", poll(machineA1+"@h", ""), transportauth.ReasonMachineLabel},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.Poll(ctx, tc.req)
			assert.Equal(t, codes.PermissionDenied, codeOf(t, err))
			assert.Equal(t, tc.reason, f.lastDecision().Reason)
		})
	}

	_, err := client.Poll(ctx, poll(machineA1, machineA1))
	require.NoError(t, err, "the bare machine id is a worker id of the machine")

	_, err = client.Heartbeat(ctx, &coordinatorv1.HeartbeatRequest{WorkerId: machineA1 + "@h", Labels: machineLabels(machineB1)})
	assert.Equal(t, codes.PermissionDenied, codeOf(t, err))
	_, err = client.RunHeartbeat(ctx, &coordinatorv1.RunHeartbeatRequest{WorkerId: machineB1 + "@h"})
	assert.Equal(t, codes.PermissionDenied, codeOf(t, err))
	_, err = client.RunHeartbeat(ctx, &coordinatorv1.RunHeartbeatRequest{WorkerId: machineA1 + "@h"})
	require.NoError(t, err)
}

func TestCredentialsThatAreNotAnEnrolledWorkerAreRefused(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.bindAndEnrol(subjectA, ownerA, clientA1Worker, machineA1)
	req := poll(machineA1+"@h", machineA1)
	ctx := context.Background()

	cases := []struct {
		name   string
		token  string
		code   codes.Code
		reason transportauth.Reason
	}{
		{"malformed", "not-a-token", codes.Unauthenticated, transportauth.ReasonTokenRefused},
		{"other issuer", f.provider.sign(tokenSpec{subject: subjectA, client: clientA1Worker, issuedAt: f.clock.Now(), issuer: "https://issuer.example/realms/other"}), codes.Unauthenticated, transportauth.ReasonTokenRefused},
		{"other audience", f.provider.sign(tokenSpec{subject: subjectA, client: clientA1Worker, issuedAt: f.clock.Now(), audience: "other"}), codes.Unauthenticated, transportauth.ReasonTokenRefused},
		{"unknown client", f.token(subjectA, "dagu-worker-unknown"), codes.Unauthenticated, transportauth.ReasonTokenRefused},
		{"lifetime over five minutes", f.provider.sign(tokenSpec{subject: subjectA, client: clientA1Worker, issuedAt: f.clock.Now(), lifetime: 6 * time.Minute}), codes.Unauthenticated, transportauth.ReasonTokenRefused},
		{"developer cli token", f.token(subjectA, clientCLI), codes.PermissionDenied, transportauth.ReasonNotMachine},
		{"reviewer token", f.token(subjectA, clientA1Reviewer), codes.PermissionDenied, transportauth.ReasonNotMachine},
		{"enrolled owner on a client never enrolled", f.token(subjectA, clientA2Worker), codes.Unauthenticated, transportauth.ReasonNotEnrolled},
		{"another subject on the machine's client", f.token(subjectB, clientA1Worker), codes.Unauthenticated, transportauth.ReasonNotEnrolled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.worker(tc.token).Poll(ctx, req)
			assert.Equal(t, tc.code, codeOf(t, err))
			assert.Equal(t, tc.reason, f.lastDecision().Reason)
			assert.Empty(t, f.lastDecision().MachineID)
		})
	}

	t.Run("no credential", func(t *testing.T) {
		_, err := f.dial().Poll(ctx, req)
		assert.Equal(t, codes.Unauthenticated, codeOf(t, err))
		assert.Equal(t, transportauth.ReasonNoCredential, f.lastDecision().Reason)
	})
	t.Run("unknown scheme", func(t *testing.T) {
		md := metadata.Pairs("authorization", "Basic abc")
		_, err := f.dial().Poll(metadata.NewOutgoingContext(ctx, md), req)
		assert.Equal(t, codes.Unauthenticated, codeOf(t, err))
		assert.Equal(t, transportauth.ReasonMalformed, f.lastDecision().Reason)
	})
	t.Run("two credentials", func(t *testing.T) {
		md := metadata.Pairs("authorization", "Bearer a", "authorization", "Bearer b")
		_, err := f.dial().Poll(metadata.NewOutgoingContext(ctx, md), req)
		assert.Equal(t, codes.Unauthenticated, codeOf(t, err))
		assert.Equal(t, transportauth.ReasonMalformed, f.lastDecision().Reason)
	})
}

func TestTokenIsRefusedAtItsExpiryWithNoGrace(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.bindAndEnrol(subjectA, ownerA, clientA1Worker, machineA1)
	client := f.worker(f.token(subjectA, clientA1Worker))
	ctx := context.Background()

	f.clock.Advance(5*time.Minute - time.Second)
	_, err := client.Poll(ctx, poll(machineA1, machineA1))
	require.NoError(t, err, "one second before expiry")

	f.clock.Advance(time.Second)
	_, err = client.Poll(ctx, poll(machineA1, machineA1))
	assert.Equal(t, codes.Unauthenticated, codeOf(t, err), "at expiry")
}

func TestUnreachableProviderIsUnavailableAndNeverAccepted(t *testing.T) {
	f := newFixture(t, fixtureOptions{keys: keysDown{}})
	client := f.worker(f.provider.sign(tokenSpec{subject: subjectA, client: clientA1Worker, issuedAt: f.clock.Now()}))

	_, err := client.Poll(context.Background(), poll(machineA1, machineA1))
	assert.Equal(t, codes.Unavailable, codeOf(t, err))
	assert.Equal(t, transportauth.ReasonProviderDown, f.lastDecision().Reason)
	assert.Empty(t, f.service.lastCaller().Kind, "the handler never ran")
}

func TestRevokedEnrolmentIsRefusedAtTheNextCall(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.bindAndEnrol(subjectA, ownerA, clientA1Worker, machineA1)
	client := f.worker(f.token(subjectA, clientA1Worker))
	ctx := context.Background()

	_, err := client.Poll(ctx, poll(machineA1, machineA1))
	require.NoError(t, err)

	f.revokeEnrolment(subjectA, machineA1)
	_, err = client.Poll(ctx, poll(machineA1, machineA1))
	assert.Equal(t, codes.Unauthenticated, codeOf(t, err))
	assert.Equal(t, transportauth.ReasonNotEnrolled, f.lastDecision().Reason)
}

func TestRevokedBindingRefusesTheOwnersMachines(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.bindAndEnrol(subjectA, ownerA, clientA1Worker, machineA1)
	client := f.worker(f.token(subjectA, clientA1Worker))
	ctx := context.Background()

	_, err := f.store.RevokeBinding(ctx, authz.PlatformAdmin("admin"), authn.Identity{Issuer: testIssuer, Subject: subjectA}, "test")
	require.NoError(t, err)
	_, err = client.Poll(ctx, poll(machineA1, machineA1))
	assert.Equal(t, codes.Unauthenticated, codeOf(t, err))
}

func TestHubSurfaceIsTheHubsOnly(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.bindAndEnrol(subjectA, ownerA, clientA1Worker, machineA1)
	ctx := context.Background()

	_, err := f.worker(f.token(subjectA, clientA1Worker)).Dispatch(ctx, &coordinatorv1.DispatchRequest{})
	assert.Equal(t, codes.PermissionDenied, codeOf(t, err))
	assert.Equal(t, transportauth.ReasonHubOnly, f.lastDecision().Reason)

	_, err = f.worker(f.token(subjectA, clientA1Worker)).GetDAG(ctx, &coordinatorv1.GetDAGRequest{Name: "job_B1"})
	assert.Equal(t, codes.PermissionDenied, codeOf(t, err))

	_, err = f.hub(testHubKey).Dispatch(ctx, &coordinatorv1.DispatchRequest{})
	require.NoError(t, err)
	assert.Equal(t, transportauth.CallerHub, f.service.lastCaller().Kind)

	// The hub is trusted with the worker surface as well, as it is today.
	_, err = f.hub(testHubKey).Poll(ctx, poll("anything", ""))
	require.NoError(t, err)

	wrong := append([]byte(nil), testHubKey...)
	wrong[0] ^= 1
	_, err = f.hub(wrong).Dispatch(ctx, &coordinatorv1.DispatchRequest{})
	assert.Equal(t, codes.Unauthenticated, codeOf(t, err))
	assert.Equal(t, transportauth.ReasonBadHubKey, f.lastDecision().Reason)

	// A provider token is never the hub, whatever scheme it is sent under.
	md := metadata.Pairs("authorization", "TXE-Hub "+f.token(subjectA, clientA1Worker))
	_, err = f.dial().Dispatch(metadata.NewOutgoingContext(ctx, md), &coordinatorv1.DispatchRequest{})
	assert.Equal(t, codes.Unauthenticated, codeOf(t, err))
}

func TestHealthIsPublic(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	resp, err := grpc_health_v1.NewHealthClient(f.conn()).Check(context.Background(), &grpc_health_v1.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, grpc_health_v1.HealthCheckResponse_SERVING, resp.GetStatus())
}

func TestMethodsWithoutASurfaceAreClosed(t *testing.T) {
	for _, mode := range []transportauth.Mode{authz.ModeEnforce, authz.ModeObserve} {
		t.Run(string(mode), func(t *testing.T) {
			f := newFixture(t, fixtureOptions{})
			var decisions []transportauth.Decision
			server, err := transportauth.NewServer(transportauth.ServerConfig{
				Mode: mode, Verifier: f.verifier, Machines: f.store, HubKey: testHubKey,
				Observe: func(_ context.Context, d transportauth.Decision) { decisions = append(decisions, d) },
			})
			require.NoError(t, err)
			hub := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "TXE-Hub "+string(testHubKey)))
			ran := false
			handler := func(context.Context, any) (any, error) { ran = true; return nil, nil }
			unknown := &grpc.UnaryServerInfo{FullMethod: "/coordinator.v1.CoordinatorService/NotYetDecided"}

			// A method the service gains later is closed, even to the hub
			// and even in observe mode, until someone gives it a surface.
			for _, ctx := range []context.Context{hub, context.Background()} {
				_, err = server.UnaryInterceptor()(ctx, &coordinatorv1.PollRequest{}, unknown, handler)
				assert.Equal(t, codes.PermissionDenied, codeOf(t, err))
				assert.False(t, ran)
				require.NotEmpty(t, decisions)
				last := decisions[len(decisions)-1]
				assert.False(t, last.Allowed)
				assert.Equal(t, transportauth.ReasonUnknownMethod, last.Reason)
			}

			_, err = server.UnaryInterceptor()(hub, &coordinatorv1.DispatchRequest{},
				&grpc.UnaryServerInfo{FullMethod: coordinatorv1.CoordinatorService_Dispatch_FullMethodName}, handler)
			require.NoError(t, err)
			assert.True(t, ran)
		})
	}
}

func TestEveryCoordinatorMethodHasASurface(t *testing.T) {
	for _, method := range coordinatorv1.CoordinatorService_ServiceDesc.Methods {
		_, ok := transportauth.SurfaceOf("/" + coordinatorv1.CoordinatorService_ServiceDesc.ServiceName + "/" + method.MethodName)
		assert.True(t, ok, method.MethodName)
	}
	for _, stream := range coordinatorv1.CoordinatorService_ServiceDesc.Streams {
		_, ok := transportauth.SurfaceOf("/" + coordinatorv1.CoordinatorService_ServiceDesc.ServiceName + "/" + stream.StreamName)
		assert.True(t, ok, stream.StreamName)
	}
}

func TestObserveAllowsAndRecordsWhatEnforceWouldRefuse(t *testing.T) {
	f := newFixture(t, fixtureOptions{mode: authz.ModeObserve})
	f.bindAndEnrol(subjectA, ownerA, clientA1Worker, machineA1)
	ctx := context.Background()

	_, err := f.dial().Poll(ctx, poll("whoever", ""))
	require.NoError(t, err)
	d := f.lastDecision()
	assert.True(t, d.Allowed)
	assert.True(t, d.WouldDeny)
	assert.Equal(t, transportauth.ReasonNoCredential, d.Reason)
	assert.Equal(t, transportauth.CallerNone, f.service.lastCaller().Kind)

	_, err = f.worker(f.token(subjectA, clientA1Worker)).Poll(ctx, poll(machineB1, machineA1))
	require.NoError(t, err)
	d = f.lastDecision()
	assert.True(t, d.WouldDeny)
	assert.Equal(t, transportauth.ReasonWorkerID, d.Reason)

	_, err = f.worker(f.token(subjectA, clientA1Worker)).Poll(ctx, poll(machineA1, machineA1))
	require.NoError(t, err)
	d = f.lastDecision()
	assert.True(t, d.Allowed)
	assert.False(t, d.WouldDeny)
}

func TestStreamMessagesAreCheckedOneByOne(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.bindAndEnrol(subjectA, ownerA, clientA1Worker, machineA1)
	ctx := context.Background()

	t.Run("own chunks are accepted", func(t *testing.T) {
		stream, err := f.worker(f.token(subjectA, clientA1Worker)).StreamLogs(ctx)
		require.NoError(t, err)
		require.NoError(t, stream.Send(&coordinatorv1.LogChunk{WorkerId: machineA1 + "@h", Data: []byte("x")}))
		require.NoError(t, stream.Send(&coordinatorv1.LogChunk{WorkerId: machineA1 + "@h", Data: []byte("y")}))
		_, err = stream.CloseAndRecv()
		require.NoError(t, err)
		assert.Equal(t, 2, f.service.received())
	})

	t.Run("a forged chunk ends the stream", func(t *testing.T) {
		before := f.service.received()
		stream, err := f.worker(f.token(subjectA, clientA1Worker)).StreamLogs(ctx)
		require.NoError(t, err)
		require.NoError(t, stream.Send(&coordinatorv1.LogChunk{WorkerId: machineB1 + "@h", Data: []byte("x")}))
		_, err = stream.CloseAndRecv()
		assert.Equal(t, codes.PermissionDenied, codeOf(t, err))
		assert.Equal(t, before, f.service.received())
	})

	t.Run("a stream outliving its token is refused", func(t *testing.T) {
		before := f.service.received()
		stream, err := f.worker(f.token(subjectA, clientA1Worker)).StreamLogs(ctx)
		require.NoError(t, err)
		require.NoError(t, stream.Send(&coordinatorv1.LogChunk{WorkerId: machineA1, Data: []byte("x")}))
		require.Eventually(t, func() bool { return f.service.received() == before+1 }, 5*time.Second, 10*time.Millisecond)
		f.clock.Advance(5 * time.Minute)
		require.NoError(t, stream.Send(&coordinatorv1.LogChunk{WorkerId: machineA1, Data: []byte("y")}))
		_, err = stream.CloseAndRecv()
		assert.Equal(t, codes.Unauthenticated, codeOf(t, err))
		assert.Equal(t, before+1, f.service.received())
	})

	t.Run("a stream sees a revoked enrolment", func(t *testing.T) {
		f.bindAndEnrol(subjectA, ownerA, clientA2Worker, machineA2)
		before := f.service.received()
		stream, err := f.worker(f.token(subjectA, clientA2Worker)).StreamLogs(ctx)
		require.NoError(t, err)
		require.NoError(t, stream.Send(&coordinatorv1.LogChunk{WorkerId: machineA2, Data: []byte("x")}))
		require.Eventually(t, func() bool { return f.service.received() == before+1 }, 5*time.Second, 10*time.Millisecond)
		f.revokeEnrolment(subjectA, machineA2)
		f.clock.Advance(time.Second)
		require.NoError(t, stream.Send(&coordinatorv1.LogChunk{WorkerId: machineA2, Data: []byte("y")}))
		_, err = stream.CloseAndRecv()
		assert.Equal(t, codes.Unauthenticated, codeOf(t, err))
		assert.Equal(t, before+1, f.service.received())
	})
}

func TestADownloadStopsWhenItsTokenExpiresOrItsEnrolmentIsRevoked(t *testing.T) {
	for _, tc := range []struct {
		name string
		end  func(f *fixture)
	}{
		{"expiry", func(f *fixture) { f.clock.Advance(5 * time.Minute) }},
		{"revocation", func(f *fixture) {
			f.revokeEnrolment(subjectA, machineA1)
			f.clock.Advance(time.Second)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, fixtureOptions{resources: allowOnly{machine: machineA1}})
			f.bindAndEnrol(subjectA, ownerA, clientA1Worker, machineA1)
			f.service.setBundle(3, func(i int) {
				if i == 1 {
					tc.end(f)
				}
			})
			stream, err := f.worker(f.token(subjectA, clientA1Worker)).GetWorkspaceBundle(context.Background(), &coordinatorv1.GetWorkspaceBundleRequest{})
			require.NoError(t, err)
			_, err = stream.Recv()
			require.NoError(t, err, "the first chunk goes out while the credential stands")
			_, err = stream.Recv()
			assert.Equal(t, codes.Unauthenticated, codeOf(t, err), "no chunk goes out after it")
		})
	}

	t.Run("the hub's download is not rechecked", func(t *testing.T) {
		f := newFixture(t, fixtureOptions{})
		f.service.setBundle(3, func(i int) {
			if i == 1 {
				f.clock.Advance(time.Hour)
			}
		})
		stream, err := f.hub(testHubKey).GetWorkspaceBundle(context.Background(), &coordinatorv1.GetWorkspaceBundleRequest{})
		require.NoError(t, err)
		for range 3 {
			_, err = stream.Recv()
			require.NoError(t, err)
		}
	})
}

// slowResolver moves the clock while it reads the enrolment.
type slowResolver struct {
	transportauth.MachineResolver
	clock *clock
	by    time.Duration
}

func (r slowResolver) ResolveMachine(ctx context.Context, p authn.Principal) (authz.Machine, authz.Reason, error) {
	machine, reason, err := r.MachineResolver.ResolveMachine(ctx, p)
	r.clock.Advance(r.by)
	return machine, reason, err
}

func TestATokenExpiringDuringItsEnrolmentReadIsRefused(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.bindAndEnrol(subjectA, ownerA, clientA1Worker, machineA1)
	token := f.token(subjectA, clientA1Worker)
	f.clock.Advance(5*time.Minute - time.Second)
	server, err := transportauth.NewServer(transportauth.ServerConfig{
		Mode: authz.ModeEnforce, Verifier: f.verifier, HubKey: testHubKey, Now: f.clock.Now,
		Machines: slowResolver{MachineResolver: f.store, clock: f.clock, by: time.Second},
	})
	require.NoError(t, err)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer "+token))
	ran := false
	_, err = server.UnaryInterceptor()(ctx, poll(machineA1, machineA1),
		&grpc.UnaryServerInfo{FullMethod: coordinatorv1.CoordinatorService_Poll_FullMethodName},
		func(context.Context, any) (any, error) { ran = true; return nil, nil })
	assert.Equal(t, codes.Unauthenticated, codeOf(t, err))
	assert.False(t, ran)
}

// refuseQuoting is an authorizer whose refusal quotes the request.
type refuseQuoting struct{}

func (refuseQuoting) AuthorizeResource(context.Context, authz.Machine, string, any) error {
	return errors.New("bundle request-secret-value is not yours")
}

func TestAResourceRefusalReportsNoTextFromTheAuthorizer(t *testing.T) {
	f := newFixture(t, fixtureOptions{resources: refuseQuoting{}})
	f.bindAndEnrol(subjectA, ownerA, clientA1Worker, machineA1)
	stream, err := f.worker(f.token(subjectA, clientA1Worker)).GetWorkspaceBundle(context.Background(), &coordinatorv1.GetWorkspaceBundleRequest{})
	require.NoError(t, err)
	_, err = stream.Recv()
	assert.Equal(t, codes.PermissionDenied, codeOf(t, err))
	assert.NotContains(t, err.Error(), "request-secret-value")
	d := f.lastDecision()
	assert.Equal(t, transportauth.ReasonNoResourceCheck, d.Reason)
	assert.NotContains(t, fmt.Sprintf("%+v", d), "request-secret-value")
}

type allowOnly struct{ machine string }

func (a allowOnly) AuthorizeResource(_ context.Context, m authz.Machine, _ string, _ any) error {
	if m.MachineID != a.machine {
		return assert.AnError
	}
	return nil
}

func TestScopedMethodNeedsAResourceDecision(t *testing.T) {
	ctx := context.Background()
	fetch := func(client coordinatorv1.CoordinatorServiceClient) error {
		stream, err := client.GetWorkspaceBundle(ctx, &coordinatorv1.GetWorkspaceBundleRequest{})
		if err != nil {
			return err
		}
		_, err = stream.Recv()
		return err
	}

	t.Run("refused without an authorizer", func(t *testing.T) {
		f := newFixture(t, fixtureOptions{})
		f.bindAndEnrol(subjectA, ownerA, clientA1Worker, machineA1)
		err := fetch(f.worker(f.token(subjectA, clientA1Worker)))
		assert.Equal(t, codes.PermissionDenied, codeOf(t, err))
		require.NoError(t, fetch(f.hub(testHubKey)))
	})

	t.Run("decided by the authorizer", func(t *testing.T) {
		f := newFixture(t, fixtureOptions{resources: allowOnly{machine: machineA1}})
		f.bindAndEnrol(subjectA, ownerA, clientA1Worker, machineA1)
		f.bindAndEnrol(subjectB, ownerB, clientB1Worker, machineB1)
		require.NoError(t, fetch(f.worker(f.token(subjectA, clientA1Worker))))
		err := fetch(f.worker(f.token(subjectB, clientB1Worker)))
		assert.Equal(t, codes.PermissionDenied, codeOf(t, err))
	})
}

func TestNewServerRefusesAnUnsafeConfiguration(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	valid := transportauth.ServerConfig{Mode: authz.ModeEnforce, Verifier: f.verifier, Machines: f.store, HubKey: testHubKey}
	_, err := transportauth.NewServer(valid)
	require.NoError(t, err)

	for name, mutate := range map[string]func(*transportauth.ServerConfig){
		"mode off":       func(c *transportauth.ServerConfig) { c.Mode = authz.ModeOff },
		"no mode":        func(c *transportauth.ServerConfig) { c.Mode = "" },
		"unknown mode":   func(c *transportauth.ServerConfig) { c.Mode = "permissive" },
		"no verifier":    func(c *transportauth.ServerConfig) { c.Verifier = nil },
		"no resolver":    func(c *transportauth.ServerConfig) { c.Machines = nil },
		"short hub key":  func(c *transportauth.ServerConfig) { c.HubKey = testHubKey[:31] },
		"absent hub key": func(c *transportauth.ServerConfig) { c.HubKey = nil },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := valid
			mutate(&cfg)
			_, err := transportauth.NewServer(cfg)
			assert.Error(t, err)
		})
	}
}

func TestWorkerIDBelongsTo(t *testing.T) {
	assert.True(t, transportauth.WorkerIDBelongsTo("mch_A", "mch_A"))
	assert.True(t, transportauth.WorkerIDBelongsTo("mch_A@host@1", "mch_A"))
	assert.False(t, transportauth.WorkerIDBelongsTo("mch_A@", "mch_A"))
	assert.False(t, transportauth.WorkerIDBelongsTo("mch_AB", "mch_A"))
	assert.False(t, transportauth.WorkerIDBelongsTo("host@mch_A", "mch_A"))
	assert.False(t, transportauth.WorkerIDBelongsTo("", "mch_A"))
	assert.False(t, transportauth.WorkerIDBelongsTo("mch_A", ""))
}
