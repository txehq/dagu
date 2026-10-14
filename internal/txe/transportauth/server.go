// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package transportauth authenticates the callers of the coordinator's gRPC
// service: enrolled worker machines and the hub's own processes.
//
// It is a library. A coordinator installs the interceptors of a Server; a
// worker dials with the credentials of a TokenSource. Nothing in it reads
// server configuration.
//
// The rules it holds:
//
//   - A worker machine presents a provider access token on every call. The
//     token is verified on every call, to its exact expiry; nothing extends
//     it, an unreachable provider included.
//   - The machine is the one its credential is enrolled for, read again on
//     every call, so a revoked enrolment or binding is refused at the next
//     call. A worker id, a label or an owner in a request is compared with
//     that machine and refused when it differs; it never chooses.
//   - The hub's own processes present a key held on the hub's storage. They
//     never present a provider token, and a provider token never makes a
//     caller the hub.
//   - Each method has a surface. A method with none is refused to everyone.
package transportauth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	// AuthorizationHeader is the metadata key every credential is sent in.
	AuthorizationHeader = "authorization"
	// BearerScheme precedes a provider access token.
	BearerScheme = "Bearer"
	// HubScheme precedes the hub's own key.
	HubScheme = "TXE-Hub"

	// MinHubKeyBytes is the shortest hub key a Server accepts.
	MinHubKeyBytes = 32

	// streamRecheckInterval bounds how long a stream goes without reading
	// the caller's enrolment again. A unary call reads it every time.
	streamRecheckInterval = time.Second
)

// Mode is what a Server does with what it finds. It is authz.Mode: off,
// observe or enforce.
type Mode = authz.Mode

// TokenVerifier verifies a provider access token. *authn.Verifier is one.
type TokenVerifier interface {
	Verify(ctx context.Context, token string) (authn.Principal, error)
}

// MachineResolver finds the machine a credential is enrolled for. *authz.Store
// is one.
type MachineResolver interface {
	ResolveMachine(ctx context.Context, p authn.Principal) (authz.Machine, authz.Reason, error)
}

// ResourceAuthorizer decides whether a machine may call a method of
// SurfaceScoped with this request. Without one, every machine is refused
// such methods.
type ResourceAuthorizer interface {
	AuthorizeResource(ctx context.Context, machine authz.Machine, fullMethod string, request any) error
}

// CallerKind says what authenticated a call.
type CallerKind string

const (
	// CallerNone is a call that presented no credential that was accepted.
	// It is seen only in ModeObserve, and on public methods.
	CallerNone CallerKind = "none"
	// CallerMachine is an enrolled worker machine.
	CallerMachine CallerKind = "machine"
	// CallerHub is one of the hub's own processes.
	CallerHub CallerKind = "hub"
)

// Caller is who a call came from, as the interceptors established it.
type Caller struct {
	Kind CallerKind
	// Machine is the enrolment the credential belongs to. It is set only for
	// CallerMachine and comes from nothing in the request.
	Machine authz.Machine
	// Principal is the verified token, for CallerMachine.
	Principal authn.Principal
}

type callerKey struct{}

// CallerFrom returns the caller the interceptors put on a handler's context.
func CallerFrom(ctx context.Context) (Caller, bool) {
	caller, ok := ctx.Value(callerKey{}).(Caller)
	return caller, ok
}

// Reason says why a call was refused, or would have been.
type Reason string

const (
	ReasonAllowed          Reason = ""
	ReasonUnknownMethod    Reason = "unknown_method"
	ReasonNoCredential     Reason = "no_credential" //nolint:gosec // a reason name, not a credential
	ReasonMalformed        Reason = "malformed_credential"
	ReasonBadHubKey        Reason = "bad_hub_key"
	ReasonTokenRefused     Reason = "token_refused"
	ReasonProviderDown     Reason = "provider_unavailable"
	ReasonNotMachine       Reason = "not_a_worker"
	ReasonNotEnrolled      Reason = "not_enrolled"
	ReasonExpired          Reason = "expired"
	ReasonStoreUnavailable Reason = "store_unavailable"
	ReasonHubOnly          Reason = "hub_only"
	ReasonNoResourceCheck  Reason = "resource_not_authorized"
	ReasonWorkerID         Reason = "worker_id_mismatch"
	ReasonMachineLabel     Reason = "machine_label_mismatch"
	ReasonBadRequest       Reason = "unexpected_request"
)

// Decision is what a Server decided about one call, or one message of a
// stream. It holds no credential and no value from the request.
type Decision struct {
	Method string
	Mode   Mode
	// Allowed is what the Server did.
	Allowed bool
	// WouldDeny is set in ModeObserve when ModeEnforce would have refused.
	WouldDeny bool
	Reason    Reason
	// Detail is the verifier's or the store's reason, when there is one.
	Detail string
	Kind   CallerKind
	// MachineID and OwnerID are the enrolment's, never the token's or the
	// request's.
	MachineID string
	OwnerID   string
}

// ServerConfig configures a Server.
type ServerConfig struct {
	// Mode is observe or enforce. A Server is not built for off: a
	// coordinator in off installs no interceptor at all.
	Mode Mode
	// Verifier checks provider access tokens.
	Verifier TokenVerifier
	// Machines finds the machine a credential is enrolled for.
	Machines MachineResolver
	// HubKey is the key the hub's own processes present. It must be at
	// least MinHubKeyBytes long. It is never printed or marshalled.
	HubKey []byte `json:"-"`
	// Resources authorizes machines on SurfaceScoped methods. Nil refuses
	// them.
	Resources ResourceAuthorizer
	// Observe receives every decision on a non-public method. It must not
	// block.
	Observe func(ctx context.Context, d Decision)
	// Now is the clock. Nil means time.Now.
	Now func() time.Time
}

// Format prints the mode and nothing of the hub key, for every verb, for the
// config and a pointer to it.
func (c ServerConfig) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "transportauth.ServerConfig{mode %s}", c.Mode)
}

// LogValue keeps the hub key out of structured logs.
func (c ServerConfig) LogValue() slog.Value {
	return slog.StringValue(fmt.Sprintf("transportauth.ServerConfig{mode %s}", c.Mode))
}

// Server authenticates coordinator calls.
type Server struct {
	mode      Mode
	verifier  TokenVerifier
	machines  MachineResolver
	hubKey    []byte
	resources ResourceAuthorizer
	observe   func(context.Context, Decision)
	now       func() time.Time
}

// Format prints the mode and nothing of the hub key, for every verb.
func (s Server) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "transportauth.Server{mode %s}", s.mode)
}

// NewServer validates cfg and returns a Server.
func NewServer(cfg ServerConfig) (*Server, error) {
	switch cfg.Mode {
	case authz.ModeObserve, authz.ModeEnforce:
	case authz.ModeOff, "":
		return nil, errors.New("transportauth: mode off installs no interceptor; do not build a Server for it")
	default:
		return nil, fmt.Errorf("transportauth: unknown mode %q", cfg.Mode)
	}
	if cfg.Verifier == nil {
		return nil, errors.New("transportauth: a token verifier is required")
	}
	if cfg.Machines == nil {
		return nil, errors.New("transportauth: a machine resolver is required")
	}
	if len(cfg.HubKey) < MinHubKeyBytes {
		return nil, fmt.Errorf("transportauth: the hub key must be at least %d bytes", MinHubKeyBytes)
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Server{
		mode:      cfg.Mode,
		verifier:  cfg.Verifier,
		machines:  cfg.Machines,
		hubKey:    append([]byte(nil), cfg.HubKey...),
		resources: cfg.Resources,
		observe:   cfg.Observe,
		now:       now,
	}, nil
}

// UnaryInterceptor authenticates each unary call before its handler runs.
func (s *Server) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		caller, err := s.admit(ctx, info.FullMethod, req)
		if err != nil {
			return nil, err
		}
		return handler(context.WithValue(ctx, callerKey{}, caller), req)
	}
}

// StreamInterceptor authenticates a stream when it opens, and checks every
// message on it. For each message a machine sends and each message sent to
// it, the token must still be unexpired and the enrolment must still stand;
// each message a machine sends must also name the machine's worker.
func (s *Server) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		caller, err := s.admit(ss.Context(), info.FullMethod, nil)
		if err != nil {
			return err
		}
		wrapped := &checkedStream{
			ServerStream: ss,
			server:       s,
			method:       info.FullMethod,
			caller:       caller,
			ctx:          context.WithValue(ss.Context(), callerKey{}, caller),
			resolvedAt:   s.now(),
		}
		return handler(srv, wrapped)
	}
}

// admit decides one call. req is nil when a stream opens: a stream's messages
// are checked as they arrive.
func (s *Server) admit(ctx context.Context, method string, req any) (Caller, error) {
	surface, known := SurfaceOf(method)
	if known && surface == SurfacePublic {
		return Caller{Kind: CallerNone}, nil
	}
	decision := Decision{Method: method, Mode: s.mode, Kind: CallerNone}
	caller, err := s.evaluate(ctx, method, surface, known, req, &decision)
	return s.settle(ctx, caller, err, decision)
}

// settle applies the mode to an evaluation and reports it. A method with no
// surface is refused in every mode.
func (s *Server) settle(ctx context.Context, caller Caller, refusal error, decision Decision) (Caller, error) {
	decision.Allowed = refusal == nil
	if refusal != nil && s.mode == authz.ModeObserve && decision.Reason != ReasonUnknownMethod {
		decision.Allowed, decision.WouldDeny = true, true
		refusal = nil
	}
	if s.observe != nil {
		s.observe(ctx, decision)
	}
	if refusal != nil {
		return Caller{}, refusal
	}
	if caller.Kind == "" {
		caller.Kind = CallerNone
	}
	return caller, nil
}

func (s *Server) evaluate(ctx context.Context, method string, surface Surface, known bool, req any, d *Decision) (Caller, error) {
	if !known {
		d.Reason = ReasonUnknownMethod
		return Caller{}, status.Error(codes.PermissionDenied, "transportauth: this method is not open to any caller")
	}
	scheme, credential, reason := credentialOf(ctx)
	if reason != ReasonAllowed {
		d.Reason = reason
		return Caller{}, status.Error(codes.Unauthenticated, "transportauth: a credential is required")
	}

	if scheme == HubScheme {
		if subtle.ConstantTimeCompare([]byte(credential), s.hubKey) != 1 {
			d.Reason = ReasonBadHubKey
			return Caller{}, status.Error(codes.Unauthenticated, "transportauth: the hub key is not accepted")
		}
		d.Kind = CallerHub
		return Caller{Kind: CallerHub}, nil
	}

	caller, err := s.machine(ctx, credential, d)
	if err != nil {
		return Caller{}, err
	}
	if surface == SurfaceHub {
		d.Reason = ReasonHubOnly
		return Caller{}, status.Error(codes.PermissionDenied, "transportauth: only the hub calls this method")
	}
	if req == nil {
		// A stream: its messages are checked as they arrive.
		return caller, nil
	}
	if err := s.checkRequest(ctx, method, surface, caller.Machine, req, d); err != nil {
		return Caller{}, err
	}
	// The request check may have taken time; the token must still be
	// unexpired when the handler runs.
	if err := s.unexpired(caller.Principal, d); err != nil {
		return Caller{}, err
	}
	return caller, nil
}

// checkRequest decides whether a machine may send this request, or this
// message of a stream, on a worker or scoped method.
func (s *Server) checkRequest(ctx context.Context, method string, surface Surface, machine authz.Machine, req any, d *Decision) error {
	switch surface {
	case SurfaceWorker:
		if reason := checkClaims(method, req, machine.MachineID); reason != ReasonAllowed {
			d.Reason = reason
			return status.Error(codes.PermissionDenied, "transportauth: the request does not match the caller's machine")
		}
		return nil
	case SurfaceScoped:
		if s.resources == nil {
			d.Reason = ReasonNoResourceCheck
			return status.Error(codes.PermissionDenied, "transportauth: this machine may not use this resource")
		}
		if err := s.resources.AuthorizeResource(ctx, machine, method, req); err != nil {
			// The authorizer's error is not reported: it may quote the
			// request.
			d.Reason = ReasonNoResourceCheck
			return status.Error(codes.PermissionDenied, "transportauth: this machine may not use this resource")
		}
		return nil
	case SurfacePublic, SurfaceHub:
		// Never reached for a machine: public methods are not evaluated and
		// hub methods are refused before the request is looked at.
		d.Reason = ReasonUnknownMethod
		return status.Error(codes.PermissionDenied, "transportauth: this method is not open to a machine")
	default:
		d.Reason = ReasonUnknownMethod
		return status.Error(codes.PermissionDenied, "transportauth: this method is not open to any caller")
	}
}

// machine verifies a provider token and finds the machine it is enrolled for.
func (s *Server) machine(ctx context.Context, token string, d *Decision) (Caller, error) {
	principal, err := s.verifier.Verify(ctx, token)
	if err != nil {
		d.Detail = string(authn.ReasonOf(err))
		if authn.ProviderUnavailable(err) {
			d.Reason = ReasonProviderDown
			return Caller{}, status.Error(codes.Unavailable, "transportauth: the identity provider's keys are unavailable")
		}
		d.Reason = ReasonTokenRefused
		return Caller{}, status.Error(codes.Unauthenticated, "transportauth: the token is not accepted")
	}
	if principal.Class != authn.ClassWorker {
		d.Reason, d.Detail = ReasonNotMachine, string(principal.Class)
		return Caller{}, status.Error(codes.PermissionDenied, "transportauth: only a worker's credential is accepted here")
	}
	machine, err := s.resolve(ctx, principal, d)
	if err != nil {
		return Caller{}, err
	}
	d.Kind = CallerMachine
	return Caller{Kind: CallerMachine, Machine: machine, Principal: principal}, nil
}

// unexpired refuses a token at or after its expiry, by the clock read now.
func (s *Server) unexpired(principal authn.Principal, d *Decision) error {
	if !s.now().Before(principal.Expires) {
		d.Reason = ReasonExpired
		return status.Error(codes.Unauthenticated, "transportauth: the token has expired")
	}
	return nil
}

// resolve reads the enrolment of a verified worker principal. The token is
// checked to be unexpired before the read and again after it.
func (s *Server) resolve(ctx context.Context, principal authn.Principal, d *Decision) (authz.Machine, error) {
	if err := s.unexpired(principal, d); err != nil {
		return authz.Machine{}, err
	}
	machine, reason, err := s.machines.ResolveMachine(ctx, principal)
	if err != nil {
		d.Reason, d.Detail = ReasonStoreUnavailable, string(reason)
		return authz.Machine{}, status.Error(codes.Unavailable, "transportauth: enrolments cannot be read")
	}
	if reason != "" || machine.MachineID == "" || machine.Class != authn.ClassWorker {
		d.Reason, d.Detail = ReasonNotEnrolled, string(reason)
		return authz.Machine{}, status.Error(codes.Unauthenticated, "transportauth: the credential is not enrolled for a worker machine")
	}
	d.MachineID, d.OwnerID = machine.MachineID, machine.OwnerID
	if err := s.unexpired(principal, d); err != nil {
		return authz.Machine{}, err
	}
	return machine, nil
}

// credentialOf reads the one authorization value of a call.
func credentialOf(ctx context.Context) (scheme, credential string, reason Reason) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", "", ReasonNoCredential
	}
	values := md.Get(AuthorizationHeader)
	switch len(values) {
	case 0:
		return "", "", ReasonNoCredential
	case 1:
	default:
		return "", "", ReasonMalformed
	}
	scheme, credential, found := strings.Cut(values[0], " ")
	if !found || credential == "" || strings.ContainsAny(credential, " \t\r\n") {
		return "", "", ReasonMalformed
	}
	switch scheme {
	case BearerScheme, HubScheme:
		return scheme, credential, ReasonAllowed
	default:
		return "", "", ReasonMalformed
	}
}

// checkClaims compares what a worker request says about its sender with the
// caller's machine.
func checkClaims(method string, req any, machineID string) Reason {
	if carriesWorkerID[method] {
		carrier, ok := req.(workerIDCarrier)
		if !ok {
			return ReasonBadRequest
		}
		if !WorkerIDBelongsTo(carrier.GetWorkerId(), machineID) {
			return ReasonWorkerID
		}
	}
	if carriesLabels[method] {
		carrier, ok := req.(labelCarrier)
		if !ok {
			return ReasonBadRequest
		}
		label, present := carrier.GetLabels()[txepkg.LabelMachine]
		if !present || label != machineID {
			return ReasonMachineLabel
		}
	}
	return ReasonAllowed
}

// WorkerIDBelongsTo reports whether a worker id names a worker of the
// machine: the machine id itself, or the machine id, "@" and a suffix that
// tells one worker process of the machine from another. The check needs no
// record, so it holds the same way before and after a coordinator restart.
func WorkerIDBelongsTo(workerID, machineID string) bool {
	if machineID == "" || workerID == "" {
		return false
	}
	if workerID == machineID {
		return true
	}
	suffix, ok := strings.CutPrefix(workerID, machineID+"@")
	return ok && suffix != ""
}

// checkedStream checks each message a machine sends on a stream.
type checkedStream struct {
	grpc.ServerStream
	server *Server
	method string
	caller Caller
	ctx    context.Context

	mu         sync.Mutex
	resolvedAt time.Time
}

func (c *checkedStream) Context() context.Context { return c.ctx }

func (c *checkedStream) RecvMsg(m any) error {
	if err := c.ServerStream.RecvMsg(m); err != nil {
		return err
	}
	if c.caller.Kind != CallerMachine {
		// The hub, and every caller in observe mode that was not a
		// machine, was decided when the stream opened.
		return nil
	}
	decision := c.decision()
	refusal := c.standing(&decision)
	if refusal == nil {
		surface, _ := SurfaceOf(c.method)
		refusal = c.server.checkRequest(c.ctx, c.method, surface, c.caller.Machine, m, &decision)
	}
	if refusal == nil {
		refusal = c.server.unexpired(c.caller.Principal, &decision)
	}
	_, err := c.server.settle(c.ctx, c.caller, refusal, decision)
	return err
}

// SendMsg checks, before each message the coordinator sends a machine, that
// the machine's token is unexpired and its enrolment still stands, so a
// download stops when either ends.
func (c *checkedStream) SendMsg(m any) error {
	if c.caller.Kind == CallerMachine {
		decision := c.decision()
		refusal := c.standing(&decision)
		if _, err := c.server.settle(c.ctx, c.caller, refusal, decision); err != nil {
			return err
		}
	}
	return c.ServerStream.SendMsg(m)
}

func (c *checkedStream) decision() Decision {
	return Decision{
		Method: c.method, Mode: c.server.mode, Kind: CallerMachine,
		MachineID: c.caller.Machine.MachineID, OwnerID: c.caller.Machine.OwnerID,
	}
}

// standing checks that the stream's token is unexpired and, at least once
// per streamRecheckInterval, that its enrolment is unchanged.
func (c *checkedStream) standing(d *Decision) error {
	now := c.server.now()
	if !now.Before(c.caller.Principal.Expires) {
		d.Reason = ReasonExpired
		return status.Error(codes.Unauthenticated, "transportauth: the stream's token has expired; open a new stream")
	}
	c.mu.Lock()
	due := now.Sub(c.resolvedAt) >= streamRecheckInterval
	c.mu.Unlock()
	if due {
		machine, err := c.server.resolve(c.ctx, c.caller.Principal, d)
		if err != nil {
			return err
		}
		if machine != c.caller.Machine {
			d.Reason = ReasonNotEnrolled
			return status.Error(codes.Unauthenticated, "transportauth: the credential's enrolment changed")
		}
		c.mu.Lock()
		c.resolvedAt = now
		c.mu.Unlock()
	}
	return nil
}
