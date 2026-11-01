// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package workerchannel carries a worker's coordinator calls over the Connect
// protocol, so that a machine reaches its hub with outbound 443 and no cluster
// access.
//
// It changes the transport and nothing above it. The worker keeps its
// generated gRPC client: Conn is the grpc.ClientConnInterface that client
// calls. The hub keeps its generated service: Handler calls it behind the
// transportauth interceptors. The messages are the generated ones, so leases,
// claims and the report fence are what they are on gRPC.
//
// A method is carried only if it is listed in methods.go. What a worker needs
// that is not listed fails closed, as it does on an enforcing coordinator.
//
// The rules it holds:
//
//   - Every request is admitted before its body is read, and a machine's
//     credential is required on every method. The hub key is never accepted.
//   - Only Connect with binary protobuf is accepted. This route never speaks
//     gRPC, gRPC-Web or JSON, and nothing is compressed.
//   - Every request has a time limit below the edge's and a size limit. A
//     Poll that finds no task answers empty before the limit.
//   - Only a Connect error is a refusal. A status from anything else, such as
//     an edge, is Unavailable, because the HTTP status alone cannot say that
//     the hub refused this machine.
//   - No redirect is followed, so a credential goes only to the hub's address.
//
// A client stream ends when its request body ends, so a stream's end says
// nothing about whether its work is complete. That is said where it always
// was: a final chunk finalizes a log and commits an artifact, and a reply
// reaches the worker only for a request it finished.
package workerchannel

import (
	"errors"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Limits bounds what one request may take. The defaults sit below Cloudflare's
// proxy read timeout of 125 s.
type Limits struct {
	// Unary is the longest a unary call may run.
	Unary time.Duration
	// PollWait is how long a Poll waits for a task before it answers empty.
	PollWait time.Duration
	// Stream is the longest a client stream may stay open.
	Stream time.Duration
	// MaxMessageBytes is the largest single message.
	MaxMessageBytes int
	// MaxRequestBytes is the most one request may carry. It must fit the
	// edge's request body limit. A longer upload is several requests.
	MaxRequestBytes int64
	// MaxCallsPerMachine is how many calls of one machine run at once. A
	// worker keeps one Poll open per run it may take.
	MaxCallsPerMachine int
}

// DefaultLimits are the limits a Handler and a Conn use unless told otherwise.
func DefaultLimits() Limits {
	return Limits{
		Unary:              30 * time.Second,
		PollWait:           25 * time.Second,
		Stream:             110 * time.Second,
		MaxMessageBytes:    16 << 20,
		MaxRequestBytes:    32 << 20,
		MaxCallsPerMachine: 256,
	}
}

func (l Limits) validate() error {
	if l.Unary <= 0 || l.PollWait <= 0 || l.Stream <= 0 || l.MaxMessageBytes <= 0 || l.MaxRequestBytes <= 0 || l.MaxCallsPerMachine <= 0 {
		return errors.New("workerchannel: every limit must be positive")
	}
	if l.PollWait >= l.Unary {
		return errors.New("workerchannel: a Poll must answer before the unary limit")
	}
	if int64(l.MaxMessageBytes) > l.MaxRequestBytes {
		return errors.New("workerchannel: a message must fit in a request")
	}
	return nil
}

// toConnect gives a gRPC status error to the Connect protocol. The codes share
// their numbers.
func toConnect(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*connect.Error](err); ok {
		return err
	}
	s := status.Convert(asStatus(err))
	return connect.NewError(connect.Code(s.Code()), errors.New(s.Message())) // #nosec G115 -- a gRPC code
}

// fromConnect gives a call's error to the generated client. An error that did
// not come from a Connect peer says nothing about this machine.
func fromConnect(err error) error {
	if err == nil {
		return nil
	}
	if !connect.IsWireError(err) {
		return status.Error(codes.Unavailable, "workerchannel: the hub did not answer: "+err.Error())
	}
	if refusal, ok := errors.AsType[*connect.Error](err); ok {
		return status.Error(codes.Code(refusal.Code()), refusal.Message())
	}
	return status.Error(codes.Unavailable, "workerchannel: the hub did not answer")
}
