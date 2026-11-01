// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package workerchannel carries a worker's coordinator calls over bounded
// HTTPS requests, so that a machine reaches its hub with outbound 443 and no
// cluster access.
//
// It changes the transport and nothing above it. The worker keeps its
// generated client: Conn is the grpc.ClientConnInterface that client calls.
// The hub keeps its generated service: Handler runs the service descriptor's
// own handlers, behind the transportauth interceptors. No call is translated,
// so leases, claims and the report fence are what they are on gRPC.
//
// The rules it holds:
//
//   - Every request is admitted before its body is read, and a machine's
//     credential is required on every method. The hub key is never accepted.
//   - Only unary and client-streaming methods are carried. A client stream is
//     one request, ended by an explicit frame, so a request that is cut short
//     never looks like one that finished.
//   - Every request has a time limit below the edge's and a size limit. A
//     Poll that finds no task answers empty before the limit.
//   - Only a response that says it is the channel's is believed. Anything an
//     edge answers on its own is Unavailable, never a refusal of the machine.
//   - No redirect is followed, so a credential goes only to the hub's address.
package workerchannel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"google.golang.org/grpc/codes"
)

const (
	// HeaderChannel marks a response as the channel's own.
	HeaderChannel = "X-Txe-Worker-Channel"
	// ChannelVersion is HeaderChannel's value.
	ChannelVersion = "1"
	// HeaderCode carries a call's gRPC status code on the channel's responses.
	HeaderCode = "X-Txe-Channel-Code"
	// HeaderTimeout carries what is left of the caller's deadline, in
	// milliseconds. It can shorten a request's limit and never lengthen it.
	HeaderTimeout = "X-Txe-Channel-Timeout-Ms"

	contentTypeMessage = "application/x-protobuf"
	contentTypeFrames  = "application/x-txe-frames"
	contentTypeError   = "text/plain; charset=utf-8"

	// frameHeaderBytes is the length prefix of a frame on a client stream.
	frameHeaderBytes = 4
	// frameEnd is the length that ends a stream. It is larger than any
	// message may be.
	frameEnd = uint32(0xFFFFFFFF)

	// maxErrorBytes bounds a refusal's text.
	maxErrorBytes = 1024
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
	// MaxMessageBytes is the largest single message, and a unary body.
	MaxMessageBytes int64
	// MaxStreamBytes is the most one client stream may carry.
	MaxStreamBytes int64
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
		MaxStreamBytes:     64 << 20,
		MaxCallsPerMachine: 256,
	}
}

func (l Limits) validate() error {
	if l.Unary <= 0 || l.PollWait <= 0 || l.Stream <= 0 || l.MaxMessageBytes <= 0 || l.MaxStreamBytes <= 0 || l.MaxCallsPerMachine <= 0 {
		return errors.New("workerchannel: every limit must be positive")
	}
	if l.PollWait >= l.Unary {
		return errors.New("workerchannel: a Poll must answer before the unary limit")
	}
	if l.MaxMessageBytes >= int64(frameEnd) {
		return fmt.Errorf("workerchannel: a message must stay below %d bytes", frameEnd)
	}
	return nil
}

func writeFrame(w io.Writer, message []byte) error {
	var header [frameHeaderBytes]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(message))) // #nosec G115 -- bounded by MaxMessageBytes
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(message)
	return err
}

func writeFrameEnd(w io.Writer) error {
	var header [frameHeaderBytes]byte
	binary.BigEndian.PutUint32(header[:], frameEnd)
	_, err := w.Write(header[:])
	return err
}

// statusOf is the HTTP status a code is answered with. It is for whoever
// reads a proxy's logs: the code in HeaderCode is what a Conn believes.
func statusOf(code codes.Code) int {
	switch code { //nolint:exhaustive // every other code is a server error to a proxy
	case codes.OK:
		return http.StatusOK
	case codes.InvalidArgument:
		return http.StatusBadRequest
	case codes.Unauthenticated:
		return http.StatusUnauthorized
	case codes.PermissionDenied:
		return http.StatusForbidden
	case codes.NotFound:
		return http.StatusNotFound
	case codes.FailedPrecondition:
		return http.StatusPreconditionFailed
	case codes.ResourceExhausted:
		return http.StatusTooManyRequests
	case codes.Unimplemented:
		return http.StatusNotImplemented
	case codes.Unavailable:
		return http.StatusServiceUnavailable
	case codes.DeadlineExceeded:
		return http.StatusGatewayTimeout
	default:
		return http.StatusInternalServerError
	}
}

// remaining is what is left of ctx's deadline, or 0 when it has none.
func remaining(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	return max(time.Until(deadline), time.Millisecond)
}
