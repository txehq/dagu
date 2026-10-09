// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Package txeclient talks to the TXE job registry served by a Dagu hub at
// /api/v1/txe, and runs the registration of a job from this machine.
package txeclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Registry refusal codes carried in an error's details.
const (
	CodeDuplicate       = "duplicate"
	CodeVersionConflict = "version_conflict"
	CodeInvalid         = "invalid"
	CodeNotFound        = "not_found"
)

// Client sends authenticated JSON requests to one hub. Typed registry calls
// are methods on it; other packages build their own calls on Do.
type Client struct {
	// BaseURL is the hub's API root, such as http://127.0.0.1:18080/api/v1.
	BaseURL string
	// APIKey is sent as a bearer token. It is read from the CLI's context
	// store by the caller and is never written anywhere by this package.
	APIKey string
	HTTP   *http.Client
}

// New returns a client for the API rooted at baseURL.
func New(baseURL, apiKey string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), APIKey: apiKey, HTTP: httpClient}
}

// Error is a response outside the 2xx range.
type Error struct {
	// Status is the HTTP status code.
	Status int
	// Message is the hub's description of the refusal.
	Message string
	// Code is the registry's own code for the refusal, such as "duplicate"
	// or "version_conflict". It is empty when the response is not a registry
	// refusal.
	Code string
	// Current is the record to re-read after a conflict, when the hub sent one.
	Current json.RawMessage
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("hub refused the request (%d %s): %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("hub refused the request (%d): %s", e.Status, e.Message)
}

// rejectsRequest reports whether the hub understood the request and refused
// it, so that sending it again cannot succeed. Authentication failures, rate
// limits and server errors are not refusals of the request itself.
func (e *Error) rejectsRequest() bool {
	switch e.Status {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}

// IsCode reports whether err is a registry refusal with the given code.
func IsCode(err error, code string) bool {
	var refusal *Error
	return errors.As(err, &refusal) && refusal.Code == code
}

// Do sends one request. in, when not nil, is the JSON body; out, when not
// nil, receives the JSON response. A response outside 2xx is returned as *Error.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	target := c.BaseURL + path
	if encoded := query.Encode(); encoded != "" {
		target += "?" + encoded
	}

	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%s %s: read response: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return decodeError(resp.StatusCode, resp.Status, data)
	}
	if out == nil {
		return nil
	}
	if raw, ok := out.(*json.RawMessage); ok {
		*raw = append((*raw)[:0], data...)
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s: decode response: %w", method, path, err)
	}
	return nil
}

// decodeError reads Dagu's error envelope. A registry refusal puts its own
// code and the current record under details.
func decodeError(status int, statusText string, data []byte) *Error {
	var envelope struct {
		Message string `json:"message"`
		Details struct {
			Code    string          `json:"code"`
			Current json.RawMessage `json:"current"`
		} `json:"details"`
	}
	refusal := &Error{Status: status}
	if err := json.Unmarshal(data, &envelope); err == nil && envelope.Message != "" {
		refusal.Message = envelope.Message
		refusal.Code = envelope.Details.Code
		refusal.Current = envelope.Details.Current
		return refusal
	}
	refusal.Message = strings.TrimSpace(string(data))
	if refusal.Message == "" {
		refusal.Message = statusText
	}
	return refusal
}
