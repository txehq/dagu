// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// KindLinearIssue is a Linear issue target; KeyLinearIssueID its stable id.
const (
	KindLinearIssue  = "linear.issue"
	KeyLinearIssueID = "id"
	// LinearCredential names the credential reference holding the API key.
	LinearCredential = "linear"
	// LinearEndpoint is Linear's GraphQL API.
	LinearEndpoint = "https://api.linear.app/graphql"
)

// Linear probes Linear issues. It never reports an issue absent: Linear
// answers null for an id it does not show this key, which may be a deleted
// issue, a mistyped id or one outside the key's reach, so a null answer is
// Unknown. An archived issue still exists.
type Linear struct {
	// Endpoint defaults to LinearEndpoint; HTTP to http.DefaultClient.
	Endpoint string
	HTTP     *http.Client
}

func (Linear) Supports(kind string) bool { return kind == KindLinearIssue }

const linearIssueQuery = `query($id: String!) { issue(id: $id) { id identifier archivedAt } }`

type linearResponse struct {
	Data *struct {
		Issue *struct {
			ID         string  `json:"id"`
			Identifier string  `json:"identifier"`
			ArchivedAt *string `json:"archivedAt"`
		} `json:"issue"`
	} `json:"data"`
	Errors []struct {
		Message    string `json:"message"`
		Extensions struct {
			Code string `json:"code"`
			Type string `json:"type"`
		} `json:"extensions"`
	} `json:"errors"`
}

func (l Linear) Probe(ctx context.Context, t Target, creds Credentials) Result {
	id := trimmed(t.StableID[KeyLinearIssueID])
	if id == "" {
		return Result{Outcome: Unknown, Detail: "target has no Linear issue id"}
	}
	cred, ok := creds.Lookup(LinearCredential)
	if !ok {
		return noCredential(creds, LinearCredential)
	}
	key, err := credentialValue(cred)
	if err != nil || key == "" {
		return noCredential(creds, LinearCredential)
	}
	body, _ := json.Marshal(map[string]any{"query": linearIssueQuery, "variables": map[string]string{"id": id}})
	endpoint := l.Endpoint
	if endpoint == "" {
		endpoint = LinearEndpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{Outcome: Unreachable, Detail: "build Linear request: " + err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", key)
	client := l.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return Result{Outcome: classify(ctx, err), Detail: "Linear request: " + redact(err.Error(), key)}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Result{Outcome: classify(ctx, err), Detail: "read Linear response: " + err.Error()}
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return Result{Outcome: AuthDenied, Detail: fmt.Sprintf("Linear refused the key (HTTP %d)", resp.StatusCode)}
	case resp.StatusCode >= 500:
		return Result{Outcome: Unreachable, Detail: fmt.Sprintf("Linear answered HTTP %d", resp.StatusCode)}
	}
	var out linearResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return Result{Outcome: Unreachable, Detail: fmt.Sprintf("Linear answered HTTP %d with an unreadable body", resp.StatusCode)}
	}
	for _, e := range out.Errors {
		code := strings.ToUpper(e.Extensions.Code + " " + e.Extensions.Type)
		if strings.Contains(code, "AUTHENTICATION") || strings.Contains(code, "FORBIDDEN") {
			return Result{Outcome: AuthDenied, Detail: "Linear refused the key: " + e.Message}
		}
	}
	if out.Data != nil && out.Data.Issue != nil {
		issue := out.Data.Issue
		detail := "issue " + issue.Identifier + " exists"
		if issue.ArchivedAt != nil {
			detail += " (archived " + *issue.ArchivedAt + ", not deleted)"
		}
		return Result{Outcome: Present, Detail: detail, Evidence: []string{"linear issue(" + id + "): " + issue.Identifier}}
	}
	detail := "Linear returned no issue for " + id + "; that does not prove it was deleted"
	if len(out.Errors) > 0 {
		detail += ": " + out.Errors[0].Message
	}
	return Result{Outcome: Unknown, Detail: detail, Evidence: []string{"linear issue(" + id + "): null"}}
}

// credentialValue reads a credential's secret: the variable's value, or the
// file's first line.
func credentialValue(c Credential) (string, error) {
	if c.Value != "" {
		return trimmed(c.Value), nil
	}
	if c.Path == "" {
		return "", nil
	}
	b, err := os.ReadFile(c.Path)
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return trimmed(line), nil
}

// redact removes the secret from a message that might echo it.
func redact(msg, secret string) string {
	if secret == "" {
		return msg
	}
	return strings.ReplaceAll(msg, secret, "[redacted]")
}
