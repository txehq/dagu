// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/cliauth"
	txepkg "github.com/dagucloud/dagu/v2/internal/txe/pkg"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
)

// txeStepClass is the credential class a step's command needs: a reviewer's
// commands need the reviewer class, and every other step, a job's, the
// worker class.
func txeStepClass(cmd *cobra.Command) authn.Class {
	for current := cmd; current != nil; current = current.Parent() {
		if current.Name() == "review" && current.Parent() != nil && current.Parent().Name() == "txe" {
			return authn.ClassReviewer
		}
	}
	return authn.ClassWorker
}

// txeStepRemote decides what a DAG step's calls to the hub carry.
//
// A step never presents a person's sign-in. When the machine is enrolled for
// the step's class (StepAuth names the class), the step presents the class's
// machine credential, and only it:
//   - the credential file must load as the worker loads it, be this
//     machine's, and be from the identity provider the hub names;
//   - every call carries its access token, renewed from the file as the
//     worker renews it;
//   - a refusal is reported, never retried with the context's API key.
//
// Anything missing or mismatched fails before a call is made. A class the
// machine is not enrolled for keeps the context's API key, and the step says
// so on standard error.
func txeStepRemote(ctx *Context, remote *remoteClient) (*remoteClient, error) {
	class := txeStepClass(ctx.Command)
	home, err := txepkg.DefaultHome()
	if err != nil {
		return nil, err
	}
	auth, err := home.StepAuth()
	if err != nil {
		return nil, fmt.Errorf("this step cannot tell how this machine reaches the hub: %w", err)
	}
	entry, enrolled := auth.Enrolled(string(class))
	if !enrolled {
		_, _ = fmt.Fprintf(ctx.Command.ErrOrStderr(), "txe: this step uses the context's API key: this machine is not enrolled for the %s class\n", class)
		return remote, nil
	}
	if class != authn.ClassWorker {
		return nil, fmt.Errorf("this machine is enrolled for the %s class, but this build reads only worker credentials; nothing was sent", class)
	}
	machine, err := home.Machine()
	if err != nil {
		return nil, err
	}
	credential, err := transportauth.ReadMachineCredential(entry.CredentialFile)
	if err != nil {
		return nil, fmt.Errorf("this machine is enrolled for the %s class, and its credential %s cannot be used (%w); nothing was sent", class, entry.CredentialFile, err)
	}
	if credential.MachineID != machine.MachineID {
		return nil, fmt.Errorf("the %s credential %s is for machine %s, but this machine is %s; nothing was sent", class, entry.CredentialFile, credential.MachineID, machine.MachineID)
	}
	cfg, err := cliauth.DiscoverHub(ctx, remote.baseURL, remote.client)
	if errors.Is(err, cliauth.ErrHubNoSignIn) {
		return nil, fmt.Errorf("the hub at %s names no identity provider, so the %s credential cannot be matched to it; nothing was sent", remote.baseURL, class)
	}
	if err != nil {
		return nil, err
	}
	if cfg.Issuer != credential.Issuer {
		return nil, fmt.Errorf("the %s credential is from %s, but the hub at %s names %s; nothing was sent", class, credential.Issuer, remote.baseURL, cfg.Issuer)
	}
	source, err := transportauth.NewRefreshingSource(entry.CredentialFile, transportauth.WithHTTPClient(&http.Client{Timeout: defaultRemoteTimeout}))
	if err != nil {
		return nil, err
	}
	return remote.withMachineCredential(source), nil
}

// withMachineCredential returns a copy of c whose every call carries the
// machine's access token from source, and never the context's API key.
func (c *remoteClient) withMachineCredential(source transportauth.TokenSource) *remoteClient {
	httpClient := *c.client
	httpClient.Transport = &txeMachineTransport{base: c.client.Transport, source: source}
	return &remoteClient{baseURL: c.baseURL, client: &httpClient}
}

// txeMachineTransport sets the machine's access token on each request.
type txeMachineTransport struct {
	base   http.RoundTripper
	source transportauth.TokenSource
}

func (t *txeMachineTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.source.Token(req.Context())
	if err != nil {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, fmt.Errorf("renew this machine's access token: %w", err)
	}
	out := req.Clone(req.Context())
	out.Header.Set("Authorization", "Bearer "+token)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(out)
}
