// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cmd

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	api "github.com/dagucloud/dagu/v2/api/v1"
)

// getDAGSpec returns a DAG's stored YAML. found is false when the hub has no
// DAG of that name.
func (c *remoteClient) getDAGSpec(ctx context.Context, fileName string) (spec string, found bool, err error) {
	var out api.GetDAGSpec200JSONResponse
	err = c.do(ctx, http.MethodGet, "/dags/"+url.PathEscape(fileName)+"/spec", nil, &out, nil)
	var remoteErr *remoteError
	if errors.As(err, &remoteErr) && remoteErr.NotFound() {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return out.Spec, true, nil
}

// createDAG creates a DAG from spec; the hub validates the spec first.
func (c *remoteClient) createDAG(ctx context.Context, fileName, spec string) error {
	body := api.CreateNewDAGJSONBody{Name: fileName, Spec: &spec}
	return c.do(ctx, http.MethodPost, "/dags", body, nil, nil)
}

// updateDAGSpec replaces a DAG's YAML. The hub reports a spec it could not
// load as errors in a successful response; they are returned as an error.
func (c *remoteClient) updateDAGSpec(ctx context.Context, fileName, spec string) error {
	var out api.UpdateDAGSpec200JSONResponse
	if err := c.do(ctx, http.MethodPut, "/dags/"+url.PathEscape(fileName)+"/spec", api.UpdateDAGSpecJSONBody{Spec: spec}, &out, nil); err != nil {
		return err
	}
	if len(out.Errors) > 0 {
		return &remoteSpecError{Errors: out.Errors}
	}
	return nil
}

// listWorkers returns the coordinator's distributed workers.
func (c *remoteClient) listWorkers(ctx context.Context) ([]api.Worker, error) {
	var out api.WorkersListResponse
	if err := c.do(ctx, http.MethodGet, "/workers", nil, &out, nil); err != nil {
		return nil, err
	}
	return out.Workers, nil
}

// remoteSpecError is a spec the hub stored but could not load.
type remoteSpecError struct{ Errors []string }

func (e *remoteSpecError) Error() string {
	return "the hub reported errors in the DAG spec: " + strings.Join(e.Errors, "; ")
}
