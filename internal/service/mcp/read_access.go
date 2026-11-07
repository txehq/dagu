// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package mcp

import (
	"context"
	"errors"
	"fmt"
)

// readTargetSource says where a dagu_read target reads from, which decides
// who may read it (TXE-5923).
type readTargetSource int

const (
	// readFromStatic is text compiled into the binary.
	readFromStatic readTargetSource = iota + 1
	// readFromAPI is the hub's API, which decides the caller's access for
	// each read.
	readFromAPI
	// readFromHostFile is a file on the hub's own host, which no API
	// decision covers: a call from Dagu Cloud never reads one, and a local
	// caller needs frontendapi.API.RequireHostFileRead.
	readFromHostFile
)

// readTargetSources is the one list of dagu_read targets and their sources.
// A target missing from it is refused to every caller, so a new target is
// denied until it is classified here; TestEveryReadTargetHasASource fails a
// target readToolImpl serves that is not listed.
var readTargetSources = map[string]readTargetSource{
	readTargetReferences:   readFromStatic,
	readTargetReference:    readFromStatic,
	readTargetDAGs:         readFromAPI,
	readTargetDAG:          readFromAPI,
	readTargetDAGSpec:      readFromAPI,
	readTargetDAGProfile:   readFromAPI,
	readTargetDAGSearch:    readFromAPI,
	readTargetWiki:         readFromAPI,
	readTargetWikiPage:     readFromAPI,
	readTargetWikiSearch:   readFromAPI,
	readTargetRuns:         readFromAPI,
	readTargetRun:          readFromAPI,
	readTargetRunLogs:      readFromAPI,
	readTargetStepLog:      readFromAPI,
	readTargetForeachItems: readFromAPI,
	readTargetForeachItem:  readFromAPI,
	readTargetWorkbook:     readFromHostFile,
}

// cloudTools is the one list of tools a call from Dagu Cloud may use. A tool
// missing from it is not offered on the Cloud server, so a new tool is denied
// to Cloud until it is listed; TestEveryToolHasACloudDecision fails a tool the
// local server offers that is not listed either way.
var cloudTools = map[string]bool{
	toolRead:    true, // each target as readTargetSources decides
	toolChange:  true, // through the API, which decides the caller's access
	toolExecute: true, // through the API, and approvals as remoteCalls decides
}

// authorizeReadTarget decides, before anything is read, whether the caller
// may read target at all.
func (svc *Service) authorizeReadTarget(ctx context.Context, target string) error {
	source, ok := readTargetSources[target]
	if !ok {
		return &readToolError{
			Code:    readErrorUnsupportedReadTarget,
			Message: fmt.Sprintf("read target %q is not available", target),
			Target:  target,
			Field:   readFieldTarget,
		}
	}
	if source != readFromHostFile {
		return nil
	}
	if svc.remote != nil {
		return &readToolError{
			Code:    readErrorUnsupportedReadTarget,
			Message: fmt.Sprintf("read target %q reads a file on this server's host, which calls from Dagu Cloud may not", target),
			Target:  target,
			Field:   readFieldTarget,
		}
	}
	if svc.api == nil {
		return errors.New("dagu API is not configured")
	}
	return svc.api.RequireHostFileRead(ctx)
}
