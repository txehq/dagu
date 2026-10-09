// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"

	api "github.com/dagucloud/dagu/v2/api/v1"
)

// The decision endpoints belong to TXE-3410, which replaces these handlers.

var errTxeDecisionsUnavailable = &Error{
	HTTPStatus: http.StatusNotImplemented,
	Code:       api.ErrorCodeInternalError,
	Message:    "TXE decisions are not available in this build",
}

func (a *API) DecideTxeProposal(context.Context, api.DecideTxeProposalRequestObject) (api.DecideTxeProposalResponseObject, error) {
	return nil, errTxeDecisionsUnavailable
}

func (a *API) ListTxeProposalDecisions(context.Context, api.ListTxeProposalDecisionsRequestObject) (api.ListTxeProposalDecisionsResponseObject, error) {
	return nil, errTxeDecisionsUnavailable
}
