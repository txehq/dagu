// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"

	api "github.com/dagucloud/dagu/v2/api/v1"
)

// RequestTxeRunRetry is a placeholder until the decision handlers implement
// it: the registry side is registry.JobTx.ProposeRetry. The handler checks
// that the run is of the job's DAG and reads its snapshot digest and package
// before calling it. Delete this file when that handler lands.
func (a *API) RequestTxeRunRetry(_ context.Context, _ api.RequestTxeRunRetryRequestObject) (api.RequestTxeRunRetryResponseObject, error) {
	return nil, &Error{HTTPStatus: http.StatusNotImplemented, Code: api.ErrorCodeInternalError, Message: "run retry requests are not implemented yet"}
}
