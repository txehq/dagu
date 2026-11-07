// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package intake

import "errors"

// ErrUnboundTriggerUndecided refuses a run no hub principal asks for (a
// webhook delivery) that reaches the queue without the owner rule's decision.
var ErrUnboundTriggerUndecided = errors.New("a run no hub principal asks for is queued only with the owner rule's decision")

// UnboundTrigger records that the owner rule allowed a run no hub principal
// asks for (TXE-5923). Its zero value is no decision, which EnqueueRun
// refuses for such a run, so a new path that queues one without the rule
// fails closed. Only txeauth.DecideUnboundTrigger makes one; a test fails a
// call to NewUnboundTrigger anywhere else.
type UnboundTrigger struct {
	decided bool
}

// NewUnboundTrigger is the owner rule's allowance. Call it only from
// txeauth.DecideUnboundTrigger.
func NewUnboundTrigger() UnboundTrigger {
	return UnboundTrigger{decided: true}
}
