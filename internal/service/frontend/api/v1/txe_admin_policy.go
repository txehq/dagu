// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api

import (
	"context"
	"net/http"

	api "github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
)

// The hub's administrator and manager roles under owner enforcement
// (TXE-6139).
//
// Under enforce only the platform administrator is decided as the hub's
// administrator (txeauth.Classify): an admin-role API key, a user a trusted
// proxy names, and every other credential the hub accepted before owners
// existed are legacy callers, and a person or token from the identity
// provider is held to its owner. The hub's roles say nothing about owners,
// so a route that asks only for a role must say what it reaches:
//
//   - txeAdminPlatform: the installation itself, or every owner at once.
//     Accounts and API keys, remote nodes and the credentials they hold,
//     the license, Git sync, the scheduler, and runtime profiles that are
//     protected or inherited by every workflow. requireAdmin decides it:
//     the hub's administrator role as before, and on top of it the platform
//     rule, txePlatformReserved. Under enforce only the platform
//     administrator passes, with errTxePlatformAdmin for anyone else; a
//     caller held to its owner never passes, in any mode; in off and
//     observe the role alone decides, and observe logs what enforce would
//     refuse.
//   - txeAdminHubRecords: a read of the whole hub's records that is not
//     decided DAG by DAG, audit and event logs. The manager role as before,
//     then txeHubHidden (TXE-4752), which is the same platform rule with
//     the hub-records refusal.
//   - txeAdminOwnerScoped: an operation on one DAG, decided on that DAG's
//     owner by txeNativeWriteClosed or txeDAGFileRoute. The role is the hub's
//     own check for the callers the hub's roles govern; the owner decision
//     is what refuses a legacy caller under enforce.
//   - txeAdminUnowned: a runtime profile that is not protected: a resource
//     of the whole hub that the hub's manager role has always administered
//     and that no owner holds. The manager role alone decides, as before;
//     what a caller held to its owner may do with a profile is decided
//     where it would use one (explicitRunProfile), and the protected ones
//     are txeAdminPlatform.
//
// Every function in this package that calls requireAdmin or
// requireManagerOrAbove is classified in txeAdminOperations, with what it
// means to owners; the guard test fails a caller that is not, a class that
// does not match the call, and an entry nothing calls.

// txeAdminClass says what a route guarded by the hub's administrator or
// manager role reaches, and so who passes it under owner enforcement.
type txeAdminClass string

const (
	// txeAdminPlatform is the installation's own, or every owner's at once:
	// under enforce the platform administrator's alone.
	txeAdminPlatform txeAdminClass = "platform"
	// txeAdminHubRecords is a whole-hub read hidden under enforce from
	// everyone but the platform administrator (txeHubHidden, TXE-4752).
	txeAdminHubRecords txeAdminClass = "hub_records"
	// txeAdminOwnerScoped is an operation on one DAG, decided on that DAG's
	// owner before or around the role.
	txeAdminOwnerScoped txeAdminClass = "owner_scoped"
	// txeAdminUnowned is a resource of the whole hub that no owner holds and
	// the manager role has always administered.
	txeAdminUnowned txeAdminClass = "unowned"
)

// txeAdminOperation is one classified use of the administrator or manager
// role: its class, and what the operation means to owners.
type txeAdminOperation struct {
	class  txeAdminClass
	owners string
}

// txeAdminOperations classifies every function in this package that asks
// for the hub's administrator or manager role, by name. It is the single
// source of truth the guard test holds the source to.
var txeAdminOperations = map[string]txeAdminOperation{
	// API keys: a key acts with a hub role on every owner's data the mode
	// lets it; only the platform administrator issues or revokes one.
	"ListAPIKeys":       {txeAdminPlatform, "lists every credential that may act on the hub"},
	"CreateAPIKey":      {txeAdminPlatform, "mints a credential with a hub role"},
	"GetAPIKey":         {txeAdminPlatform, "reads a credential's role and surfaces"},
	"UpdateAPIKey":      {txeAdminPlatform, "changes a credential's role or surfaces"},
	"DeleteAPIKey":      {txeAdminPlatform, "revokes a credential"},
	"ListUsers":         {txeAdminPlatform, "lists every account, owners' persons included"},
	"CreateUser":        {txeAdminPlatform, "creates an account with a hub role"},
	"GetUser":           {txeAdminPlatform, "reads an account and its role"},
	"UpdateUser":        {txeAdminPlatform, "changes an account's role or disables it"},
	"DeleteUser":        {txeAdminPlatform, "removes an account"},
	"ResetUserPassword": {txeAdminPlatform, "takes over an account by setting its password"},
	// Remote nodes carry stored credentials to other hubs.
	"ListRemoteNodes":          {txeAdminPlatform, "lists the hubs this one holds credentials for"},
	"CreateRemoteNode":         {txeAdminPlatform, "stores a credential for another hub"},
	"GetRemoteNode":            {txeAdminPlatform, "reads a remote hub's connection"},
	"UpdateRemoteNode":         {txeAdminPlatform, "changes a stored credential"},
	"DeleteRemoteNode":         {txeAdminPlatform, "removes a remote hub"},
	"TestRemoteNodeConnection": {txeAdminPlatform, "uses a stored credential against another hub"},
	// The license is the installation's.
	"ActivateLicense":   {txeAdminPlatform, "binds the installation to a license"},
	"DeactivateLicense": {txeAdminPlatform, "ends the installation's license"},
	// Git sync publishes and pulls every owner's DAG files.
	"syncProxyAuthorization": {txeAdminPlatform, "configures or tests Git sync on a remote hub, before its credential is used"},
	"SyncTestConnection":     {txeAdminPlatform, "uses the Git credential against the remote repository"},
	"UpdateSyncConfig":       {txeAdminPlatform, "changes where every owner's DAG files are published"},
	// The scheduler runs every owner's schedules.
	"UpdateSchedulerPauseState": {txeAdminPlatform, "pauses or resumes every owner's schedules at once"},
	// Runtime profiles: a protected profile, and the defaults every
	// workflow inherits, carry values into every owner's runs.
	"requireRuntimeProfileManage":            {txeAdminUnowned, "changes a profile; a protected one is the platform's"},
	"requireRuntimeProfileUpdate":            {txeAdminUnowned, "changes a profile or protects it; a protected one is the platform's"},
	"requireRuntimeProfileView":              {txeAdminPlatform, "reads a protected profile's entries"},
	"ListRuntimeProfiles":                    {txeAdminUnowned, "lists the profiles; protected ones only for the platform administrator"},
	"CreateRuntimeProfile":                   {txeAdminUnowned, "creates a profile; a protected one is the platform's"},
	"GetGlobalRuntimeProfileDefaults":        {txeAdminPlatform, "reads the values every owner's run inherits"},
	"UpdateGlobalRuntimeProfileDefaults":     {txeAdminPlatform, "changes the values every owner's run inherits"},
	"SetGlobalRuntimeProfileDefaultVariable": {txeAdminPlatform, "sets a value every owner's run inherits"},
	"SetGlobalRuntimeProfileDefaultSecret":   {txeAdminPlatform, "sets a secret every owner's run inherits"},
	"DeleteGlobalRuntimeProfileDefaultEntry": {txeAdminPlatform, "removes a value every owner's run inherits"},
	"getRuntimeProfileForView":               {txeAdminUnowned, "reads a profile"},
	"ensureRunnableRuntimeProfileAccess":     {txeAdminPlatform, "runs with a protected profile's values"},
	// Webhooks: decided on the DAG first; the role is reached only by the
	// callers the hub's roles govern.
	"ConfigureDAGWebhookProfileSelection": {txeAdminOwnerScoped, "chooses which profiles a DAG's webhook callers may run with"},
	"CreateDAGWebhookProfileToken":        {txeAdminOwnerScoped, "mints a webhook token that runs a DAG with a profile"},
	"RevokeDAGWebhookProfileToken":        {txeAdminOwnerScoped, "revokes such a token"},
	// Whole-hub records.
	"ListAuditLogs": {txeAdminHubRecords, "reads every owner's actions"},
	"ListEventLogs": {txeAdminHubRecords, "reads every owner's run events"},
	// A DAG's settings, decided as a write to that DAG.
	"ValidateDAGProfileUpdate": {txeAdminOwnerScoped, "sets the profile a DAG runs with"},
}

// errTxePlatformAdmin refuses the hub's administration to a caller owner
// enforcement does not take for the platform administrator.
var errTxePlatformAdmin = &Error{
	HTTPStatus: http.StatusForbidden,
	Code:       api.ErrorCodeForbidden,
	Message:    "under owner enforcement only the platform administrator administers the hub",
	Details:    map[string]any{"code": "platform_admin_required"},
}

// txePlatformReserved is the platform rule: whether what is the platform's
// is held from the request's caller. It is a caller held to its owner, in
// every mode, or under enforce anyone but the platform administrator. In
// observe it reports false and logs what enforce would refuse. An error is
// an owner store that could not be read where the mode decides; the caller
// refuses. Every decision on the platform's own resources goes through it,
// so they cannot drift: requireAdmin, txeHubHidden, and the writes to what
// the whole hub shares.
func (a *API) txePlatformReserved(ctx context.Context) (bool, error) {
	if a.txeAuth == nil {
		return false, nil
	}
	c, err := a.txeResolve(ctx)
	if err != nil {
		return true, err
	}
	if c.ownerOnly() {
		return true, nil
	}
	if c.mode == authz.ModeOff || c.failed || c.scope.Kind() == authz.ScopePlatformAdmin {
		return false, nil
	}
	a.txeLogDecision(ctx, c, authz.PermissionAdminister, authz.Platform(), authz.Decision{
		Allowed: c.mode == authz.ModeObserve, Mode: c.mode, Evaluated: true,
		WouldDeny: c.mode == authz.ModeObserve, Reason: authz.ReasonNotOwner})
	return c.mode == authz.ModeEnforce, nil
}

// txeRequirePlatform applies the platform rule to a route of the
// txeAdminPlatform class, after the hub's own role check.
func (a *API) txeRequirePlatform(ctx context.Context) error {
	reserved, err := a.txePlatformReserved(ctx)
	if err != nil {
		return err
	}
	if reserved {
		return errTxePlatformAdmin
	}
	return nil
}
