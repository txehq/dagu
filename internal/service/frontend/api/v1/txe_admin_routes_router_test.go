// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dagucloud/dagu/v2/api/v1"
	"github.com/dagucloud/dagu/v2/internal/cmn/config"
	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/license"
	"github.com/dagucloud/dagu/v2/internal/service/frontend"
	"github.com/dagucloud/dagu/v2/internal/test"
	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/authz"
	"github.com/dagucloud/dagu/v2/internal/txe/registry"
	"github.com/dagucloud/dagu/v2/internal/txe/txeauth"
)

// adminHub is a hub in the given owner mode, served through its real
// router, with every kind of caller the hub's administrator and manager
// routes can meet (TXE-6139): the platform administrator (the builtin
// administrator), a second builtin account with the administrator role, a
// builtin manager, an API key with the administrator role, an administrator
// a trusted proxy named, and the bound command-line token of an owner. It
// holds an ownerless DAG, a plain runtime profile and a protected one.
type adminHub struct {
	server    test.Server
	base      string
	bearers   map[string]string
	protected string
	plain     string
}

// The callers, by what txeauth.Classify makes of them.
const (
	callerPlatformAdmin = "platform administrator"
	callerSecondAdmin   = "a second builtin administrator"
	callerManager       = "a builtin manager"
	callerAdminKey      = "an admin-role API key"
	callerProxyAdmin    = "a trusted-proxy administrator"
	callerOwner         = "an owner's command line"
)

var adminHubCallers = []string{callerPlatformAdmin, callerSecondAdmin, callerManager, callerAdminKey, callerProxyAdmin, callerOwner}

func newAdminHub(t *testing.T, mode string) adminHub {
	t.Helper()
	jwks := providerKeys(t)
	server := test.SetupServer(t, test.WithConfigMutator(func(cfg *config.Config) {
		cfg.Server.Auth.Mode = config.AuthModeBuiltin
		cfg.Server.Auth.Builtin.Token.Secret = "jwt-secret-key"
		cfg.Server.Auth.Builtin.Token.TTL = 24 * time.Hour
		cfg.Server.Auth.Proxy.Enabled = true
		cfg.Server.Auth.Proxy.Headers.User = "X-Proxy-User"
		cfg.Server.Auth.Proxy.Headers.Groups = "X-Proxy-Groups"
		cfg.Server.Auth.Proxy.AutoSignup = true
		cfg.Server.Auth.Proxy.RoleMapping.DefaultRole = "viewer"
		cfg.Server.Auth.Proxy.RoleMapping.GroupMappings = map[string]string{"hub-admins": "admin"}
		cfg.Server.Auth.Proxy.RoleMapping.DefaultWorkspaceAccess = config.TrustedProxyDefaultWorkspaceAccessAll
		cfg.TXE.Authz.Mode = mode
		cfg.TXE.Authn = config.TXEAuthnConfig{
			Issuer: providerIssuer, Audience: providerAudience, JWKSURL: jwks + "/certs",
			Clients: []config.TXEAuthnClient{{ID: providerCLI, Class: "cli"}},
		}
	}), test.WithServerOptions(frontend.WithLicenseManager(license.NewTestManager(license.FeatureRBAC, license.FeatureAudit, license.FeatureSSO))))
	server.Client().Post("/api/v1/auth/setup", api.SetupRequest{Username: "admin", Password: "adminpass"}).
		ExpectStatus(http.StatusOK).Send(t)
	h := adminHub{server: server, bearers: map[string]string{}}
	h.base = fmt.Sprintf("http://%s:%d", server.Config.Server.Host, server.Config.Server.Port)
	admin := getAdminToken(t, server)
	h.bearers[callerPlatformAdmin] = admin

	login := func(username, password string, role api.UserRole) string {
		server.Client().Post("/api/v1/users", api.CreateUserRequest{Username: username, Password: password, Role: role}).
			WithBearerToken(admin).ExpectStatus(http.StatusCreated).Send(t)
		var in api.LoginResponse
		server.Client().Post("/api/v1/auth/login", api.LoginRequest{Username: username, Password: password}).
			ExpectStatus(http.StatusOK).Send(t).Unmarshal(t, &in)
		return in.Token
	}
	h.bearers[callerSecondAdmin] = login("second-admin", "secondpass1", api.UserRoleAdmin)
	h.bearers[callerManager] = login("legacy-manager", "legacypass1", api.UserRoleManager)
	h.bearers[callerAdminKey] = createAPIKeyForRole(t, server, admin, "automation", api.UserRoleAdmin)
	h.bearers[callerProxyAdmin] = h.proxyLogin(t, "proxied-admin", "hub-admins")

	// Owner A, its machine, and subject-a bound to A, written where the hub
	// reads them; the command line's token acts for A.
	ctx := context.Background()
	dataDir := server.Config.Paths.DataDir
	reg, err := registry.NewFileStore(dataDir)
	require.NoError(t, err)
	owners, err := txeauth.NewService(config.TXEConfig{}, dataDir, reg)
	require.NoError(t, err)
	system := registry.Actor{Kind: registry.ActorSystem, ID: "test"}
	ownerA, err := registry.NewID(registry.PrefixOwner, time.Now())
	require.NoError(t, err)
	_, err = reg.CreateOwner(ctx, registry.Owner{OwnerID: ownerA, DisplayName: ownerA}, system)
	require.NoError(t, err)
	id := authn.Identity{Issuer: providerIssuer, Subject: "subject-a"}
	_, err = owners.Store().RequestBinding(ctx, authn.Principal{Identity: id, Class: authn.ClassPerson}, authz.Shown{})
	require.NoError(t, err)
	_, err = owners.Store().ApproveBinding(ctx, authz.PlatformAdmin("admin"), id, ownerA)
	require.NoError(t, err)
	h.bearers[callerOwner] = providerToken(t, time.Now(), 5*time.Minute)

	server.CreateDAGFile(t, server.Config.Paths.DAGsDir, "ownerless", []byte("steps:\n  - name: s\n    run: echo s\n"))
	h.plain, h.protected = "plain", "protected"
	server.Client().Post("/api/v1/profiles", api.CreateRuntimeProfileJSONRequestBody{Name: h.plain}).
		WithBearerToken(admin).ExpectStatus(http.StatusCreated).Send(t)
	yes := true
	server.Client().Post("/api/v1/profiles", api.CreateRuntimeProfileJSONRequestBody{Name: h.protected, Protected: &yes}).
		WithBearerToken(admin).ExpectStatus(http.StatusCreated).Send(t)
	// What a caller may remove is its own: a profile per caller, and an
	// entry per caller on the plain profile, so a removal that passes
	// leaves nothing in another caller's way.
	for _, caller := range adminHubCallers {
		server.Client().Post("/api/v1/profiles", api.CreateRuntimeProfileJSONRequestBody{Name: "del-" + slug(caller)}).
			WithBearerToken(admin).ExpectStatus(http.StatusCreated).Send(t)
		server.Client().Put("/api/v1/profiles/"+h.plain+"/variables/"+callerKey(caller), map[string]any{"value": "v"}).
			WithBearerToken(admin).ExpectStatus(http.StatusOK).Send(t)
	}
	return h
}

// callerKey is an environment key naming the caller, for an entry of its own.
func callerKey(caller string) string {
	return "K_" + strings.ToUpper(strings.ReplaceAll(slug(caller), "-", "_"))
}

// routePath fills a route's path for the caller: {caller} is the caller's
// slug and {key} its environment key.
func routePath(path, caller string) string {
	return strings.NewReplacer("{caller}", slug(caller), "{key}", callerKey(caller)).Replace(path)
}

// proxyLogin signs a user the trusted proxy names in, with the groups the
// proxy reports, and returns the hub token the login hands the browser in
// the redirect's fragment.
func (h adminHub) proxyLogin(t *testing.T, user, groups string) string {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, h.base+"/proxy-login", nil)
	require.NoError(t, err)
	req.Header.Set("X-Proxy-User", user)
	req.Header.Set("X-Proxy-Groups", groups)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	fragment, err := url.ParseQuery(location.Fragment)
	require.NoError(t, err)
	require.NotEmpty(t, fragment.Get("token"), resp.Header.Get("Location"))
	return fragment.Get("token")
}

// call sends one request as the caller and returns the status and body.
func (h adminHub) call(t *testing.T, method, path string, body any, caller string) (int, string) {
	t.Helper()
	c := h.server.Client()
	var req *test.Request
	switch method {
	case http.MethodGet:
		req = c.Get(path)
	case http.MethodPost:
		req = c.Post(path, body)
	case http.MethodPut:
		req = c.Put(path, body)
	case http.MethodPatch:
		req = c.Patch(path, body)
	case http.MethodDelete:
		req = c.Delete(path)
	default:
		t.Fatalf("method %s", method)
	}
	resp := req.WithBearerToken(h.bearers[caller]).Send(t)
	return resp.Response.StatusCode(), resp.Body
}

// adminRoute is one route the hub's administrator or manager role guards,
// as the sweep exercises it. Its body may name the caller, so that a
// create that passes leaves nothing in another caller's way.
type adminRoute struct {
	handler, method, path string
	body                  func(caller string) any
	class                 string
	// managerPasses says whether the builtin manager passes the route's
	// own role check: an owner-scoped or unowned route the manager role
	// opens, or a platform-class write the manager role opens in off and
	// observe (a profile that is not protected).
	managerPasses bool
	// dagFirst marks a platform-class decision reached only after the
	// DAG's owner decision (a run with a protected profile): under enforce
	// a legacy caller is refused by that decision, as not found, before the
	// platform rule is asked.
	dagFirst bool
}

const (
	classPlatform   = "platform"
	classHubRecords = "hub_records"
	classOwner      = "owner_scoped"
	classUnowned    = "unowned"
)

func none(string) any { return map[string]any{} }

func slug(caller string) string {
	return strings.NewReplacer(" ", "-", "'", "").Replace(strings.ToLower(caller))
}

// adminRoutes are the routes under every function txeAdminOperations
// classifies, each reached through the real router; the set of functions
// they reach is held to the inventory and to the source by
// TestTxeAdminRoutesReachEveryClassifiedFunction.
func (h adminHub) adminRoutes() []adminRoute {
	p := func(handler, method, path string, body func(string) any) adminRoute {
		return adminRoute{handler: handler, method: method, path: path, body: body, class: classPlatform}
	}
	return []adminRoute{
		p("ListAPIKeys", http.MethodGet, "/api/v1/api-keys", none),
		p("CreateAPIKey", http.MethodPost, "/api/v1/api-keys", func(c string) any { return newCreateAPIKeyRequest("key-of-"+slug(c), api.UserRoleViewer) }),
		p("GetAPIKey", http.MethodGet, "/api/v1/api-keys/nope", none),
		p("UpdateAPIKey", http.MethodPatch, "/api/v1/api-keys/nope", func(string) any { return map[string]any{"name": "renamed"} }),
		p("DeleteAPIKey", http.MethodDelete, "/api/v1/api-keys/nope", none),
		p("ListUsers", http.MethodGet, "/api/v1/users", none),
		p("CreateUser", http.MethodPost, "/api/v1/users", func(c string) any {
			return api.CreateUserRequest{Username: "user-of-" + slug(c), Password: "password1234", Role: api.UserRoleViewer}
		}),
		p("GetUser", http.MethodGet, "/api/v1/users/nope", none),
		p("UpdateUser", http.MethodPatch, "/api/v1/users/nope", none),
		p("DeleteUser", http.MethodDelete, "/api/v1/users/nope", none),
		p("ResetUserPassword", http.MethodPost, "/api/v1/users/nope/reset-password", func(string) any { return api.ResetPasswordRequest{NewPassword: "password1234"} }),
		p("ListRemoteNodes", http.MethodGet, "/api/v1/remote-nodes", none),
		p("CreateRemoteNode", http.MethodPost, "/api/v1/remote-nodes", func(c string) any {
			return api.CreateRemoteNodeRequest{Name: "node-of-" + slug(c), ApiBaseUrl: "http://127.0.0.1:9/api/v1"}
		}),
		p("GetRemoteNode", http.MethodGet, "/api/v1/remote-nodes/nope", none),
		p("UpdateRemoteNode", http.MethodPatch, "/api/v1/remote-nodes/nope", none),
		p("DeleteRemoteNode", http.MethodDelete, "/api/v1/remote-nodes/nope", none),
		p("TestRemoteNodeConnection", http.MethodPost, "/api/v1/remote-nodes/nope/test-connection", none),
		p("SyncTestConnection", http.MethodPost, "/api/v1/sync/test-connection", none),
		p("UpdateSyncConfig", http.MethodPut, "/api/v1/sync/config", none),
		p("syncProxyAuthorization", http.MethodPut, "/api/v1/sync/config?remoteNode=nope", none),
		p("syncProxyAuthorization", http.MethodPost, "/api/v1/sync/test-connection?remoteNode=nope", none),
		p("UpdateSchedulerPauseState", http.MethodPost, "/api/v1/services/scheduler/pause", func(string) any { return map[string]any{"paused": false} }),
		p("requireRuntimeProfileView", http.MethodGet, "/api/v1/profiles/"+h.protected, none),
		// Writes to a protected profile: the administrator role, as before.
		p("requireRuntimeProfileWrite", http.MethodPatch, "/api/v1/profiles/"+h.protected, func(string) any { return map[string]any{"description": "touched"} }),
		p("requireRuntimeProfileWrite", http.MethodPut, "/api/v1/profiles/"+h.protected+"/variables/K", func(string) any { return map[string]any{"value": "v"} }),
		p("requireRuntimeProfileWrite", http.MethodPost, "/api/v1/profiles", func(c string) any {
			yes := true
			return api.CreateRuntimeProfileJSONRequestBody{Name: "protected-of-" + slug(c), Protected: &yes}
		}),
		p("GetGlobalRuntimeProfileDefaults", http.MethodGet, "/api/v1/profiles/_global", none),
		p("UpdateGlobalRuntimeProfileDefaults", http.MethodPatch, "/api/v1/profiles/_global", none),
		p("SetGlobalRuntimeProfileDefaultVariable", http.MethodPut, "/api/v1/profiles/_global/variables/K", func(string) any { return map[string]any{"value": "v"} }),
		p("SetGlobalRuntimeProfileDefaultSecret", http.MethodPut, "/api/v1/profiles/_global/secrets/S", func(string) any { return map[string]any{"value": "v"} }),
		p("DeleteGlobalRuntimeProfileDefaultEntry", http.MethodDelete, "/api/v1/profiles/_global/entries/K", none),
		{handler: "ensureRunnableRuntimeProfileAccess", method: http.MethodPost, path: "/api/v1/dags/ownerless/start", body: func(c string) any {
			runID, profile := "run-"+slug(c), h.protected
			return api.ExecuteDAGJSONRequestBody{DagRunId: &runID, Profile: &profile}
		}, class: classPlatform, dagFirst: true},

		{handler: "ListRuntimeProfiles", method: http.MethodGet, path: "/api/v1/profiles", body: none, class: classUnowned, managerPasses: true},
		{handler: "getRuntimeProfileForView", method: http.MethodGet, path: "/api/v1/profiles/" + h.plain, body: none, class: classUnowned, managerPasses: true},

		// Every write to a profile that is not protected: the manager role
		// in off and observe, the platform administrator alone under
		// enforce (requireRuntimeProfileWrite).
		{handler: "requireRuntimeProfileWrite", method: http.MethodPost, path: "/api/v1/profiles", body: func(c string) any {
			return api.CreateRuntimeProfileJSONRequestBody{Name: "plain-of-" + slug(c)}
		}, class: classPlatform, managerPasses: true},
		{handler: "requireRuntimeProfileWrite", method: http.MethodPatch, path: "/api/v1/profiles/" + h.plain, body: func(string) any { return map[string]any{"description": "touched"} }, class: classPlatform, managerPasses: true},
		{handler: "requireRuntimeProfileWrite", method: http.MethodPut, path: "/api/v1/profiles/" + h.plain + "/variables/K", body: func(string) any { return map[string]any{"value": "v"} }, class: classPlatform, managerPasses: true},
		{handler: "requireRuntimeProfileWrite", method: http.MethodPut, path: "/api/v1/profiles/" + h.plain + "/secrets/S", body: func(string) any { return map[string]any{"value": "v"} }, class: classPlatform, managerPasses: true},
		{handler: "requireRuntimeProfileWrite", method: http.MethodDelete, path: "/api/v1/profiles/" + h.plain + "/entries/{key}", body: none, class: classPlatform, managerPasses: true},
		{handler: "requireRuntimeProfileWrite", method: http.MethodDelete, path: "/api/v1/profiles/del-{caller}", body: none, class: classPlatform, managerPasses: true},

		{handler: "ListAuditLogs", method: http.MethodGet, path: "/api/v1/audit", body: none, class: classHubRecords, managerPasses: true},
		{handler: "ListEventLogs", method: http.MethodGet, path: "/api/v1/event-logs", body: none, class: classHubRecords, managerPasses: true},

		{handler: "ValidateDAGProfileUpdate", method: http.MethodPut, path: "/api/v1/dags/ownerless/settings", body: none, class: classOwner, managerPasses: true},
		{handler: "ConfigureDAGWebhookProfileSelection", method: http.MethodPut, path: "/api/v1/dags/ownerless/webhook/profile-selection", body: func(string) any { return map[string]any{"allowedProfiles": []string{}} }, class: classOwner},
		{handler: "CreateDAGWebhookProfileToken", method: http.MethodPost, path: "/api/v1/dags/ownerless/webhook/profile-tokens", body: func(string) any { return map[string]any{"name": "t", "profile": h.plain} }, class: classOwner},
		{handler: "RevokeDAGWebhookProfileToken", method: http.MethodDelete, path: "/api/v1/dags/ownerless/webhook/profile-tokens/nope", body: none, class: classOwner},

		// Last: the platform administrator's deactivation takes the test
		// license away, and the audit route above needs it. An empty key
		// is refused after the decision, before anything is activated;
		// nothing leaves the hub.
		p("ActivateLicense", http.MethodPost, "/api/v1/license/activate", func(string) any { return map[string]any{"key": ""} }),
		p("DeactivateLicense", http.MethodPost, "/api/v1/license/deactivate", none),
	}
}

// An outcome of one call at the guard.
type guardOutcome string

const (
	// passes: the route's role and owner decisions let the caller through;
	// what the route then answers is its own.
	passes guardOutcome = "passes the guard"
	// platformAdminRequired: refused by the platform rule.
	platformAdminRequired guardOutcome = "platform_admin_required"
	// hubRecordsHidden: refused as the hub's records (TXE-4752).
	hubRecordsHidden guardOutcome = "hub_records_not_permitted"
	// insufficient: refused by the hub's own role check, as before.
	insufficient guardOutcome = "Insufficient permissions"
	// ownerNotFound: refused by the DAG's owner decision, as before.
	ownerNotFound guardOutcome = "not found by owner"
	// refused: refused, as before, as a caller with no hub role.
	refused guardOutcome = "refused"
)

// expected is the policy (TXE-6139): what each caller meets at each class
// of route in each mode.
func expected(caller, mode string, route adminRoute) guardOutcome {
	enforce := mode == config.TXEAuthzModeEnforce
	switch caller {
	case callerPlatformAdmin, callerSecondAdmin:
		// A builtin account with the administrator role is the platform
		// administrator (txeauth.Classify), whichever account it is.
		return passes
	case callerAdminKey, callerProxyAdmin:
		switch route.class {
		case classPlatform:
			if enforce && route.dagFirst {
				return ownerNotFound
			}
			if enforce {
				return platformAdminRequired
			}
		case classHubRecords:
			if enforce {
				return hubRecordsHidden
			}
		case classOwner:
			if enforce {
				return ownerNotFound
			}
		}
		return passes
	case callerManager:
		switch route.class {
		case classPlatform:
			if enforce && route.dagFirst {
				return ownerNotFound
			}
			if !route.managerPasses {
				return insufficient
			}
			if enforce {
				return platformAdminRequired
			}
		case classHubRecords:
			if enforce {
				return hubRecordsHidden
			}
		case classOwner:
			if enforce {
				return ownerNotFound
			}
			if !route.managerPasses {
				return insufficient
			}
		}
		return passes
	case callerOwner:
		// A provider token is admitted only on the native DAG routes
		// (txeTokenRoute), and there carries a hub user with no role
		// (txeNeutralUser): it is refused everywhere here, as before, by
		// the route's own role check where that comes first, and otherwise
		// at the door or by the DAG's owner decision. The platform rule's
		// own refusal of a caller held to its owner is a person's,
		// exercised in the package's own tests.
		if route.dagFirst {
			return ownerNotFound
		}
		if route.class == classOwner && !route.managerPasses {
			return insufficient
		}
		return refused
	}
	panic("caller " + caller)
}

func (h adminHub) outcome(t *testing.T, caller string, route adminRoute) (guardOutcome, string) {
	t.Helper()
	status, body := h.call(t, route.method, routePath(route.path, caller), route.body(caller), caller)
	var e api.Error
	_ = json.Unmarshal([]byte(body), &e)
	code := ""
	if e.Details != nil {
		code, _ = (*e.Details)["code"].(string)
	}
	answer := fmt.Sprintf("%d %s", status, body)
	// A middleware's refusal (WriteErrorResponse) carries the message and
	// not the details, so both are read.
	switch {
	case status == http.StatusForbidden && (code == string(platformAdminRequired) || e.Message == "under owner enforcement only the platform administrator administers the hub"):
		return platformAdminRequired, answer
	case status == http.StatusForbidden && (code == string(hubRecordsHidden) || e.Message == "under owner enforcement only the platform administrator reads the hub's records"):
		return hubRecordsHidden, answer
	case status == http.StatusForbidden && e.Message == string(insufficient):
		return insufficient, answer
	case status == http.StatusNotFound && e.Message == "not found":
		return ownerNotFound, answer
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		return refused, answer
	}
	return passes, answer
}

// Through the real router, every route the hub's administrator or manager
// role guards answers each kind of caller as the policy says, in each mode
// (TXE-6139). Under enforce an admin-role API key and a trusted-proxy
// administrator lose the platform's routes, with platform_admin_required,
// among them every write to a runtime profile, and keep the reads the
// manager role has always opened to them; in off and observe nothing
// changes for them; the platform administrator keeps everything; a caller
// held to its owner never administers the platform.
func TestTxeAdminRoutesDecideEachCallerThroughTheRouter(t *testing.T) {
	for _, mode := range []string{config.TXEAuthzModeOff, config.TXEAuthzModeObserve, config.TXEAuthzModeEnforce} {
		t.Run(mode, func(t *testing.T) {
			h := newAdminHub(t, mode)
			covered := map[string]bool{}
			for _, route := range h.adminRoutes() {
				covered[route.handler] = true
				for _, caller := range adminHubCallers {
					got, answer := h.outcome(t, caller, route)
					want := expected(caller, mode, route)
					require.Equal(t, want, got, "%s: %s %s: %s", caller, route.method, route.path, answer)
				}
			}
		})
	}
}

// adminPolicyFromSource reads, from the package's source, the functions
// txeAdminOperations classifies and the functions that call requireAdmin or
// requireManagerOrAbove. The sweep's route registry is held to both, so a
// new caller, a new classification or a phantom route each fails loudly.
func adminPolicyFromSource(t *testing.T) (classified, callers []string) {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	fset := gotoken.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		require.NoError(t, err)
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					v, ok := spec.(*ast.ValueSpec)
					if !ok || len(v.Names) != 1 || v.Names[0].Name != "txeAdminOperations" || len(v.Values) != 1 {
						continue
					}
					lit, ok := v.Values[0].(*ast.CompositeLit)
					require.True(t, ok, "txeAdminOperations is a map literal")
					for _, elt := range lit.Elts {
						kv, ok := elt.(*ast.KeyValueExpr)
						require.True(t, ok)
						key, ok := kv.Key.(*ast.BasicLit)
						require.True(t, ok, "each key is a function name literal")
						classified = append(classified, strings.Trim(key.Value, `"`))
					}
				}
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				calls := false
				ast.Inspect(d.Body, func(n ast.Node) bool {
					if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "requireAdmin" || sel.Sel.Name == "requireManagerOrAbove") {
						calls = true
					}
					return true
				})
				if calls {
					callers = append(callers, d.Name.Name)
				}
			}
		}
	}
	slices.Sort(classified)
	slices.Sort(callers)
	return classified, callers
}

// The sweep's routes reach exactly the functions the policy classifies, and
// those are exactly the functions that ask for the role: one registry, held
// to the source on both sides.
func TestTxeAdminRoutesReachEveryClassifiedFunction(t *testing.T) {
	t.Parallel()
	classified, callers := adminPolicyFromSource(t)
	require.NotEmpty(t, classified)
	assert.Equal(t, callers, classified, "txeAdminOperations names exactly the functions that ask for the administrator or manager role")
	var reached []string
	for _, route := range (adminHub{plain: "plain", protected: "protected"}).adminRoutes() {
		reached = append(reached, route.handler)
	}
	slices.Sort(reached)
	assert.Equal(t, classified, slices.Compact(reached), "the sweep reaches every classified function, and no other")
}

// A protected runtime profile is the platform's (TXE-6139): under enforce
// an admin-role API key no longer lists it, reads it, changes it, or runs
// an ownerless DAG with it; the platform administrator does all of these;
// and in observe the key still does, as before. The plain profile stays
// the manager role's in every mode.
func TestTxeProtectedProfilesArePlatformOnlyUnderEnforce(t *testing.T) {
	listed := func(t *testing.T, h adminHub, caller string) []string {
		t.Helper()
		status, body := h.call(t, http.MethodGet, "/api/v1/profiles", nil, caller)
		require.Equal(t, http.StatusOK, status, body)
		var out api.ListRuntimeProfiles200JSONResponse
		require.NoError(t, json.Unmarshal([]byte(body), &out))
		var names []string
		for _, p := range out.Profiles {
			names = append(names, p.Name)
		}
		return names
	}
	deletable := func() []string {
		var names []string
		for _, caller := range adminHubCallers {
			names = append(names, "del-"+slug(caller))
		}
		return names
	}
	start := func(t *testing.T, h adminHub, caller, profile string) (int, string) {
		t.Helper()
		runID := "run-" + slug(caller) + "-" + profile
		return h.call(t, http.MethodPost, "/api/v1/dags/ownerless/start", api.ExecuteDAGJSONRequestBody{DagRunId: &runID, Profile: &profile}, caller)
	}

	t.Run("enforce", func(t *testing.T) {
		h := newAdminHub(t, config.TXEAuthzModeEnforce)
		require.ElementsMatch(t, append([]string{h.plain}, deletable()...), listed(t, h, callerAdminKey), "the key lists the profiles that are not protected only")
		require.ElementsMatch(t, append([]string{h.plain, h.protected}, deletable()...), listed(t, h, callerPlatformAdmin))
		for _, caller := range []string{callerAdminKey, callerProxyAdmin} {
			got, answer := h.outcome(t, caller, adminRoute{method: http.MethodGet, path: "/api/v1/profiles/" + h.protected, body: none})
			require.Equal(t, platformAdminRequired, got, "%s reads the protected profile: %s", caller, answer)
			got, answer = h.outcome(t, caller, adminRoute{method: http.MethodPatch, path: "/api/v1/profiles/" + h.plain, body: func(string) any {
				yes := true
				return api.UpdateRuntimeProfileRequest{Protected: &yes}
			}})
			require.Equal(t, platformAdminRequired, got, "%s protects a profile: %s", caller, answer)
			got, answer = h.outcome(t, caller, adminRoute{method: http.MethodPatch, path: "/api/v1/profiles/" + h.plain, body: func(string) any {
				return map[string]any{"description": "the platform administrator's under enforce"}
			}})
			require.Equal(t, platformAdminRequired, got, "%s changes the plain profile: %s", caller, answer)
			got, answer = h.outcome(t, caller, adminRoute{method: http.MethodGet, path: "/api/v1/profiles/" + h.plain, body: none})
			require.Equal(t, passes, got, "%s reads the plain profile: %s", caller, answer)
		}
		// The run path: a legacy caller sees no DAG under enforce, so the
		// protected profile's rule is not what refuses it there; the
		// platform administrator runs with it.
		status, body := start(t, h, callerAdminKey, h.protected)
		require.Equal(t, http.StatusNotFound, status, body)
		status, body = start(t, h, callerPlatformAdmin, h.protected)
		require.Equal(t, http.StatusOK, status, body)
	})

	t.Run("observe", func(t *testing.T) {
		h := newAdminHub(t, config.TXEAuthzModeObserve)
		require.ElementsMatch(t, append([]string{h.plain, h.protected}, deletable()...), listed(t, h, callerAdminKey), "unchanged in observe")
		got, answer := h.outcome(t, callerAdminKey, adminRoute{method: http.MethodPatch, path: "/api/v1/profiles/" + h.plain, body: func(string) any {
			return map[string]any{"description": "still the manager role's in observe"}
		}})
		require.Equal(t, passes, got, "the key changes the plain profile in observe: %s", answer)
		status, body := start(t, h, callerAdminKey, h.protected)
		require.Equal(t, http.StatusOK, status, body)
		var started api.ExecuteDAG200JSONResponse
		require.NoError(t, json.Unmarshal([]byte(body), &started))
		waitForStoredDAGRunStatus(t, h.server, "ownerless", started.DagRunId, 10*time.Second, func(s *ir.DAGRunStatus) bool {
			return s.Status == ir.Succeeded || s.Status == ir.Failed
		})
		attempt, err := h.server.DAGRunRepository.FindAttempt(h.server.Context, ir.NewDAGRunRef("ownerless", started.DagRunId))
		require.NoError(t, err)
		stored, err := attempt.ReadStatus(h.server.Context)
		require.NoError(t, err)
		require.Equal(t, h.protected, stored.ProfileName)
	})
}
