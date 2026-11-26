// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditedTargetParams is the audit of every Target command the gate passes
// on (TXE-7856): the params the DevTools protocol defines for it, all of
// which the gate passes, since none changes the browser's networking,
// proxying or isolation. A method added to forwardedTargetMethods without a
// row here, or a policy that differs from its row, fails
// TestMuxForwardedTargetMethodsHaveAuditedParamPolicies.
var auditedTargetParams = map[string][]string{
	"Target.activateTarget": {"targetId"},
	"Target.closeTarget":    {"targetId"},
	"Target.createTarget": {
		"url", "left", "top", "width", "height", "windowState", "browserContextId",
		"enableBeginFrameControl", "newWindow", "background", "forTab", "hidden", "focus",
	},
	"Target.getBrowserContexts": nil,
	"Target.getTargetInfo":      {"targetId"},
	"Target.getTargets":         {"filter"},
}

// refusedTargetMethods are the Target commands the audit refused whole: a
// new browser context is set apart from the browser's own, whatever its
// params, and disposing of one has nothing left to act on.
var refusedTargetMethods = []string{"Target.createBrowserContext", "Target.disposeBrowserContext"}

// An allowlist entry is a method and its param policy. Every forwarded
// method has a policy that matches its audit row and refuses a param it does
// not name, so a param the browser adds later is refused until someone reads
// it; the methods the audit refused are not forwarded.
func TestMuxForwardedTargetMethodsHaveAuditedParamPolicies(t *testing.T) {
	t.Parallel()
	assert.ElementsMatch(t, slices.Collect(maps.Keys(auditedTargetParams)), slices.Collect(maps.Keys(forwardedTargetMethods)),
		"every forwarded Target method needs an audit row in auditedTargetParams, and every row a policy")
	for method, policy := range forwardedTargetMethods {
		assert.ElementsMatch(t, auditedTargetParams[method], policy.passed, "%s passes exactly its audited params", method)
		_, err := policy.check(method, json.RawMessage(`{"someFutureParam":true}`))
		assert.ErrorContains(t, err, "the gate does not pass on "+method+` with the param "someFutureParam"`)
	}
	for _, method := range refusedTargetMethods {
		assert.NotContains(t, forwardedTargetMethods, method)
	}
	assert.ElementsMatch(t, []string{"autoAttach", "waitForDebuggerOnStart", "flatten", "filter"}, clientAutoAttachParams.passed)
	for method, policy := range handledTargetMethods {
		assert.ElementsMatch(t, auditedHandledTargetParams[method], policy.passed, "%s accepts exactly its audited params", method)
	}
	assert.ElementsMatch(t, slices.Collect(maps.Keys(auditedHandledTargetParams)), slices.Collect(maps.Keys(handledTargetMethods)))
}

// auditedHandledTargetParams is the audit of the Target commands the gate
// handles itself: the params the DevTools protocol defines for each.
var auditedHandledTargetParams = map[string][]string{
	"Target.setAutoAttach":      {"autoAttach", "waitForDebuggerOnStart", "flatten", "filter"},
	"Target.setDiscoverTargets": {"discover", "filter"},
	"Target.attachToTarget":     {"targetId", "flatten"},
	"Target.detachFromTarget":   {"sessionId", "targetId"},
}

// Every Target command the gate accepts is held to a param policy, whether
// it passes the command on or handles it itself: each case of
// handleClientCommand that names a Target command either has a policy in
// handledTargetMethods or refuses the command whole. A Target command the
// gate starts to handle without a policy fails here.
func TestMuxEveryAcceptedTargetMethodHasAParamPolicy(t *testing.T) {
	t.Parallel()
	refusedWhole := []string{"Target.attachToBrowserTarget"}
	file, err := parser.ParseFile(token.NewFileSet(), "mux.go", nil, 0)
	require.NoError(t, err)
	var cased []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "handleClientCommand" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			clause, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, expr := range clause.List {
				if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					name, err := strconv.Unquote(lit.Value)
					require.NoError(t, err)
					if strings.HasPrefix(name, "Target.") {
						cased = append(cased, name)
					}
				}
			}
			return true
		})
	}
	require.NotEmpty(t, cased, "handleClientCommand names the Target commands it handles")
	for _, method := range cased {
		_, handled := handledTargetMethods[method]
		assert.True(t, handled || slices.Contains(refusedWhole, method), "%s is handled by the gate without a param policy", method)
	}
}

// A param outside the policy of a Target command the gate handles itself is
// refused too, on the browser's session as on any other, and the browser
// never receives a command for it.
func TestMuxRefusesUnknownParamsOnTheTargetCommandsItHandles(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	c := tg.dial("")
	for method, params := range map[string]map[string]any{
		"Target.setAutoAttach":      {"autoAttach": false, "someFutureParam": true},
		"Target.setDiscoverTargets": {"discover": true, "someFutureParam": true},
		"Target.attachToTarget":     {"targetId": "T1", "flatten": true, "someFutureParam": true},
		"Target.detachFromTarget":   {"sessionId": "S", "someFutureParam": true},
	} {
		_, err := c.call("", method, params)
		assert.ErrorContains(t, err, "the gate does not pass on "+method+` with the param "someFutureParam"`)
	}
	for _, s := range tg.state(c).TargetParams {
		assert.NotContains(t, s, "someFutureParam")
	}
	assert.Empty(t, sentOf(tg.state(c), "Target.setDiscoverTargets"), "the refused discovery never reached the browser")
	c.mustCall("", "Target.setDiscoverTargets", map[string]any{"discover": true, "filter": []map[string]any{{}}})
}

// No client creates a browser context, whatever it asks of it, and the
// browser never hears of the attempt.
func TestMuxRefusesNewBrowserContexts(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	c := tg.dial("")
	for _, params := range []any{
		nil,
		map[string]any{},
		map[string]any{"disposeOnDetach": true},
		map[string]any{"proxyServer": "http://127.0.0.1:1"},
		map[string]any{"proxyBypassList": "<-loopback>"},
		map[string]any{"originsWithUniversalNetworkAccess": []string{"https://example.com"}},
	} {
		_, err := c.call("", "Target.createBrowserContext", params)
		assert.ErrorContains(t, err, "the gate does not pass on Target.createBrowserContext", "%v", params)
	}
	_, err := c.call("", "Target.disposeBrowserContext", map[string]any{"browserContextId": "CTX1"})
	assert.ErrorContains(t, err, "the gate does not pass on Target.disposeBrowserContext")
	assert.Empty(t, sentOf(tg.state(c), "Target.createBrowserContext"))
	assert.Empty(t, sentOf(tg.state(c), "Target.disposeBrowserContext"))
	c.mustCall("", "Target.getBrowserContexts", map[string]any{})
}

// A param outside a forwarded method's policy is refused under any spelling
// the gate reads, and so are params that are not a JSON object; the browser
// never receives the command.
func TestMuxRefusesParamsOutsideThePolicy(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	c := tg.dial("")
	for params, refused := range map[string]string{
		`{"url":"about:blank","someFutureParam":true}`: "someFutureParam",
		`{"URL":"about:blank"}`:                        "URL",
		`{"url":"about:blank","\u0055RL":"x"}`:         "URL",
		`{"url":"about:blank","a":1,"a":2}`:            "a",
	} {
		_, err := c.call("", "Target.createTarget", json.RawMessage(params))
		assert.ErrorContains(t, err, `the gate does not pass on Target.createTarget with the param "`+refused+`"`, params)
	}
	for _, params := range []string{`[]`, `"x"`, `1`} {
		_, err := c.call("", "Target.createTarget", json.RawMessage(params))
		assert.ErrorContains(t, err, "params must be a JSON object", params)
	}
	assert.Empty(t, sentOf(tg.state(c), "Target.createTarget"))
}

// What the browser reads is what the gate checked: a repeated key reaches
// it once, as the gate read it, and an escaped key in its plain spelling.
func TestMuxPassesTargetParamsAsTheGateReadThem(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	c := tg.dial("")
	c.mustCall("", "Target.createTarget", json.RawMessage(`{"url":"about:blank#first","url":"about:blank"}`))
	c.mustCall("", "Target.createTarget", json.RawMessage(`{"ur\u006c":"about:blank#escaped"}`))
	assert.Equal(t, []string{
		`Target.createTarget {"url":"about:blank"}`,
		`Target.createTarget {"url":"about:blank#escaped"}`,
	}, sentOf(tg.state(c), "Target.createTarget"))
}

// Every Target call the gate's real clients make still passes, with its
// params as they sent them: the write gate (writegate/gate.go,
// extension.go), Stagehand's Go SDK (cdp_client.go: createTarget with a url,
// getTargets with {}, closeTarget, attachToTarget) and the browser package
// (cdp.go: setAutoAttach).
func TestMuxPassesTheTargetCallsRealClientsMake(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	c := tg.dial("")
	c.mustCall("", "Target.setAutoAttach", map[string]any{"autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true})
	c.mustCall("", "Target.getTargets", nil)
	c.mustCall("", "Target.getTargets", map[string]any{})
	c.mustCall("", "Target.getTargets", map[string]any{"filter": []map[string]any{{"type": "page"}}})
	var created struct {
		TargetID string `json:"targetId"`
	}
	require.NoError(t, json.Unmarshal(c.mustCall("", "Target.createTarget", map[string]any{"url": "about:blank", "background": true}), &created))
	c.mustCall("", "Target.createTarget", map[string]any{"url": "about:blank"})
	c.mustCall("", "Target.createTarget", map[string]any{
		"url": "about:blank", "newWindow": false, "background": false,
		"enableBeginFrameControl": false, "forTab": false, "hidden": false,
	})
	c.mustCall("", "Target.attachToTarget", map[string]any{"targetId": created.TargetID, "flatten": true})
	c.mustCall("", "Target.getTargetInfo", map[string]any{"targetId": created.TargetID})
	c.mustCall("", "Target.activateTarget", map[string]any{"targetId": created.TargetID})
	c.mustCall("", "Target.getBrowserContexts", map[string]any{})
	c.mustCall("", "Target.closeTarget", map[string]any{"targetId": created.TargetID})

	sent := tg.state(c).TargetParams
	assert.Contains(t, sent, `Target.createTarget {"background":true,"url":"about:blank"}`)
	assert.Contains(t, sent, `Target.getTargets {"filter":[{"type":"page"}]}`)
	assert.Contains(t, sent, `Target.closeTarget {"targetId":"`+created.TargetID+`"}`)

	// The write gate's own-session auto-attach, filter included, passes too.
	page := tg.dial("T1")
	page.mustCall("", "Target.setAutoAttach", map[string]any{
		"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true,
		"filter": []map[string]any{{"type": "service_worker"}, {"type": "shared_worker"}, {"exclude": true}},
	})
}

// A client's auto-attach on a session it attached itself is passed on, so
// its params are held to a policy too: a param outside it is refused, and
// the browser never receives that call.
func TestMuxClientAutoAttachOnItsOwnSessionRefusesUnknownParams(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	pageClient := tg.dial("T1")
	_, err := pageClient.call("", "Target.setAutoAttach", map[string]any{
		"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true, "someFutureParam": true,
	})
	assert.ErrorContains(t, err, `the gate does not pass on Target.setAutoAttach with the param "someFutureParam"`)
	for _, sent := range sentOf(tg.state(pageClient), "Target.setAutoAttach") {
		assert.NotContains(t, sent, "someFutureParam")
	}
	pageClient.mustCall("", "Target.setAutoAttach", autoAttach(true))
}

// sentOf returns the browser's record of the commands named method.
func sentOf(state fakeState, method string) []string {
	var sent []string
	for _, s := range state.TargetParams {
		if strings.HasPrefix(s, method+" ") {
			sent = append(sent, s)
		}
	}
	return sent
}
