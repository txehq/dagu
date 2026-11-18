// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// auditedTargetParams is the audit of every Target command the gate passes
// on (TXE-7856): each param the DevTools protocol defines for it, and
// whether the gate passes it. A param that changes the browser's
// networking, proxying or isolation is refused. A method added to
// forwardedTargetMethods without a row here, or a policy that differs from
// its row, fails TestMuxForwardedTargetMethodsHaveAuditedParamPolicies.
var auditedTargetParams = map[string]struct {
	passed, refused []string
}{
	"Target.activateTarget": {passed: []string{"targetId"}},
	"Target.closeTarget":    {passed: []string{"targetId"}},
	"Target.createBrowserContext": {
		passed:  []string{"disposeOnDetach"},
		refused: []string{"proxyServer", "proxyBypassList", "originsWithUniversalNetworkAccess"},
	},
	"Target.createTarget": {passed: []string{
		"url", "left", "top", "width", "height", "windowState", "browserContextId",
		"enableBeginFrameControl", "newWindow", "background", "forTab", "hidden", "focus",
	}},
	"Target.disposeBrowserContext": {passed: []string{"browserContextId"}},
	"Target.getBrowserContexts":    {},
	"Target.getTargetInfo":         {passed: []string{"targetId"}},
	"Target.getTargets":            {passed: []string{"filter"}},
}

// An allowlist entry is a method and its param policy. Every forwarded
// method has a policy that matches its audit row, passes none of the params
// the audit refuses, and refuses a param it does not name, so a param the
// browser adds later is refused until someone reads it.
func TestMuxForwardedTargetMethodsHaveAuditedParamPolicies(t *testing.T) {
	t.Parallel()
	assert.ElementsMatch(t, slices.Collect(maps.Keys(auditedTargetParams)), slices.Collect(maps.Keys(forwardedTargetMethods)),
		"every forwarded Target method needs an audit row in auditedTargetParams, and every row a policy")
	for method, policy := range forwardedTargetMethods {
		audit := auditedTargetParams[method]
		assert.ElementsMatch(t, audit.passed, policy.passed, "%s passes exactly its audited params", method)
		for _, name := range audit.refused {
			assert.NotContains(t, policy.passed, name, "%s refuses %s", method, name)
			_, err := policy.check(method, json.RawMessage(`{"`+name+`":"x"}`))
			assert.ErrorContains(t, err, "the gate does not pass on "+method+` with the param "`+name+`"`)
		}
		_, err := policy.check(method, json.RawMessage(`{"someFutureParam":true}`))
		assert.ErrorContains(t, err, "the gate does not pass on "+method+` with the param "someFutureParam"`)
	}
	for _, name := range []string{"autoAttach", "waitForDebuggerOnStart", "flatten", "filter"} {
		assert.Contains(t, clientAutoAttachParams.passed, name)
	}
	assert.Len(t, clientAutoAttachParams.passed, 4)
}

// A context that would not use the browser's networking is refused, and the
// browser never sees the command: a proxy of its own, a list of hosts that
// skip the proxy, or origins freed of cross-origin isolation, under any
// spelling the browser would read as one of them, and whatever the value.
func TestMuxRefusesCreateBrowserContextParamsThatChangeNetworking(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	c := tg.dial("")
	for _, params := range []string{
		`{"proxyServer":"http://127.0.0.1:1"}`,
		`{"proxyServer":""}`,
		`{"proxyServer":null}`,
		`{"proxyBypassList":"<-loopback>"}`,
		`{"originsWithUniversalNetworkAccess":["https://example.com"]}`,
		`{"disposeOnDetach":true,"proxyServer":"http://127.0.0.1:1"}`,
		`{"proxyServer":"http://127.0.0.1:1"}`,
		`{"disposeOnDetach":true,"proxyServer":"a","proxyServer":"b"}`,
		`{"ProxyServer":"http://127.0.0.1:1"}`,
	} {
		_, err := c.call("", "Target.createBrowserContext", json.RawMessage(params))
		assert.ErrorContains(t, err, "the gate does not pass on Target.createBrowserContext with the param ", params)
	}
	for _, params := range []string{`[]`, `"x"`, `1`} {
		_, err := c.call("", "Target.createBrowserContext", json.RawMessage(params))
		assert.ErrorContains(t, err, "params must be a JSON object", params)
	}
	for _, sent := range tg.state(c).TargetParams {
		assert.False(t, strings.HasPrefix(sent, "Target.createBrowserContext"), "the browser received %s", sent)
	}

	// A context on the browser's own networking is created as before.
	var created struct {
		BrowserContextID string `json:"browserContextId"`
	}
	require.NoError(t, json.Unmarshal(c.mustCall("", "Target.createBrowserContext", map[string]any{"disposeOnDetach": true}), &created))
	assert.Equal(t, "CTX1", created.BrowserContextID)
	// Params left out reach the browser as before (null).
	c.mustCall("", "Target.createBrowserContext", nil)
	assert.Equal(t, []string{
		`Target.createBrowserContext {"disposeOnDetach":true}`,
		`Target.createBrowserContext null`,
	}, sentOf(tg.state(c), "Target.createBrowserContext"))
}

// What the browser reads is what the gate checked: a repeated key reaches
// it once, as the gate read it.
func TestMuxPassesTargetParamsAsTheGateReadThem(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	c := tg.dial("")
	c.mustCall("", "Target.createTarget", json.RawMessage(`{"url":"about:blank#first","url":"about:blank"}`))
	assert.Equal(t, []string{`Target.createTarget {"url":"about:blank"}`}, sentOf(tg.state(c), "Target.createTarget"))
}

// Every Target call the gate's real clients make still passes, with its
// params as they sent them: the write gate (writegate/gate.go,
// extension.go), Stagehand's Go SDK (cdp_client.go: createTarget with a url,
// getTargets with {}, closeTarget, attachToTarget) and the browser package
// (cdp.go: setAutoAttach), and the browser-context calls of chromedp,
// Playwright and Puppeteer when no proxy is asked for.
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
		"url": "about:blank", "browserContextId": "CTX1", "newWindow": false, "background": false,
		"enableBeginFrameControl": false, "forTab": false, "hidden": false,
	})
	c.mustCall("", "Target.getTargetInfo", map[string]any{"targetId": created.TargetID})
	c.mustCall("", "Target.activateTarget", map[string]any{"targetId": created.TargetID})
	c.mustCall("", "Target.createBrowserContext", map[string]any{"disposeOnDetach": false})
	c.mustCall("", "Target.getBrowserContexts", map[string]any{})
	c.mustCall("", "Target.disposeBrowserContext", map[string]any{"browserContextId": "CTX1"})
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
// its params are held to a policy too: a param outside it is refused.
func TestMuxClientAutoAttachOnItsOwnSessionRefusesUnknownParams(t *testing.T) {
	t.Parallel()
	tg := startTestGate(t)
	pageClient := tg.dial("T1")
	_, err := pageClient.call("", "Target.setAutoAttach", map[string]any{
		"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true, "someFutureParam": true,
	})
	assert.ErrorContains(t, err, `the gate does not pass on Target.setAutoAttach with the param "someFutureParam"`)
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
