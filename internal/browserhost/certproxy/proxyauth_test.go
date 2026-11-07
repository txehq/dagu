// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package certproxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingListener is a site that only counts the connections it accepts.
func countingListener(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	var accepted atomic.Int64
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = conn.Close()
		}
	}()
	return listener.Addr().String(), &accepted
}

// A process that reaches the proxy's port without the browser's credential,
// such as another local account, is refused before the proxy matches a
// host, chooses a route or dials anything, on the certificate port and on
// the guard alike: it cannot have the proxy present a client certificate
// or carry a request for it.
func TestProxyRefusesClientsWithoutTheCredential(t *testing.T) {
	t.Parallel()

	site, accepted := countingListener(t)
	ca := newTestCA(t, "corp CA")
	cfg := testConfig(t, "", ca.clientEntry(t, testLabel, "127.0.0.1"))
	cfg.Guard = true
	ready := serveProxy(t, cfg)
	require.NotZero(t, ready.GuardPort)

	wrong := "Basic " + base64.StdEncoding.EncodeToString([]byte(ProxyUser+":not-the-credential"))
	otherUser := "Basic " + base64.StdEncoding.EncodeToString([]byte("someone:"+testCredential))
	for _, port := range []int{ready.Port, ready.GuardPort} {
		proxyAddr := fmt.Sprintf("127.0.0.1:%d", port)
		for name, authorization := range map[string]string{
			"None":      "",
			"Wrong":     wrong,
			"OtherUser": otherUser,
			"Bearer":    "Bearer " + testCredential,
			"Garbled":   "Basic !!!",
		} {
			conn, status, err := connectWith(proxyAddr, site, authorization)
			require.NoError(t, err, name)
			_ = conn.Close()
			assert.Equal(t, http.StatusProxyAuthRequired, status, "%s on port %d", name, port)
		}
	}
	assert.Zero(t, accepted.Load(), "a refused client makes the proxy dial nothing")
	events, err := Events(context.Background(), controlURL(ready.Port, cfg.Token), 0)
	require.NoError(t, err)
	assert.Empty(t, events, "a refused client is not one of the browser's connections")

	// The browser's credential opens the tunnel.
	conn, status, err := connectThrough(fmt.Sprintf("127.0.0.1:%d", ready.Port), site)
	require.NoError(t, err)
	_ = conn.Close()
	assert.Equal(t, http.StatusOK, status)
}

// The challenge names the scheme the browser answers with.
func TestProxyChallengeAsksForBasic(t *testing.T) {
	t.Parallel()

	request := httptest.NewRequest(http.MethodConnect, "http://"+siteHost+":443", nil)
	recorder := httptest.NewRecorder()
	(&server{credential: testCredential}).ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusProxyAuthRequired, recorder.Code)
	assert.Equal(t, `Basic realm="dagu"`, recorder.Header().Get("Proxy-Authenticate"))
}

// A plain request a manual proxy carries for another site needs the
// credential too.
func TestForwardedRequestNeedsTheCredential(t *testing.T) {
	t.Parallel()

	site, accepted := countingListener(t)
	ca := newTestCA(t, "corp CA")
	ready := serveProxy(t, testConfig(t, "", ca.clientEntry(t, testLabel, "127.0.0.1")))
	require.True(t, ready.Manual)

	proxyURL := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", ready.Port)}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	response, err := client.Get("http://" + site + "/")
	require.NoError(t, err)
	_ = response.Body.Close()
	assert.Equal(t, http.StatusProxyAuthRequired, response.StatusCode)
	assert.Zero(t, accepted.Load(), "a refused request is not forwarded")
}

// The browser's runtime opens its DevTools WebSocket from inside the
// browser, which a manual proxy receives as a tunnel Chrome answers no
// challenge for. A tunnel to the browser's own gate is spliced without the
// credential; any other address still needs it.
func TestTunnelToTheBrowsersGateNeedsNoCredential(t *testing.T) {
	t.Parallel()

	gate, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = gate.Close() })
	go func() {
		for {
			conn, err := gate.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 5)
				if _, err := io.ReadFull(conn, buf); err == nil {
					_, _ = conn.Write(buf)
				}
			}()
		}
	}()
	other, accepted := countingListener(t)

	ca := newTestCA(t, "corp CA")
	cfg := testConfig(t, "", ca.clientEntry(t, testLabel, "127.0.0.1"))
	cfg.CDPURL = "http://" + gate.Addr().String() + "/" + testGateToken
	ready := serveProxy(t, cfg)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", ready.Port)

	conn, status, err := connectWith(proxyAddr, gate.Addr().String(), "")
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()
	require.Equal(t, http.StatusOK, status)
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)
	echoed := make([]byte, 5)
	_, err = io.ReadFull(conn, echoed)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(echoed), "the tunnel reaches the gate unread")

	conn, status, err = connectWith(proxyAddr, other, "")
	require.NoError(t, err)
	_ = conn.Close()
	assert.Equal(t, http.StatusProxyAuthRequired, status, "another loopback port needs the credential")
	assert.Zero(t, accepted.Load())

	// Only a tunnel is exempt: a plain request the proxy would forward to
	// the gate's very address needs the credential like any other.
	proxyURL := &url.URL{Scheme: "http", Host: proxyAddr}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	response, err := client.Get("http://" + gate.Addr().String() + "/" + testGateToken + "/json/version")
	require.NoError(t, err)
	_ = response.Body.Close()
	assert.Equal(t, http.StatusProxyAuthRequired, response.StatusCode, "a plain request to the gate's address")

	// The exemption is the gate's whole authority: the same host on the
	// gate's port written another way is not it.
	_, gatePort, err := net.SplitHostPort(gate.Addr().String())
	require.NoError(t, err)
	conn, status, err = connectWith(proxyAddr, "localhost:"+gatePort, "")
	require.NoError(t, err)
	_ = conn.Close()
	assert.Equal(t, http.StatusProxyAuthRequired, status, "another spelling of the gate's address")
}
