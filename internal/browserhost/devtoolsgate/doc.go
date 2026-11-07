// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

// Package devtoolsgate launches Chrome behind an authenticated DevTools
// address.
//
// Chrome's own remote debugging listens on a loopback TCP port that every
// account on the host can reach, and it authenticates nobody. The gate
// launches Chrome with --remote-debugging-pipe instead, so Chrome listens on
// no port at all, and serves the browser itself at
//
//	http://127.0.0.1:<port>/<token>/…
//
// with the paths DevTools clients expect: /json/version, /json and
// /json/list, and the websockets /devtools/browser/<id> and
// /devtools/page/<targetId>. The token is a per-browser credential compared
// in constant time; any other path, including the root and a wrong token,
// answers 404. Every websocket client gets a virtual DevTools connection of
// its own over the one pipe: its own command ids, its own Target.setAutoAttach
// and Target.setDiscoverTargets state, and sessions it attached explicitly,
// which the gate detaches when the client goes away.
//
// The gate is a helper process, `dagu browser devtools-gate`, so it can
// outlive the step that started the browser: a browser left waiting for a
// person's input keeps its gate. The helper reads its configuration from
// stdin, so the token never appears in a process listing, writes one ready
// line to stdout, and exits when Chrome exits. Chrome, for its part, closes
// itself when the pipe closes, so neither outlives the other. A lifetime cap
// ends a gate nobody came back for.
//
// Scope. The gate keeps another local account from driving the browser or
// reading what it holds. Code running as the same user can already read the
// record that stores the URL, the browser's profile and the gate's memory;
// no authentication defends against that, and this package claims none.
package devtoolsgate
