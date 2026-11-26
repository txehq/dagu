// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package machineauth_test

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// The issuer's clients the hub's configuration names (the rig, rig_test.go,
// registers them at its issuer).
const (
	cliClient     = "dagu-cli-rig"
	browserClient = "dagu-hub-browser"
)

// hubConfigInput is what the hub's configuration is rendered from.
type hubConfigInput struct {
	// Scope is the hub build's scope: the worker channel is configured only
	// for a hub whose scope has the channel route.
	Scope     buildScope
	HubPort   int
	CoordPort int
	IssuerURL string
	// MachineIDs get one worker and one reviewer client each, in this order.
	MachineIDs []string
}

// renderHubConfig is the hub's configuration: builtin person auth with the
// browser SSO at the issuer, the fork's licence policy for SSO, the
// coordinator in enforce advertising loopback, the worker channel on when the
// hub's scope has the channel route, and txe.authn naming the issuer, the CLI
// client and one worker and one reviewer client per machine. A native-only
// hub (txe-v2.18.2-17) gets no coordinator.worker_channel block: its source
// has none, and it would ignore the key rather than refuse it.
func renderHubConfig(in hubConfigInput) string {
	var clients strings.Builder
	fmt.Fprintf(&clients, "      - id: %s\n        class: cli\n", cliClient)
	for _, id := range in.MachineIDs {
		fmt.Fprintf(&clients, "      - id: dagu-worker-%s\n        class: worker\n      - id: dagu-reviewer-%s\n        class: reviewer\n", id, id)
	}
	channel := ""
	if in.Scope.has(routeChannel) {
		channel = "  worker_channel:\n    enabled: true\n"
	}
	hubURL := fmt.Sprintf("http://127.0.0.1:%d", in.HubPort)
	return fmt.Sprintf(`host: 127.0.0.1
port: %d
auth:
  mode: builtin
  builtin:
    initial_admin:
      username: rig-admin
  oidc:
    client_id: %s
    client_url: %s
    issuer: %s
    scopes: [openid, profile, email]
    auto_signup: true
    allowed_domains: [rig.test]
    pkce: true
license:
  fork_policy:
    features: [sso]
coordinator:
  host: 127.0.0.1
  advertise: 127.0.0.1
  port: %d
  auth:
    mode: enforce
%stxe:
  authn:
    issuer: %s
    audience: dagu-hub
    jwks_url: %s/jwks
    cli_client: %s
    clients:
%s  authz:
    mode: enforce
`, in.HubPort, browserClient, hubURL, in.IssuerURL, in.CoordPort, channel, in.IssuerURL, in.IssuerURL, cliClient, clients.String())
}

// configKeyPaths lists the keys a YAML configuration writes, one dotted path
// per leaf, sorted and distinct. A list of mappings is "<path>[]" followed by
// its entries' keys; a list of scalars is a leaf.
func configKeyPaths(config string) ([]string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(config), &doc); err != nil {
		return nil, fmt.Errorf("hub configuration: %w", err)
	}
	set := map[string]bool{}
	var walk func(prefix string, v any) error
	walk = func(prefix string, v any) error {
		switch x := v.(type) {
		case map[string]any:
			if len(x) == 0 {
				set[prefix] = true
			}
			for k, sub := range x {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				if err := walk(p, sub); err != nil {
					return err
				}
			}
		case []any:
			maps := 0
			for _, e := range x {
				if _, ok := e.(map[string]any); ok {
					maps++
				}
			}
			switch {
			case maps == 0:
				set[prefix] = true
			case maps != len(x):
				return fmt.Errorf("hub configuration: %s mixes entries and values", prefix)
			default:
				for _, e := range x {
					if err := walk(prefix+"[]", e); err != nil {
						return err
					}
				}
			}
		default:
			set[prefix] = true
		}
		return nil
	}
	if err := walk("", doc); err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(set))
	for p := range set {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, nil
}

// checkHubConfigKeys refuses a hub configuration that writes a key the hub
// build's own source does not read. It applies to a narrowed hub, whose entry
// lists the keys its source reads; a narrowed hub without that list is refused
// too, so a new entry cannot skip the check. A full-scope hub is the template's
// own generation and is not checked here.
func checkHubConfigKeys(name string, n *narrowedScope, config string) error {
	if n == nil || !n.Scope.hub() {
		return nil
	}
	if len(n.HubConfigKeys) == 0 {
		return fmt.Errorf("build %s (version %s) runs as a narrowed hub, but narrowedScopes lists no configuration keys its source reads", name, n.Version)
	}
	paths, err := configKeyPaths(config)
	if err != nil {
		return fmt.Errorf("build %s: %w", name, err)
	}
	var unknown []string
	for _, p := range paths {
		if !slices.Contains(n.HubConfigKeys, p) {
			unknown = append(unknown, p)
		}
	}
	if len(unknown) > 0 {
		return fmt.Errorf("build %s (version %s, commit %s) would be started as a hub with configuration keys its source does not read: %s; it would ignore them, so no cell runs",
			name, n.Version, n.Commit, strings.Join(unknown, ", "))
	}
	return nil
}
