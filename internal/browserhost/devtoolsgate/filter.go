// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import "encoding/json"

// targetFilter is DevTools' TargetFilter: the first entry whose type matches
// (an entry without a type matches every type) decides, and a type no entry
// names is excluded.
type targetFilter []targetFilterEntry

type targetFilterEntry struct {
	Type    string `json:"type,omitempty"`
	Exclude bool   `json:"exclude,omitempty"`
}

// defaultTargetFilter is what Target.setAutoAttach and
// Target.setDiscoverTargets use when a client passes no filter: every target
// except the browser itself and tabs.
var defaultTargetFilter = targetFilter{
	{Type: "browser", Exclude: true},
	{Type: "tab", Exclude: true},
	{},
}

// parseTargetFilter reads the filter of a Target command's params, or
// returns the default when the params carry none.
func parseTargetFilter(params json.RawMessage) targetFilter {
	var fields struct {
		Filter *targetFilter `json:"filter"`
	}
	if len(params) == 0 || json.Unmarshal(params, &fields) != nil || fields.Filter == nil {
		return defaultTargetFilter
	}
	return *fields.Filter
}

func (f targetFilter) matches(targetType string) bool {
	for _, entry := range f {
		if entry.Type == "" || entry.Type == targetType {
			return !entry.Exclude
		}
	}
	return false
}
