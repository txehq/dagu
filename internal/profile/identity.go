// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// runtimeIdentityPrefix marks the version of the identity's encoding: a run
// recorded under another encoding never compares equal to this one.
const runtimeIdentityPrefix = "rp1:"

// The roles of the layers a run takes, in order of precedence.
const (
	layerRoleGlobal    = "global"
	layerRoleWorkspace = "workspace"
	layerRoleSelected  = "selected"
)

// layerRevision names the stored state of one profile layer that a run took:
// the profile's ID and store-assigned generation, and the managed version of
// each of its secrets. It holds no value of a variable or a secret, and
// nothing derived from one (TXE-6145).
type layerRevision struct {
	Role       string           `json:"role"`
	ProfileID  string           `json:"profileId"`
	Generation string           `json:"generation"`
	Secrets    []secretRevision `json:"secrets,omitempty"`
}

type secretRevision struct {
	Key      string `json:"key"`
	SecretID string `json:"secretId"`
	Version  int    `json:"version"`
}

// runtimeIdentity names the profile layers of a run: two runs with the same
// identity took the same stored state of every layer, and so the same
// variables and secrets from profiles. Empty means unknown: a layer whose
// state has no generation cannot be told from another state of it. No
// layers at all is a known state, the same for every run without one.
//
// It covers the profile layers only. Context without a server-side version
// (external DAG secrets, dotenv, the base config) is the caller's to treat as
// unknown (TXE-6222).
func runtimeIdentity(layers []layerRevision) string {
	canonical := make([]layerRevision, 0, len(layers))
	for _, layer := range layers {
		if layer.Generation == "" || layer.ProfileID == "" {
			return ""
		}
		secrets := append([]secretRevision(nil), layer.Secrets...)
		sort.Slice(secrets, func(i, j int) bool { return secrets[i].Key < secrets[j].Key })
		for _, s := range secrets {
			if s.SecretID == "" || s.Version <= 0 {
				return ""
			}
		}
		layer.Secrets = secrets
		canonical = append(canonical, layer)
	}
	data, err := json.Marshal(canonical)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return runtimeIdentityPrefix + hex.EncodeToString(sum[:])
}
