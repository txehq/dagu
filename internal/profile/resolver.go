// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package profile

import (
	"context"
	"errors"
	"fmt"

	"github.com/dagucloud/dagu/v2/internal/cmn/stringutil"
	"github.com/dagucloud/dagu/v2/internal/secret"
)

type Resolver struct {
	profileStore Store
	secretStore  secret.Store
}

type Resolved struct {
	Name      string
	Variables map[string]string
	Secrets   map[string]string
	Entries   []ResolvedEntry
}

type ResolvedEntry struct {
	Key  string
	Kind EntryKind
}

type RuntimeRequest struct {
	ProfileName string
	Workspace   string
}

type RuntimeResolved struct {
	Defaults *Resolved
	Selected *Resolved
	// Identity names the stored state of every layer the values were read
	// from, taken in the same reads (see runtimeIdentity). Empty is unknown.
	Identity string
}

type RuntimeResolver interface {
	ResolveRuntime(context.Context, RuntimeRequest) (*RuntimeResolved, error)
}

func (r *Resolved) EnvVars(kind EntryKind) []string {
	if r == nil {
		return nil
	}
	envs := make([]string, 0, len(r.Entries))
	for _, entry := range r.Entries {
		if entry.Kind != kind {
			continue
		}
		switch kind {
		case EntryKindVariable:
			envs = append(envs, stringutil.NewKeyValue(entry.Key, r.Variables[entry.Key]).String())
		case EntryKindSecret:
			envs = append(envs, stringutil.NewKeyValue(entry.Key, r.Secrets[entry.Key]).String())
		}
	}
	return envs
}

func MergeResolved(name string, layers ...*Resolved) *Resolved {
	merged := &Resolved{
		Name:      name,
		Variables: make(map[string]string),
		Secrets:   make(map[string]string),
		Entries:   make([]ResolvedEntry, 0),
	}
	entryIndex := make(map[string]int)
	for _, layer := range layers {
		if layer == nil {
			continue
		}
		for _, entry := range layer.Entries {
			if idx, ok := entryIndex[entry.Key]; ok {
				merged.Entries[idx] = entry
			} else {
				entryIndex[entry.Key] = len(merged.Entries)
				merged.Entries = append(merged.Entries, entry)
			}
			switch entry.Kind {
			case EntryKindVariable:
				merged.Variables[entry.Key] = layer.Variables[entry.Key]
				delete(merged.Secrets, entry.Key)
			case EntryKindSecret:
				merged.Secrets[entry.Key] = layer.Secrets[entry.Key]
				delete(merged.Variables, entry.Key)
			}
		}
	}
	return merged
}

func NewResolver(profileStore Store, secretStore secret.Store) *Resolver {
	return &Resolver{
		profileStore: profileStore,
		secretStore:  secretStore,
	}
}

func (r *Resolver) Resolve(ctx context.Context, name string) (*Resolved, error) {
	if r == nil || r.profileStore == nil {
		return nil, fmt.Errorf("profile store is not configured")
	}
	p, err := r.profileStore.GetByName(ctx, name)
	if err != nil {
		return nil, err
	}
	return r.resolve(ctx, p)
}

func (r *Resolver) ResolveInherited(ctx context.Context, ref InheritedRef) (*Resolved, error) {
	if r == nil || r.profileStore == nil {
		return nil, fmt.Errorf("profile store is not configured")
	}
	p, err := r.profileStore.GetInherited(ctx, ref)
	if err != nil {
		return nil, err
	}
	return r.resolve(ctx, p)
}

func (r *Resolver) ResolveRuntime(ctx context.Context, req RuntimeRequest) (*RuntimeResolved, error) {
	if r == nil || r.profileStore == nil {
		return nil, fmt.Errorf("profile store is not configured")
	}
	layers, err := r.runtimeLayers(ctx, req)
	if err != nil {
		return nil, err
	}

	defaultLayers := make([]*Resolved, 0, 2)
	revisions := make([]layerRevision, 0, len(layers))
	var selected *Resolved
	for _, layer := range layers {
		resolved, revision, err := r.resolveWithRevision(ctx, layer.profile)
		if err != nil {
			return nil, layer.wrap(err)
		}
		revision.Role = layer.role
		revisions = append(revisions, revision)
		if layer.role == layerRoleSelected {
			selected = resolved
		} else {
			defaultLayers = append(defaultLayers, resolved)
		}
	}

	var defaults *Resolved
	if len(defaultLayers) > 0 {
		defaults = MergeResolved("defaults", defaultLayers...)
	}
	return &RuntimeResolved{Defaults: defaults, Selected: selected, Identity: runtimeIdentity(revisions)}, nil
}

// RuntimeIdentity answers the identity that a run with req would take now
// (see RuntimeResolved.Identity), from the same layers as ResolveRuntime.
// It reads no value: each secret's version comes from its metadata. It is an
// expectation only; the run compares it with the identity of its own
// resolve before it uses anything that relied on it (TXE-6145).
func (r *Resolver) RuntimeIdentity(ctx context.Context, req RuntimeRequest) (string, error) {
	if r == nil || r.profileStore == nil {
		return "", fmt.Errorf("profile store is not configured")
	}
	layers, err := r.runtimeLayers(ctx, req)
	if err != nil {
		return "", err
	}
	revisions := make([]layerRevision, 0, len(layers))
	for _, layer := range layers {
		revision, err := r.currentRevision(ctx, layer.profile)
		if err != nil {
			return "", layer.wrap(err)
		}
		revision.Role = layer.role
		revisions = append(revisions, revision)
	}
	return runtimeIdentity(revisions), nil
}

// runtimeLayer is one stored profile that a run takes, read once.
type runtimeLayer struct {
	role    string
	profile *Profile
	wrap    func(error) error
}

// runtimeLayers reads the profiles a run with req takes, in order of
// precedence: the global defaults and the workspace defaults when they
// exist, then the selected profile.
func (r *Resolver) runtimeLayers(ctx context.Context, req RuntimeRequest) ([]runtimeLayer, error) {
	layers := make([]runtimeLayer, 0, 3)
	global, err := r.profileStore.GetInherited(ctx, GlobalInheritedRef())
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, fmt.Errorf("resolve global profile defaults: %w", err)
	}
	if global != nil {
		layers = append(layers, runtimeLayer{role: layerRoleGlobal, profile: global, wrap: func(err error) error {
			return fmt.Errorf("resolve global profile defaults: %w", err)
		}})
	}

	if req.Workspace != "" {
		ref, err := WorkspaceInheritedRef(req.Workspace)
		if err != nil {
			return nil, fmt.Errorf("resolve workspace profile defaults: %w", err)
		}
		workspaceDefaults, err := r.profileStore.GetInherited(ctx, ref)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("resolve workspace profile defaults %q: %w", req.Workspace, err)
		}
		if workspaceDefaults != nil {
			layers = append(layers, runtimeLayer{role: layerRoleWorkspace, profile: workspaceDefaults, wrap: func(err error) error {
				return fmt.Errorf("resolve workspace profile defaults %q: %w", req.Workspace, err)
			}})
		}
	}

	if req.ProfileName != "" {
		wrap := func(err error) error {
			return fmt.Errorf("resolve profile %q: %w", req.ProfileName, err)
		}
		selected, err := r.profileStore.GetByName(ctx, req.ProfileName)
		if err != nil {
			return nil, wrap(err)
		}
		layers = append(layers, runtimeLayer{role: layerRoleSelected, profile: selected, wrap: wrap})
	}
	return layers, nil
}

// currentRevision is the revision of p without reading a value: each
// secret's version is its current one in the secret store's metadata.
func (r *Resolver) currentRevision(ctx context.Context, p *Profile) (layerRevision, error) {
	if p.Status == StatusDisabled {
		return layerRevision{}, ErrDisabled
	}
	revision := layerRevision{ProfileID: p.ID, Generation: p.Generation}
	for _, entry := range p.Entries {
		switch entry.Kind {
		case EntryKindVariable:
		case EntryKindSecret:
			if r.secretStore == nil {
				return layerRevision{}, fmt.Errorf("secret store is not configured")
			}
			version, err := r.secretStore.GetCurrentVersion(ctx, entry.SecretID)
			if err != nil {
				return layerRevision{}, fmt.Errorf("resolve profile secret %s: %w", entry.Key, err)
			}
			revision.Secrets = append(revision.Secrets, secretRevision{Key: entry.Key, SecretID: entry.SecretID, Version: version.Version})
		default:
			return layerRevision{}, fmt.Errorf("unsupported profile entry kind %q", entry.Kind)
		}
	}
	return revision, nil
}

func (r *Resolver) resolve(ctx context.Context, p *Profile) (*Resolved, error) {
	resolved, _, err := r.resolveWithRevision(ctx, p)
	return resolved, err
}

// resolveWithRevision resolves p and names the state its values came from:
// the profile as read, and the version that each secret's value was read at.
func (r *Resolver) resolveWithRevision(ctx context.Context, p *Profile) (*Resolved, layerRevision, error) {
	if p.Status == StatusDisabled {
		return nil, layerRevision{}, ErrDisabled
	}
	revision := layerRevision{ProfileID: p.ID, Generation: p.Generation}

	resolved := &Resolved{
		Name:      p.Name,
		Variables: make(map[string]string),
		Secrets:   make(map[string]string),
		Entries:   make([]ResolvedEntry, 0, len(p.Entries)),
	}
	for _, entry := range p.Entries {
		switch entry.Kind {
		case EntryKindVariable:
			resolved.Variables[entry.Key] = entry.Value
		case EntryKindSecret:
			if r.secretStore == nil {
				return nil, layerRevision{}, fmt.Errorf("secret store is not configured")
			}
			value, version, err := r.secretStore.ResolveValue(ctx, entry.SecretID)
			if err != nil {
				return nil, layerRevision{}, fmt.Errorf("resolve profile secret %s: %w", entry.Key, err)
			}
			resolved.Secrets[entry.Key] = value
			// The version comes with the value, from the same read.
			secretVersion := 0
			if version != nil {
				secretVersion = version.Version
			}
			revision.Secrets = append(revision.Secrets, secretRevision{Key: entry.Key, SecretID: entry.SecretID, Version: secretVersion})
		default:
			return nil, layerRevision{}, fmt.Errorf("unsupported profile entry kind %q", entry.Kind)
		}
		resolved.Entries = append(resolved.Entries, ResolvedEntry{
			Key:  entry.Key,
			Kind: entry.Kind,
		})
	}
	return resolved, revision, nil
}
