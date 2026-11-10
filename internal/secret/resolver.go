// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package secret

import (
	"context"
	"errors"
	"fmt"

	secretref "github.com/dagucloud/dagu/v2/internal/secret/ref"
)

type ReferenceResolver struct {
	store     Store
	workspace string
}

func NewReferenceResolver(store Store, workspace string) *ReferenceResolver {
	return &ReferenceResolver{
		store:     store,
		workspace: NormalizeWorkspace(workspace),
	}
}

func (r *ReferenceResolver) ResolveReference(ctx context.Context, ref secretref.Ref) (string, error) {
	sec, err := r.lookup(ctx, ref)
	if err != nil {
		return "", err
	}
	value, _, err := r.store.ResolveValue(ctx, sec.ID)
	return value, err
}

// ResolveReferenceRevision is ResolveReference that also names the stored
// revision the value was read from: the secret's ID and the version of the
// value, taken from the same read (TXE-6222).
func (r *ReferenceResolver) ResolveReferenceRevision(ctx context.Context, ref secretref.Ref) (string, secretref.Revision, error) {
	sec, err := r.lookup(ctx, ref)
	if err != nil {
		return "", secretref.Revision{}, err
	}
	value, version, err := r.store.ResolveValue(ctx, sec.ID)
	if err != nil {
		return "", secretref.Revision{}, err
	}
	return value, versionRevision(sec, version), nil
}

// Revision names the stored revision ref resolves to now, from metadata
// alone: no value is read. A revision that cannot be named is the zero
// Revision.
func (r *ReferenceResolver) Revision(ctx context.Context, ref secretref.Ref) (secretref.Revision, error) {
	sec, err := r.lookup(ctx, ref)
	if err != nil {
		return secretref.Revision{}, err
	}
	version, err := r.store.GetCurrentVersion(ctx, sec.ID)
	if err != nil {
		return secretref.Revision{}, err
	}
	return versionRevision(sec, version), nil
}

// versionRevision is the revision of sec's value version, or the zero
// Revision when the version is not one of sec.
func versionRevision(sec *Secret, version *VersionMetadata) secretref.Revision {
	if version == nil || version.SecretID != sec.ID {
		return secretref.Revision{}
	}
	return secretref.Revision{SecretID: sec.ID, Version: version.Version}
}

// ReadReference returns the secret ref resolves to and its current value,
// like ResolveReference, without recording the resolution on the secret.
func (r *ReferenceResolver) ReadReference(ctx context.Context, ref secretref.Ref) (*Secret, string, error) {
	sec, err := r.lookup(ctx, ref)
	if err != nil {
		return nil, "", err
	}
	value, _, err := r.store.ReadValue(ctx, sec.ID)
	if err != nil {
		return nil, "", err
	}
	return sec, value, nil
}

func (r *ReferenceResolver) CheckReferenceAccessibility(ctx context.Context, ref secretref.Ref) error {
	sec, err := r.lookup(ctx, ref)
	if err != nil {
		return err
	}
	_, err = r.store.GetCurrentVersion(ctx, sec.ID)
	return err
}

func (r *ReferenceResolver) lookup(ctx context.Context, ref secretref.Ref) (*Secret, error) {
	if r == nil || r.store == nil {
		return nil, fmt.Errorf("secret store is not configured")
	}
	sec, err := r.getByRef(ctx, ref.Ref)
	if err != nil {
		return nil, err
	}
	if err := ensureResolvable(sec); err != nil {
		return nil, err
	}
	return sec, nil
}

func (r *ReferenceResolver) getByRef(ctx context.Context, ref string) (*Secret, error) {
	sec, err := r.store.GetByRef(ctx, r.workspace, ref)
	if err == nil {
		return sec, nil
	}
	if !errors.Is(err, ErrNotFound) || r.workspace == GlobalWorkspace {
		return nil, err
	}
	return r.store.GetByRef(ctx, GlobalWorkspace, ref)
}

func ensureResolvable(sec *Secret) error {
	if sec.Status == StatusDisabled {
		return ErrDisabled
	}
	if sec.ProviderType != ProviderDaguManaged {
		return fmt.Errorf("%w: %s", ErrUnsupportedProvider, sec.ProviderType)
	}
	return nil
}
