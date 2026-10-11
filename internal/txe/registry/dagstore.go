// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package registry

import (
	"context"
	"errors"
	"fmt"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/persis"
)

// DAGRepository is the subset of the hub's DAG repository the registry uses.
type DAGRepository interface {
	Create(ctx context.Context, id string, source []byte) error
	GetSpec(ctx context.Context, id string) (string, error)
	UpdateSpec(ctx context.Context, id string, source []byte) error
	LoadSpec(ctx context.Context, source []byte, name string, opts persis.DAGLoadOptions) (*ir.DAG, error)
}

type repoDAGStore struct {
	repo DAGRepository
}

// NewDAGStore adapts the hub's DAG repository for the registry.
func NewDAGStore(repo DAGRepository) DAGStore {
	return &repoDAGStore{repo: repo}
}

func (d *repoDAGStore) CheckSpec(ctx context.Context, name string, spec []byte) (DAGFacts, error) {
	dag, err := d.repo.LoadSpec(ctx, spec, name, persis.DAGLoadOptions{})
	if err != nil {
		return DAGFacts{}, err
	}
	return DAGFacts{WorkerSelector: dag.WorkerSelector}, nil
}

func (d *repoDAGStore) SpecSHA256(ctx context.Context, name string) (string, error) {
	spec, err := d.repo.GetSpec(ctx, name)
	if err != nil {
		if errors.Is(err, persis.ErrDAGNotFound) {
			return "", fmt.Errorf("DAG %s: %w", name, persis.ErrNotFound)
		}
		return "", err
	}
	return specDigest([]byte(spec)), nil
}

func (d *repoDAGStore) WriteSpec(ctx context.Context, name string, spec []byte) error {
	err := d.repo.Create(ctx, name, spec)
	if errors.Is(err, persis.ErrDAGAlreadyExists) {
		return d.repo.UpdateSpec(ctx, name, spec)
	}
	return err
}
