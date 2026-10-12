// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/dagucloud/dagu/v2/internal/persis"
	persisfile "github.com/dagucloud/dagu/v2/internal/persis/file"
)

// Registry is what this package needs to know about owners and what they
// hold. The TXE registry is the authority for all of it; an adapter over it
// is supplied by whoever wires this package. Each lookup returns ErrNotFound
// for something the registry does not hold.
type Registry interface {
	// OwnerExists reports whether the owner is registered.
	OwnerExists(ctx context.Context, ownerID string) (bool, error)
	// JobFacts returns who owns a job and where it runs.
	JobFacts(ctx context.Context, jobID string) (JobFacts, error)
	// ProjectOwner returns the owner of a project.
	ProjectOwner(ctx context.Context, projectID string) (string, error)
	// MachineOwner returns the owner of a machine.
	MachineOwner(ctx context.Context, machineID string) (string, error)
}

// JobFacts is what the registry records about a job's place.
type JobFacts struct {
	OwnerID   string
	ProjectID string
	MachineID string
}

// Dir returns the directory this package's records live in, under the Dagu
// data directory. It is beside the registry's and separate from it.
func Dir(dataDir string) string {
	return filepath.Join(dataDir, "txe", "authz", "v1")
}

// Store holds bindings, binding requests, shares and enrolments, and decides
// from them. It is safe for concurrent use, by several processes too when its
// collection is.
//
// Each record changes by create-only insert or by compare-and-swap, so two
// changes to one record never overwrite each other: one of them is applied
// and the other is judged against the result.
type Store struct {
	col      persis.Collection
	registry Registry
	now      func() time.Time
}

// Option configures a Store.
type Option func(*Store)

// WithClock overrides the clock.
func WithClock(now func() time.Time) Option {
	return func(s *Store) { s.now = now }
}

// New returns a store over col that looks owners up in registry.
func New(col persis.Collection, registry Registry, opts ...Option) (*Store, error) {
	if col == nil {
		return nil, errors.New("authz: a collection is required")
	}
	if registry == nil {
		return nil, errors.New("authz: a registry is required")
	}
	s := &Store{col: col, registry: registry, now: time.Now}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// NewFileStore returns a store kept under Dir(dataDir), in the same file
// format and with the same locking as the registry's records.
func NewFileStore(dataDir string, registry Registry, opts ...Option) (*Store, error) {
	if dataDir == "" {
		return nil, errors.New("authz: a data directory is required")
	}
	return New(persisfile.NewCollection(Dir(dataDir), persisfile.WithIndentedJSON()), registry, opts...)
}

func (s *Store) clock() time.Time { return s.now().UTC() }

// read loads a record into v and returns its stored bytes, which a later
// compare-and-swap names as what it expects to replace. found is false, with
// no error, when there is no such record.
func (s *Store) read(ctx context.Context, id string, v any) (raw []byte, found bool, err error) {
	rec, err := s.col.Get(ctx, id)
	if err != nil {
		if errors.Is(err, persis.ErrNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	if err := json.Unmarshal(rec.Data, v); err != nil {
		return nil, false, fmt.Errorf("authz: decode %s: %w", id, err)
	}
	return rec.Data, true, nil
}

// create inserts a record. created is false, with no error, when one with
// that id is already there.
func (s *Store) create(ctx context.Context, id string, v any) (created bool, err error) {
	data, err := json.Marshal(v)
	if err != nil {
		return false, err
	}
	now := s.clock()
	err = s.col.Create(ctx, &persis.Record{ID: id, Data: data, CreatedAt: now, UpdatedAt: now})
	if errors.Is(err, persis.ErrConflict) {
		return false, nil
	}
	return err == nil, err
}

// swap replaces a record whose stored bytes are still expected. swapped is
// false, with no error, when another change got there first.
func (s *Store) swap(ctx context.Context, id string, expected []byte, v any) (swapped bool, err error) {
	next, err := json.Marshal(v)
	if err != nil {
		return false, err
	}
	err = s.col.CompareAndSwap(ctx, id, expected, next)
	if errors.Is(err, persis.ErrConflict) || errors.Is(err, persis.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// attempts bounds how often a change is retried after losing a race for its
// record. Every lost race means another change was applied, so this many in a
// row is contention no caller should wait out.
const attempts = 16

// errContended is returned when a change kept losing the race for its record.
var errContended = errors.New("authz: the record kept changing; try again")

// archive keeps a record that is about to be replaced by a newer generation.
// Nothing in this package is ever deleted.
func (s *Store) archive(ctx context.Context, prefix, digest string, generation int, v any) error {
	_, err := s.create(ctx, fmt.Sprintf("%s%s/%06d", prefix, digest, generation), v)
	return err
}

// lookupOwner reports a registry lookup as this package's errors.
func lookupOwner(owner string, err error, what, id string) (string, error) {
	if errors.Is(err, ErrNotFound) {
		return "", refuse(CodeNotFound, "%s %s is not registered", what, id)
	}
	if err != nil {
		return "", err
	}
	if owner == "" {
		return "", fmt.Errorf("authz: the registry returned no owner for %s %s", what, id)
	}
	return owner, nil
}
