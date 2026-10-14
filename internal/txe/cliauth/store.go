// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package cliauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gofrs/flock"

	"github.com/dagucloud/dagu/v2/internal/cmn/crypto"
	"github.com/dagucloud/dagu/v2/internal/cmn/fileutil"
)

// ErrNotSignedIn reports that there is no usable sign-in for a hub.
var ErrNotSignedIn = errors.New("not signed in to this hub: run \"dagu txe login\"")

// RenewMargin is how long before its expiry an access token is renewed.
const RenewMargin = 30 * time.Second

// storeSchema is the version of the entry file.
const storeSchema = 1

const (
	storeDirPerm  = 0o700
	storeFilePerm = 0o600
	lockTimeout   = 30 * time.Second
	lockRetry     = 50 * time.Millisecond
	// renewTimeout bounds a renewal made under the lock. It is shorter than
	// lockTimeout, so a process waiting for the lock outlasts a renewal
	// that gets no answer.
	renewTimeout = 20 * time.Second
)

// Entry is a hub's sign-in: one identity at one provider.
type Entry struct {
	Hub      string
	Provider Provider
	Identity Identity
	// Username is for showing only.
	Username     string
	AccessToken  string
	RefreshToken string
	// Expiry is when AccessToken stops being usable.
	Expiry     time.Time
	SignedInAt time.Time
	RenewedAt  time.Time
}

// storedEntry is an Entry as written. Sealed holds the tokens, encrypted
// together with what they are bound to.
type storedEntry struct {
	Schema     int       `json:"schema"`
	Hub        string    `json:"hub"`
	Issuer     string    `json:"issuer"`
	ClientID   string    `json:"client_id"`
	Scopes     []string  `json:"scopes,omitempty"`
	Subject    string    `json:"subject"`
	Username   string    `json:"username,omitempty"`
	Sealed     string    `json:"sealed"`
	Expiry     time.Time `json:"expiry"`
	SignedInAt time.Time `json:"signed_in_at"`
	RenewedAt  time.Time `json:"renewed_at,omitzero"`
}

// sealedEntry is the plaintext of storedEntry.Sealed. The binding is sealed
// with the tokens, so that editing the file's hub, issuer, client or subject
// cannot send a refresh token to another provider: the entry stops reading.
type sealedEntry struct {
	Hub          string   `json:"hub"`
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	Scopes       []string `json:"scopes,omitempty"`
	Subject      string   `json:"subject"`
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
}

func (b sealedEntry) binds(stored *storedEntry) bool {
	return b.Hub == stored.Hub && b.Issuer == stored.Issuer && b.ClientID == stored.ClientID &&
		b.Subject == stored.Subject && slices.Equal(b.Scopes, stored.Scopes)
}

// Store keeps one sign-in per hub in a directory only this user can read.
// The tokens are encrypted with the key that protects the CLI context
// store's API keys.
//
// Every change happens under an exclusive lock on the hub's entry, and the
// entry is read again once the lock is held, so CLIs running at the same
// time (several Claude Code and Codex sessions) renew once between them and
// a renewal never writes over a newer sign-in.
type Store struct {
	dir string
	enc *crypto.Encryptor
	// now is the clock, replaceable in tests.
	now func() time.Time
	// renew is Refresh, replaceable in tests.
	renew func(ctx context.Context, p Provider, want Identity, refreshToken string, client *http.Client) (*Tokens, error)
}

// NewStore returns the store kept in dir, creating dir when it is absent.
func NewStore(dir string, enc *crypto.Encryptor) (*Store, error) {
	if dir == "" {
		return nil, errors.New("cliauth: a store directory is required")
	}
	if enc == nil {
		return nil, errors.New("cliauth: an encryptor is required")
	}
	if err := os.MkdirAll(dir, storeDirPerm); err != nil {
		return nil, fmt.Errorf("create sign-in store: %w", err)
	}
	if err := checkPrivate(dir, true); err != nil {
		return nil, err
	}
	return &Store{dir: dir, enc: enc, now: time.Now, renew: Refresh}, nil
}

// NormalizeHub returns the form of a hub URL its entry is keyed by: scheme
// and host in lower case, no trailing slash, no query or fragment.
func NormalizeHub(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("invalid hub URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("invalid hub URL %q", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func (s *Store) paths(hub string) (file, lock string, err error) {
	hub, err = NormalizeHub(hub)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(hub))
	name := hex.EncodeToString(sum[:16])
	return filepath.Join(s.dir, name+".json"), filepath.Join(s.dir, name+".lock"), nil
}

// Load returns the hub's sign-in, or ErrNotSignedIn.
func (s *Store) Load(hub string) (*Entry, error) {
	file, _, err := s.paths(hub)
	if err != nil {
		return nil, err
	}
	return s.read(file, hub)
}

func (s *Store) read(file, hub string) (*Entry, error) {
	if err := checkPrivate(file, false); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, ErrNotSignedIn
		}
		return nil, err
	}
	data, err := os.ReadFile(file) //nolint:gosec // a file in the store's own directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotSignedIn
	}
	if err != nil {
		return nil, fmt.Errorf("read sign-in: %w", err)
	}
	var stored storedEntry
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("read sign-in %s: %w", file, err)
	}
	if stored.Schema != storeSchema {
		return nil, fmt.Errorf("sign-in %s has schema %d, this CLI reads %d: run \"dagu txe login\"", file, stored.Schema, storeSchema)
	}
	want, err := NormalizeHub(hub)
	if err != nil {
		return nil, err
	}
	if stored.Hub != want {
		return nil, fmt.Errorf("sign-in %s is for %s, not %s", file, stored.Hub, want)
	}
	plain, err := s.enc.Decrypt(stored.Sealed)
	if err != nil {
		return nil, fmt.Errorf("read sign-in %s: %w", file, err)
	}
	var sealed sealedEntry
	if err := json.Unmarshal([]byte(plain), &sealed); err != nil {
		return nil, fmt.Errorf("read sign-in %s: %w", file, err)
	}
	if !sealed.binds(&stored) {
		return nil, fmt.Errorf("sign-in %s was changed outside dagu: run \"dagu txe login\"", file)
	}
	return &Entry{
		Hub:          stored.Hub,
		Provider:     Provider{Issuer: stored.Issuer, ClientID: stored.ClientID, Scopes: stored.Scopes},
		Identity:     Identity{Issuer: stored.Issuer, Subject: stored.Subject},
		Username:     stored.Username,
		AccessToken:  sealed.AccessToken,
		RefreshToken: sealed.RefreshToken,
		Expiry:       stored.Expiry,
		SignedInAt:   stored.SignedInAt,
		RenewedAt:    stored.RenewedAt,
	}, nil
}

func (s *Store) write(file string, e *Entry) error {
	if e.Identity.Issuer != e.Provider.Issuer {
		return errors.New("cliauth: an entry's identity must be at its provider's issuer")
	}
	if e.Identity.Subject == "" || e.RefreshToken == "" || e.AccessToken == "" {
		return errors.New("cliauth: an entry needs a subject and both tokens")
	}
	plain, err := json.Marshal(sealedEntry{ //nolint:gosec // the plaintext that is encrypted below; never written as it is
		Hub:          e.Hub,
		Issuer:       e.Provider.Issuer,
		ClientID:     e.Provider.ClientID,
		Scopes:       e.Provider.Scopes,
		Subject:      e.Identity.Subject,
		AccessToken:  e.AccessToken,
		RefreshToken: e.RefreshToken,
	})
	if err != nil {
		return err
	}
	sealed, err := s.enc.Encrypt(string(plain))
	if err != nil {
		return fmt.Errorf("encrypt sign-in: %w", err)
	}
	data, err := json.MarshalIndent(storedEntry{
		Schema:     storeSchema,
		Hub:        e.Hub,
		Issuer:     e.Provider.Issuer,
		ClientID:   e.Provider.ClientID,
		Scopes:     e.Provider.Scopes,
		Subject:    e.Identity.Subject,
		Username:   e.Username,
		Sealed:     sealed,
		Expiry:     e.Expiry.UTC(),
		SignedInAt: e.SignedInAt.UTC(),
		RenewedAt:  e.RenewedAt.UTC(),
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := fileutil.WriteFileAtomic(file, data, storeFilePerm); err != nil {
		return fmt.Errorf("write sign-in: %w", err)
	}
	return nil
}

// locked runs fn with the hub's entry lock held.
func (s *Store) locked(ctx context.Context, lockPath string, fn func() error) error {
	lock := flock.New(lockPath, flock.SetPermissions(storeFilePerm))
	lockCtx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	ok, err := lock.TryLockContext(lockCtx, lockRetry)
	if err != nil || !ok {
		if err == nil {
			err = lockCtx.Err()
		}
		return fmt.Errorf("another dagu process holds this hub's sign-in: %w", err)
	}
	defer func() { _ = lock.Unlock() }()
	return fn()
}

// Replace makes e the hub's sign-in and returns the one it replaced, if
// any. Nothing of the previous sign-in is kept: revoking its refresh token
// is the caller's to do.
func (s *Store) Replace(ctx context.Context, e *Entry) (*Entry, error) {
	hub, err := NormalizeHub(e.Hub)
	if err != nil {
		return nil, err
	}
	file, lockPath, err := s.paths(hub)
	if err != nil {
		return nil, err
	}
	copied := *e
	copied.Hub = hub
	var previous *Entry
	err = s.locked(ctx, lockPath, func() error {
		old, err := s.read(file, hub)
		switch {
		case err == nil:
			previous = old
		case !errors.Is(err, ErrNotSignedIn):
			// An unreadable entry is replaced: signing in again is how
			// one recovers from it.
		}
		return s.write(file, &copied)
	})
	if err != nil {
		return nil, err
	}
	return previous, nil
}

// Remove deletes the hub's sign-in and returns it, or ErrNotSignedIn.
func (s *Store) Remove(ctx context.Context, hub string) (*Entry, error) {
	file, lockPath, err := s.paths(hub)
	if err != nil {
		return nil, err
	}
	var removed *Entry
	err = s.locked(ctx, lockPath, func() error {
		old, readErr := s.read(file, hub)
		if errors.Is(readErr, ErrNotSignedIn) {
			return ErrNotSignedIn
		}
		if readErr == nil {
			removed = old
		}
		if err := fileutil.RemoveFileDurable(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove sign-in: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return removed, nil
}

// AccessToken returns an access token for the hub, renewing it when it has
// less than RenewMargin left.
//
// A renewal the provider refuses, or one that names another identity, ends
// the sign-in: the entry is removed and the error says to sign in again. A
// renewal that gets no verdict keeps the entry; the current token is
// returned while it is still valid, and otherwise the *UnverifiableError.
func (s *Store) AccessToken(ctx context.Context, hub string, client *http.Client) (string, error) {
	e, err := s.Load(hub)
	if err != nil {
		return "", err
	}
	if s.now().Add(RenewMargin).Before(e.Expiry) {
		return e.AccessToken, nil
	}
	return s.renewAfter(ctx, hub, "", client)
}

// Renew renews the hub's access token because the hub refused stale, the
// token the caller sent. When another process has already replaced it, the
// newer token is returned without asking the provider.
func (s *Store) Renew(ctx context.Context, hub, stale string, client *http.Client) (string, error) {
	if stale == "" {
		return "", errors.New("cliauth: Renew needs the token the hub refused")
	}
	return s.renewAfter(ctx, hub, stale, client)
}

func (s *Store) renewAfter(ctx context.Context, hub, stale string, client *http.Client) (string, error) {
	file, lockPath, err := s.paths(hub)
	if err != nil {
		return "", err
	}
	var token string
	err = s.locked(ctx, lockPath, func() error {
		e, err := s.read(file, hub)
		if err != nil {
			return err
		}
		fresh := s.now().Add(RenewMargin).Before(e.Expiry)
		if stale == "" && fresh {
			token = e.AccessToken
			return nil
		}
		if stale != "" && !constantTimeEqual(e.AccessToken, stale) && fresh {
			token = e.AccessToken
			return nil
		}
		renewCtx, cancel := context.WithTimeout(ctx, renewTimeout)
		renewed, err := s.renew(renewCtx, e.Provider, e.Identity, e.RefreshToken, client)
		cancel()
		var refused *RefusedError
		switch {
		case err == nil:
		case errors.As(err, &refused), errors.Is(err, ErrIdentityChanged), errors.Is(err, ErrNotSignedIn):
			if rmErr := fileutil.RemoveFileDurable(file); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
				return errors.Join(err, fmt.Errorf("remove ended sign-in: %w", rmErr))
			}
			return err
		default:
			if stale == "" && s.now().Before(e.Expiry) {
				token = e.AccessToken
				return nil
			}
			return err
		}
		if renewed.Identity != e.Identity {
			if rmErr := fileutil.RemoveFileDurable(file); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
				return errors.Join(ErrIdentityChanged, rmErr)
			}
			return ErrIdentityChanged
		}
		next := *e
		next.AccessToken = renewed.AccessToken
		next.RefreshToken = renewed.RefreshToken
		next.Expiry = renewed.Expiry
		next.RenewedAt = s.now()
		if renewed.Username != "" {
			next.Username = renewed.Username
		}
		if err := s.write(file, &next); err != nil {
			return err
		}
		token = next.AccessToken
		return nil
	})
	if err != nil {
		return "", err
	}
	return token, nil
}
