// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package oidcsession

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dagucloud/dagu/v2/internal/cmn/crypto"
	"github.com/dagucloud/dagu/v2/internal/persis"
	persisfile "github.com/dagucloud/dagu/v2/internal/persis/file"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testIssuer  = "https://issuer.example/realms/test"
	testSubject = "subject-1"
	testUser    = "user-1"
)

var alice = Identity{UserID: testUser, Issuer: testIssuer, Subject: testSubject}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// fakeProvider is an identity provider whose answer the test chooses.
type fakeProvider struct {
	mu sync.Mutex
	// answer is called for each refresh with the token presented.
	answer func(refreshToken string) (Renewal, error)
	// gate, when set, holds every refresh until it is closed.
	gate      chan struct{}
	started   chan struct{}
	refreshes []string
	revoked   []string
	issued    int
}

func (p *fakeProvider) Refresh(_ context.Context, refreshToken string) (Renewal, error) {
	p.mu.Lock()
	p.refreshes = append(p.refreshes, refreshToken)
	answer, gate, started := p.answer, p.gate, p.started
	p.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if gate != nil {
		<-gate
	}
	return answer(refreshToken)
}

func (p *fakeProvider) Revoke(_ context.Context, refreshToken string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.revoked = append(p.revoked, refreshToken)
	return nil
}

func (p *fakeProvider) set(answer func(string) (Renewal, error)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.answer = answer
}

func (p *fakeProvider) calls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.refreshes)
}

func (p *fakeProvider) revocations() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.revoked...)
}

// rotate grants every refresh and returns a new refresh token each time, as
// the measured provider does.
func (p *fakeProvider) rotate() func(string) (Renewal, error) {
	return func(string) (Renewal, error) {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.issued++
		return Renewal{RefreshToken: fmt.Sprintf("refresh-token-%d", p.issued)}, nil
	}
}

func refuse(code string) func(string) (Renewal, error) {
	return func(string) (Renewal, error) {
		return Renewal{}, &RefusedError{Status: 400, Code: code}
	}
}

func unavailable(string) (Renewal, error) {
	return Renewal{}, errors.New("the identity provider did not answer")
}

type fixture struct {
	t        *testing.T
	clock    *testClock
	provider *fakeProvider
	manager  *Manager
	col      persis.Collection
	dir      string
}

func newFixture(t *testing.T, checkID IDTokenChecker) *fixture {
	t.Helper()
	f := &fixture{
		t:        t,
		clock:    &testClock{now: time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)},
		provider: &fakeProvider{},
		dir:      t.TempDir(),
	}
	f.provider.set(f.provider.rotate())
	f.col = persisfile.NewCollection(f.dir)
	enc, err := crypto.NewEncryptor("a-test-key-that-is-long-enough-for-aes")
	require.NoError(t, err)
	manager, err := NewManager(Config{
		RevalidateAfter: 4 * time.Minute, RevalidateLimit: 5 * time.Minute, Now: f.clock.Now,
	}, f.col, enc, f.provider, checkID)
	require.NoError(t, err)
	f.manager = manager
	return f
}

// signIn starts a session good for a day.
func (f *fixture) signIn() *Session {
	f.t.Helper()
	session, err := f.manager.Create(context.Background(), alice, "refresh-token-0", f.clock.Now().Add(24*time.Hour))
	require.NoError(f.t, err)
	return session
}

func (f *fixture) check(session *Session) error {
	return f.manager.Check(context.Background(), session.ID, alice)
}

func (f *fixture) stored(session *Session) *Session {
	f.t.Helper()
	stored, _, err := f.manager.load(context.Background(), session.ID)
	require.NoError(f.t, err)
	return stored
}

// Inside revalidate_after a request is served and the provider is not asked.
// After it the provider is asked once, and the session is good for another
// stretch.
func TestSessionIsRevalidatedAfterFourMinutes(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()

	for range 8 {
		f.clock.Advance(29 * time.Second)
		require.NoError(t, f.check(session))
	}
	assert.Zero(t, f.provider.calls(), "3 minutes 52 seconds after sign-in")

	f.clock.Advance(8 * time.Second)
	require.NoError(t, f.check(session), "at four minutes")
	assert.Equal(t, 1, f.provider.calls())

	stored := f.stored(session)
	assert.True(t, stored.LastConfirmedAt.Equal(f.clock.Now()))
	assert.Equal(t, 1, stored.Rotations)

	f.clock.Advance(4*time.Minute - time.Second)
	require.NoError(t, f.check(session))
	assert.Equal(t, 1, f.provider.calls(), "confirmed again; quiet for four more minutes")
	f.clock.Advance(time.Second)
	require.NoError(t, f.check(session))
	assert.Equal(t, 2, f.provider.calls())
}

// The provider replaces the refresh token on every refresh. The next refresh
// presents the newest one.
func TestRefreshTokenRotation(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()

	for range 3 {
		f.clock.Advance(4 * time.Minute)
		require.NoError(t, f.check(session))
	}
	f.provider.mu.Lock()
	presented := append([]string(nil), f.provider.refreshes...)
	f.provider.mu.Unlock()
	assert.Equal(t, []string{"refresh-token-0", "refresh-token-1", "refresh-token-2"}, presented)

	// A provider that returns no new token leaves the one it was sent.
	f.provider.set(func(string) (Renewal, error) { return Renewal{}, nil })
	f.clock.Advance(4 * time.Minute)
	require.NoError(t, f.check(session))
	f.clock.Advance(4 * time.Minute)
	require.NoError(t, f.check(session))
	f.provider.mu.Lock()
	assert.Equal(t, "refresh-token-3", f.provider.refreshes[len(f.provider.refreshes)-1])
	f.provider.mu.Unlock()
}

// Every refusal the provider was measured to give ends the session, and none
// of them is mistaken for an outage.
func TestARefusalEndsTheSession(t *testing.T) {
	t.Parallel()
	for _, code := range []string{"invalid_grant", "not_allowed", "invalid_client", "unauthorized_client", "other"} {
		t.Run(code, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, nil)
			session := f.signIn()
			f.provider.set(refuse(code))

			f.clock.Advance(4 * time.Minute)
			require.ErrorIs(t, f.check(session), ErrSessionEnded, "refused while still inside the limit")

			stored := f.stored(session)
			require.NotNil(t, stored.EndedAt)
			assert.Contains(t, stored.EndReason, code)
			assert.Empty(t, stored.RefreshToken, "an ended session keeps no refresh token")

			// It stays ended, and the provider is not asked about it again,
			// even if it would now say yes.
			f.provider.set(f.provider.rotate())
			for range 3 {
				f.clock.Advance(time.Minute)
				require.ErrorIs(t, f.check(session), ErrSessionEnded)
			}
			assert.Equal(t, 1, f.provider.calls())
		})
	}
}

// An outage never ends a session. Requests are served until the limit, and
// from the limit on they are told the provider is unavailable, for as long as
// it is. When it answers again the same session carries on.
func TestAnOutageIsNotARefusal(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()
	f.provider.set(unavailable)

	f.clock.Advance(4 * time.Minute)
	require.NoError(t, f.check(session), "four minutes: asked, no answer, still served")
	assert.Equal(t, 1, f.provider.calls())

	f.clock.Advance(time.Minute - time.Nanosecond)
	require.NoError(t, f.check(session), "the instant before the limit")
	f.clock.Advance(time.Nanosecond)
	require.ErrorIs(t, f.check(session), ErrProviderUnavailable, "at the limit, with no grace")

	for range 6 {
		f.clock.Advance(time.Hour)
		err := f.check(session)
		require.ErrorIs(t, err, ErrProviderUnavailable)
		require.NotErrorIs(t, err, ErrSessionEnded)
	}
	stored := f.stored(session)
	assert.Nil(t, stored.EndedAt, "six hours of outage did not end the session")
	assert.NotEmpty(t, stored.RefreshToken)

	f.provider.set(f.provider.rotate())
	f.clock.Advance(time.Minute)
	require.NoError(t, f.check(session), "the provider is back and confirms")
	assert.True(t, f.stored(session).LastConfirmedAt.Equal(f.clock.Now()))
}

// While the provider gives nothing usable it is asked at most once per retry
// interval for a session, however many requests arrive.
func TestAnOutageDoesNotHammerTheProvider(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()
	f.provider.set(unavailable)

	f.clock.Advance(4 * time.Minute)
	for range 50 {
		require.NoError(t, f.check(session))
	}
	assert.Equal(t, 1, f.provider.calls())

	f.clock.Advance(defaultRetryInterval)
	for range 50 {
		require.NoError(t, f.check(session))
	}
	assert.Equal(t, 2, f.provider.calls())

	f.clock.Advance(time.Minute)
	for range 50 {
		require.ErrorIs(t, f.check(session), ErrProviderUnavailable)
	}
	assert.Equal(t, 3, f.provider.calls(), "past the limit the answer is immediate between attempts")
}

// The provider granted a refresh and the answer never arrived. If the
// provider still accepts the token it was sent, the session carries on. If it
// accepts each token once only, the session ends. It is never left open.
func TestALostRefreshResponse(t *testing.T) {
	t.Parallel()

	t.Run("ProviderStillAcceptsTheOldToken", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		f.provider.set(unavailable) // the grant happened; the response was lost
		f.clock.Advance(4 * time.Minute)
		require.NoError(t, f.check(session))

		f.provider.set(f.provider.rotate())
		f.clock.Advance(defaultRetryInterval)
		require.NoError(t, f.check(session))
		f.provider.mu.Lock()
		assert.Equal(t, []string{"refresh-token-0", "refresh-token-0"}, f.provider.refreshes, "the token that was stored is presented again")
		f.provider.mu.Unlock()
		assert.Nil(t, f.stored(session).EndedAt)
	})

	t.Run("ProviderAcceptsEachTokenOnce", func(t *testing.T) {
		t.Parallel()
		f := newFixture(t, nil)
		session := f.signIn()
		f.provider.set(unavailable)
		f.clock.Advance(4 * time.Minute)
		require.NoError(t, f.check(session))

		f.provider.set(refuse("invalid_grant")) // the old token was used up
		f.clock.Advance(defaultRetryInterval)
		require.ErrorIs(t, f.check(session), ErrSessionEnded)
		assert.NotNil(t, f.stored(session).EndedAt)
	})
}

// Many requests at once cause one refresh. Inside the limit the others are
// served without waiting for it.
func TestConcurrentRequestsCauseOneRefresh(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()
	gate := make(chan struct{})
	f.provider.mu.Lock()
	f.provider.gate, f.provider.started = gate, make(chan struct{}, 1)
	started := f.provider.started
	f.provider.mu.Unlock()
	f.clock.Advance(4*time.Minute + 30*time.Second)

	leader := make(chan error, 1)
	go func() { leader <- f.check(session) }()
	<-started

	// The refresh is in progress and held. Everyone else is served now.
	const others = 50
	errs := make(chan error, others)
	for range others {
		go func() { errs <- f.check(session) }()
	}
	for range others {
		select {
		case err := <-errs:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Fatal("a request inside the limit waited for another request's refresh")
		}
	}
	close(gate)
	require.NoError(t, <-leader)
	assert.Equal(t, 1, f.provider.calls())
}

// Past the limit nobody is served until the provider answers. They all wait
// for the one refresh and all get its answer.
func TestPastTheLimitRequestsWaitForTheOneRefresh(t *testing.T) {
	t.Parallel()
	for name, tt := range map[string]struct {
		answer func(*fakeProvider) func(string) (Renewal, error)
		want   error
	}{
		"Granted":     {func(p *fakeProvider) func(string) (Renewal, error) { return p.rotate() }, nil},
		"Refused":     {func(*fakeProvider) func(string) (Renewal, error) { return refuse("invalid_grant") }, ErrSessionEnded},
		"Unavailable": {func(*fakeProvider) func(string) (Renewal, error) { return unavailable }, ErrProviderUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, nil)
			session := f.signIn()
			gate := make(chan struct{})
			f.provider.mu.Lock()
			f.provider.gate, f.provider.started = gate, make(chan struct{}, 1)
			started := f.provider.started
			f.provider.mu.Unlock()
			f.provider.set(tt.answer(f.provider))
			f.clock.Advance(6 * time.Minute)

			const requests = 30
			errs := make(chan error, requests)
			for range requests {
				go func() { errs <- f.check(session) }()
			}
			<-started
			select {
			case err := <-errs:
				t.Fatalf("a request past the limit was answered before the provider was: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			close(gate)
			for range requests {
				err := <-errs
				if tt.want == nil {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, tt.want)
				}
			}
			assert.Equal(t, 1, f.provider.calls())
		})
	}
}

// A sign-out that arrives while a refresh is at the provider wins: the
// session is ended, the refresh that comes back does not revive it, and the
// token it brought back is revoked at the provider.
func TestSignOutDuringARefresh(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()
	gate := make(chan struct{})
	f.provider.mu.Lock()
	f.provider.gate, f.provider.started = gate, make(chan struct{}, 1)
	started := f.provider.started
	f.provider.mu.Unlock()
	f.clock.Advance(4 * time.Minute)

	refreshing := make(chan error, 1)
	go func() { refreshing <- f.check(session) }()
	<-started

	require.NoError(t, f.manager.End(context.Background(), session.ID, "signed out"))
	close(gate)
	require.ErrorIs(t, <-refreshing, ErrSessionEnded)

	stored := f.stored(session)
	require.NotNil(t, stored.EndedAt)
	assert.Equal(t, "signed out", stored.EndReason)
	assert.Empty(t, stored.RefreshToken)
	assert.ElementsMatch(t, []string{"refresh-token-0", "refresh-token-1"}, f.provider.revocations(),
		"the token the session held and the one the late refresh brought back")
	require.ErrorIs(t, f.check(session), ErrSessionEnded)

	// Ending it again, or ending one that never existed, is not an error.
	require.NoError(t, f.manager.End(context.Background(), session.ID, "again"))
	require.NoError(t, f.manager.End(context.Background(), strings.Repeat("0", 32), "nothing there"))
	require.NoError(t, f.manager.End(context.Background(), "../../etc/passwd", "not an id"))
}

// A sign-out ends the session for the very next request, with no provider
// call, and revokes its refresh token.
func TestSignOut(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()
	require.NoError(t, f.check(session))

	require.NoError(t, f.manager.End(context.Background(), session.ID, "signed out"))
	require.ErrorIs(t, f.check(session), ErrSessionEnded)
	assert.Zero(t, f.provider.calls())
	assert.Equal(t, []string{"refresh-token-0"}, f.provider.revocations())
}

// A renewed token must be for the session's own issuer and subject.
func TestARenewedTokenForSomeoneElseEndsTheSession(t *testing.T) {
	t.Parallel()
	for name, tt := range map[string]struct {
		issuer, subject string
		err             error
		ended           bool
	}{
		"SameIdentity":     {testIssuer, testSubject, nil, false},
		"AnotherSubject":   {testIssuer, "subject-2", nil, true},
		"AnotherIssuer":    {"https://issuer.example/realms/other", testSubject, nil, true},
		"TokenNotVerified": {"", "", errors.New("bad signature"), true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, func(_ context.Context, raw string) (string, string, error) {
				require.Equal(t, "the-id-token", raw)
				return tt.issuer, tt.subject, tt.err
			})
			session := f.signIn()
			f.provider.set(func(string) (Renewal, error) {
				return Renewal{RefreshToken: "refresh-token-new", IDToken: "the-id-token"}, nil
			})
			f.clock.Advance(4 * time.Minute)

			err := f.check(session)
			if !tt.ended {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrSessionEnded)
			assert.NotNil(t, f.stored(session).EndedAt)
			assert.ElementsMatch(t, []string{"refresh-token-new", "refresh-token-0"}, f.provider.revocations())
		})
	}
}

// A session serves only the user, issuer and subject it was made for, only
// until it expires, and only under the id it was given.
func TestSessionBelongsToOneIdentityAndExpires(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()
	ctx := context.Background()

	for name, who := range map[string]Identity{
		"AnotherUser":    {UserID: "user-2", Issuer: testIssuer, Subject: testSubject},
		"AnotherSubject": {UserID: testUser, Issuer: testIssuer, Subject: "subject-2"},
		"AnotherIssuer":  {UserID: testUser, Issuer: "https://other", Subject: testSubject},
		"NoIdentity":     {UserID: testUser},
	} {
		require.ErrorIs(t, f.manager.Check(ctx, session.ID, who), ErrSessionEnded, name)
	}
	for _, id := range []string{"", "unknown", strings.Repeat("f", 32), strings.ToUpper(session.ID), session.ID + "0", "../" + session.ID} {
		require.ErrorIs(t, f.manager.Check(ctx, id, alice), ErrSessionEnded, "%q", id)
	}
	require.NoError(t, f.check(session), "none of that ended the real session")

	// It expires with the hub token it was issued for, even though the
	// provider would still confirm it.
	f.clock.Advance(24*time.Hour - time.Nanosecond)
	require.NoError(t, f.check(session))
	f.clock.Advance(time.Nanosecond)
	require.ErrorIs(t, f.check(session), ErrSessionEnded)
}

func TestCreateNeedsARefreshToken(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	ctx := context.Background()
	expires := f.clock.Now().Add(time.Hour)

	_, err := f.manager.Create(ctx, alice, "", expires)
	require.ErrorContains(t, err, "no refresh token")
	for _, who := range []Identity{{}, {UserID: testUser}, {UserID: testUser, Issuer: testIssuer}, {Issuer: testIssuer, Subject: testSubject}} {
		_, err := f.manager.Create(ctx, who, "refresh-token-0", expires)
		require.Error(t, err)
	}
	first, second := f.signIn(), f.signIn()
	assert.NotEqual(t, first.ID, second.ID)
	assert.Len(t, first.ID, 32)
}

// The refresh token is encrypted where it is stored, and no error or log line
// of this package repeats it.
func TestTheRefreshTokenIsNeverInTheClear(t *testing.T) {
	// Not parallel: it swaps the process's default logger.
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	const secret = "refresh-token-0"
	f := newFixture(t, func(context.Context, string) (string, string, error) { return testIssuer, "subject-2", nil })
	var said []string
	say := func(err error) {
		if err != nil {
			said = append(said, err.Error())
		}
	}

	// At rest.
	session := f.signIn()
	onDisk := readAll(t, f.dir)
	require.NotEmpty(t, onDisk)
	assert.NotContains(t, onDisk, secret)
	assert.Contains(t, onDisk, session.ID)

	// An outage, with a provider error that repeats the token.
	f.provider.set(func(token string) (Renewal, error) { return Renewal{}, &echoError{token} })
	f.clock.Advance(5 * time.Minute)
	say(f.check(session))
	// A renewed token for someone else, then a refusal on another session.
	f.provider.set(func(string) (Renewal, error) { return Renewal{RefreshToken: secret + "-next", IDToken: "id"}, nil })
	f.clock.Advance(defaultRetryInterval)
	say(f.check(session))
	other := f.signIn()
	f.provider.set(refuse("invalid_grant"))
	f.clock.Advance(4 * time.Minute)
	say(f.check(other))
	say(f.manager.End(context.Background(), f.signIn().ID, "signed out"))

	for _, text := range append(said, logs.String(), readAll(t, f.dir)) {
		assert.NotContains(t, text, secret)
	}
	assert.Contains(t, logs.String(), "refused", "the refusal itself is logged")
}

// echoError is a provider error whose text repeats the refresh token. The
// real HTTP provider never produces one; the manager does not rely on that.
type echoError struct{ token string }

func (e *echoError) Error() string { return "request failed: refresh_token=" + e.token }

func readAll(t *testing.T, dir string) string {
	t.Helper()
	var all strings.Builder
	require.NoError(t, filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path) //nolint:gosec // a file under the test's own temporary directory
		all.Write(data)
		return err
	}))
	return all.String()
}

// A store that cannot be read is a failure, not an answer: the request is
// neither let in nor told it is signed out.
func TestAStoreFailureIsNotAnAnswer(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	session := f.signIn()
	broken := &failingCollection{Collection: f.col}
	f.manager.col = broken

	broken.fail = errors.New("disk unavailable")
	err := f.check(session)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrSessionEnded)
	require.NotErrorIs(t, err, ErrProviderUnavailable)

	broken.fail = nil
	require.NoError(t, f.check(session))
}

type failingCollection struct {
	persis.Collection
	fail error
}

func (c *failingCollection) Get(ctx context.Context, id string) (*persis.Record, error) {
	if c.fail != nil {
		return nil, c.fail
	}
	return c.Collection.Get(ctx, id)
}

// Records of sessions that ended or expired more than a day ago are removed
// at the next sign-in.
func TestOldSessionRecordsArePurged(t *testing.T) {
	t.Parallel()
	f := newFixture(t, nil)
	ctx := context.Background()
	ended := f.signIn()
	require.NoError(t, f.manager.End(ctx, ended.ID, "signed out"))
	expired, err := f.manager.Create(ctx, alice, "refresh-token-x", f.clock.Now().Add(time.Hour))
	require.NoError(t, err)
	live := f.signIn()

	f.clock.Advance(23 * time.Hour)
	f.signIn()
	_, _, err = f.manager.load(ctx, ended.ID)
	require.NoError(t, err, "kept for a day")

	f.clock.Advance(2*time.Hour + time.Minute)
	f.signIn()
	_, _, err = f.manager.load(ctx, ended.ID)
	require.ErrorIs(t, err, ErrSessionEnded)
	_, _, err = f.manager.load(ctx, expired.ID)
	require.ErrorIs(t, err, ErrSessionEnded)
	_, _, err = f.manager.load(ctx, live.ID)
	require.NoError(t, err, "a session that is neither ended nor long expired is kept")
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()
	require.NoError(t, Config{RevalidateAfter: 4 * time.Minute, RevalidateLimit: 5 * time.Minute}.Validate())
	require.NoError(t, Config{RevalidateAfter: time.Second, RevalidateLimit: 2 * time.Second}.Validate())
	for name, cfg := range map[string]Config{
		"Unset":             {},
		"OnlyAfter":         {RevalidateAfter: 4 * time.Minute},
		"OnlyLimit":         {RevalidateLimit: 5 * time.Minute},
		"AfterEqualsLimit":  {RevalidateAfter: 5 * time.Minute, RevalidateLimit: 5 * time.Minute},
		"AfterOverLimit":    {RevalidateAfter: 5 * time.Minute, RevalidateLimit: 4 * time.Minute},
		"LimitOverTheMost":  {RevalidateAfter: 4 * time.Minute, RevalidateLimit: 5*time.Minute + time.Second},
		"NegativeAfter":     {RevalidateAfter: -time.Minute, RevalidateLimit: 5 * time.Minute},
		"NegativeRetry":     {RevalidateAfter: 4 * time.Minute, RevalidateLimit: 5 * time.Minute, RetryInterval: -time.Second},
		"OutageGraceIsNone": {RevalidateAfter: 4 * time.Minute, RevalidateLimit: 35 * time.Minute},
	} {
		require.Error(t, cfg.Validate(), name)
	}

	enc, err := crypto.NewEncryptor("a-test-key-that-is-long-enough-for-aes")
	require.NoError(t, err)
	valid := Config{RevalidateAfter: 4 * time.Minute, RevalidateLimit: 5 * time.Minute}
	col := persisfile.NewCollection(t.TempDir())
	_, err = NewManager(valid, nil, enc, &fakeProvider{}, nil)
	require.Error(t, err)
	_, err = NewManager(valid, col, nil, &fakeProvider{}, nil)
	require.Error(t, err)
	_, err = NewManager(valid, col, enc, nil, nil)
	require.Error(t, err)
	_, err = NewManager(Config{}, col, enc, &fakeProvider{}, nil)
	require.Error(t, err)
}
