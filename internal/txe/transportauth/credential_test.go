// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package transportauth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/dagucloud/dagu/v2/internal/txe/authn"
	"github.com/dagucloud/dagu/v2/internal/txe/transportauth"
)

// tokenEndpoint is a fake provider token endpoint. Its answer is set per
// test; it records the refresh tokens it was sent.
type tokenEndpoint struct {
	mu       sync.Mutex
	status   int
	body     string
	ctype    string
	rotateTo string
	issue    func() string
	// during runs while a request is being answered, before the answer.
	during func()
	seen   []string
	calls  int
}

func (e *tokenEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.mu.Lock()
	during := e.during
	e.mu.Unlock()
	if during != nil {
		during()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	_ = r.ParseForm()
	if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("client_id") != clientA1Worker {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
		return
	}
	e.seen = append(e.seen, r.Form.Get("refresh_token"))
	if e.status != 0 {
		if e.ctype != "" {
			w.Header().Set("Content-Type", e.ctype)
		}
		w.WriteHeader(e.status)
		_, _ = w.Write([]byte(e.body))
		return
	}
	access := "access-token"
	if e.issue != nil {
		access = e.issue()
	}
	answer := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 300}
	if e.rotateTo != "" {
		answer["refresh_token"] = e.rotateTo
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(answer)
}

func (e *tokenEndpoint) set(f func(e *tokenEndpoint)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f(e)
}

func (e *tokenEndpoint) callCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.calls
}

func writeCredential(t *testing.T, dir, endpoint string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a machine credential is refused on Windows")
	}
	path := filepath.Join(dir, "machine-credential.json")
	require.NoError(t, transportauth.WriteMachineCredential(path, transportauth.MachineCredential{
		Schema:        transportauth.CredentialSchema,
		Issuer:        testIssuer,
		TokenEndpoint: endpoint,
		ClientID:      clientA1Worker,
		Class:         authn.ClassWorker,
		MachineID:     machineA1,
		RefreshToken:  "offline-1",
	}))
	return path
}

func newSource(t *testing.T, endpoint *tokenEndpoint, c *clock) (*transportauth.RefreshingSource, string) {
	t.Helper()
	server := httptest.NewServer(endpoint)
	t.Cleanup(server.Close)
	path := writeCredential(t, t.TempDir(), server.URL+"/token")
	source, err := transportauth.NewRefreshingSource(path, transportauth.WithSourceClock(c.Now))
	require.NoError(t, err)
	return source, path
}

func TestCredentialFileIsWrittenOwnerOnlyAndReadBack(t *testing.T) {
	path := writeCredential(t, t.TempDir(), "https://issuer.example/token")
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
	credential, err := transportauth.ReadMachineCredential(path)
	require.NoError(t, err)
	assert.Equal(t, machineA1, credential.MachineID)
	assert.NotContains(t, fmt.Sprint(credential), "offline-1")
	assert.NotContains(t, fmt.Sprintf("%v %+v %#v", credential, credential, credential), "offline-1")
}

func TestCredentialFileIsRefusedWhenOthersCanReadIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not permission bits on Windows")
	}
	path := writeCredential(t, t.TempDir(), "https://issuer.example/token")
	require.NoError(t, os.Chmod(path, 0o640))
	_, err := transportauth.ReadMachineCredential(path)
	require.ErrorContains(t, err, "0600")
}

func TestCredentialFileMustBeComplete(t *testing.T) {
	valid := transportauth.MachineCredential{
		Schema: 1, Issuer: testIssuer, TokenEndpoint: "https://issuer.example/token", ClientID: clientA1Worker,
		Class: authn.ClassWorker, MachineID: machineA1, RefreshToken: "r",
	}
	require.NoError(t, valid.Validate())
	for name, mutate := range map[string]func(*transportauth.MachineCredential){
		"schema":             func(c *transportauth.MachineCredential) { c.Schema = 2 },
		"reviewer class":     func(c *transportauth.MachineCredential) { c.Class = authn.ClassReviewer },
		"cli class":          func(c *transportauth.MachineCredential) { c.Class = authn.ClassCLI },
		"no machine":         func(c *transportauth.MachineCredential) { c.MachineID = "" },
		"no refresh token":   func(c *transportauth.MachineCredential) { c.RefreshToken = "" },
		"padded client":      func(c *transportauth.MachineCredential) { c.ClientID = " " + clientA1Worker },
		"plain http":         func(c *transportauth.MachineCredential) { c.TokenEndpoint = "http://issuer.example/token" },
		"relative endpoint":  func(c *transportauth.MachineCredential) { c.TokenEndpoint = "/token" },
		"endpoint with user": func(c *transportauth.MachineCredential) { c.TokenEndpoint = "https://u:p@issuer.example/token" },
	} {
		t.Run(name, func(t *testing.T) {
			c := valid
			mutate(&c)
			assert.Error(t, c.Validate())
		})
	}
	c := valid
	c.TokenEndpoint = "http://127.0.0.1:8080/token"
	assert.NoError(t, c.Validate(), "plain http to a loopback provider")
}

func TestUnknownFieldsInTheCredentialFileAreRefused(t *testing.T) {
	dir := t.TempDir()
	path := writeCredential(t, dir, "https://issuer.example/token")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	edited := strings.Replace(string(raw), `"schema": 1,`, `"schema": 1, "owner_id": "own_B",`, 1)
	require.NoError(t, os.WriteFile(path, []byte(edited), 0o600))
	_, err = transportauth.ReadMachineCredential(path)
	require.Error(t, err)
}

func TestSourceRenewsBeforeExpiryAndNeverHandsOutAnExpiredToken(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	n := 0
	endpoint := &tokenEndpoint{issue: func() string { n++; return fmt.Sprintf("access-%d", n) }}
	source, _ := newSource(t, endpoint, c)
	ctx := context.Background()

	token, err := source.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "access-1", token)

	c.Advance(3 * time.Minute)
	token, err = source.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "access-1", token, "cached while more than a minute is left")
	assert.Equal(t, 1, endpoint.callCount())

	c.Advance(time.Minute + time.Second)
	token, err = source.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "access-2", token, "renewed inside the last minute")

	// The provider stops answering: the held token is used until its
	// expiry and not one moment past it.
	endpoint.set(func(e *tokenEndpoint) { e.status, e.body = http.StatusServiceUnavailable, "down" })
	c.Advance(4*time.Minute + 30*time.Second)
	token, err = source.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "access-2", token)

	c.Advance(30 * time.Second)
	_, err = source.Token(ctx)
	require.ErrorIs(t, err, transportauth.ErrProviderUnavailable)

	// The provider answers again: work resumes.
	endpoint.set(func(e *tokenEndpoint) { e.status = 0 })
	token, err = source.Token(ctx)
	require.NoError(t, err)
	assert.Equal(t, "access-3", token)
}

func TestProviderVerdictsRevokeForGood(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		code   string
	}{
		{"disabled user", http.StatusBadRequest, "invalid_grant"},
		{"lost offline access", http.StatusBadRequest, "not_allowed"},
		{"disabled client", http.StatusUnauthorized, "invalid_client"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &clock{now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
			endpoint := &tokenEndpoint{}
			source, _ := newSource(t, endpoint, c)
			ctx := context.Background()
			_, err := source.Token(ctx)
			require.NoError(t, err)

			endpoint.set(func(e *tokenEndpoint) {
				e.status, e.ctype, e.body = tc.status, "application/json", `{"error":"`+tc.code+`","error_description":"secret detail"}`
			})
			c.Advance(4*time.Minute + time.Second)
			_, err = source.Token(ctx)
			require.ErrorIs(t, err, transportauth.ErrRevoked)
			assert.Contains(t, err.Error(), tc.code)
			assert.NotContains(t, err.Error(), "secret detail")

			// Sticky: even a provider that answers again is not asked.
			endpoint.set(func(e *tokenEndpoint) { e.status = 0 })
			calls := endpoint.callCount()
			_, err = source.Token(ctx)
			require.ErrorIs(t, err, transportauth.ErrRevoked)
			assert.Equal(t, calls, endpoint.callCount())
		})
	}
}

func TestAnswersThatAreNotVerdictsAreOutages(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		ctype  string
		body   string
	}{
		{"server error", http.StatusInternalServerError, "application/json", `{"error":"server_error"}`},
		{"rate limited", http.StatusTooManyRequests, "application/json", `{"error":"slow_down"}`},
		{"proxy page on 400", http.StatusBadRequest, "text/html", `<html>bad gateway</html>`},
		{"json without error on 401", http.StatusUnauthorized, "application/json", `{"message":"no"}`},
		{"empty error on 400", http.StatusBadRequest, "application/json", `{"error":""}`},
		{"invalid request on 400", http.StatusBadRequest, "application/json", `{"error":"invalid_request"}`},
		{"temporarily unavailable on 400", http.StatusBadRequest, "application/json", `{"error":"temporarily_unavailable"}`},
		{"unauthorized client on 401", http.StatusUnauthorized, "application/json", `{"error":"unauthorized_client"}`},
		{"redirect", http.StatusFound, "", ""},
		{"ok without a token", http.StatusOK, "application/json", `{"token_type":"Bearer","expires_in":300}`},
		{"ok with a long-lived token", http.StatusOK, "application/json", `{"access_token":"a","token_type":"Bearer","expires_in":3600}`},
		{"ok with another token type", http.StatusOK, "application/json", `{"access_token":"a","token_type":"DPoP","expires_in":300}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &clock{now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
			endpoint := &tokenEndpoint{status: tc.status, ctype: tc.ctype, body: tc.body}
			source, _ := newSource(t, endpoint, c)
			_, err := source.Token(context.Background())
			require.ErrorIs(t, err, transportauth.ErrProviderUnavailable)
			require.NotErrorIs(t, err, transportauth.ErrRevoked)
		})
	}

	t.Run("unreachable", func(t *testing.T) {
		server := httptest.NewServer(http.NotFoundHandler())
		url := server.URL
		server.Close()
		path := writeCredential(t, t.TempDir(), url+"/token")
		source, err := transportauth.NewRefreshingSource(path)
		require.NoError(t, err)
		_, err = source.Token(context.Background())
		require.ErrorIs(t, err, transportauth.ErrProviderUnavailable)
	})
}

func TestRotatedRefreshTokenIsSavedAndUsedNext(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	endpoint := &tokenEndpoint{rotateTo: "offline-2"}
	source, path := newSource(t, endpoint, c)
	ctx := context.Background()

	_, err := source.Token(ctx)
	require.NoError(t, err)
	saved, err := transportauth.ReadMachineCredential(path)
	require.NoError(t, err, "still owner-only after the rewrite")
	assert.Equal(t, "offline-2", saved.RefreshToken)

	endpoint.set(func(e *tokenEndpoint) { e.rotateTo = "" })
	c.Advance(5 * time.Minute)
	_, err = source.Token(ctx)
	require.NoError(t, err)
	endpoint.mu.Lock()
	assert.Equal(t, []string{"offline-1", "offline-2"}, endpoint.seen)
	endpoint.mu.Unlock()

	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	for _, entry := range entries {
		assert.False(t, strings.HasPrefix(entry.Name(), "."+filepath.Base(path)), "no temporary file is left behind: %s", entry.Name())
	}
}

func TestWorkerCredentialsReachTheCoordinatorOnEveryCall(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.bindAndEnrol(subjectA, ownerA, clientA1Worker, machineA1)
	endpoint := &tokenEndpoint{issue: func() string { return f.token(subjectA, clientA1Worker) }}
	source, _ := newSource(t, endpoint, f.clock)
	client := f.dial(grpc.WithPerRPCCredentials(transportauth.NewWorkerCredentials(source)))
	ctx := context.Background()

	for range 3 {
		_, err := client.Poll(ctx, poll(source.MachineID()+"@host@1", source.MachineID()))
		require.NoError(t, err)
		f.clock.Advance(2 * time.Minute)
	}
	assert.Equal(t, 2, endpoint.callCount(), "renewed once, inside the last minute of the first token")

	endpoint.set(func(e *tokenEndpoint) {
		e.status, e.ctype, e.body = http.StatusBadRequest, "application/json", `{"error":"invalid_grant"}`
	})
	f.clock.Advance(5 * time.Minute)
	calls := f.service.lastCaller()
	_, err := client.Poll(ctx, poll(machineA1, machineA1))
	assert.Equal(t, codes.Unauthenticated, codeOf(t, err))
	assert.Equal(t, calls, f.service.lastCaller(), "nothing reached the coordinator")
}

func TestCredentialIsNeverSentInTheClearToARemoteHost(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	f.bindAndEnrol(subjectA, ownerA, clientA1Worker, machineA1)
	asked := false
	source := tokenFunc(func(context.Context) (string, error) { asked = true; return f.token(subjectA, clientA1Worker), nil })
	client := f.dial(
		grpc.WithPerRPCCredentials(transportauth.NewWorkerCredentials(source)),
		grpc.WithAuthority("coordinator.example:50055"),
	)
	_, err := client.Poll(context.Background(), poll(machineA1, machineA1))
	assert.Equal(t, codes.Unauthenticated, codeOf(t, err))
	assert.False(t, asked, "the token was not even fetched")
}

type tokenFunc func(context.Context) (string, error)

func (f tokenFunc) Token(ctx context.Context) (string, error) { return f(ctx) }

func TestProviderOutageReachesTheCallerAsUnavailable(t *testing.T) {
	f := newFixture(t, fixtureOptions{})
	source := tokenFunc(func(context.Context) (string, error) {
		return "", fmt.Errorf("%w: test", transportauth.ErrProviderUnavailable)
	})
	client := f.dial(grpc.WithPerRPCCredentials(transportauth.NewWorkerCredentials(source)))
	_, err := client.Poll(context.Background(), poll(machineA1, machineA1))
	assert.Equal(t, codes.Unavailable, codeOf(t, err))
}

func TestNoTokenIsHandedOutThatExpiredDuringItsRenewal(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	endpoint := &tokenEndpoint{}
	source, _ := newSource(t, endpoint, c)
	ctx := context.Background()
	_, err := source.Token(ctx)
	require.NoError(t, err)

	// The held token has 5 s left when renewal starts; the provider takes
	// 10 s to fail.
	c.Advance(4*time.Minute + 55*time.Second)
	endpoint.set(func(e *tokenEndpoint) {
		e.status, e.body = http.StatusServiceUnavailable, "down"
		e.during = func() { c.Advance(10 * time.Second) }
	})
	_, err = source.Token(ctx)
	require.ErrorIs(t, err, transportauth.ErrProviderUnavailable)

	// The provider answers, but only after the token it issues has expired.
	endpoint.set(func(e *tokenEndpoint) {
		e.status = 0
		e.during = func() { c.Advance(5*time.Minute + time.Second) }
	})
	_, err = source.Token(ctx)
	require.ErrorIs(t, err, transportauth.ErrProviderUnavailable)
}

func TestAnUnsavedRotationIsReportedAndSavedLater(t *testing.T) {
	if runtime.GOOS != "windows" && os.Geteuid() == 0 {
		t.Skip("root writes to a read-only directory")
	}
	c := &clock{now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	endpoint := &tokenEndpoint{}
	source, path := newSource(t, endpoint, c)
	ctx := context.Background()
	_, err := source.Token(ctx)
	require.NoError(t, err)
	require.NoError(t, source.Unsaved())

	dir := filepath.Dir(path)
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	endpoint.set(func(e *tokenEndpoint) { e.rotateTo = "offline-2" })
	c.Advance(5 * time.Minute)
	token, err := source.Token(ctx)
	require.NoError(t, err, "the process keeps working on the new refresh token")
	assert.NotEmpty(t, token)
	require.Error(t, source.Unsaved())
	saved, err := transportauth.ReadMachineCredential(path)
	require.NoError(t, err)
	assert.Equal(t, "offline-1", saved.RefreshToken)

	// The directory is writable again: the next call after the retry
	// interval saves the new refresh token, without asking the provider.
	require.NoError(t, os.Chmod(dir, 0o700))
	endpoint.set(func(e *tokenEndpoint) { e.rotateTo = "" })
	calls := endpoint.callCount()
	c.Advance(10 * time.Second)
	_, err = source.Token(ctx)
	require.NoError(t, err)
	require.NoError(t, source.Unsaved())
	assert.Equal(t, calls, endpoint.callCount())
	saved, err = transportauth.ReadMachineCredential(path)
	require.NoError(t, err)
	assert.Equal(t, "offline-2", saved.RefreshToken)
}

func TestSourcesSharingACredentialFileUseTheLatestRefreshToken(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	var mu sync.Mutex
	current, next := "offline-1", 1
	reused := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("refresh_token") != current {
			// The provider retires a refresh token once it is used.
			reused++
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		next++
		current = fmt.Sprintf("offline-%d", next)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": fmt.Sprintf("access-%d", next), "token_type": "Bearer", "expires_in": 300, "refresh_token": current,
		})
	}))
	t.Cleanup(server.Close)
	path := writeCredential(t, t.TempDir(), server.URL+"/token")
	first, err := transportauth.NewRefreshingSource(path, transportauth.WithSourceClock(c.Now))
	require.NoError(t, err)
	second, err := transportauth.NewRefreshingSource(path, transportauth.WithSourceClock(c.Now))
	require.NoError(t, err)
	ctx := context.Background()

	for range 3 {
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i, source := range []*transportauth.RefreshingSource{first, second} {
			wg.Go(func() { _, errs[i] = source.Token(ctx) })
		}
		wg.Wait()
		require.NoError(t, errs[0])
		require.NoError(t, errs[1])
		c.Advance(5 * time.Minute)
	}
	mu.Lock()
	assert.Zero(t, reused, "no retired refresh token was presented")
	mu.Unlock()
	saved, err := transportauth.ReadMachineCredential(path)
	require.NoError(t, err)
	assert.Equal(t, "offline-7", saved.RefreshToken)
}

func TestASourceRefusesACredentialFileReplacedUnderIt(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	endpoint := &tokenEndpoint{}
	source, path := newSource(t, endpoint, c)
	other, err := transportauth.ReadMachineCredential(path)
	require.NoError(t, err)
	other.MachineID = machineA2
	require.NoError(t, transportauth.WriteMachineCredential(path, other))

	_, err = source.Token(context.Background())
	require.ErrorContains(t, err, "different credential")
	assert.Zero(t, endpoint.callCount())
}

func TestWaitingForARenewalEndsWithTheCallersContext(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	entered, release := make(chan struct{}, 1), make(chan struct{})
	endpoint := &tokenEndpoint{during: func() { entered <- struct{}{}; <-release }}
	source, _ := newSource(t, endpoint, c)

	done := make(chan error, 1)
	go func() { _, err := source.Token(context.Background()); done <- err }()
	<-entered // the first renewal is waiting on the provider

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := source.Token(ctx)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(started), 5*time.Second)

	close(release)
	require.NoError(t, <-done)
}

func TestCredentialFilesAreRefusedOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	path := filepath.Join(t.TempDir(), "machine-credential.json")
	err := transportauth.WriteMachineCredential(path, transportauth.MachineCredential{
		Schema: 1, Issuer: testIssuer, TokenEndpoint: "https://issuer.example/token", ClientID: clientA1Worker,
		Class: authn.ClassWorker, MachineID: machineA1, RefreshToken: "r",
	})
	require.Error(t, err)
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o600))
	_, err = transportauth.ReadMachineCredential(path)
	require.Error(t, err)
}

func TestNothingSecretIsPrinted(t *testing.T) {
	c := &clock{now: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)}
	source, path := newSource(t, &tokenEndpoint{issue: func() string { return "access-secret" }}, c)
	_, err := source.Token(context.Background())
	require.NoError(t, err)
	credential, err := transportauth.ReadMachineCredential(path)
	require.NoError(t, err)
	f := newFixture(t, fixtureOptions{})
	server, err := transportauth.NewServer(transportauth.ServerConfig{
		Mode: "enforce", Verifier: f.verifier, Machines: f.store, HubKey: testHubKey,
	})
	require.NoError(t, err)
	key := transportauth.StaticHubKey(testHubKey)
	hubCredentials := transportauth.NewHubCredentials(testHubKey)
	workerCredentials := transportauth.NewWorkerCredentials(source)

	secrets := []string{"offline-1", "access-secret", string(testHubKey)}
	// A secret printed as text, as hex, or as the decimal bytes of a slice.
	forms := func(secret string) []string {
		var digits []string
		for _, b := range []byte(secret)[:4] {
			digits = append(digits, strconv.Itoa(int(b)))
		}
		return []string{secret, fmt.Sprintf("%x", secret), strings.Join(digits, " ")}
	}
	values := map[string]any{
		"credential": credential, "*credential": &credential,
		"source": source, "*source": *source,
		"server": server, "*server": *server,
		"key": key, "*key": &key,
		"hub credentials": hubCredentials, "*hub credentials": *hubCredentials,
		"worker credentials": workerCredentials,
	}
	var logs strings.Builder
	text := slog.New(slog.NewTextHandler(&logs, nil))
	jsonLog := slog.New(slog.NewJSONHandler(&logs, nil))
	for name, value := range values {
		var out strings.Builder
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
			out.WriteString(fmt.Sprintf(verb, value) + "\n")
		}
		text.Info("value", "v", value)
		jsonLog.Info("value", "v", value)
		for _, secret := range secrets {
			for _, form := range forms(secret) {
				assert.NotContains(t, out.String(), form, name)
			}
		}
	}
	for _, secret := range secrets {
		for _, form := range forms(secret) {
			assert.NotContains(t, logs.String(), form)
		}
	}
}
