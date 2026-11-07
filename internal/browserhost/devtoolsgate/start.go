// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/dagucloud/dagu/v2/internal/cmn/procutil"
)

// stderrTail is how much of the helper's stderr is kept for the error when
// it fails before it is ready.
const stderrTail = 4 << 10

// Handle is a running gate and the browser behind it.
type Handle struct {
	// URL is the browser's DevTools address, http://127.0.0.1:<port>/<token>.
	// It is a credential: keep it in the record and nowhere else.
	URL string
	// PID and StartedAt identify the gate process.
	PID       int
	StartedAt int64
	// BrowserPID and BrowserStartedAt identify the browser process.
	BrowserPID       int
	BrowserStartedAt int64
}

// Start runs executable's `browser devtools-gate` command with cfg and
// returns once the browser answers through the gate. The gate outlives the
// caller: it runs in a process group of its own and exits with the browser.
func Start(ctx context.Context, executable string, cfg Config) (*Handle, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	// The gate runs in the executable's directory, so every path it is
	// given must stand on its own.
	executable, err := filepath.Abs(executable)
	if err != nil {
		return nil, fmt.Errorf("resolve the dagu executable: %w", err)
	}
	if cfg.Executable, err = filepath.Abs(cfg.Executable); err != nil {
		return nil, fmt.Errorf("resolve the browser executable: %w", err)
	}
	input, err := json.Marshal(wireConfig{Version: configVersion, Config: cfg})
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(executable, "browser", "devtools-gate") //nolint:gosec // starting this executable's own helper is the purpose
	// The gate outlives the caller, so it does not keep the caller's
	// directory in use.
	cmd.Dir = filepath.Dir(executable)
	cmd.Stdin = bytes.NewReader(input)
	stderr := &tailBuffer{limit: stderrTail}
	cmd.Stderr = stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	detachGate(cmd)
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start the devtools gate: %w", err)
	}
	startedAt, _ := procutil.StartTime(cmd.Process.Pid)
	ready, err := readReady(ctx, stdout)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if tail := strings.TrimSpace(stderr.String()); tail != "" {
			err = fmt.Errorf("%w: %s", err, RedactString(tail, BaseURL(0, cfg.Token)))
		}
		return nil, fmt.Errorf("start the devtools gate: %w", err)
	}
	go func() { _ = cmd.Wait() }()
	return &Handle{
		URL:              BaseURL(ready.Port, cfg.Token),
		PID:              cmd.Process.Pid,
		StartedAt:        startedAt,
		BrowserPID:       ready.BrowserPID,
		BrowserStartedAt: ready.BrowserStartedAt,
	}, nil
}

// readReady reads the gate's one line of stdout.
func readReady(ctx context.Context, stdout io.Reader) (Ready, error) {
	type result struct {
		line readyLine
		err  error
	}
	results := make(chan result, 1)
	go func() {
		data, err := bufio.NewReader(stdout).ReadBytes('\n')
		var line readyLine
		switch {
		case len(data) == 0 && err != nil:
			err = errors.New("the gate exited before it was ready")
		default:
			err = json.Unmarshal(data, &line)
		}
		results <- result{line: line, err: err}
	}()
	select {
	case r := <-results:
		switch {
		case r.err != nil:
			return Ready{}, r.err
		case r.line.Error != "":
			return Ready{}, errors.New(r.line.Error)
		case r.line.Ready == nil || r.line.Ready.Port == 0:
			return Ready{}, errors.New("the gate reported no address")
		}
		return *r.line.Ready, nil
	case <-ctx.Done():
		return Ready{}, ctx.Err()
	}
}

// Kill ends the gate when its process is still the one Start saw. The
// browser then sees its pipe close and closes itself.
func (h *Handle) Kill() error {
	if h == nil || h.PID <= 0 {
		return nil
	}
	matched, _, ok := procutil.MatchesStartTime(h.PID, h.StartedAt)
	if !ok || !matched {
		return nil
	}
	process, err := os.FindProcess(h.PID)
	if err != nil {
		return nil
	}
	defer func() { _ = process.Release() }()
	if err := process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return fmt.Errorf("end the devtools gate: %w", err)
	}
	return nil
}

// tailBuffer keeps the last limit bytes written to it.
type tailBuffer struct {
	mu    sync.Mutex
	limit int
	data  []byte
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data = append(b.data, p...)
	if len(b.data) > b.limit {
		b.data = b.data[len(b.data)-b.limit:]
	}
	return len(p), nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.data)
}
