// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

const (
	// startupTimeout bounds the browser's first answer over the pipe.
	startupTimeout = 60 * time.Second
	// closeGrace is how long the browser gets to leave after Browser.close
	// before its pipe is closed and it is ended.
	closeGrace = 10 * time.Second
	// exitSettle is how long a browser that stopped answering gets to be
	// reaped before its failure is reported.
	exitSettle = 2 * time.Second
)

// Main runs the gate: it reads its configuration from stdin, starts the
// browser, writes one ready line to stdout and serves until the browser
// exits, ctx ends or the lifetime cap passes. It loads no Dagu configuration.
func Main(ctx context.Context, stdin io.Reader, stdout io.Writer) error {
	cfg, err := readConfig(stdin)
	if err != nil {
		writeReadyLine(stdout, readyLine{Error: err.Error()})
		return err
	}
	return run(ctx, cfg, stdout)
}

func readConfig(stdin io.Reader) (Config, error) {
	var wire wireConfig
	if err := json.NewDecoder(io.LimitReader(stdin, 1<<20)).Decode(&wire); err != nil {
		return Config{}, fmt.Errorf("devtools gate: read the configuration: %w", err)
	}
	if wire.Version != configVersion {
		return Config{}, fmt.Errorf("devtools gate: configuration version %d is not %d", wire.Version, configVersion)
	}
	if err := wire.Config.validate(); err != nil {
		return Config{}, err
	}
	return wire.Config, nil
}

func writeReadyLine(stdout io.Writer, line readyLine) {
	data, err := json.Marshal(line)
	if err != nil {
		return
	}
	_, _ = stdout.Write(append(data, '\n'))
}

func run(ctx context.Context, cfg Config, stdout io.Writer) error {
	browser, err := launchBrowser(cfg)
	if err != nil {
		writeReadyLine(stdout, readyLine{Error: err.Error()})
		return err
	}
	m := newMux(browser.pipe)
	runErr := make(chan error, 1)
	go func() { runErr <- m.run(ctx) }()

	fail := func(err error) error {
		// A browser that could not adopt its pipes exits at once; its exit
		// is the useful part of the error, and the pipe's end-of-file can
		// arrive a moment before the process is reaped.
		settle, cancelSettle := context.WithTimeout(context.Background(), exitSettle)
		exitedEarly := browser.waitExit(settle) == nil
		cancelSettle()
		if exitErr := browser.exitError(); exitedEarly && exitErr != nil {
			err = fmt.Errorf("%w (%w)", err, exitErr)
		}
		writeReadyLine(stdout, readyLine{Error: err.Error()})
		_ = browser.end()
		return err
	}

	startCtx, cancelStart := context.WithTimeout(ctx, startupTimeout)
	defer cancelStart()
	version, err := readVersion(startCtx, m)
	if err != nil {
		return fail(fmt.Errorf("devtools gate: the browser did not answer over its pipe: %w", err))
	}
	if err := m.start(startCtx); err != nil {
		return fail(fmt.Errorf("devtools gate: attach to the browser's targets: %w", err))
	}
	g := newGate(m, cfg.Token, NewToken(), version)
	port, err := g.listen()
	if err != nil {
		return fail(fmt.Errorf("devtools gate: %w", err))
	}
	defer g.close()
	writeReadyLine(stdout, readyLine{Ready: &Ready{
		Port:             port,
		BrowserID:        g.browserID,
		BrowserPID:       browser.pid(),
		BrowserStartedAt: browser.startedAt,
	}})

	lifetime := time.NewTimer(cfg.maxLifetime())
	defer lifetime.Stop()
	select {
	case err := <-runErr:
		// The browser closed its pipe, which it does on its way out, or ctx
		// ended and the clients are gone.
		if ctx.Err() != nil {
			closeBrowser(m, browser)
			return nil
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return browser.end()
		}
		return errors.Join(err, browser.end())
	case <-lifetime.C:
		closeBrowser(m, browser)
		return nil
	}
}

// readVersion asks the browser what it is, which is also the first proof
// that it speaks over the pipe.
func readVersion(ctx context.Context, m *mux) (browserVersion, error) {
	result, err := m.call(ctx, "", "Browser.getVersion", map[string]any{})
	if err != nil {
		return browserVersion{}, err
	}
	var version browserVersion
	if err := json.Unmarshal(result, &version); err != nil {
		return browserVersion{}, fmt.Errorf("decode Browser.getVersion: %w", err)
	}
	return version, nil
}

// closeBrowser asks the browser to close, then ends it.
func closeBrowser(m *mux, browser *browserProcess) {
	ctx, cancel := context.WithTimeout(context.Background(), closeGrace)
	defer cancel()
	_, _ = m.call(ctx, "", "Browser.close", map[string]any{})
	_ = browser.waitExit(ctx)
	_ = browser.end()
}
