// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

// Command edgeproof measures the worker channel through an edge that a local
// test cannot stand in for. It has two halves.
//
// "edgeproof origin" serves the channel's real handler and machines-only
// authentication over a stub coordinator. It holds no stores and no job, knows
// one token, binds loopback only, and exits by itself.
//
// "edgeproof client" runs the checks against an address and prints one JSON
// line for each. What it can send is capped here, not by its flags, and it stops
// at the first challenge.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"
)

// maxOriginLife is the longest an origin lives, whatever it is asked.
const maxOriginLife = 60 * time.Minute

// maxBudget is the longest one client run may take, whatever it is asked.
const maxBudget = 30 * time.Minute

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("usage: edgeproof origin|client [flags]"))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "origin":
		err = runOriginCommand(ctx, os.Args[2:])
	case "client":
		err = runClientCommand(ctx, os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "edgeproof:", err)
	os.Exit(1)
}

func runOriginCommand(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("origin", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:0", "loopback address to serve on")
	tokenFile := flags.String("token-file", "", "file holding the one token this origin accepts")
	life := flags.Duration("life", maxOriginLife, "how long to serve; at most 60m")
	if err := flags.Parse(args); err != nil {
		return err
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	if *life <= 0 || *life > maxOriginLife {
		return fmt.Errorf("--life must be above zero and at most %s", maxOriginLife)
	}
	ctx, cancel := context.WithTimeout(ctx, *life)
	defer cancel()
	return serveOrigin(ctx, originConfig{Listen: *listen, Token: token, Log: os.Stdout})
}

func runClientCommand(ctx context.Context, args []string) error {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	url := flags.String("url", "", "the address the origin's API root is reached at")
	tokenFile := flags.String("token-file", "", "file holding the origin's token")
	checks := flags.String("checks", strings.Join(defaultChecks, ","), "comma-separated checks; "+strings.Join(allChecks(), ", "))
	watch := flags.Duration("watch", 2*time.Minute, "how long the reconnect check watches; at most 10m")
	budget := flags.Duration("budget", 12*time.Minute, "how long the whole run may take; at most 30m")
	if err := flags.Parse(args); err != nil {
		return err
	}
	token, err := readToken(*tokenFile)
	if err != nil {
		return err
	}
	if *watch <= 0 || *watch > maxWatch {
		return fmt.Errorf("--watch must be above zero and at most %s", maxWatch)
	}
	if *budget <= 0 || *budget > maxBudget {
		return fmt.Errorf("--budget must be above zero and at most %s", maxBudget)
	}
	ctx, cancel := context.WithTimeout(ctx, *budget)
	defer cancel()
	// Each line is written as it happens: a run stopped from outside keeps them.
	encoder := json.NewEncoder(os.Stdout)
	emit := func(event Event) { _ = encoder.Encode(event) }
	results, err := runChecks(ctx, clientConfig{URL: *url, Token: token, Watch: *watch, Emit: emit}, strings.Split(*checks, ","))
	if err != nil {
		return err
	}
	if slices.ContainsFunc(results, func(r Result) bool { return !r.Pass && r.Skipped == "" }) {
		return errors.New("a check failed")
	}
	return nil
}

func readToken(path string) (string, error) {
	if path == "" {
		return "", errors.New("--token-file is required")
	}
	data, err := os.ReadFile(path) //nolint:gosec // the path is the operator's own
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(data))
	if len(token) < 32 {
		return "", errors.New("the token must be at least 32 characters")
	}
	return token, nil
}
