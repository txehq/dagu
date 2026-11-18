// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

// Command cleanuplint fails when code in this repository cleans a Go cache or
// recursively deletes a tree whose path comes from the environment (TXE-7550).
//
// On 2026-11-16 a test cleanup ran `go clean -modcache` with its private
// GOMODCACHE entry dropped from the environment, and Go deleted the machine's
// shared module cache (TXE-7547). `go clean -modcache`, `-cache` and
// `-fuzzcache` remove whatever the environment names at the moment they run;
// so does `os.RemoveAll(os.Getenv(...))` or `rm -rf "$HOME/..."`. A cleanup
// may remove only a path the code created itself, such as t.TempDir(),
// os.MkdirTemp or mktemp -d, whose identity is known when it is made.
//
// It reports these rules:
//
//   - go-clean-cache: `go clean` with -modcache, -cache or -fuzzcache, bare
//     or set to a true value (-modcache=true), as an argv
//     (exec.Command("go", "clean", "-modcache"), a Python list) or as shell
//     text, anywhere in Go, shell, Makefile, workflow, PowerShell or Python
//     files.
//   - env-path-delete: a recursive delete (os.RemoveAll, rm -r, find -delete,
//     Remove-Item -Recurse, shutil.rmtree) of a path read from os.Getenv,
//     os.UserHomeDir, os.TempDir, `go env`, HOME, TMPDIR, a GO* variable,
//     in a script any upper-case variable the script never assigns, or in a
//     workflow any ${{ }} expression (env, vars, inputs, runner, a step's
//     outputs), which the runner fills in before the script starts.
//
// A workflow's run: blocks are each read as their own script (TXE-7563): a
// variable one step assigns is not defined in another step, and any name an
// env: map in the file sets, or a step writing $GITHUB_ENV may export, is a
// source unless the step assigns it itself.
//
// A third rule, trap-status (TXE-7857, the port of txehq/txe's TXE-7835),
// reads the shell traps of CI code: workflow and action run: blocks,
// everything else under .github, and every script those name, transitively.
// A trap on EXIT or ERR, inline or through a function the script defines,
// starts with RC=$?, then set +e (or guards each command with ||), and ends
// with exit "$RC", so a failing cleanup neither fails a passing step nor
// hides a failing one; and no trap, nor a function it calls, sends stderr to
// /dev/null, so a cleanup that fails says why. Under set -e, which every run:
// step has, the first trap command that fails ends the script with its own
// status: `trap 'docker rm -f x >/dev/null 2>&1' EXIT` turned a passing step
// red with an empty log (txe PR 5184). See trap.go.
//
// A finding that is right as written is kept with a directive on its line or
// the line above, and the directive must say why:
//
//	//cleanuplint:allow <reason of at least three words>
//	# cleanuplint:allow <reason of at least three words>
//
// A directive with no reason, or one that allows nothing, is itself a finding.
//
// Usage:
//
//	go run ./internal/tools/cleanuplint [-v] [repository root]
//
// It lints the files git lists as tracked or untracked-but-not-ignored. It
// reads source text only; it does not build or run anything.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cleanuplint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	verbose := fs.Bool("v", false, "also list the findings kept by a cleanuplint:allow directive")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	root := "."
	switch fs.NArg() {
	case 0:
	case 1:
		root = fs.Arg(0)
	default:
		_, _ = fmt.Fprintln(stderr, "usage: cleanuplint [-v] [repository root]")
		return 2
	}
	files, err := listFiles(root)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cleanuplint: %v\n", err)
		return 2
	}
	res, err := lintFiles(root, files)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "cleanuplint: %v\n", err)
		return 2
	}
	if *verbose {
		for _, f := range res.Allowed {
			_, _ = fmt.Fprintf(stdout, "allowed %s (%s)\n", f, f.Reason)
		}
	}
	for _, f := range res.Findings {
		_, _ = fmt.Fprintln(stdout, f)
	}
	_, _ = fmt.Fprintf(stdout, "cleanuplint: %d files, %d findings, %d allowed\n", res.Files, len(res.Findings), len(res.Allowed))
	if len(res.Findings) > 0 {
		_, _ = fmt.Fprintln(stdout, "A cleanup may remove only a path it created (t.TempDir, os.MkdirTemp, mktemp -d), and a trap keeps the script's status (RC=$?; set +e; ...; exit \"$RC\") and its stderr. See internal/tools/cleanuplint/main.go.")
		return 1
	}
	return 0
}
