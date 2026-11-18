// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

// Package gopin holds the test that keeps every Go version this repository
// pins equal to go.mod's (TXE-7844).
//
// go.mod is the one source: its toolchain directive when it has one,
// otherwise its go directive. The Dockerfiles' golang: build images and the
// workflows' Go setup cannot read it at run time, so each repeats the
// version, and the test fails when one of them disagrees:
//
//   - every `FROM ... golang:<version>` line in a Dockerfile;
//   - every GO_VERSION a workflow or action sets in its env;
//   - every step that uses actions/setup-go or the setup-go-cache action: it
//     must say which Go to install, as `go-version-file: go.mod`, as a literal
//     equal to go.mod's, or as `${{ env.GO_VERSION }}` (inside the composite
//     action, `${{ inputs.go-version }}`, which its callers set).
//
// Run it with `go test ./internal/tools/gopin`. CI runs it in the cleanup lint
// job, which has no path filter, so a change to a Dockerfile or a workflow
// alone is checked too.
package gopin
