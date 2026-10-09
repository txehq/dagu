// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package masking

import (
	"strings"
	"unicode/utf8"
)

const (
	// DefaultMaskString is the default replacement string for masked values
	DefaultMaskString = "*******"
)

// SourcedEnvVars groups environment variables by their source
type SourcedEnvVars struct {
	Secrets []string // Environment variables from secrets
	// MinDerivedLen is the fewest characters a value's stripped form may have
	// to be masked as well. A caller that refuses short values, because they
	// would match ordinary text, sets it to the same limit.
	MinDerivedLen int
}

// Masker provides masking functionality for sensitive data
type Masker struct {
	sensitiveVals map[string]bool // Set of values to mask
}

// NewMasker creates a masker from sourced environment variables.
//
// A value is also masked with its surrounding whitespace removed. A secret
// read from a file usually ends with a newline, and a script strips it before
// using the value, so the stripped form is the one that appears in output.
func NewMasker(sources SourcedEnvVars) *Masker {
	sensitiveVals := make(map[string]bool)

	for _, env := range sources.Secrets {
		_, val := splitEnv(env)
		// Skip empty or invalid values to avoid masking everything
		// (strings.ReplaceAll with empty string would insert mask between every character)
		if val != "" {
			sensitiveVals[val] = true
		}
		if trimmed := strings.TrimSpace(val); trimmed != "" && utf8.RuneCountInString(trimmed) >= sources.MinDerivedLen {
			sensitiveVals[trimmed] = true
		}
	}

	return &Masker{
		sensitiveVals: sensitiveVals,
	}
}

// MaskString replaces sensitive values in the input string
func (m *Masker) MaskString(input string) string {
	if len(m.sensitiveVals) == 0 {
		return input // Fast path
	}

	// Sort values by length (longest first) to avoid partial matches
	values := make([]string, 0, len(m.sensitiveVals))
	for val := range m.sensitiveVals {
		values = append(values, val)
	}

	// Simple sort by length (descending)
	for i := 0; i < len(values); i++ {
		for j := i + 1; j < len(values); j++ {
			if len(values[j]) > len(values[i]) {
				values[i], values[j] = values[j], values[i]
			}
		}
	}

	result := input
	for _, val := range values {
		result = strings.ReplaceAll(result, val, DefaultMaskString)
	}

	return result
}

// MaskBytes replaces sensitive values in the input bytes
func (m *Masker) MaskBytes(input []byte) []byte {
	return []byte(m.MaskString(string(input)))
}

// splitEnv splits an environment variable string of the form "KEY=value" into its key and value.
// If the input does not contain an '=', it returns two empty strings.
func splitEnv(env string) (string, string) {
	key, value, found := strings.Cut(env, "=")
	if !found {
		return "", ""
	}
	return key, value
}
