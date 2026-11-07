// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import (
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errSentinel = errors.New("sentinel")

func TestRedact(t *testing.T) {
	t.Parallel()
	token := NewToken()
	base := BaseURL(5555, token)

	// net/http's url.Error prints the whole URL it dialed.
	dialErr := &url.Error{Op: "Get", URL: base + "/json/version", Err: errSentinel}
	wrapped := fmt.Errorf("open CDP WebSocket: %w", dialErr)
	redacted := Redact(wrapped, base)
	assert.NotContains(t, redacted.Error(), token)
	assert.Contains(t, redacted.Error(), "http://127.0.0.1:5555/<token>/json/version")
	assert.True(t, errors.Is(redacted, errSentinel), "the chain is kept")
	var asURLErr *url.Error
	assert.True(t, errors.As(redacted, &asURLErr))

	// The SDK's resolve error names the base URL in its own words.
	sdkErr := fmt.Errorf("resolve CDP WebSocket URL from %s: %w (last error: %s)", base, errSentinel, "connection refused")
	assert.NotContains(t, Redact(sdkErr, base).Error(), token)

	plain := errors.New("nothing to hide")
	assert.Same(t, plain, Redact(plain, base), "an error without the token is returned as is")
	assert.Same(t, plain, Redact(plain, "http://127.0.0.1:9222"), "an address without a token redacts nothing")
	assert.NoError(t, Redact(nil, base))

	text := "browser at " + base + " closed; token " + token
	assert.Equal(t, "browser at http://127.0.0.1:5555/<token> closed; token <token>", RedactString(text, base))
	assert.Equal(t, text, RedactString(text, "http://127.0.0.1:9222"))
	require.NotContains(t, RedactString(text, base), token)
}
