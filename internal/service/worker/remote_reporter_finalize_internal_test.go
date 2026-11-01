// Copyright (C) 2026 TXE
// SPDX-License-Identifier: GPL-3.0-or-later

package worker

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/dagucloud/dagu/v2/internal/service/coordinator"
	"github.com/dagucloud/dagu/v2/internal/serviceregistry"
)

type segmentingClient struct {
	coordinator.Client
	bytes int64
}

func (c segmentingClient) ArtifactSegmentBytes() int64 { return c.bytes }

// The agent sees the reporter, not the uploader behind it, so what the uploader
// says of itself has to come through.
func TestTheReporterSaysWhatItsUploadersSayOfTheirFinalize(t *testing.T) {
	segments := newRemoteRunReporter(segmentingClient{bytes: 16 << 20}, "worker-1", remoteRunMetadata{}, serviceregistry.HostInfo{})
	assert.True(t, segments.BoundsItsOwnFinalize())
	none := newRemoteRunReporter(segmentingClient{}, "worker-1", remoteRunMetadata{}, serviceregistry.HostInfo{})
	assert.False(t, none.BoundsItsOwnFinalize(), "gRPC keeps the fixed time")
}
