// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package spec_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/dagucloud/dagu/v2/internal/ir"
	"github.com/dagucloud/dagu/v2/internal/spec"
	"github.com/stretchr/testify/require"
)

// A schedule that does not parse reaches the caller as an *ir.ScheduleError,
// through the file loader the spec update uses and through the YAML loader,
// and nothing else does (TXE-5404).
func TestScheduleErrorIsTypedThroughTheLoaders(t *testing.T) {
	const steps = "steps:\n  - id: a\n    run: echo hi\n"
	sourcePath := filepath.Join(t.TempDir(), "probe.yaml")
	load := map[string]func(source []byte) error{
		"file": func(source []byte) error {
			_, err := spec.LoadYAMLAt(context.Background(), source, sourcePath, spec.WithoutEval())
			return err
		},
		"yaml": func(source []byte) error {
			_, err := spec.LoadYAML(context.Background(), source, spec.WithName("probe"), spec.WithoutEval())
			return err
		},
	}
	for loader, loadSpec := range load {
		t.Run(loader, func(t *testing.T) {
			for _, schedule := range []string{`"1"`, `"TZ=UTC"`, `["0 1 * * *", "61 * * * *"]`, "\n  start: \"nope\"", `{start: 7}`} {
				err := loadSpec([]byte("schedule: " + schedule + "\n" + steps))
				require.Error(t, err, schedule)
				scheduleErr, ok := errors.AsType[*ir.ScheduleError](err)
				require.True(t, ok, "%s: %v", schedule, err)
				require.ErrorContains(t, err, scheduleErr.Error())
			}
			for name, source := range map[string]string{
				"valid":        "schedule: \"0 1 * * *\"\n" + steps,
				"depends":      "steps:\n  - id: a\n    run: echo hi\n    depends: [nope]\n",
				"unknown key":  "steps:\n  - id: a\n    run: echo hi\n    timeoutSec: 1\n",
				"yaml syntax":  "steps: [\n",
				"not a string": "name: [a]\n" + steps,
			} {
				err := loadSpec([]byte(source))
				_, ok := errors.AsType[*ir.ScheduleError](err)
				require.False(t, ok, "%s: %v", name, err)
			}
		})
	}
}
