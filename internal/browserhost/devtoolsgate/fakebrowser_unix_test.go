// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package devtoolsgate

import (
	"fmt"
	"os"
	"syscall"
)

// fakeBrowserPipes adopts the pipes as Chrome does on Unix: commands on
// descriptor 3, replies on 4.
func fakeBrowserPipes(_ []string) (*os.File, *os.File, error) {
	for _, fd := range []int{3, 4} {
		var st syscall.Stat_t
		if err := syscall.Fstat(fd, &st); err != nil {
			return nil, nil, fmt.Errorf("descriptor %d: %w", fd, err)
		}
	}
	return os.NewFile(3, "pipe-in"), os.NewFile(4, "pipe-out"), nil
}
