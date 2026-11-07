// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package devtoolsgate

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// fakeBrowserPipes adopts the pipes as Chrome's AdoptHandle does on
// Windows: the two handle values of --remote-debugging-io-pipes, each of
// which must be a pipe.
func fakeBrowserPipes(args []string) (*os.File, *os.File, error) {
	for _, arg := range args {
		value, ok := strings.CutPrefix(arg, "--remote-debugging-io-pipes=")
		if !ok {
			continue
		}
		parts := strings.Split(value, ",")
		if len(parts) != 2 {
			return nil, nil, errors.New("io-pipes needs two handle values")
		}
		handles := make([]syscall.Handle, 2)
		for i, part := range parts {
			n, err := strconv.ParseUint(strings.TrimSpace(part), 10, 32)
			if err != nil {
				return nil, nil, err
			}
			handles[i] = syscall.Handle(n)
			kind, err := syscall.GetFileType(handles[i])
			if err != nil {
				return nil, nil, fmt.Errorf("handle %d: %w", n, err)
			}
			if kind != syscall.FILE_TYPE_PIPE {
				return nil, nil, fmt.Errorf("handle %d is not a pipe", n)
			}
		}
		return os.NewFile(uintptr(handles[0]), "pipe-in"), os.NewFile(uintptr(handles[1]), "pipe-out"), nil
	}
	return nil, nil, errors.New("no --remote-debugging-io-pipes argument")
}
