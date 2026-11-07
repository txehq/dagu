// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

import "os"

// pipeFlagsForTest builds the pipe flags on a scratch pipe pair, as the
// launcher does, so a test can read them.
func pipeFlagsForTest() []string {
	r, w, err := os.Pipe()
	if err != nil {
		return nil
	}
	defer func() {
		_ = r.Close()
		_ = w.Close()
	}()
	return pipeFlags(r, w)
}
