// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows && (amd64 || arm64)

package desktop

import (
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TXE-7832 soak only, removed before the PR is ready: times each phase of
// actAlone on a runner, so its deadline can be sized from measurements.
func TestSoakActAlonePhases(t *testing.T) {
	t.Parallel()

	type phases struct {
		coinit, actor, locate, total time.Duration
		err                          error
	}
	result := make(chan phases, 1)
	go func() {
		runtime.LockOSThread()
		var p phases
		start := time.Now()
		if err := windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED); err != nil {
			p.err = err
			result <- p
			return
		}
		defer windows.CoUninitialize()
		p.coinit = time.Since(start)
		mark := time.Now()
		w, err := newActor()
		p.actor = time.Since(mark)
		if err != nil {
			p.err = err
			result <- p
			return
		}
		defer w.release()
		mark = time.Now()
		el, err := w.locate(Element{Role: RoleButton, Name: "nope", Path: []PathStep{{Role: RoleButton, Name: "nope"}}}, nil)
		p.locate = time.Since(mark)
		if err == nil {
			el.release()
		}
		p.err = err
		p.total = time.Since(start)
		result <- p
	}()
	select {
	case p := <-result:
		t.Logf("TXE7832-SOAK actalone coinit=%s actor=%s locate=%s total=%s err=%v",
			p.coinit.Round(time.Millisecond), p.actor.Round(time.Millisecond), p.locate.Round(time.Millisecond), p.total.Round(time.Millisecond), p.err)
	case <-time.After(2 * time.Minute):
		t.Logf("TXE7832-SOAK actalone no answer in 2m")
	}
}
