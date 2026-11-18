// Copyright (C) 2026 Yota Hamada
// SPDX-License-Identifier: GPL-3.0-or-later

package devtoolsgate

// TEMPORARY soak instrumentation for TXE-7834. It is removed before the PR
// leaves draft and is never merged. With TXE7834_TRACE_DIR set, each gate
// gives Chrome a log file there and appends one JSON line per launch with
// its start-up timings.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	soakDir     = os.Getenv("TXE7834_TRACE_DIR")
	soakLogPath string
	soakMu      sync.Mutex
)

func soakChromeArgs() []string {
	if soakDir == "" {
		return nil
	}
	v := os.Getenv("TXE7834_CHROME_V")
	if v == "" {
		v = "0"
	}
	soakLogPath = filepath.Join(soakDir, fmt.Sprintf("chrome-%d-%d.log", os.Getpid(), time.Now().UnixNano()))
	return []string{"--enable-logging", "--v=" + v, "--log-file=" + soakLogPath}
}

type soakRecord struct {
	Began     string  `json:"began"`
	Binary    string  `json:"binary"`
	GatePID   int     `json:"gatePid"`
	ChromePID int     `json:"chromePid"`
	StartMs   float64 `json:"startMs"`
	AnswerMs  float64 `json:"answerMs"`
	ReadyMs   float64 `json:"readyMs"`
	Err       string  `json:"err,omitempty"`
	Exited    bool    `json:"exited"`
	Log       string  `json:"log"`
}

func soakWrite(rec soakRecord) {
	if soakDir == "" {
		return
	}
	rec.Binary = filepath.Base(os.Args[0])
	rec.GatePID = os.Getpid()
	rec.Log = filepath.Base(soakLogPath)
	data, err := json.Marshal(rec)
	if err != nil {
		return
	}
	soakMu.Lock()
	defer soakMu.Unlock()
	f, err := os.OpenFile(filepath.Join(soakDir, "launches.jsonl"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(append(data, '\n'))
	_ = f.Close()
}

func soakMs(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
