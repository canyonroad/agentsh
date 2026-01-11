//go:build linux && cgo

package main

import (
	"testing"

	"github.com/agentsh/agentsh/internal/signal"
)

func TestSignalFilterAvailable(t *testing.T) {
	// This just verifies the signal package is importable and has the expected functions
	cfg := signal.DefaultSignalFilterConfig()
	if !cfg.Enabled {
		t.Error("DefaultSignalFilterConfig should be enabled")
	}
	if len(cfg.Syscalls) == 0 {
		t.Error("DefaultSignalFilterConfig should have syscalls")
	}
}
