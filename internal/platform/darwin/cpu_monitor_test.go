//go:build darwin && cgo

package darwin

import (
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestCPUMonitorCalculatePercent(t *testing.T) {
	m := &cpuMonitor{
		pid:          1,
		limitPercent: 50,
		interval:     100 * time.Millisecond,
		lastCPUTime:  1000000000,
		lastSample:   time.Now().Add(-1 * time.Second),
	}

	currentCPUTime := uint64(1500000000)
	elapsed := time.Second

	percent := m.calculateCPUPercentFromDelta(currentCPUTime, elapsed)

	if percent < 45 || percent > 55 {
		t.Errorf("expected ~50%%, got %.2f%%", percent)
	}
}

func TestCPUMonitorStartStop(t *testing.T) {
	var stopped atomic.Bool

	m := &cpuMonitor{
		pid:          os.Getpid(),
		limitPercent: 50,
		interval:     50 * time.Millisecond,
		stopCh:       make(chan struct{}),
		onStop: func() {
			stopped.Store(true)
		},
	}

	go m.run()

	time.Sleep(150 * time.Millisecond)

	m.stop()

	time.Sleep(100 * time.Millisecond)
	if !stopped.Load() {
		t.Error("monitor did not stop")
	}
}
