//go:build darwin && cgo

package darwin

import (
	"log/slog"
	"sync"
	"syscall"
	"time"
)

// cpuMonitor monitors CPU usage of a process and throttles if needed.
type cpuMonitor struct {
	pid          int
	limitPercent uint32
	interval     time.Duration

	// These fields are only accessed from the run() goroutine (single-writer).
	// start() initializes them before launching the goroutine.
	lastCPUTime uint64
	lastSample  time.Time

	// lastCPUPercent is read via getCPUPercent() from other goroutines,
	// so it requires mutex protection.
	lastCPUPercent float64

	mu      sync.Mutex
	stopCh  chan struct{}
	stopped bool
	onStop  func() // callback when monitor exits
}

// newCPUMonitor creates a new CPU monitor for a process.
func newCPUMonitor(pid int, limitPercent uint32) *cpuMonitor {
	return &cpuMonitor{
		pid:          pid,
		limitPercent: limitPercent,
		interval:     500 * time.Millisecond,
		stopCh:       make(chan struct{}),
	}
}

// start begins monitoring in a goroutine.
func (m *cpuMonitor) start() {
	// Initialize baseline
	if rusage, err := getProcRusage(m.pid); err == nil {
		m.lastCPUTime = rusage.UserTime + rusage.SystemTime
	}
	m.lastSample = time.Now()
	go m.run()
}

// stop signals the monitor to stop.
func (m *cpuMonitor) stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return
	}
	m.stopped = true
	close(m.stopCh)
}

// run is the main monitoring loop.
func (m *cpuMonitor) run() {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	defer func() {
		if m.onStop != nil {
			m.onStop()
		}
	}()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			if !m.processAlive() {
				return
			}
			m.checkAndThrottle()
		}
	}
}

// processAlive checks if the process still exists.
func (m *cpuMonitor) processAlive() bool {
	err := syscall.Kill(m.pid, 0)
	return err == nil
}

// checkAndThrottle checks CPU usage and throttles if over limit.
func (m *cpuMonitor) checkAndThrottle() {
	rusage, err := getProcRusage(m.pid)
	if err != nil {
		slog.Debug("cpu monitor: failed to get rusage", "pid", m.pid, "error", err)
		return
	}

	currentCPUTime := rusage.UserTime + rusage.SystemTime
	elapsed := time.Since(m.lastSample)

	cpuPercent := m.calculateCPUPercentFromDelta(currentCPUTime, elapsed)
	m.mu.Lock()
	m.lastCPUPercent = cpuPercent
	m.mu.Unlock()
	m.lastCPUTime = currentCPUTime
	m.lastSample = time.Now()

	if cpuPercent > float64(m.limitPercent) {
		m.throttle(cpuPercent)
	}
}

// calculateCPUPercentFromDelta calculates CPU percentage from time delta.
func (m *cpuMonitor) calculateCPUPercentFromDelta(currentCPUTime uint64, elapsed time.Duration) float64 {
	if elapsed <= 0 {
		return 0
	}
	cpuDelta := currentCPUTime - m.lastCPUTime
	// Both values are in consistent time units, ratio gives percentage
	percent := (float64(cpuDelta) / float64(elapsed.Nanoseconds())) * 100
	return percent
}

// throttle pauses the process proportionally to how much it exceeded the limit.
func (m *cpuMonitor) throttle(cpuPercent float64) {
	excess := cpuPercent - float64(m.limitPercent)
	if excess <= 0 {
		return
	}

	pauseRatio := excess / cpuPercent
	pauseDuration := time.Duration(float64(m.interval) * pauseRatio)

	if pauseDuration > m.interval {
		pauseDuration = m.interval
	}

	slog.Debug("cpu monitor: throttling", "pid", m.pid, "cpu", cpuPercent, "limit", m.limitPercent, "pause", pauseDuration)

	if err := syscall.Kill(m.pid, syscall.SIGSTOP); err != nil {
		slog.Debug("cpu monitor: SIGSTOP failed", "pid", m.pid, "error", err)
		return
	}

	select {
	case <-time.After(pauseDuration):
	case <-m.stopCh:
	}

	if err := syscall.Kill(m.pid, syscall.SIGCONT); err != nil {
		slog.Debug("cpu monitor: SIGCONT failed", "pid", m.pid, "error", err)
	}
}

// getCPUPercent returns the last measured CPU percentage.
func (m *cpuMonitor) getCPUPercent() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastCPUPercent
}
