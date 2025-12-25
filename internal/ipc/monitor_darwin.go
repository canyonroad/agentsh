//go:build darwin

package ipc

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DarwinIPCMonitor monitors Unix sockets using lsof.
type DarwinIPCMonitor struct {
	onConnect func(SocketEvent)
	onBind    func(SocketEvent)
	onPipe    func(PipeEvent)

	known map[string]bool
	mu    sync.RWMutex
	done  chan struct{}
}

func newPlatformMonitor() IPCMonitor {
	return &DarwinIPCMonitor{
		known: make(map[string]bool),
		done:  make(chan struct{}),
	}
}

// Start implements IPCMonitor.
func (m *DarwinIPCMonitor) Start(ctx context.Context) error {
	go m.pollLsof(ctx)
	return nil
}

func (m *DarwinIPCMonitor) pollLsof(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.done:
			return
		case <-ticker.C:
			m.scanLsof()
		}
	}
}

func (m *DarwinIPCMonitor) scanLsof() {
	// lsof -U lists Unix domain sockets
	// -F pcn outputs in field mode: p=pid, c=command, n=name
	out, err := exec.Command("lsof", "-U", "-F", "pcn").Output()
	if err != nil {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Parse lsof output (field mode)
	// p<pid>
	// c<command>
	// n<name>
	var currentPID int
	var currentCmd string

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		switch line[0] {
		case 'p':
			currentPID, _ = strconv.Atoi(line[1:])
		case 'c':
			currentCmd = line[1:]
		case 'n':
			path := line[1:]
			key := fmt.Sprintf("%d-%s", currentPID, path)

			if !m.known[key] {
				m.known[key] = true

				event := SocketEvent{
					Timestamp:  time.Now(),
					PID:        currentPID,
					Operation:  "observed",
					SocketType: "unix",
					Path:       path,
					Peer: &PeerInfo{
						PID:  currentPID,
						Comm: currentCmd,
					},
				}

				if m.onConnect != nil {
					m.onConnect(event)
				}
			}
		}
	}
}

// Stop implements IPCMonitor.
func (m *DarwinIPCMonitor) Stop() error {
	close(m.done)
	return nil
}

// OnSocketConnect implements IPCMonitor.
func (m *DarwinIPCMonitor) OnSocketConnect(cb func(SocketEvent)) {
	m.onConnect = cb
}

// OnSocketBind implements IPCMonitor.
func (m *DarwinIPCMonitor) OnSocketBind(cb func(SocketEvent)) {
	m.onBind = cb
}

// OnPipeOpen implements IPCMonitor.
func (m *DarwinIPCMonitor) OnPipeOpen(cb func(PipeEvent)) {
	m.onPipe = cb
}

// ListConnections implements IPCMonitor.
func (m *DarwinIPCMonitor) ListConnections() []Connection {
	// Use lsof to get current connections
	out, err := exec.Command("lsof", "-U", "-F", "pn").Output()
	if err != nil {
		return nil
	}

	var conns []Connection
	var currentPID int

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}

		switch line[0] {
		case 'p':
			currentPID, _ = strconv.Atoi(line[1:])
		case 'n':
			path := line[1:]
			if path != "" {
				conns = append(conns, Connection{
					LocalPath: path,
					LocalPID:  currentPID,
					State:     "connected",
				})
			}
		}
	}

	return conns
}

// Capabilities implements IPCMonitor.
func (m *DarwinIPCMonitor) Capabilities() MonitorCapabilities {
	return MonitorCapabilities{
		RealTime:    false, // Polling-based
		Enforcement: false, // No blocking
		ProcessInfo: true,  // lsof provides process info
		UnixSockets: true,
		NamedPipes:  false,
	}
}

var _ IPCMonitor = (*DarwinIPCMonitor)(nil)
