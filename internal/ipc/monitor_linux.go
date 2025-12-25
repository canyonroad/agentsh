//go:build linux

package ipc

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// LinuxIPCMonitor monitors Unix sockets using /proc/net/unix.
type LinuxIPCMonitor struct {
	onConnect func(SocketEvent)
	onBind    func(SocketEvent)
	onPipe    func(PipeEvent)

	known map[string]bool
	mu    sync.RWMutex
	done  chan struct{}
}

func newPlatformMonitor() IPCMonitor {
	return &LinuxIPCMonitor{
		known: make(map[string]bool),
		done:  make(chan struct{}),
	}
}

// Start implements IPCMonitor.
func (m *LinuxIPCMonitor) Start(ctx context.Context) error {
	go m.pollProcNetUnix(ctx)
	return nil
}

func (m *LinuxIPCMonitor) pollProcNetUnix(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.done:
			return
		case <-ticker.C:
			m.scanProcNetUnix()
		}
	}
}

func (m *LinuxIPCMonitor) scanProcNetUnix() {
	f, err := os.Open("/proc/net/unix")
	if err != nil {
		return
	}
	defer f.Close()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Parse /proc/net/unix
	// Format: Num RefCount Protocol Flags Type St Inode Path
	scanner := bufio.NewScanner(f)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 7 {
			continue
		}

		// Path is optional (8th field)
		path := ""
		if len(fields) >= 8 {
			path = fields[7]
		}
		if path == "" {
			continue
		}

		inode := fields[6]
		key := fmt.Sprintf("%s-%s", inode, path)

		if !m.known[key] {
			m.known[key] = true

			// Determine socket type
			socketType := "unix"
			if strings.HasPrefix(path, "@") {
				socketType = "abstract"
				path = path[1:] // Remove @ prefix
			}

			event := SocketEvent{
				Timestamp:  time.Now(),
				Operation:  "observed",
				SocketType: socketType,
				Path:       path,
			}

			// Try to find owning process
			if pid := m.findSocketOwner(inode); pid > 0 {
				event.PID = pid
			}

			if m.onConnect != nil {
				m.onConnect(event)
			}
		}
	}
}

func (m *LinuxIPCMonitor) findSocketOwner(inode string) int {
	// Scan /proc/*/fd/* for socket:[inode]
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}

	target := fmt.Sprintf("socket:[%s]", inode)

	for _, proc := range procs {
		if !proc.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(proc.Name())
		if err != nil {
			continue
		}

		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(fmt.Sprintf("%s/%s", fdDir, fd.Name()))
			if err != nil {
				continue
			}

			if link == target {
				return pid
			}
		}
	}

	return 0
}

// Stop implements IPCMonitor.
func (m *LinuxIPCMonitor) Stop() error {
	close(m.done)
	return nil
}

// OnSocketConnect implements IPCMonitor.
func (m *LinuxIPCMonitor) OnSocketConnect(cb func(SocketEvent)) {
	m.onConnect = cb
}

// OnSocketBind implements IPCMonitor.
func (m *LinuxIPCMonitor) OnSocketBind(cb func(SocketEvent)) {
	m.onBind = cb
}

// OnPipeOpen implements IPCMonitor.
func (m *LinuxIPCMonitor) OnPipeOpen(cb func(PipeEvent)) {
	m.onPipe = cb
}

// ListConnections implements IPCMonitor.
func (m *LinuxIPCMonitor) ListConnections() []Connection {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Parse /proc/net/unix for connected sockets
	f, err := os.Open("/proc/net/unix")
	if err != nil {
		return nil
	}
	defer f.Close()

	var conns []Connection
	scanner := bufio.NewScanner(f)
	scanner.Scan() // Skip header

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}

		// State field (index 5): 01=UNCONNECTED, 03=CONNECTED
		state := fields[5]
		if state != "03" {
			continue
		}

		path := fields[7]
		if path == "" {
			continue
		}

		conns = append(conns, Connection{
			LocalPath: path,
			State:     "connected",
		})
	}

	return conns
}

// Capabilities implements IPCMonitor.
func (m *LinuxIPCMonitor) Capabilities() MonitorCapabilities {
	return MonitorCapabilities{
		RealTime:    false, // Polling-based
		Enforcement: false, // No blocking
		ProcessInfo: true,  // Can find via /proc
		UnixSockets: true,
		NamedPipes:  false, // Linux uses Unix sockets
	}
}

var _ IPCMonitor = (*LinuxIPCMonitor)(nil)
