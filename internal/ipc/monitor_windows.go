//go:build windows

package ipc

import (
	"context"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WindowsIPCMonitor monitors named pipes on Windows.
type WindowsIPCMonitor struct {
	onConnect func(SocketEvent)
	onBind    func(SocketEvent)
	onPipe    func(PipeEvent)

	known map[string]bool
	mu    sync.RWMutex
	done  chan struct{}
}

func newPlatformMonitor() IPCMonitor {
	return &WindowsIPCMonitor{
		known: make(map[string]bool),
		done:  make(chan struct{}),
	}
}

// Start implements IPCMonitor.
func (m *WindowsIPCMonitor) Start(ctx context.Context) error {
	go m.pollNamedPipes(ctx)
	return nil
}

func (m *WindowsIPCMonitor) pollNamedPipes(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.done:
			return
		case <-ticker.C:
			m.scanNamedPipes()
		}
	}
}

func (m *WindowsIPCMonitor) scanNamedPipes() {
	// Enumerate \\.\pipe\*
	pipePath := `\\.\pipe\*`
	pattern, err := syscall.UTF16PtrFromString(pipePath)
	if err != nil {
		return
	}

	var findData windows.Win32finddata
	handle, err := windows.FindFirstFile(pattern, &findData)
	if err != nil {
		return
	}
	defer windows.FindClose(handle)

	m.mu.Lock()
	defer m.mu.Unlock()

	for {
		name := syscall.UTF16ToString(findData.FileName[:])
		fullPath := `\\.\pipe\` + name

		if !m.known[fullPath] {
			m.known[fullPath] = true

			event := PipeEvent{
				Timestamp: time.Now(),
				Operation: "observed",
				Path:      fullPath,
			}

			if m.onPipe != nil {
				m.onPipe(event)
			}
		}

		if err := windows.FindNextFile(handle, &findData); err != nil {
			break
		}
	}
}

// getPipeOwner attempts to get the owner of a named pipe.
func (m *WindowsIPCMonitor) getPipeOwner(pipePath string) int {
	pathPtr, err := syscall.UTF16PtrFromString(pipePath)
	if err != nil {
		return 0
	}

	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(handle)

	// Get process ID from named pipe
	var serverPID uint32
	err = windows.GetNamedPipeServerProcessId(handle, &serverPID)
	if err != nil {
		return 0
	}

	return int(serverPID)
}

// Stop implements IPCMonitor.
func (m *WindowsIPCMonitor) Stop() error {
	close(m.done)
	return nil
}

// OnSocketConnect implements IPCMonitor.
func (m *WindowsIPCMonitor) OnSocketConnect(cb func(SocketEvent)) {
	m.onConnect = cb
}

// OnSocketBind implements IPCMonitor.
func (m *WindowsIPCMonitor) OnSocketBind(cb func(SocketEvent)) {
	m.onBind = cb
}

// OnPipeOpen implements IPCMonitor.
func (m *WindowsIPCMonitor) OnPipeOpen(cb func(PipeEvent)) {
	m.onPipe = cb
}

// ListConnections implements IPCMonitor.
func (m *WindowsIPCMonitor) ListConnections() []Connection {
	pipePath := `\\.\pipe\*`
	pattern, err := syscall.UTF16PtrFromString(pipePath)
	if err != nil {
		return nil
	}

	var findData windows.Win32finddata
	handle, err := windows.FindFirstFile(pattern, &findData)
	if err != nil {
		return nil
	}
	defer windows.FindClose(handle)

	var conns []Connection
	for {
		name := syscall.UTF16ToString(findData.FileName[:])
		fullPath := `\\.\pipe\` + name

		conns = append(conns, Connection{
			LocalPath: fullPath,
			State:     "active",
		})

		if err := windows.FindNextFile(handle, &findData); err != nil {
			break
		}
	}

	return conns
}

// Capabilities implements IPCMonitor.
func (m *WindowsIPCMonitor) Capabilities() MonitorCapabilities {
	return MonitorCapabilities{
		RealTime:    false, // Polling-based
		Enforcement: false, // No blocking
		ProcessInfo: true,  // Can get via GetNamedPipeServerProcessId
		UnixSockets: false, // Windows doesn't have Unix sockets
		NamedPipes:  true,
	}
}

// sensitivePipes lists pipes that should be monitored carefully.
var sensitivePipes = []string{
	`\\.\pipe\docker_engine`,
	`\\.\pipe\openssh-ssh-agent`,
}

// IsSensitivePipe checks if a pipe path is on the sensitive list.
func IsSensitivePipe(path string) bool {
	for _, p := range sensitivePipes {
		if path == p {
			return true
		}
	}
	return false
}

var _ IPCMonitor = (*WindowsIPCMonitor)(nil)

// Suppress unused import warning
var _ = unsafe.Sizeof(0)
var _ = fmt.Sprint("")
