package ipc

import (
	"context"
	"time"
)

// IPCMonitor monitors inter-process communication.
type IPCMonitor interface {
	// Start monitoring.
	Start(ctx context.Context) error

	// Stop monitoring.
	Stop() error

	// Register event handlers.
	OnSocketConnect(func(event SocketEvent))
	OnSocketBind(func(event SocketEvent))
	OnPipeOpen(func(event PipeEvent))

	// Get active connections.
	ListConnections() []Connection

	// Capabilities returns what the monitor can do.
	Capabilities() MonitorCapabilities
}

// SocketEvent represents a Unix socket operation.
type SocketEvent struct {
	Timestamp  time.Time
	PID        int
	Operation  string // "connect", "bind", "listen", "accept", "observed"
	SocketType string // "unix", "abstract", "netlink"
	Path       string // Socket path (if filesystem-based)
	Address    string // Abstract name or other address
	Peer       *PeerInfo
	Decision   string
	PolicyRule string
}

// PipeEvent represents a named pipe operation.
type PipeEvent struct {
	Timestamp time.Time
	PID       int
	Operation string // "open", "create", "write", "read", "observed"
	Path      string // Named pipe path
	Flags     int
	Decision  string
}

// PeerInfo contains information about a peer process.
type PeerInfo struct {
	PID  int
	UID  int
	GID  int
	Comm string
}

// Connection represents an active IPC connection.
type Connection struct {
	LocalPath  string
	RemotePath string
	LocalPID   int
	RemotePID  int
	State      string
	BytesSent  int64
	BytesRecv  int64
}

// MonitorCapabilities describes what features the monitor supports.
type MonitorCapabilities struct {
	RealTime    bool // Real-time notifications vs polling
	Enforcement bool // Can block connections
	ProcessInfo bool // Can identify processes
	UnixSockets bool // Unix domain socket support
	NamedPipes  bool // Named pipe support (Windows)
}

// NewIPCMonitor creates a platform-specific IPC monitor.
func NewIPCMonitor() IPCMonitor {
	return newPlatformMonitor()
}
