//go:build !linux && !darwin && !windows

package ipc

import (
	"context"
	"fmt"
)

// NoopIPCMonitor is a no-op implementation for unsupported platforms.
type NoopIPCMonitor struct{}

func newPlatformMonitor() IPCMonitor {
	return &NoopIPCMonitor{}
}

// Start implements IPCMonitor.
func (m *NoopIPCMonitor) Start(ctx context.Context) error {
	return fmt.Errorf("IPC monitoring not supported on this platform")
}

// Stop implements IPCMonitor.
func (m *NoopIPCMonitor) Stop() error {
	return nil
}

// OnSocketConnect implements IPCMonitor.
func (m *NoopIPCMonitor) OnSocketConnect(cb func(SocketEvent)) {}

// OnSocketBind implements IPCMonitor.
func (m *NoopIPCMonitor) OnSocketBind(cb func(SocketEvent)) {}

// OnPipeOpen implements IPCMonitor.
func (m *NoopIPCMonitor) OnPipeOpen(cb func(PipeEvent)) {}

// ListConnections implements IPCMonitor.
func (m *NoopIPCMonitor) ListConnections() []Connection {
	return nil
}

// Capabilities implements IPCMonitor.
func (m *NoopIPCMonitor) Capabilities() MonitorCapabilities {
	return MonitorCapabilities{}
}

var _ IPCMonitor = (*NoopIPCMonitor)(nil)
