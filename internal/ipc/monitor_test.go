package ipc

import (
	"testing"
	"time"
)

func TestSocketEvent(t *testing.T) {
	event := SocketEvent{
		Timestamp:  time.Now(),
		PID:        1234,
		Operation:  "connect",
		SocketType: "unix",
		Path:       "/var/run/docker.sock",
		Decision:   "deny",
		PolicyRule: "docker-socket",
	}

	if event.PID != 1234 {
		t.Errorf("PID = %d, want 1234", event.PID)
	}
	if event.Operation != "connect" {
		t.Errorf("Operation = %q, want connect", event.Operation)
	}
	if event.SocketType != "unix" {
		t.Errorf("SocketType = %q, want unix", event.SocketType)
	}
	if event.Path != "/var/run/docker.sock" {
		t.Errorf("Path = %q, want /var/run/docker.sock", event.Path)
	}
}

func TestSocketEvent_WithPeer(t *testing.T) {
	event := SocketEvent{
		Timestamp:  time.Now(),
		PID:        1234,
		Operation:  "connect",
		SocketType: "unix",
		Path:       "/tmp/test.sock",
		Peer: &PeerInfo{
			PID:  5678,
			UID:  1000,
			GID:  1000,
			Comm: "server",
		},
	}

	if event.Peer == nil {
		t.Fatal("Peer should not be nil")
	}
	if event.Peer.PID != 5678 {
		t.Errorf("Peer.PID = %d, want 5678", event.Peer.PID)
	}
	if event.Peer.Comm != "server" {
		t.Errorf("Peer.Comm = %q, want server", event.Peer.Comm)
	}
}

func TestPipeEvent(t *testing.T) {
	event := PipeEvent{
		Timestamp: time.Now(),
		PID:       1234,
		Operation: "open",
		Path:      `\\.\pipe\docker_engine`,
		Flags:     0,
		Decision:  "allow",
	}

	if event.PID != 1234 {
		t.Errorf("PID = %d, want 1234", event.PID)
	}
	if event.Operation != "open" {
		t.Errorf("Operation = %q, want open", event.Operation)
	}
	if event.Path != `\\.\pipe\docker_engine` {
		t.Errorf("Path = %q, want %s", event.Path, `\\.\pipe\docker_engine`)
	}
}

func TestConnection(t *testing.T) {
	conn := Connection{
		LocalPath:  "/tmp/test.sock",
		RemotePath: "/tmp/server.sock",
		LocalPID:   1234,
		RemotePID:  5678,
		State:      "connected",
		BytesSent:  1024,
		BytesRecv:  2048,
	}

	if conn.LocalPID != 1234 {
		t.Errorf("LocalPID = %d, want 1234", conn.LocalPID)
	}
	if conn.RemotePID != 5678 {
		t.Errorf("RemotePID = %d, want 5678", conn.RemotePID)
	}
	if conn.State != "connected" {
		t.Errorf("State = %q, want connected", conn.State)
	}
	if conn.BytesSent != 1024 {
		t.Errorf("BytesSent = %d, want 1024", conn.BytesSent)
	}
}

func TestMonitorCapabilities_Defaults(t *testing.T) {
	caps := MonitorCapabilities{}

	if caps.RealTime {
		t.Error("RealTime should default to false")
	}
	if caps.Enforcement {
		t.Error("Enforcement should default to false")
	}
	if caps.ProcessInfo {
		t.Error("ProcessInfo should default to false")
	}
	if caps.UnixSockets {
		t.Error("UnixSockets should default to false")
	}
	if caps.NamedPipes {
		t.Error("NamedPipes should default to false")
	}
}

func TestMonitorCapabilities_Full(t *testing.T) {
	caps := MonitorCapabilities{
		RealTime:    true,
		Enforcement: true,
		ProcessInfo: true,
		UnixSockets: true,
		NamedPipes:  true,
	}

	if !caps.RealTime {
		t.Error("RealTime should be true")
	}
	if !caps.Enforcement {
		t.Error("Enforcement should be true")
	}
	if !caps.ProcessInfo {
		t.Error("ProcessInfo should be true")
	}
	if !caps.UnixSockets {
		t.Error("UnixSockets should be true")
	}
	if !caps.NamedPipes {
		t.Error("NamedPipes should be true")
	}
}

func TestNewIPCMonitor(t *testing.T) {
	monitor := NewIPCMonitor()
	if monitor == nil {
		t.Fatal("NewIPCMonitor() returned nil")
	}
}

func TestPeerInfo(t *testing.T) {
	peer := PeerInfo{
		PID:  1234,
		UID:  1000,
		GID:  1000,
		Comm: "test-process",
	}

	if peer.PID != 1234 {
		t.Errorf("PID = %d, want 1234", peer.PID)
	}
	if peer.UID != 1000 {
		t.Errorf("UID = %d, want 1000", peer.UID)
	}
	if peer.GID != 1000 {
		t.Errorf("GID = %d, want 1000", peer.GID)
	}
	if peer.Comm != "test-process" {
		t.Errorf("Comm = %q, want test-process", peer.Comm)
	}
}
