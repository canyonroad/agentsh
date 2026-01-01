// internal/platform/windows/driver_client_test.go
package windows

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestMessageHeaderEncoding(t *testing.T) {
	// Test that we can encode/decode message headers correctly
	msg := make([]byte, 28)

	// Encode a pong message
	binary.LittleEndian.PutUint32(msg[0:4], MsgPong)
	binary.LittleEndian.PutUint32(msg[4:8], 28)
	binary.LittleEndian.PutUint64(msg[8:16], 12345)
	binary.LittleEndian.PutUint32(msg[16:20], DriverClientVersion)
	binary.LittleEndian.PutUint64(msg[20:28], uint64(time.Now().UnixNano()))

	// Decode and verify
	msgType := binary.LittleEndian.Uint32(msg[0:4])
	size := binary.LittleEndian.Uint32(msg[4:8])
	requestId := binary.LittleEndian.Uint64(msg[8:16])
	version := binary.LittleEndian.Uint32(msg[16:20])

	if msgType != MsgPong {
		t.Errorf("expected MsgPong (%d), got %d", MsgPong, msgType)
	}
	if size != 28 {
		t.Errorf("expected size 28, got %d", size)
	}
	if requestId != 12345 {
		t.Errorf("expected requestId 12345, got %d", requestId)
	}
	if version != DriverClientVersion {
		t.Errorf("expected version 0x%08X, got 0x%08X", DriverClientVersion, version)
	}
}

func TestDriverClientNotConnected(t *testing.T) {
	client := NewDriverClient()

	if client.Connected() {
		t.Error("new client should not be connected")
	}

	err := client.SendPong()
	if err == nil {
		t.Error("SendPong should fail when not connected")
	}
}

func TestDriverClientDisconnectIdempotent(t *testing.T) {
	client := NewDriverClient()

	// Disconnect when not connected should succeed
	err := client.Disconnect()
	if err != nil {
		t.Errorf("Disconnect should succeed when not connected: %v", err)
	}

	// Multiple disconnects should succeed
	err = client.Disconnect()
	if err != nil {
		t.Errorf("Multiple Disconnect calls should succeed: %v", err)
	}
}

func TestMessageConstants(t *testing.T) {
	// Verify message constants match protocol.h
	tests := []struct {
		name     string
		got      uint32
		expected uint32
	}{
		{"MsgPing", MsgPing, 0},
		{"MsgPolicyCheckFile", MsgPolicyCheckFile, 1},
		{"MsgPolicyCheckRegistry", MsgPolicyCheckRegistry, 2},
		{"MsgProcessCreated", MsgProcessCreated, 3},
		{"MsgProcessTerminated", MsgProcessTerminated, 4},
		{"MsgPong", MsgPong, 50},
		{"MsgRegisterSession", MsgRegisterSession, 100},
		{"MsgUnregisterSession", MsgUnregisterSession, 101},
	}

	for _, tc := range tests {
		if tc.got != tc.expected {
			t.Errorf("%s: expected %d, got %d", tc.name, tc.expected, tc.got)
		}
	}
}
