// internal/platform/windows/driver_client_windows_test.go
//go:build windows

package windows

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestDriverClient_RegistryPolicyHandler(t *testing.T) {
	handlerCalled := false
	var capturedReq *RegistryRequest

	handler := func(req *RegistryRequest) (PolicyDecision, uint32) {
		handlerCalled = true
		capturedReq = req
		return DecisionDeny, 5000
	}

	client := NewDriverClient()
	client.SetRegistryPolicyHandler(handler)

	// Simulate a registry policy check message
	// Header(16) + token(8) + pid(4) + tid(4) + op(4) + valueType(4) + dataSize(4) + keyPath(520*2) + valueName(256*2)
	msg := make([]byte, 16+8+4+4+4+4+4+520*2+256*2)
	binary.LittleEndian.PutUint32(msg[0:4], MsgPolicyCheckRegistry)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(len(msg)))
	binary.LittleEndian.PutUint64(msg[8:16], 123)   // request ID
	binary.LittleEndian.PutUint64(msg[16:24], 456)  // session token
	binary.LittleEndian.PutUint32(msg[24:28], 1234) // pid
	binary.LittleEndian.PutUint32(msg[28:32], 5678) // tid
	binary.LittleEndian.PutUint32(msg[32:36], uint32(DriverRegOpSetValue))

	// Encode key path as UTF-16LE
	keyPath := `HKLM\SOFTWARE\Test`
	pathBytes := utf16Encode(keyPath)
	copy(msg[44:], pathBytes)

	reply := make([]byte, 512)
	replyLen := client.handleRegistryPolicyCheck(msg, reply)

	if !handlerCalled {
		t.Error("handler was not called")
	}
	if capturedReq == nil {
		t.Fatal("captured request is nil")
	}
	if capturedReq.ProcessId != 1234 {
		t.Errorf("ProcessId = %d, want 1234", capturedReq.ProcessId)
	}
	if capturedReq.Operation != DriverRegOpSetValue {
		t.Errorf("Operation = %v, want DriverRegOpSetValue", capturedReq.Operation)
	}
	if !strings.HasPrefix(capturedReq.KeyPath, "HKLM") {
		t.Errorf("KeyPath = %q, want prefix HKLM", capturedReq.KeyPath)
	}
	if replyLen != 24 {
		t.Errorf("replyLen = %d, want 24", replyLen)
	}

	// Check reply contains deny decision
	decision := binary.LittleEndian.Uint32(reply[16:20])
	if PolicyDecision(decision) != DecisionDeny {
		t.Errorf("reply decision = %d, want DecisionDeny", decision)
	}
}
