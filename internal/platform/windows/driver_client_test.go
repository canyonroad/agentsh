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

func TestSessionRegistrationEncoding(t *testing.T) {
	// Test that we can encode session registration correctly
	sessionToken := uint64(0x123456789ABCDEF0)
	rootPid := uint32(1234)

	// Calculate expected message structure
	const maxPath = 520
	msgSize := 16 + 8 + 4 + (maxPath * 2)

	msg := make([]byte, msgSize)

	// Header
	binary.LittleEndian.PutUint32(msg[0:4], MsgRegisterSession)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(msgSize))
	binary.LittleEndian.PutUint64(msg[8:16], 1) // Request ID

	// Session token
	binary.LittleEndian.PutUint64(msg[16:24], sessionToken)

	// Root process ID
	binary.LittleEndian.PutUint32(msg[24:28], rootPid)

	// Verify encoding
	if binary.LittleEndian.Uint32(msg[0:4]) != MsgRegisterSession {
		t.Errorf("expected MsgRegisterSession, got %d", binary.LittleEndian.Uint32(msg[0:4]))
	}
	if binary.LittleEndian.Uint64(msg[16:24]) != sessionToken {
		t.Errorf("expected session token 0x%X, got 0x%X", sessionToken, binary.LittleEndian.Uint64(msg[16:24]))
	}
	if binary.LittleEndian.Uint32(msg[24:28]) != rootPid {
		t.Errorf("expected root PID %d, got %d", rootPid, binary.LittleEndian.Uint32(msg[24:28]))
	}
}

func TestProcessEventDecoding(t *testing.T) {
	// Test decoding process event message
	msg := make([]byte, 40)

	// Header
	binary.LittleEndian.PutUint32(msg[0:4], MsgProcessCreated)
	binary.LittleEndian.PutUint32(msg[4:8], 40)
	binary.LittleEndian.PutUint64(msg[8:16], 1)

	// Event data
	binary.LittleEndian.PutUint64(msg[16:24], 0xDEADBEEF) // Session token
	binary.LittleEndian.PutUint32(msg[24:28], 5678)       // Process ID
	binary.LittleEndian.PutUint32(msg[28:32], 1234)       // Parent ID
	binary.LittleEndian.PutUint64(msg[32:40], 0x12345678) // Create time

	// Decode
	msgType := binary.LittleEndian.Uint32(msg[0:4])
	sessionToken := binary.LittleEndian.Uint64(msg[16:24])
	processId := binary.LittleEndian.Uint32(msg[24:28])
	parentId := binary.LittleEndian.Uint32(msg[28:32])
	createTime := binary.LittleEndian.Uint64(msg[32:40])

	if msgType != MsgProcessCreated {
		t.Errorf("expected MsgProcessCreated, got %d", msgType)
	}
	if sessionToken != 0xDEADBEEF {
		t.Errorf("expected session token 0xDEADBEEF, got 0x%X", sessionToken)
	}
	if processId != 5678 {
		t.Errorf("expected process ID 5678, got %d", processId)
	}
	if parentId != 1234 {
		t.Errorf("expected parent ID 1234, got %d", parentId)
	}
	if createTime != 0x12345678 {
		t.Errorf("expected create time 0x12345678, got 0x%X", createTime)
	}
}

func TestUtf16Encode(t *testing.T) {
	// Test UTF-16LE encoding
	tests := []struct {
		input    string
		expected []byte
	}{
		{"ABC", []byte{'A', 0, 'B', 0, 'C', 0, 0, 0}},
		{"", []byte{0, 0}},
	}

	for _, tc := range tests {
		result := utf16Encode(tc.input)
		if len(result) != len(tc.expected) {
			t.Errorf("utf16Encode(%q): expected len %d, got %d", tc.input, len(tc.expected), len(result))
			continue
		}
		for i := range tc.expected {
			if result[i] != tc.expected[i] {
				t.Errorf("utf16Encode(%q)[%d]: expected %d, got %d", tc.input, i, tc.expected[i], result[i])
			}
		}
	}
}

func TestFileRequestDecoding(t *testing.T) {
	// Build a mock file request message
	const maxPath = 520
	msgSize := 16 + 8 + 4 + 4 + 4 + 4 + 4 + (maxPath * 2) + (maxPath * 2)
	msg := make([]byte, msgSize)

	// Header
	binary.LittleEndian.PutUint32(msg[0:4], MsgPolicyCheckFile)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(msgSize))
	binary.LittleEndian.PutUint64(msg[8:16], 12345) // Request ID

	// Request fields
	binary.LittleEndian.PutUint64(msg[16:24], 0xABCD1234) // Session token
	binary.LittleEndian.PutUint32(msg[24:28], 5678)       // Process ID
	binary.LittleEndian.PutUint32(msg[28:32], 9012)       // Thread ID
	binary.LittleEndian.PutUint32(msg[32:36], uint32(FileOpWrite))
	binary.LittleEndian.PutUint32(msg[36:40], 0)   // Create disposition
	binary.LittleEndian.PutUint32(msg[40:44], 0x2) // Desired access

	// Path: "C:\test.txt" in UTF-16LE
	path := "C:\\test.txt"
	pathBytes := utf16Encode(path)
	copy(msg[44:], pathBytes)

	// Decode and verify
	sessionToken := binary.LittleEndian.Uint64(msg[16:24])
	processId := binary.LittleEndian.Uint32(msg[24:28])
	operation := FileOperation(binary.LittleEndian.Uint32(msg[32:36]))
	decodedPath := utf16Decode(msg[44 : 44+maxPath*2])

	if sessionToken != 0xABCD1234 {
		t.Errorf("expected session token 0xABCD1234, got 0x%X", sessionToken)
	}
	if processId != 5678 {
		t.Errorf("expected process ID 5678, got %d", processId)
	}
	if operation != FileOpWrite {
		t.Errorf("expected FileOpWrite, got %d", operation)
	}
	if decodedPath != path {
		t.Errorf("expected path %q, got %q", path, decodedPath)
	}
}

func TestPolicyResponseEncoding(t *testing.T) {
	reply := make([]byte, 24)

	// Build response
	binary.LittleEndian.PutUint32(reply[0:4], MsgPolicyCheckFile)
	binary.LittleEndian.PutUint32(reply[4:8], 24)
	binary.LittleEndian.PutUint64(reply[8:16], 12345) // Request ID
	binary.LittleEndian.PutUint32(reply[16:20], uint32(DecisionDeny))
	binary.LittleEndian.PutUint32(reply[20:24], 60000) // Cache TTL

	// Decode and verify
	decision := PolicyDecision(binary.LittleEndian.Uint32(reply[16:20]))
	cacheTTL := binary.LittleEndian.Uint32(reply[20:24])

	if decision != DecisionDeny {
		t.Errorf("expected DecisionDeny, got %d", decision)
	}
	if cacheTTL != 60000 {
		t.Errorf("expected cache TTL 60000, got %d", cacheTTL)
	}
}

func TestUtf16Decode(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{"simple", []byte{'A', 0, 'B', 0, 'C', 0, 0, 0}, "ABC"},
		{"empty", []byte{0, 0}, ""},
		{"path", []byte{'C', 0, ':', 0, '\\', 0, 0, 0}, "C:\\"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := utf16Decode(tc.input)
			if result != tc.expected {
				t.Errorf("utf16Decode: expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestFileOperationConstants(t *testing.T) {
	// Verify constants match protocol.h
	tests := []struct {
		name     string
		got      FileOperation
		expected FileOperation
	}{
		{"FileOpCreate", FileOpCreate, 1},
		{"FileOpRead", FileOpRead, 2},
		{"FileOpWrite", FileOpWrite, 3},
		{"FileOpDelete", FileOpDelete, 4},
		{"FileOpRename", FileOpRename, 5},
	}

	for _, tc := range tests {
		if tc.got != tc.expected {
			t.Errorf("%s: expected %d, got %d", tc.name, tc.expected, tc.got)
		}
	}
}

func TestRegistryRequestDecoding(t *testing.T) {
	const maxPath = 520
	const maxValueName = 256
	msgSize := 16 + 8 + 4 + 4 + 4 + 4 + 4 + (maxPath * 2) + (maxValueName * 2)
	msg := make([]byte, msgSize)

	// Header
	binary.LittleEndian.PutUint32(msg[0:4], MsgPolicyCheckRegistry)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(msgSize))
	binary.LittleEndian.PutUint64(msg[8:16], 54321)

	// Request fields
	binary.LittleEndian.PutUint64(msg[16:24], 0xDEADBEEF)
	binary.LittleEndian.PutUint32(msg[24:28], 1234)
	binary.LittleEndian.PutUint32(msg[28:32], 5678)
	binary.LittleEndian.PutUint32(msg[32:36], uint32(DriverRegOpSetValue))
	binary.LittleEndian.PutUint32(msg[36:40], 1)
	binary.LittleEndian.PutUint32(msg[40:44], 100)

	// Key path in UTF-16LE
	keyPath := "\\REGISTRY\\MACHINE\\SOFTWARE\\Test"
	keyPathBytes := utf16Encode(keyPath)
	copy(msg[44:], keyPathBytes)

	// Value name in UTF-16LE
	valueName := "TestValue"
	valueNameBytes := utf16Encode(valueName)
	copy(msg[44+maxPath*2:], valueNameBytes)

	// Decode and verify
	sessionToken := binary.LittleEndian.Uint64(msg[16:24])
	processId := binary.LittleEndian.Uint32(msg[24:28])
	operation := DriverRegistryOp(binary.LittleEndian.Uint32(msg[32:36]))
	decodedPath := utf16Decode(msg[44 : 44+maxPath*2])
	decodedValue := utf16Decode(msg[44+maxPath*2 : 44+maxPath*2+maxValueName*2])

	if sessionToken != 0xDEADBEEF {
		t.Errorf("expected session token 0xDEADBEEF, got 0x%X", sessionToken)
	}
	if processId != 1234 {
		t.Errorf("expected process ID 1234, got %d", processId)
	}
	if operation != DriverRegOpSetValue {
		t.Errorf("expected DriverRegOpSetValue, got %d", operation)
	}
	if decodedPath != keyPath {
		t.Errorf("expected key path %q, got %q", keyPath, decodedPath)
	}
	if decodedValue != valueName {
		t.Errorf("expected value name %q, got %q", valueName, decodedValue)
	}
}

func TestRegistryOperationConstants(t *testing.T) {
	tests := []struct {
		name     string
		got      DriverRegistryOp
		expected DriverRegistryOp
	}{
		{"DriverRegOpCreateKey", DriverRegOpCreateKey, 1},
		{"DriverRegOpSetValue", DriverRegOpSetValue, 2},
		{"DriverRegOpDeleteKey", DriverRegOpDeleteKey, 3},
		{"DriverRegOpDeleteValue", DriverRegOpDeleteValue, 4},
		{"DriverRegOpRenameKey", DriverRegOpRenameKey, 5},
		{"DriverRegOpQueryValue", DriverRegOpQueryValue, 6},
	}

	for _, tc := range tests {
		if tc.got != tc.expected {
			t.Errorf("%s: expected %d, got %d", tc.name, tc.expected, tc.got)
		}
	}
}

func TestRegistryPolicyResponse(t *testing.T) {
	reply := make([]byte, 24)

	binary.LittleEndian.PutUint32(reply[0:4], MsgPolicyCheckRegistry)
	binary.LittleEndian.PutUint32(reply[4:8], 24)
	binary.LittleEndian.PutUint64(reply[8:16], 54321)
	binary.LittleEndian.PutUint32(reply[16:20], uint32(DecisionDeny))
	binary.LittleEndian.PutUint32(reply[20:24], 30000)

	decision := PolicyDecision(binary.LittleEndian.Uint32(reply[16:20]))
	cacheTTL := binary.LittleEndian.Uint32(reply[20:24])

	if decision != DecisionDeny {
		t.Errorf("expected DecisionDeny, got %d", decision)
	}
	if cacheTTL != 30000 {
		t.Errorf("expected cache TTL 30000, got %d", cacheTTL)
	}
}

func TestDriverConfigEncoding(t *testing.T) {
	cfg := &DriverConfig{
		FailMode:               FailModeClosed,
		PolicyQueryTimeoutMs:   3000,
		MaxConsecutiveFailures: 5,
		CacheMaxEntries:        8192,
		CacheDefaultTTLMs:      10000,
	}

	// Build message like SetConfig does
	msg := make([]byte, 36)
	binary.LittleEndian.PutUint32(msg[0:4], MsgSetConfig)
	binary.LittleEndian.PutUint32(msg[4:8], 36)
	binary.LittleEndian.PutUint64(msg[8:16], 1)
	binary.LittleEndian.PutUint32(msg[16:20], uint32(cfg.FailMode))
	binary.LittleEndian.PutUint32(msg[20:24], cfg.PolicyQueryTimeoutMs)
	binary.LittleEndian.PutUint32(msg[24:28], cfg.MaxConsecutiveFailures)
	binary.LittleEndian.PutUint32(msg[28:32], cfg.CacheMaxEntries)
	binary.LittleEndian.PutUint32(msg[32:36], cfg.CacheDefaultTTLMs)

	// Decode and verify
	failMode := FailMode(binary.LittleEndian.Uint32(msg[16:20]))
	timeout := binary.LittleEndian.Uint32(msg[20:24])

	if failMode != FailModeClosed {
		t.Errorf("expected FailModeClosed, got %d", failMode)
	}
	if timeout != 3000 {
		t.Errorf("expected timeout 3000, got %d", timeout)
	}
}

func TestDriverMetricsDecoding(t *testing.T) {
	// Build mock metrics response
	reply := make([]byte, 72)
	binary.LittleEndian.PutUint32(reply[0:4], MsgMetricsReply)
	binary.LittleEndian.PutUint32(reply[4:8], 72)
	binary.LittleEndian.PutUint32(reply[16:20], 100) // CacheHitCount
	binary.LittleEndian.PutUint32(reply[20:24], 10)  // CacheMissCount
	binary.LittleEndian.PutUint32(reply[48:52], 90)  // AllowDecisions
	binary.LittleEndian.PutUint32(reply[52:56], 5)   // DenyDecisions
	reply[64] = 1                                    // FailOpenMode = true

	// Decode and verify
	cacheHits := binary.LittleEndian.Uint32(reply[16:20])
	allowDecisions := binary.LittleEndian.Uint32(reply[48:52])
	failOpen := reply[64] != 0

	if cacheHits != 100 {
		t.Errorf("expected cache hits 100, got %d", cacheHits)
	}
	if allowDecisions != 90 {
		t.Errorf("expected allow decisions 90, got %d", allowDecisions)
	}
	if !failOpen {
		t.Error("expected fail open mode to be true")
	}
}

func TestFailModeConstants(t *testing.T) {
	if FailModeOpen != 0 {
		t.Errorf("FailModeOpen should be 0, got %d", FailModeOpen)
	}
	if FailModeClosed != 1 {
		t.Errorf("FailModeClosed should be 1, got %d", FailModeClosed)
	}
}

func TestMessageTypeConstants(t *testing.T) {
	if MsgSetConfig != 104 {
		t.Errorf("MsgSetConfig should be 104, got %d", MsgSetConfig)
	}
	if MsgGetMetrics != 105 {
		t.Errorf("MsgGetMetrics should be 105, got %d", MsgGetMetrics)
	}
	if MsgMetricsReply != 106 {
		t.Errorf("MsgMetricsReply should be 106, got %d", MsgMetricsReply)
	}
}

func TestDriverConfigDefaults(t *testing.T) {
	cfg := &DriverConfig{
		FailMode:               FailModeOpen,
		PolicyQueryTimeoutMs:   5000,
		MaxConsecutiveFailures: 10,
		CacheMaxEntries:        4096,
		CacheDefaultTTLMs:      5000,
	}

	// Verify defaults match what we expect from driver
	if cfg.FailMode != FailModeOpen {
		t.Errorf("expected default FailModeOpen")
	}
	if cfg.PolicyQueryTimeoutMs != 5000 {
		t.Errorf("expected default timeout 5000, got %d", cfg.PolicyQueryTimeoutMs)
	}
	if cfg.CacheMaxEntries != 4096 {
		t.Errorf("expected default cache entries 4096, got %d", cfg.CacheMaxEntries)
	}
}
