// internal/shim/mcp_exec_test.go
package shim

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// testBinaryPath returns the absolute path to a real binary for testing.
// Uses "go" since it's always available when running Go tests.
func testBinaryPath(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("go")
	if err != nil {
		t.Skip("cannot find 'go' binary for test")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatalf("cannot resolve absolute path: %v", err)
	}
	return abs
}

func TestMCPExecConfig(t *testing.T) {
	cfg := MCPExecConfig{
		SessionID:       "sess_123",
		ServerID:        "test-server",
		EnableDetection: true,
	}

	if cfg.SessionID != "sess_123" {
		t.Errorf("SessionID = %q, want sess_123", cfg.SessionID)
	}
}

func TestBuildMCPExecWrapper(t *testing.T) {
	cfg := MCPExecConfig{
		SessionID:       "sess_123",
		ServerID:        "test-server",
		EnableDetection: true,
		EventEmitter: func(event interface{}) {
			// Capture events
		},
	}

	wrapper, err := BuildMCPExecWrapper(cfg)
	if err != nil {
		t.Fatalf("BuildMCPExecWrapper failed: %v", err)
	}
	if wrapper == nil {
		t.Fatal("BuildMCPExecWrapper returned nil")
	}
}

func TestMCPExecWrapper_WrapCommand(t *testing.T) {
	var capturedEvents []interface{}
	emitter := func(event interface{}) {
		capturedEvents = append(capturedEvents, event)
	}

	cfg := MCPExecConfig{
		SessionID:       "sess_123",
		ServerID:        "test-server",
		EnableDetection: false,
		EventEmitter:    emitter,
	}

	wrapper, err := BuildMCPExecWrapper(cfg)
	if err != nil {
		t.Fatalf("BuildMCPExecWrapper failed: %v", err)
	}

	// Create a simple command
	cmd := exec.Command("cat")

	cleanup, err := wrapper.WrapCommand(cmd)
	if err != nil {
		t.Fatalf("WrapCommand failed: %v", err)
	}
	defer cleanup()

	// Verify cleanup function is not nil
	if cleanup == nil {
		t.Error("expected non-nil cleanup function")
	}
}

// mockPinStore implements BinaryPinVerifier for testing.
type mockPinStore struct {
	verifyStatus string
	verifyHash   string
	verifyErr    error
	trustErr     error
}

func (m *mockPinStore) TrustBinary(serverID, binaryPath, hash string) error {
	return m.trustErr
}

func (m *mockPinStore) VerifyBinary(serverID, hash string) (status, pinnedHash string, err error) {
	return m.verifyStatus, m.verifyHash, m.verifyErr
}

func TestBuildMCPExecWrapper_TrustBinaryFailure_BlockMode(t *testing.T) {
	bin := testBinaryPath(t)
	store := &mockPinStore{
		verifyStatus: "not_pinned",
		trustErr:     errors.New("db readonly"),
	}

	cfg := MCPExecConfig{
		SessionID:      "sess_1",
		ServerID:       "srv-1",
		Command:        bin,
		PinBinary:      true,
		PinStore:       store,
		AutoTrustFirst: true,
		OnChange:       "block",
	}

	_, err := BuildMCPExecWrapper(cfg)
	if err == nil {
		t.Fatal("expected error when TrustBinary fails in block mode")
	}
	if !strings.Contains(err.Error(), "failed to persist trust") {
		t.Errorf("error should mention persist trust failure, got: %v", err)
	}
}

func TestBuildMCPExecWrapper_TrustBinaryFailure_AlertMode(t *testing.T) {
	bin := testBinaryPath(t)
	store := &mockPinStore{
		verifyStatus: "not_pinned",
		trustErr:     errors.New("db readonly"),
	}

	cfg := MCPExecConfig{
		SessionID:      "sess_1",
		ServerID:       "srv-1",
		Command:        bin,
		PinBinary:      true,
		PinStore:       store,
		AutoTrustFirst: true,
		OnChange:       "alert",
	}

	// In alert mode, TrustBinary failure should log but not block
	wrapper, err := BuildMCPExecWrapper(cfg)
	if err != nil {
		t.Fatalf("alert mode should not error on TrustBinary failure, got: %v", err)
	}
	if wrapper == nil {
		t.Fatal("wrapper should not be nil")
	}
}

func TestBuildMCPExecWrapper_PinMisconfigured_BlockMode(t *testing.T) {
	cfg := MCPExecConfig{
		SessionID: "sess_1",
		ServerID:  "srv-1",
		PinBinary: true,
		PinStore:  nil, // Missing store
		Command:   testBinaryPath(t),
		OnChange:  "block",
	}

	_, err := BuildMCPExecWrapper(cfg)
	if err == nil {
		t.Fatal("expected error when PinStore is nil in block mode")
	}
}

func TestBuildMCPExecWrapper_ResolvedCommand(t *testing.T) {
	bin := testBinaryPath(t)
	store := &mockPinStore{
		verifyStatus: "not_pinned",
	}

	cfg := MCPExecConfig{
		SessionID:      "sess_1",
		ServerID:       "srv-1",
		Command:        bin,
		PinBinary:      true,
		PinStore:       store,
		AutoTrustFirst: true,
		OnChange:       "block",
	}

	wrapper, err := BuildMCPExecWrapper(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resolved := wrapper.ResolvedCommand()
	if resolved == "" {
		t.Fatal("ResolvedCommand should return the absolute path after pin verification")
	}
	if resolved != bin {
		t.Errorf("ResolvedCommand = %q, want %q", resolved, bin)
	}
}

func TestBuildMCPExecWrapper_ResolvedCommand_NoPinning(t *testing.T) {
	cfg := MCPExecConfig{
		SessionID: "sess_1",
		ServerID:  "srv-1",
		PinBinary: false,
	}

	wrapper, err := BuildMCPExecWrapper(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wrapper.ResolvedCommand() != "" {
		t.Errorf("ResolvedCommand should be empty when pin is disabled, got %q", wrapper.ResolvedCommand())
	}
}

func TestBuildMCPExecWrapper_UnknownStatus_BlockMode(t *testing.T) {
	bin := testBinaryPath(t)
	store := &mockPinStore{
		verifyStatus: "something_unexpected",
	}

	cfg := MCPExecConfig{
		SessionID: "sess_1",
		ServerID:  "srv-1",
		Command:   bin,
		PinBinary: true,
		PinStore:  store,
		OnChange:  "block",
	}

	_, err := BuildMCPExecWrapper(cfg)
	if err == nil {
		t.Fatal("expected error for unknown verify status in block mode")
	}
	if !strings.Contains(err.Error(), "unexpected verify status") {
		t.Errorf("error should mention unexpected status, got: %v", err)
	}
}

func TestBuildMCPExecWrapper_UnknownStatus_AlertMode(t *testing.T) {
	bin := testBinaryPath(t)
	store := &mockPinStore{
		verifyStatus: "something_unexpected",
	}

	cfg := MCPExecConfig{
		SessionID: "sess_1",
		ServerID:  "srv-1",
		Command:   bin,
		PinBinary: true,
		PinStore:  store,
		OnChange:  "alert",
	}

	// Alert mode: should log and continue, not error
	wrapper, err := BuildMCPExecWrapper(cfg)
	if err != nil {
		t.Fatalf("alert mode should not error on unknown status, got: %v", err)
	}
	if wrapper == nil {
		t.Fatal("wrapper should not be nil")
	}
}
