// internal/platform/windows/driver_client_stub.go
//go:build !windows

package windows

import "fmt"

// Message types (must match protocol.h)
const (
	MsgPing                = 0
	MsgPolicyCheckFile     = 1
	MsgPolicyCheckRegistry = 2
	MsgProcessCreated      = 3
	MsgProcessTerminated   = 4
	MsgPong                = 50
	MsgRegisterSession     = 100
	MsgUnregisterSession   = 101
)

// Driver client version
const DriverClientVersion = 0x00010000

// DriverClient stub for non-Windows builds
type DriverClient struct{}

// NewDriverClient creates a stub driver client
func NewDriverClient() *DriverClient {
	return &DriverClient{}
}

// Connect always fails on non-Windows
func (c *DriverClient) Connect() error {
	return fmt.Errorf("driver client only available on Windows")
}

// Disconnect is a no-op on non-Windows
func (c *DriverClient) Disconnect() error {
	return nil
}

// Connected always returns false on non-Windows
func (c *DriverClient) Connected() bool {
	return false
}

// SendPong is a no-op on non-Windows
func (c *DriverClient) SendPong() error {
	return fmt.Errorf("driver client only available on Windows")
}

// RegisterSession stub for non-Windows
func (c *DriverClient) RegisterSession(sessionToken uint64, rootPid uint32, workspacePath string) error {
	return fmt.Errorf("driver client only available on Windows")
}

// UnregisterSession stub for non-Windows
func (c *DriverClient) UnregisterSession(sessionToken uint64) error {
	return fmt.Errorf("driver client only available on Windows")
}

// ProcessEventHandler is called when the driver notifies about process events
type ProcessEventHandler func(sessionToken uint64, processId, parentId uint32, createTime uint64, isCreation bool)

// FileOperation represents the type of file operation
type FileOperation uint32

const (
	FileOpCreate FileOperation = 1
	FileOpRead   FileOperation = 2
	FileOpWrite  FileOperation = 3
	FileOpDelete FileOperation = 4
	FileOpRename FileOperation = 5
)

// FileRequest represents a file policy check request from the driver
type FileRequest struct {
	SessionToken      uint64
	ProcessId         uint32
	ThreadId          uint32
	Operation         FileOperation
	CreateDisposition uint32
	DesiredAccess     uint32
	Path              string
	RenameDest        string
}

// PolicyDecision represents a policy decision
type PolicyDecision uint32

const (
	DecisionAllow   PolicyDecision = 0
	DecisionDeny    PolicyDecision = 1
	DecisionPending PolicyDecision = 2
)

// FilePolicyHandler is called when the driver requests a file policy decision
type FilePolicyHandler func(req *FileRequest) (PolicyDecision, uint32)

// SetProcessEventHandler stub for non-Windows
func (c *DriverClient) SetProcessEventHandler(handler ProcessEventHandler) {
	// No-op on non-Windows
}

// SetFilePolicyHandler stub for non-Windows
func (c *DriverClient) SetFilePolicyHandler(handler FilePolicyHandler) {
	// No-op on non-Windows
}

// utf16Encode converts a Go string to UTF-16LE bytes
func utf16Encode(s string) []byte {
	runes := []rune(s)
	result := make([]byte, len(runes)*2+2) // +2 for null terminator

	for i, r := range runes {
		result[i*2] = byte(r)
		result[i*2+1] = byte(r >> 8)
	}
	// Null terminator already zero from make()

	return result
}

// utf16Decode decodes UTF-16LE bytes to a Go string (stops at null terminator)
func utf16Decode(b []byte) string {
	if len(b) < 2 {
		return ""
	}

	// Find null terminator
	var runes []rune
	for i := 0; i+1 < len(b); i += 2 {
		r := rune(uint16(b[i]) | uint16(b[i+1])<<8)
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}
