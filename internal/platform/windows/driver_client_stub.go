// internal/platform/windows/driver_client_stub.go
//go:build !windows

package windows

import (
	"encoding/binary"
	"fmt"
)

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
	MsgSetConfig           = 104
	MsgGetMetrics          = 105
	MsgMetricsReply        = 106

	// Exec interception messages
	MsgProcessSuspended = 200
	MsgResumeProcess    = 201
	MsgTerminateProcess = 202
)

// Driver client version
const DriverClientVersion = 0x00010000

// DriverClient stub for non-Windows builds
type DriverClient struct {
	suspendedHandler SuspendedProcessHandler
}

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

// DriverRegistryOp represents the type of registry operation from driver protocol
type DriverRegistryOp uint32

const (
	DriverRegOpCreateKey   DriverRegistryOp = 1
	DriverRegOpSetValue    DriverRegistryOp = 2
	DriverRegOpDeleteKey   DriverRegistryOp = 3
	DriverRegOpDeleteValue DriverRegistryOp = 4
	DriverRegOpRenameKey   DriverRegistryOp = 5
	DriverRegOpQueryValue  DriverRegistryOp = 6
)

// RegistryRequest represents a registry policy check request from the driver
type RegistryRequest struct {
	SessionToken uint64
	ProcessId    uint32
	ThreadId     uint32
	Operation    DriverRegistryOp
	ValueType    uint32
	DataSize     uint32
	KeyPath      string
	ValueName    string
}

// RegistryPolicyHandler is called when the driver requests a registry policy decision
type RegistryPolicyHandler func(req *RegistryRequest) (PolicyDecision, uint32)

// SetProcessEventHandler stub for non-Windows
func (c *DriverClient) SetProcessEventHandler(handler ProcessEventHandler) {
	// No-op on non-Windows
}

// SetFilePolicyHandler stub for non-Windows
func (c *DriverClient) SetFilePolicyHandler(handler FilePolicyHandler) {
	// No-op on non-Windows
}

// SetRegistryPolicyHandler stub for non-Windows
func (c *DriverClient) SetRegistryPolicyHandler(handler RegistryPolicyHandler) {
	// No-op on non-Windows
}

// FailMode represents the driver fail mode
type FailMode uint32

const (
	FailModeOpen   FailMode = 0
	FailModeClosed FailMode = 1
)

// DriverConfig represents driver configuration
type DriverConfig struct {
	FailMode               FailMode
	PolicyQueryTimeoutMs   uint32
	MaxConsecutiveFailures uint32
	CacheMaxEntries        uint32
	CacheDefaultTTLMs      uint32
}

// DriverMetrics represents driver metrics
type DriverMetrics struct {
	CacheHitCount         uint32
	CacheMissCount        uint32
	CacheEntryCount       uint32
	CacheEvictionCount    uint32
	FilePolicyQueries     uint32
	RegistryPolicyQueries uint32
	PolicyQueryTimeouts   uint32
	PolicyQueryFailures   uint32
	AllowDecisions        uint32
	DenyDecisions         uint32
	ActiveSessions        uint32
	TrackedProcesses      uint32
	FailOpenMode          bool
	ConsecutiveFailures   uint32
}

// SetConfig stub for non-Windows
func (c *DriverClient) SetConfig(cfg *DriverConfig) error {
	return fmt.Errorf("driver client only available on Windows")
}

// GetMetrics stub for non-Windows
func (c *DriverClient) GetMetrics() (*DriverMetrics, error) {
	return nil, fmt.Errorf("driver client only available on Windows")
}

// ExcludeSelf stub for non-Windows
func (c *DriverClient) ExcludeSelf() error {
	return fmt.Errorf("driver client only available on Windows")
}

// ExecDecision represents the decision for a suspended process
type ExecDecision uint32

const (
	ExecDecisionResume    ExecDecision = 0
	ExecDecisionTerminate ExecDecision = 1
	ExecDecisionRedirect  ExecDecision = 2
)

// SuspendedProcessRequest contains information about a process suspended by the driver
type SuspendedProcessRequest struct {
	SessionToken uint64
	ProcessId    uint32
	ParentId     uint32
	CreateTime   uint64
	ImagePath    string
	CommandLine  string
}

// SuspendedProcessHandler is called when the driver notifies about a suspended process
type SuspendedProcessHandler func(req *SuspendedProcessRequest) ExecDecision

// SetSuspendedProcessHandler stub for non-Windows
func (c *DriverClient) SetSuspendedProcessHandler(handler SuspendedProcessHandler) {
	c.suspendedHandler = handler
}

// handleSuspendedProcess decodes a MsgProcessSuspended message, calls the handler,
// and builds the appropriate reply.
func (c *DriverClient) handleSuspendedProcess(msg []byte, reply []byte) int {
	const maxPath = 520
	const maxCmdLine = 2048
	const minSize = 16 + 8 + 4 + 4 + 8 + 8 // header + token + pid + ppid + createTime + padding

	if len(msg) < minSize {
		return 0
	}
	if len(reply) < 24 {
		return 0
	}

	requestId := binary.LittleEndian.Uint64(msg[8:16])

	req := &SuspendedProcessRequest{
		SessionToken: binary.LittleEndian.Uint64(msg[16:24]),
		ProcessId:    binary.LittleEndian.Uint32(msg[24:28]),
		ParentId:     binary.LittleEndian.Uint32(msg[28:32]),
		CreateTime:   binary.LittleEndian.Uint64(msg[32:40]),
	}

	// Decode imagePath (UTF-16LE at offset 48)
	if len(msg) >= 48+maxPath*2 {
		req.ImagePath = utf16Decode(msg[48 : 48+maxPath*2])
	}
	// Decode cmdLine (UTF-16LE at offset 48 + maxPath*2)
	cmdLineStart := 48 + maxPath*2
	if len(msg) >= cmdLineStart+maxCmdLine*2 {
		req.CommandLine = utf16Decode(msg[cmdLineStart : cmdLineStart+maxCmdLine*2])
	}

	// Call handler or default to resume (fail-open)
	decision := ExecDecisionResume
	if c.suspendedHandler != nil {
		decision = c.suspendedHandler(req)
	}

	// Build reply: header(16) + decision(4) + reserved(4) = 24
	var replyMsgType uint32
	switch decision {
	case ExecDecisionResume:
		replyMsgType = MsgResumeProcess
	case ExecDecisionTerminate:
		replyMsgType = MsgTerminateProcess
	case ExecDecisionRedirect:
		// Redirect: tell driver to terminate, Go-side handles the redirect
		replyMsgType = MsgTerminateProcess
	default:
		replyMsgType = MsgResumeProcess
	}

	binary.LittleEndian.PutUint32(reply[0:4], replyMsgType)
	binary.LittleEndian.PutUint32(reply[4:8], 24)
	binary.LittleEndian.PutUint64(reply[8:16], requestId)
	binary.LittleEndian.PutUint32(reply[16:20], uint32(decision))
	binary.LittleEndian.PutUint32(reply[20:24], 0) // reserved

	return 24
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
