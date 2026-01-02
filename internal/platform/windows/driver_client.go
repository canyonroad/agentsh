// internal/platform/windows/driver_client.go
//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
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
)

// Driver client version
const DriverClientVersion = 0x00010000

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

// DriverClient communicates with the agentsh.sys mini filter
type DriverClient struct {
	port                  windows.Handle
	connected             atomic.Bool
	stopChan              chan struct{}
	wg                    sync.WaitGroup
	mu                    sync.Mutex
	msgCounter            atomic.Uint64
	processHandler        ProcessEventHandler
	filePolicyHandler     FilePolicyHandler
	registryPolicyHandler RegistryPolicyHandler
}

// NewDriverClient creates a new driver client
func NewDriverClient() *DriverClient {
	return &DriverClient{
		stopChan: make(chan struct{}),
	}
}

// Connect establishes connection to the mini filter driver
func (c *DriverClient) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected.Load() {
		return fmt.Errorf("already connected")
	}

	portName, err := windows.UTF16PtrFromString(`\AgentshPort`)
	if err != nil {
		return fmt.Errorf("invalid port name: %w", err)
	}

	// Connection context
	ctx := struct {
		ClientVersion uint32
		ClientPid     uint32
	}{
		ClientVersion: DriverClientVersion,
		ClientPid:     uint32(windows.GetCurrentProcessId()),
	}

	var port windows.Handle
	err = filterConnectCommunicationPort(
		portName,
		0,
		unsafe.Pointer(&ctx),
		uint16(unsafe.Sizeof(ctx)),
		nil,
		&port,
	)
	if err != nil {
		return fmt.Errorf("failed to connect to driver: %w", err)
	}

	c.port = port
	c.connected.Store(true)

	// Start message loop
	c.wg.Add(1)
	go c.messageLoop()

	return nil
}

// Disconnect closes the connection to the driver
func (c *DriverClient) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected.Load() {
		return nil
	}

	close(c.stopChan)
	c.wg.Wait()

	if c.port != 0 {
		windows.CloseHandle(c.port)
		c.port = 0
	}

	c.connected.Store(false)
	c.stopChan = make(chan struct{})

	return nil
}

// Connected returns whether the client is connected
func (c *DriverClient) Connected() bool {
	return c.connected.Load()
}

// SetProcessEventHandler sets the callback for process events
func (c *DriverClient) SetProcessEventHandler(handler ProcessEventHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processHandler = handler
}

// SetFilePolicyHandler sets the callback for file policy requests
func (c *DriverClient) SetFilePolicyHandler(handler FilePolicyHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.filePolicyHandler = handler
}

// SetRegistryPolicyHandler sets the callback for registry policy requests
func (c *DriverClient) SetRegistryPolicyHandler(handler RegistryPolicyHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.registryPolicyHandler = handler
}

// messageLoop handles incoming messages from the driver
func (c *DriverClient) messageLoop() {
	defer c.wg.Done()

	msgBuf := make([]byte, 4096)
	replyBuf := make([]byte, 512)

	for {
		select {
		case <-c.stopChan:
			return
		default:
		}

		// Get message from driver with timeout
		var bytesReturned uint32
		err := filterGetMessage(c.port, msgBuf, uint32(len(msgBuf)), &bytesReturned)
		if err != nil {
			// Timeout or error, check if we should stop
			select {
			case <-c.stopChan:
				return
			default:
				continue
			}
		}

		// Handle message
		replyLen := c.handleMessage(msgBuf[:bytesReturned], replyBuf)
		if replyLen > 0 {
			_ = filterReplyMessage(c.port, replyBuf[:replyLen])
		}
	}
}

// handleMessage processes a message from the driver
func (c *DriverClient) handleMessage(msg []byte, reply []byte) int {
	if len(msg) < 12 { // Minimum header size
		return 0
	}

	msgType := binary.LittleEndian.Uint32(msg[0:4])
	// size := binary.LittleEndian.Uint32(msg[4:8])
	requestId := binary.LittleEndian.Uint64(msg[8:16])

	switch msgType {
	case MsgPing:
		return c.handlePing(msg, reply, requestId)
	case MsgPolicyCheckFile:
		return c.handleFilePolicyCheck(msg, reply)
	case MsgPolicyCheckRegistry:
		return c.handleRegistryPolicyCheck(msg, reply)
	case MsgProcessCreated:
		return c.handleProcessEvent(msg, true)
	case MsgProcessTerminated:
		return c.handleProcessEvent(msg, false)
	default:
		// Unknown message type
		return 0
	}
}

// handlePing responds to a ping from the driver
func (c *DriverClient) handlePing(msg []byte, reply []byte, requestId uint64) int {
	// Build pong response
	binary.LittleEndian.PutUint32(reply[0:4], MsgPong)
	binary.LittleEndian.PutUint32(reply[4:8], 24) // Size
	binary.LittleEndian.PutUint64(reply[8:16], requestId)
	binary.LittleEndian.PutUint32(reply[16:20], DriverClientVersion)
	binary.LittleEndian.PutUint64(reply[20:28], uint64(time.Now().UnixNano()))

	return 28
}

// handleProcessEvent processes process creation/termination notifications
func (c *DriverClient) handleProcessEvent(msg []byte, isCreation bool) int {
	// Message format: header (16) + token (8) + pid (4) + ppid (4) + createTime (8)
	if len(msg) < 40 {
		return 0
	}

	sessionToken := binary.LittleEndian.Uint64(msg[16:24])
	processId := binary.LittleEndian.Uint32(msg[24:28])
	parentId := binary.LittleEndian.Uint32(msg[28:32])
	createTime := binary.LittleEndian.Uint64(msg[32:40])

	c.mu.Lock()
	handler := c.processHandler
	c.mu.Unlock()

	if handler != nil {
		handler(sessionToken, processId, parentId, createTime, isCreation)
	}

	return 0 // No reply needed for notifications
}

// handleFilePolicyCheck handles file policy check requests from driver
func (c *DriverClient) handleFilePolicyCheck(msg []byte, reply []byte) int {
	// Minimum size: header(16) + token(8) + pid(4) + tid(4) + op(4) + disp(4) + access(4)
	const minSize = 16 + 8 + 4 + 4 + 4 + 4 + 4
	if len(msg) < minSize {
		return 0
	}

	req := &FileRequest{
		SessionToken:      binary.LittleEndian.Uint64(msg[16:24]),
		ProcessId:         binary.LittleEndian.Uint32(msg[24:28]),
		ThreadId:          binary.LittleEndian.Uint32(msg[28:32]),
		Operation:         FileOperation(binary.LittleEndian.Uint32(msg[32:36])),
		CreateDisposition: binary.LittleEndian.Uint32(msg[36:40]),
		DesiredAccess:     binary.LittleEndian.Uint32(msg[40:44]),
	}

	// Decode path (UTF-16LE)
	const maxPath = 520
	if len(msg) >= 44+maxPath*2 {
		req.Path = utf16Decode(msg[44 : 44+maxPath*2])
	}
	if len(msg) >= 44+maxPath*4 {
		req.RenameDest = utf16Decode(msg[44+maxPath*2 : 44+maxPath*4])
	}

	// Get handler
	c.mu.Lock()
	handler := c.filePolicyHandler
	c.mu.Unlock()

	// Default to allow
	decision := DecisionAllow
	cacheTTL := uint32(5000)

	if handler != nil {
		decision, cacheTTL = handler(req)
	}

	// Build response: header(16) + decision(4) + cacheTTL(4)
	requestId := binary.LittleEndian.Uint64(msg[8:16])
	binary.LittleEndian.PutUint32(reply[0:4], MsgPolicyCheckFile)
	binary.LittleEndian.PutUint32(reply[4:8], 24)
	binary.LittleEndian.PutUint64(reply[8:16], requestId)
	binary.LittleEndian.PutUint32(reply[16:20], uint32(decision))
	binary.LittleEndian.PutUint32(reply[20:24], cacheTTL)

	return 24
}

// handleRegistryPolicyCheck handles registry policy check requests from driver
func (c *DriverClient) handleRegistryPolicyCheck(msg []byte, reply []byte) int {
	const minSize = 16 + 8 + 4 + 4 + 4 + 4 + 4
	if len(msg) < minSize {
		return 0
	}

	const maxPath = 520
	const maxValueName = 256

	req := &RegistryRequest{
		SessionToken: binary.LittleEndian.Uint64(msg[16:24]),
		ProcessId:    binary.LittleEndian.Uint32(msg[24:28]),
		ThreadId:     binary.LittleEndian.Uint32(msg[28:32]),
		Operation:    DriverRegistryOp(binary.LittleEndian.Uint32(msg[32:36])),
		ValueType:    binary.LittleEndian.Uint32(msg[36:40]),
		DataSize:     binary.LittleEndian.Uint32(msg[40:44]),
	}

	keyPathStart := 44
	if len(msg) >= keyPathStart+maxPath*2 {
		req.KeyPath = utf16Decode(msg[keyPathStart : keyPathStart+maxPath*2])
	}

	valueNameStart := keyPathStart + maxPath*2
	if len(msg) >= valueNameStart+maxValueName*2 {
		req.ValueName = utf16Decode(msg[valueNameStart : valueNameStart+maxValueName*2])
	}

	c.mu.Lock()
	handler := c.registryPolicyHandler
	c.mu.Unlock()

	decision := DecisionAllow
	cacheTTL := uint32(5000)

	if handler != nil {
		decision, cacheTTL = handler(req)
	}

	requestId := binary.LittleEndian.Uint64(msg[8:16])
	binary.LittleEndian.PutUint32(reply[0:4], MsgPolicyCheckRegistry)
	binary.LittleEndian.PutUint32(reply[4:8], 24)
	binary.LittleEndian.PutUint64(reply[8:16], requestId)
	binary.LittleEndian.PutUint32(reply[16:20], uint32(decision))
	binary.LittleEndian.PutUint32(reply[20:24], cacheTTL)

	return 24
}

// SendPong sends a pong message to the driver (for testing)
func (c *DriverClient) SendPong() error {
	if !c.connected.Load() {
		return fmt.Errorf("not connected")
	}

	msg := make([]byte, 28)
	binary.LittleEndian.PutUint32(msg[0:4], MsgPong)
	binary.LittleEndian.PutUint32(msg[4:8], 28)
	binary.LittleEndian.PutUint64(msg[8:16], c.msgCounter.Add(1))
	binary.LittleEndian.PutUint32(msg[16:20], DriverClientVersion)
	binary.LittleEndian.PutUint64(msg[20:28], uint64(time.Now().UnixNano()))

	return filterSendMessage(c.port, msg, nil)
}

// RegisterSession registers a session with the driver
func (c *DriverClient) RegisterSession(sessionToken uint64, rootPid uint32, workspacePath string) error {
	if !c.connected.Load() {
		return fmt.Errorf("not connected")
	}

	// Build message: header (16) + token (8) + pid (4) + path (520*2)
	const maxPath = 520
	msgSize := 16 + 8 + 4 + (maxPath * 2)
	msg := make([]byte, msgSize)

	// Header
	binary.LittleEndian.PutUint32(msg[0:4], MsgRegisterSession)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(msgSize))
	binary.LittleEndian.PutUint64(msg[8:16], c.msgCounter.Add(1))

	// Session token
	binary.LittleEndian.PutUint64(msg[16:24], sessionToken)

	// Root process ID
	binary.LittleEndian.PutUint32(msg[24:28], rootPid)

	// Workspace path (UTF-16LE, null-terminated)
	if workspacePath != "" {
		pathBytes := utf16Encode(workspacePath)
		maxBytes := maxPath * 2
		if len(pathBytes) > maxBytes {
			pathBytes = pathBytes[:maxBytes-2] // Leave room for null terminator
		}
		copy(msg[28:], pathBytes)
	}

	return filterSendMessage(c.port, msg, nil)
}

// UnregisterSession unregisters a session from the driver
func (c *DriverClient) UnregisterSession(sessionToken uint64) error {
	if !c.connected.Load() {
		return fmt.Errorf("not connected")
	}

	// Build message: header (16) + token (8)
	msgSize := 24
	msg := make([]byte, msgSize)

	// Header
	binary.LittleEndian.PutUint32(msg[0:4], MsgUnregisterSession)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(msgSize))
	binary.LittleEndian.PutUint64(msg[8:16], c.msgCounter.Add(1))

	// Session token
	binary.LittleEndian.PutUint64(msg[16:24], sessionToken)

	return filterSendMessage(c.port, msg, nil)
}

// SetConfig sends configuration to the driver
func (c *DriverClient) SetConfig(cfg *DriverConfig) error {
	if !c.connected.Load() {
		return fmt.Errorf("not connected")
	}

	// Build message: header(16) + failMode(4) + timeout(4) + maxFail(4) + cacheMax(4) + cacheTTL(4)
	msgSize := 16 + 4 + 4 + 4 + 4 + 4
	msg := make([]byte, msgSize)

	binary.LittleEndian.PutUint32(msg[0:4], MsgSetConfig)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(msgSize))
	binary.LittleEndian.PutUint64(msg[8:16], c.msgCounter.Add(1))
	binary.LittleEndian.PutUint32(msg[16:20], uint32(cfg.FailMode))
	binary.LittleEndian.PutUint32(msg[20:24], cfg.PolicyQueryTimeoutMs)
	binary.LittleEndian.PutUint32(msg[24:28], cfg.MaxConsecutiveFailures)
	binary.LittleEndian.PutUint32(msg[28:32], cfg.CacheMaxEntries)
	binary.LittleEndian.PutUint32(msg[32:36], cfg.CacheDefaultTTLMs)

	return filterSendMessage(c.port, msg, nil)
}

// GetMetrics retrieves current metrics from the driver
func (c *DriverClient) GetMetrics() (*DriverMetrics, error) {
	if !c.connected.Load() {
		return nil, fmt.Errorf("not connected")
	}

	// Build request
	msgSize := 16
	msg := make([]byte, msgSize)
	binary.LittleEndian.PutUint32(msg[0:4], MsgGetMetrics)
	binary.LittleEndian.PutUint32(msg[4:8], uint32(msgSize))
	binary.LittleEndian.PutUint64(msg[8:16], c.msgCounter.Add(1))

	// Response buffer
	reply := make([]byte, 128)

	err := filterSendMessage(c.port, msg, reply)
	if err != nil {
		return nil, err
	}

	// Parse response (header(16) + metrics fields)
	if len(reply) < 72 {
		return nil, fmt.Errorf("response too short")
	}

	return &DriverMetrics{
		CacheHitCount:         binary.LittleEndian.Uint32(reply[16:20]),
		CacheMissCount:        binary.LittleEndian.Uint32(reply[20:24]),
		CacheEntryCount:       binary.LittleEndian.Uint32(reply[24:28]),
		CacheEvictionCount:    binary.LittleEndian.Uint32(reply[28:32]),
		FilePolicyQueries:     binary.LittleEndian.Uint32(reply[32:36]),
		RegistryPolicyQueries: binary.LittleEndian.Uint32(reply[36:40]),
		PolicyQueryTimeouts:   binary.LittleEndian.Uint32(reply[40:44]),
		PolicyQueryFailures:   binary.LittleEndian.Uint32(reply[44:48]),
		AllowDecisions:        binary.LittleEndian.Uint32(reply[48:52]),
		DenyDecisions:         binary.LittleEndian.Uint32(reply[52:56]),
		ActiveSessions:        binary.LittleEndian.Uint32(reply[56:60]),
		TrackedProcesses:      binary.LittleEndian.Uint32(reply[60:64]),
		FailOpenMode:          reply[64] != 0,
		ConsecutiveFailures:   binary.LittleEndian.Uint32(reply[68:72]),
	}, nil
}

// utf16Encode converts a Go string to UTF-16LE bytes
func utf16Encode(s string) []byte {
	runes := []rune(s)
	result := make([]byte, len(runes)*2+2) // +2 for null terminator

	for i, r := range runes {
		binary.LittleEndian.PutUint16(result[i*2:], uint16(r))
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
		r := rune(binary.LittleEndian.Uint16(b[i : i+2]))
		if r == 0 {
			break
		}
		runes = append(runes, r)
	}
	return string(runes)
}

// Ensure unused imports don't cause build errors
var _ = context.Background
