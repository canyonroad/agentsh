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
)

// Driver client version
const DriverClientVersion = 0x00010000

// ProcessEventHandler is called when the driver notifies about process events
type ProcessEventHandler func(sessionToken uint64, processId, parentId uint32, createTime uint64, isCreation bool)

// DriverClient communicates with the agentsh.sys mini filter
type DriverClient struct {
	port           windows.Handle
	connected      atomic.Bool
	stopChan       chan struct{}
	wg             sync.WaitGroup
	mu             sync.Mutex
	msgCounter     atomic.Uint64
	processHandler ProcessEventHandler
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

// Ensure unused imports don't cause build errors
var _ = context.Background
