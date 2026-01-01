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

// DriverClient communicates with the agentsh.sys mini filter
type DriverClient struct {
	port       windows.Handle
	connected  atomic.Bool
	stopChan   chan struct{}
	wg         sync.WaitGroup
	mu         sync.Mutex
	msgCounter atomic.Uint64
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

// Ensure unused imports don't cause build errors
var _ = context.Background
