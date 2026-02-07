package stub

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Wire protocol message types for the agentsh stub <-> server communication.
// Frame format: [1 byte type][4 bytes length big-endian][payload]
const (
	MsgReady  = byte(0x01) // stub -> server: ready to receive
	MsgStdout = byte(0x02) // server -> stub: stdout data
	MsgStderr = byte(0x03) // server -> stub: stderr data
	MsgStdin  = byte(0x04) // stub -> server: stdin data
	MsgExit   = byte(0x05) // server -> stub: exit code (4 bytes big-endian int32)
	MsgError  = byte(0x06) // server -> stub: error message
)

// headerSize is the size of the frame header: 1 byte type + 4 bytes length.
const headerSize = 5

// MakeFrame constructs a wire protocol frame from a message type and payload.
func MakeFrame(msgType byte, payload []byte) []byte {
	frame := make([]byte, headerSize+len(payload))
	frame[0] = msgType
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[headerSize:], payload)
	return frame
}

// ReadFrame reads a single wire protocol frame from the reader, returning
// the message type and payload. Returns io.EOF if the connection is closed.
func ReadFrame(r io.Reader) (msgType byte, payload []byte, err error) {
	header := make([]byte, headerSize)
	if _, err = io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	msgType = header[0]
	length := binary.BigEndian.Uint32(header[1:5])

	// Sanity check: reject frames larger than 16 MiB.
	const maxPayload = 16 << 20
	if length > maxPayload {
		return 0, nil, fmt.Errorf("frame payload too large: %d bytes", length)
	}

	payload = make([]byte, length)
	if length > 0 {
		if _, err = io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return msgType, payload, nil
}
