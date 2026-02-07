package stub

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// RunProxy connects the stub to the agentsh server over conn,
// forwarding stdin/stdout/stderr and returning the remote exit code.
//
// Flow:
//  1. Send MsgReady to signal that the stub is ready.
//  2. If stdin is provided, forward it in a background goroutine as MsgStdin frames.
//  3. Read frames from the server in a loop:
//     - MsgStdout: write payload to stdout
//     - MsgStderr: write payload to stderr
//     - MsgExit:   extract int32 exit code, return it
//     - MsgError:  return the payload as an error
func RunProxy(conn net.Conn, stdin io.Reader, stdout, stderr io.Writer) (exitCode int, err error) {
	// Step 1: send MsgReady.
	readyFrame := MakeFrame(MsgReady, nil)
	if _, err := conn.Write(readyFrame); err != nil {
		return -1, fmt.Errorf("failed to send ready: %w", err)
	}

	// Step 2: forward stdin in background if provided.
	if stdin != nil {
		go forwardStdin(conn, stdin)
	}

	// Step 3: read frames from server.
	for {
		msgType, payload, err := ReadFrame(conn)
		if err != nil {
			return -1, fmt.Errorf("failed to read frame: %w", err)
		}

		switch msgType {
		case MsgStdout:
			if _, err := stdout.Write(payload); err != nil {
				return -1, fmt.Errorf("failed to write stdout: %w", err)
			}
		case MsgStderr:
			if _, err := stderr.Write(payload); err != nil {
				return -1, fmt.Errorf("failed to write stderr: %w", err)
			}
		case MsgExit:
			if len(payload) < 4 {
				return -1, fmt.Errorf("exit frame payload too short: %d bytes", len(payload))
			}
			code := int32(binary.BigEndian.Uint32(payload[:4]))
			return int(code), nil
		case MsgError:
			return -1, fmt.Errorf("server error: %s", string(payload))
		default:
			// Unknown message type; ignore for forward compatibility.
		}
	}
}

// forwardStdin reads from stdin and sends MsgStdin frames to the server.
// On EOF, sends a MsgStdinClose frame so the server can close the command's stdin pipe.
func forwardStdin(conn net.Conn, stdin io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, err := stdin.Read(buf)
		if n > 0 {
			frame := MakeFrame(MsgStdin, buf[:n])
			if _, werr := conn.Write(frame); werr != nil {
				return
			}
		}
		if err != nil {
			// Signal stdin EOF to the server
			closeFrame := MakeFrame(MsgStdinClose, nil)
			conn.Write(closeFrame) //nolint:errcheck
			return
		}
	}
}
