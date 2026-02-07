package stub

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"
	"syscall"
)

// ServeConfig configures the server-side stub handler.
type ServeConfig struct {
	Command    string
	Args       []string
	Env        []string
	WorkingDir string
}

// ServeStubConnection handles one stub connection. It waits for the stub's
// ready message, starts the command, proxies stdout/stderr to the stub,
// forwards stdin from the stub to the command, and sends the exit code.
func ServeStubConnection(ctx context.Context, conn net.Conn, cfg ServeConfig) error {
	defer conn.Close()

	// Wait for ready.
	msgType, _, err := ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("waiting for ready: %w", err)
	}
	if msgType != MsgReady {
		return fmt.Errorf("expected ready (0x%02x), got 0x%02x", MsgReady, msgType)
	}

	// Start command.
	cmd := exec.CommandContext(ctx, cfg.Command, cfg.Args[1:]...)
	if cfg.WorkingDir != "" {
		cmd.Dir = cfg.WorkingDir
	}
	if len(cfg.Env) > 0 {
		cmd.Env = cfg.Env
	}

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		sendError(conn, fmt.Sprintf("stdin pipe: %v", err))
		return err
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		sendError(conn, fmt.Sprintf("stdout pipe: %v", err))
		return err
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		sendError(conn, fmt.Sprintf("stderr pipe: %v", err))
		return err
	}

	if err := cmd.Start(); err != nil {
		sendError(conn, fmt.Sprintf("start: %v", err))
		return err
	}

	// Proxy I/O.
	var ioWg sync.WaitGroup

	// stdout -> stub
	ioWg.Add(1)
	go func() {
		defer ioWg.Done()
		pipeToFrame(stdoutPipe, conn, MsgStdout)
	}()

	// stderr -> stub
	ioWg.Add(1)
	go func() {
		defer ioWg.Done()
		pipeToFrame(stderrPipe, conn, MsgStderr)
	}()

	// stdin from stub -> command. This goroutine runs independently; it
	// will terminate when the connection is closed (deferred above) after
	// the exit frame has been sent and the function returns.
	go func() {
		defer stdinPipe.Close()
		for {
			mt, payload, rerr := ReadFrame(conn)
			if rerr != nil {
				return
			}
			if mt == MsgStdin && len(payload) > 0 {
				if _, werr := stdinPipe.Write(payload); werr != nil {
					return
				}
			}
		}
	}()

	// Wait for stdout/stderr to drain, then wait for process.
	ioWg.Wait()
	waitErr := cmd.Wait()

	// Determine exit code.
	exitCode := 0
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				exitCode = ws.ExitStatus()
			}
		} else {
			exitCode = 126
		}
	}

	// Send exit code frame.
	frame := make([]byte, 9)
	frame[0] = MsgExit
	binary.BigEndian.PutUint32(frame[1:5], 4)
	binary.BigEndian.PutUint32(frame[5:9], uint32(int32(exitCode)))
	_, _ = conn.Write(frame)

	return nil
}

// pipeToFrame reads from r and writes framed messages of the given type to conn.
func pipeToFrame(r io.Reader, conn net.Conn, msgType byte) {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			frame := MakeFrame(msgType, buf[:n])
			if _, werr := conn.Write(frame); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// sendError sends an error message frame to the stub.
func sendError(conn net.Conn, msg string) {
	frame := MakeFrame(MsgError, []byte(msg))
	_, _ = conn.Write(frame)
}
