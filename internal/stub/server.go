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
	// Command is the executable path.
	Command string

	// Args is the full argv (Args[0] is typically the command name).
	// If empty, only Command is used.
	Args []string

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

	// Build args safely: Args[0] is the command name (argv[0]), rest are actual args.
	var cmdArgs []string
	if len(cfg.Args) > 1 {
		cmdArgs = cfg.Args[1:]
	}

	// Start command.
	cmd := exec.CommandContext(ctx, cfg.Command, cmdArgs...)
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

	// connWriter serializes frame writes to the connection, preventing
	// interleaved/corrupted framing from concurrent stdout/stderr/exit goroutines.
	cw := &connWriter{conn: conn}

	// Proxy I/O.
	var ioWg sync.WaitGroup

	// stdout -> stub
	ioWg.Add(1)
	go func() {
		defer ioWg.Done()
		pipeToFrame(stdoutPipe, cw, MsgStdout)
	}()

	// stderr -> stub
	ioWg.Add(1)
	go func() {
		defer ioWg.Done()
		pipeToFrame(stderrPipe, cw, MsgStderr)
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
			switch mt {
			case MsgStdin:
				if len(payload) > 0 {
					if _, werr := stdinPipe.Write(payload); werr != nil {
						return
					}
				}
			case MsgStdinClose:
				// Client signaled stdin EOF; close the command's stdin pipe
				// so the command receives EOF on its stdin.
				return
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
	cw.WriteFrame(frame)

	return nil
}

// connWriter serializes writes to a net.Conn using a mutex.
// This prevents interleaved frames from concurrent goroutines.
type connWriter struct {
	mu   sync.Mutex
	conn net.Conn
}

// WriteFrame writes a complete frame to the connection under the mutex.
func (w *connWriter) WriteFrame(frame []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.conn.Write(frame)
	return err
}

// pipeToFrame reads from r and writes framed messages of the given type to the writer.
func pipeToFrame(r io.Reader, cw *connWriter, msgType byte) {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			frame := MakeFrame(msgType, buf[:n])
			if werr := cw.WriteFrame(frame); werr != nil {
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
